from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Literal
import re
import json
import argparse
import sys

RULES_PATH = Path(__file__).resolve().parent / "rules.json"


# Use dataclass to automatically generate init, repr, and comparison methods.
# frozen=True makes HashCandidate immutable, and slots=True reduces memory usage.
@dataclass(frozen=True, slots=True)
class HashCandidate:
    # Represents a candidate hash identification result.
    # algorithm: the detected hash algorithm name.
    # confidence: how confident the detection is.
    # reason: why this candidate was selected.
    algorithm: str
    confidence: Literal["high", "medium", "low"]
    reason: str


def _is_hex(text):
    # Check whether the string contains only hexadecimal characters.
    # This is used to identify hash types represented as a hex string.
    return bool(re.match(r"^[0-9a-fA-F]+$", text))


def _is_mysql5(text):
    # Check whether the string follows the MySQL5 hash format.
    # MySQL5 hashes start with '*' and contain 40 uppercase hex digits after it.
    return text.startswith("*") and len(text) == 41 and bool(re.match(r"^[0-9A-F]+$", text[1:]))


def _is_netntlm(text):
    # Check whether the string matches the NetNTLM hash shape.
    # Format is user::domain:challenge:response:... with an 8-byte hex
    # challenge and a 24-byte (or longer) hex response.
    parts = text.split(":")
    if len(parts) != 6 or parts[1] != "":
        return False
    challenge, response = parts[3], parts[4]
    return (
        len(challenge) == 16 and _is_hex(challenge)
        and len(response) >= 48 and _is_hex(response)
    )


def _is_descrypt(text):
    # Check whether the string matches the DES-Crypt hash format.
    # DES-Crypt hashes are 13 characters long and use the ./0-9A-Za-z alphabet.
    return bool(re.match(r"^[./0-9a-zA-Z]{13}$", text))


def detect_by_prefix(text, prefix_rules):
    # Detect a hash type based on a predefined prefix rule set.
    # Returns a HashCandidate when the input starts with a known prefix.
    # A prefix match alone doesn't mean much for variable-length formats
    # (bcrypt, argon2, pbkdf2, ...), so min_length catches obviously
    # truncated/garbage input and downgrades confidence instead of
    # trusting the prefix blindly.
    for key, value in prefix_rules.items():
        if not text.startswith(key):
            continue

        confidence = value["confidence"]
        reason = f"matched prefix '{key}'"
        min_length = value.get("min_length")
        if min_length and len(text) < min_length:
            confidence = "low"
            reason += f", but length {len(text)} is shorter than the expected minimum {min_length}"

        return HashCandidate(algorithm=value["algorithm"], confidence=confidence, reason=reason)
    return None


def detect_special(text):
    # Detect hash formats that cannot be identified by prefix or generic hex length.
    # These are special-case hash shapes like NetNTLM, MySQL5, and DES-Crypt.
    if _is_netntlm(text):
        return HashCandidate(algorithm="NetNTLM", confidence="high", reason="special shape")

    if _is_mysql5(text):
        return HashCandidate(algorithm="MySQL5", confidence="high", reason="special shape")

    if _is_descrypt(text):
        return HashCandidate(algorithm="DES-Crypt", confidence="medium", reason="special shape")

    return None


def detect_by_hex_length(text, hex_rules):
    # Try to identify a hash by matching its hex length against known rules.
    # Returns a list of candidates because multiple algorithms can share the same hex length.
    length = str(len(text))
    if _is_hex(text) and length in hex_rules:
        algorithms = hex_rules[length]
        results = []
        for i, algo in enumerate(algorithms):
            confidence = "medium" if i == 0 else "low"
            results.append(HashCandidate(
                algorithm=algo,
                confidence=confidence,
                reason="hex length match"
            ))
        return results
    return []

def detect_generic_phc(text):
    # Detect hashes that follow the generic PHC string format.
    # If it starts with '$' and has at least three parts, assume a PHC-like format.
    parts = text.split("$")
    if text.startswith("$") and len(parts) >= 3:
        return HashCandidate(
            algorithm="PHC",
            confidence="low",
            reason="PHC-like format, unknown algorithm"
        )
    return None

_BASE64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")


def detect_shape_hint(text):
    # Detect non-hash formats by simple shape hints.
    # For example JWT and Base64 strings are often mistaken for hashes.
    if text.startswith("eyJ"):
        return HashCandidate(
            algorithm="JWT",
            confidence="low",
            reason="looks like a JWT, not a hash"
        )
    if len(text) % 4 == 0 and _BASE64_RE.match(text):
        return HashCandidate(
            algorithm="Base64",
            confidence="low",
            reason="looks like Base64, not a hash"
        )
    return None


@lru_cache(maxsize=1)
def _load_rules():
    try:
        with open(RULES_PATH, "r") as f:
            data = json.load(f)
    except FileNotFoundError:
        raise SystemExit(f"rules file not found: {RULES_PATH}")
    except json.JSONDecodeError as e:
        raise SystemExit(f"rules file is not valid JSON ({RULES_PATH}): {e}")

    for key in ("prefix_rules", "hex_rules"):
        if key not in data:
            raise SystemExit(f"rules file is missing required key '{key}': {RULES_PATH}")

    prefix_rules = data["prefix_rules"]
    valid_confidence = {"high", "medium", "low"}
    for prefix, rule in prefix_rules.items():
        if rule.get("confidence") not in valid_confidence:
            raise SystemExit(
                f"rules file has invalid confidence for prefix '{prefix}': {rule.get('confidence')!r}"
            )
        if not rule.get("algorithm"):
            raise SystemExit(f"rules file is missing algorithm for prefix '{prefix}'")

    hashcat_modes = data.get("hashcat_modes", {})
    if not isinstance(hashcat_modes, dict):
        raise SystemExit(f"rules file has invalid 'hashcat_modes', expected an object: {RULES_PATH}")

    return prefix_rules, data["hex_rules"], hashcat_modes


def hashcat_mode_for(algorithm):
    # Look up the hashcat mode number for a detected algorithm, if known.
    _, _, hashcat_modes = _load_rules()
    return hashcat_modes.get(algorithm, "-")


def identify(text):
    # Load detection rules and try a sequence of identification methods.
    # Always returns a list of candidates (empty if none matched).
    prefix_rules, hex_rules, _ = _load_rules()

    result = detect_by_prefix(text, prefix_rules)
    if result is not None:
        return [result]

    result = detect_special(text)
    if result is not None:
        return [result]

    results = detect_by_hex_length(text, hex_rules)
    if results:
        return results

    result = detect_generic_phc(text)
    if result is not None:
        return [result]

    result = detect_shape_hint(text)
    if result is not None:
        return [result]

    return []


_CONFIDENCE_RANK = {"high": 0, "medium": 1, "low": 2}
_CONFIDENCE_COLOR = {"high": "\033[1;92m", "medium": "\033[1;93m", "low": "\033[1;91m"}
_TITLE_COLOR = "\033[1;96m"
_HEADER_COLOR = "\033[1;97m"
_ALGO_COLOR = "\033[1;97m"
_REASON_COLOR = "\033[0;37m"
_BORDER_COLOR = "\033[0;90m"
_ERROR_COLOR = "\033[1;91m"
_RESET = "\033[0m"

_PAD = 2  # spaces of breathing room on each side of a cell

_UNICODE_BOX = dict(tl="┌", tm="┬", tr="┐", ml="├", mm="┼", mr="┤",
                     bl="└", bm="┴", br="┘", v="│", h="─", dash="—")
_ASCII_BOX = dict(tl="+", tm="+", tr="+", ml="+", mm="+", mr="+",
                  bl="+", bm="+", br="+", v="|", h="-", dash="-")


def _box_charset():
    encoding = getattr(sys.stdout, "encoding", None) or "ascii"
    try:
        "".join(_UNICODE_BOX.values()).encode(encoding)
        return _UNICODE_BOX
    except (UnicodeEncodeError, LookupError):
        return _ASCII_BOX


def _c(text, color, use_color):
    return f"{color}{text}{_RESET}" if use_color else text


def _print_batch(groups, use_color):
    # groups: list of (hash_text, results) tuples. results may be empty.
    box = _box_charset()
    headers = ["Algorithm", "Confidence", "Hashcat Mode", "Reason"]
    no_match_row = ["-", "-", "-", "No hash type identified"]

    group_rows = []
    for hash_text, results in groups:
        results = sorted(results, key=lambda r: _CONFIDENCE_RANK[r.confidence])
        rows = [
            [r.algorithm, r.confidence.upper(), hashcat_mode_for(r.algorithm), r.reason]
            for r in results
        ] or [no_match_row]
        group_rows.append((hash_text, results, rows))

    all_rows = [row for _, _, rows in group_rows for row in rows]
    widths = [
        max(len(headers[i]), *(len(row[i]) for row in all_rows))
        for i in range(len(headers))
    ]
    cell_widths = [w + _PAD * 2 for w in widths]
    inner_width = sum(cell_widths) + (len(widths) - 1)

    count = len(groups)
    title = f" Hash Identification Results {box['dash']} {count} hash{'es' if count != 1 else ''} "
    labels = [f" Hash: {hash_text} " for hash_text, _, _ in group_rows]
    widest_line = max([len(title)] + [len(label) for label in labels])
    if widest_line > inner_width:
        # widen the last column so the box stays rectangular for long input hashes
        deficit = widest_line - inner_width
        widths[-1] += deficit
        cell_widths[-1] += deficit
        inner_width += deficit

    def border(left, mid, right, full_width=False):
        if full_width:
            line = left + box["h"] * inner_width + right
        else:
            line = left + mid.join(box["h"] * w for w in cell_widths) + right
        return _c(line, _BORDER_COLOR, use_color)

    def single_row(text, color):
        v = _c(box["v"], _BORDER_COLOR, use_color)
        return v + _c(text.ljust(inner_width), color, use_color) + v

    def cell_row(cells, cell_colors):
        v = _c(box["v"], _BORDER_COLOR, use_color)
        parts = []
        for text, width, color in zip(cells, widths, cell_colors):
            padded = text.ljust(width)
            styled = _c(padded, color, use_color) if color else padded
            parts.append(" " * _PAD + styled + " " * _PAD)
        return v + v.join(parts) + v

    print(border(box["tl"], box["tm"], box["tr"], full_width=True))
    print(single_row(title, _TITLE_COLOR))
    print(border(box["ml"], box["tm"], box["mr"]))
    print(cell_row(headers, [_HEADER_COLOR] * len(headers)))

    for i, (hash_text, results, rows) in enumerate(group_rows):
        if len(groups) > 1:
            print(border(box["ml"], box["bm"], box["mr"]))
            print(single_row(f" Hash: {hash_text} ", _TITLE_COLOR))
            print(border(box["ml"], box["tm"], box["mr"]))
        else:
            print(border(box["ml"], box["mm"], box["mr"]))
        if results:
            for r, row in zip(results, rows):
                print(cell_row(row, [_ALGO_COLOR, _CONFIDENCE_COLOR[r.confidence], _ALGO_COLOR, _REASON_COLOR]))
        else:
            print(cell_row(rows[0], [_ERROR_COLOR, _ERROR_COLOR, _ERROR_COLOR, _ERROR_COLOR]))

    print(border(box["bl"], box["bm"], box["br"], full_width=True))


def _read_hashes(args):
    if args.file:
        with open(args.file, "r") as f:
            lines = f.readlines()
        return [line.strip() for line in lines if line.strip()]
    return [args.hash.strip()]


def main():
    # Parse command line input and print the identified hash candidates.
    parser = argparse.ArgumentParser(description="Identify hash types from input text.")
    parser.add_argument("hash", nargs="?", help="The hash to identify.")
    parser.add_argument("--file", help="Path to a text file with one hash per line.")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output.")
    args = parser.parse_args()

    if not args.file and not args.hash:
        parser.error("provide a hash, or use --file to identify multiple hashes.")
    if args.file and args.hash:
        parser.error("provide either a hash or --file, not both.")

    try:
        hash_texts = _read_hashes(args)
    except FileNotFoundError:
        parser.error(f"file not found: {args.file}")

    use_color = not args.no_color and sys.stdout.isatty()
    groups = [(h, identify(h)) for h in hash_texts]
    _print_batch(groups, use_color)


if __name__ == "__main__":
    main()
