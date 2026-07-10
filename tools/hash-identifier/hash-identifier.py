"""Hash type identifier.

A command-line tool that inspects a string and guesses which hashing
algorithm (or hash-like format) produced it. Identification is purely
structural — it looks at the prefix, length, and character set of the
input; it never tries to reverse or crack the hash.

Detection strategy, tried in order by ``identify()``:
    1. Known prefix          (e.g. ``$2b$`` -> bcrypt)         -> high
    2. Special fixed shapes   (NetNTLMv1/v2, MySQL5, DES-Crypt) -> high/medium
    3. Hex length             (e.g. 32 hex chars -> MD5/NTLM/...) -> medium/low
    4. Generic PHC string      (``$name$...`` we don't have a rule for) -> low
    5. Non-hash shape hints    (JWT, Base64)                    -> low

Detection rules live in ``rules.json`` next to this file, so new
algorithms can be added without touching the code.

Usage:
    python hash-identifier.py <hash>
    python hash-identifier.py --file hashes.txt
"""

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Literal
import re
import json
import argparse
import sys

# Absolute path to the rules file, resolved relative to THIS script (not the
# caller's working directory) so the tool works no matter where it's run from.
RULES_PATH = Path(__file__).resolve().parent / "rules.json"


@dataclass(frozen=True, slots=True)
class HashCandidate:
    """One possible identification of a hash string.

    Using ``@dataclass`` auto-generates ``__init__``/``__repr__``/``__eq__``.
    ``frozen=True`` makes instances immutable (a result should never be
    mutated after detection); ``slots=True`` drops the per-instance ``__dict__``
    to keep these lightweight value objects cheap in memory.

    Attributes:
        algorithm: Human-readable algorithm name, e.g. ``"MD5"`` or ``"bcrypt"``.
        confidence: How sure the detector is — ``"high"`` (definitive prefix or
            shape), ``"medium"`` (most likely candidate for a length), or
            ``"low"`` (plausible but ambiguous).
        reason: Short explanation of why this candidate fired, shown to the user.
    """

    algorithm: str
    confidence: Literal["high", "medium", "low"]
    reason: str


def _is_hex(text):
    """Return True if ``text`` is a non-empty string of only hex digits (0-9a-fA-F)."""
    return bool(re.match(r"^[0-9a-fA-F]+$", text))


def _is_mysql5(text):
    """Return True if ``text`` matches the MySQL5 password format.

    MySQL5 stores ``SHA1(SHA1(password))`` as a leading ``*`` followed by 40
    UPPERCASE hex digits (41 chars total). The case check is intentional:
    real MySQL5 output is always uppercase, so a lowercase look-alike is
    rejected rather than reported with false confidence.
    """
    return text.startswith("*") and len(text) == 41 and bool(re.match(r"^[0-9A-F]+$", text[1:]))


def _netntlm_parts(text):
    """Return the 6 colon-separated fields shared by both NetNTLM versions.

    Both NetNTLMv1 and v2 have the shape ``user::domain:field3:field4:field5``
    — exactly 6 fields with an empty second field (where the LM hash used to
    sit). Returns the field list if the shape matches, otherwise ``None``.
    """
    parts = text.split(":")
    if len(parts) != 6 or parts[1] != "":
        return None
    return parts


def _is_netntlmv1(text):
    """Return True if ``text`` is a NetNTLMv1 challenge/response record.

    Layout: ``user::domain:LM-response:NT-response:challenge`` where the LM and
    NT responses are 48 hex chars each and the server challenge is 16 hex chars.
    """
    parts = _netntlm_parts(text)
    if parts is None:
        return False
    lm, nt, challenge = parts[3], parts[4], parts[5]
    return (
        len(lm) == 48 and _is_hex(lm)
        and len(nt) == 48 and _is_hex(nt)
        and len(challenge) == 16 and _is_hex(challenge)
    )


def _is_netntlmv2(text):
    """Return True if ``text`` is a NetNTLMv2 challenge/response record.

    Layout: ``user::domain:server-challenge:NTLMv2-HMAC:blob`` where the
    challenge is 16 hex chars, the HMAC is exactly 32 hex chars, and the blob
    is a variable-length hex string. The 32-hex HMAC is what distinguishes v2
    from v1 (whose fields at the same positions are 48 hex chars).
    """
    parts = _netntlm_parts(text)
    if parts is None:
        return False
    challenge, hmac, blob = parts[3], parts[4], parts[5]
    return (
        len(challenge) == 16 and _is_hex(challenge)
        and len(hmac) == 32 and _is_hex(hmac)
        and len(blob) >= 40 and _is_hex(blob)
    )


def _is_descrypt(text):
    """Return True if ``text`` looks like a traditional 13-char DES-Crypt hash.

    Legacy ``/etc/passwd`` format with no prefix: exactly 13 characters from
    the ``./0-9A-Za-z`` alphabet. Reported at medium confidence because other
    short tokens can share this shape.
    """
    return bool(re.match(r"^[./0-9a-zA-Z]{13}$", text))


def detect_by_prefix(text, prefix_rules):
    """Identify a hash by matching a known leading prefix (strongest signal).

    Walks ``prefix_rules`` (from ``rules.json``) and returns a candidate for
    the first prefix ``text`` starts with. A prefix alone is weak for
    variable-length formats (bcrypt, argon2, ...), so if the rule defines a
    ``min_length`` and the input is shorter, the confidence is downgraded to
    ``"low"`` rather than blindly trusting the prefix.

    Args:
        text: The hash string being identified.
        prefix_rules: Mapping of prefix -> {"algorithm", "confidence", ["min_length"]}.

    Returns:
        A ``HashCandidate`` on the first matching prefix, or ``None``.
    """
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
    """Identify fixed-shape formats that have no prefix and aren't plain hex.

    Covers challenge/response and vendor formats with a distinctive structure:
    NetNTLMv1/v2, MySQL5, and DES-Crypt. Checked before the generic hex-length
    step because their shapes are specific enough to report with confidence.

    Returns:
        A ``HashCandidate`` for the first shape that matches, or ``None``.
    """
    if _is_netntlmv1(text):
        return HashCandidate(algorithm="NetNTLMv1", confidence="high", reason="special shape (LM+NT response, 16-hex challenge)")

    if _is_netntlmv2(text):
        return HashCandidate(algorithm="NetNTLMv2", confidence="high", reason="special shape (16-hex challenge, 32-hex HMAC, blob)")

    if _is_mysql5(text):
        return HashCandidate(algorithm="MySQL5", confidence="high", reason="special shape")

    if _is_descrypt(text):
        return HashCandidate(algorithm="DES-Crypt", confidence="medium", reason="special shape")

    return None


def detect_by_hex_length(text, hex_rules):
    """Identify a raw hex hash by how many hex characters it has.

    Many algorithms emit fixed-width hex (e.g. 32 chars -> MD5/NTLM/MD4/...),
    so length narrows the field but rarely pins a single answer. The first
    algorithm listed for a length (the most common one) gets ``"medium"``
    confidence; the rest get ``"low"``.

    Args:
        text: The hash string being identified.
        hex_rules: Mapping of length-as-string -> ordered list of algorithm names.

    Returns:
        A list of ``HashCandidate`` (possibly several), or ``[]`` if the input
        isn't pure hex or its length isn't in the rules.
    """
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
    """Recognize a PHC-style ``$name$...`` string we have no specific rule for.

    If the input starts with ``$`` and splits into at least three ``$``-parts,
    it's probably a Password Hashing Competition (PHC) formatted hash from an
    algorithm not in our prefix table. Reported as generic ``"PHC"`` at low
    confidence — better than a silent no-match. Returns ``None`` otherwise.
    """
    parts = text.split("$")
    if text.startswith("$") and len(parts) >= 3:
        return HashCandidate(
            algorithm="PHC",
            confidence="low",
            reason="PHC-like format, unknown algorithm"
        )
    return None


# Base64 alphabet with optional 1-2 chars of '=' padding, anchored end to end.
_BASE64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")


def detect_shape_hint(text):
    """Flag common non-hash inputs that users often paste by mistake.

    JWTs (start with ``eyJ``, the Base64 of ``{"``) and Base64 blobs aren't
    hashes, but telling the user what they actually pasted is more helpful
    than "no match". Both are reported at low confidence. Returns ``None`` if
    the input doesn't look like either.
    """
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
    """Load, validate, and cache the detection rules from ``rules.json``.

    Reads the JSON file once (result is memoized via ``lru_cache``) and
    validates its structure so a malformed rules file fails loudly with a
    clear message instead of causing confusing errors deep in detection.

    Returns:
        Tuple of ``(prefix_rules, hex_rules, hashcat_modes)``.

    Raises:
        SystemExit: if the file is missing, isn't valid JSON, lacks a required
            key, or contains an invalid confidence / missing algorithm / a
            non-object ``hashcat_modes``.
    """
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
    """Return the hashcat ``-m`` mode number for an algorithm, or ``"-"`` if unknown."""
    _, _, hashcat_modes = _load_rules()
    return hashcat_modes.get(algorithm, "-")


def identify(text):
    """Identify the hash type(s) of ``text`` by trying each detector in order.

    Runs the detection strategy (prefix -> special shape -> hex length ->
    generic PHC -> shape hint) and returns as soon as one produces a result.

    Args:
        text: The hash string to identify.

    Returns:
        A list of ``HashCandidate``. May contain several candidates (ambiguous
        hex lengths) or be empty if nothing matched. Always a list, so callers
        never need to type-check the return value.
    """
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


# ---------------------------------------------------------------------------
# Output rendering (CLI presentation only — no detection logic below here)
# ---------------------------------------------------------------------------

# Confidence sort order (high first) and the ANSI color used for each level.
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

# Box-drawing glyphs: Unicode for capable terminals, ASCII as a fallback.
_UNICODE_BOX = dict(tl="┌", tm="┬", tr="┐", ml="├", mm="┼", mr="┤",
                     bl="└", bm="┴", br="┘", v="│", h="─", dash="—")
_ASCII_BOX = dict(tl="+", tm="+", tr="+", ml="+", mm="+", mr="+",
                  bl="+", bm="+", br="+", v="|", h="-", dash="-")


def _box_charset(encoding=None):
    """Return the Unicode box-drawing glyphs, or an ASCII fallback.

    Some Windows consoles use a legacy codepage (e.g. cp1252) that can't encode
    ``┌│─``; on those, printing Unicode would crash. This probes whether the
    target encoding can represent the glyphs and picks accordingly. Defaults
    to stdout's encoding; pass ``encoding`` explicitly when rendering for
    something other than the live terminal (e.g. a UTF-8 output file).
    """
    encoding = encoding or getattr(sys.stdout, "encoding", None) or "ascii"
    try:
        "".join(_UNICODE_BOX.values()).encode(encoding)
        return _UNICODE_BOX
    except (UnicodeEncodeError, LookupError):
        return _ASCII_BOX


def _c(text, color, use_color):
    """Wrap ``text`` in an ANSI ``color`` code when ``use_color`` is on, else return it plain."""
    return f"{color}{text}{_RESET}" if use_color else text


def _render_batch(groups, use_color, box_encoding=None):
    """Render all identification results into a single aligned, bordered table.

    Draws one box containing every input hash. Each hash gets a labeled section
    with its candidate rows (Algorithm / Confidence / Hashcat Mode / Reason),
    candidates sorted highest-confidence first. Column widths are computed
    across all rows so everything lines up, and the box auto-widens if a hash
    string or title is longer than the columns. A hash with no matches renders
    a single "No hash type identified" row.

    Args:
        groups: List of ``(hash_text, results)`` tuples; ``results`` may be empty.
        use_color: Whether to emit ANSI color codes.
        box_encoding: Encoding to pick box-drawing glyphs for (see ``_box_charset``).
            Defaults to stdout's encoding.

    Returns:
        A list of rendered lines (no trailing newlines), ready to print or
        write to a file.
    """
    box = _box_charset(box_encoding)
    headers = ["Algorithm", "Confidence", "Hashcat Mode", "Reason"]
    no_match_row = ["-", "-", "-", "No hash type identified"]

    # Build the display rows for each hash, sorting candidates by confidence.
    group_rows = []
    for hash_text, results in groups:
        results = sorted(results, key=lambda r: _CONFIDENCE_RANK[r.confidence])
        rows = [
            [r.algorithm, r.confidence.upper(), hashcat_mode_for(r.algorithm), r.reason]
            for r in results
        ] or [no_match_row]
        group_rows.append((hash_text, results, rows))

    # Column widths = widest cell (or header) in each column, across all hashes.
    all_rows = [row for _, _, rows in group_rows for row in rows]
    widths = [
        max(len(headers[i]), *(len(row[i]) for row in all_rows))
        for i in range(len(headers))
    ]
    cell_widths = [w + _PAD * 2 for w in widths]
    inner_width = sum(cell_widths) + (len(widths) - 1)

    # The title and per-hash label rows span the full width; if any is wider
    # than the columns, grow the last column so the box stays rectangular.
    count = len(groups)
    title = f" Hash Identification Results {box['dash']} {count} hash{'es' if count != 1 else ''} "
    labels = [f" Hash: {hash_text} " for hash_text, _, _ in group_rows]
    widest_line = max([len(title)] + [len(label) for label in labels])
    if widest_line > inner_width:
        deficit = widest_line - inner_width
        widths[-1] += deficit
        cell_widths[-1] += deficit
        inner_width += deficit

    def border(left, mid, right, full_width=False):
        """Build a horizontal border line; ``full_width`` skips column junctions."""
        if full_width:
            line = left + box["h"] * inner_width + right
        else:
            line = left + mid.join(box["h"] * w for w in cell_widths) + right
        return _c(line, _BORDER_COLOR, use_color)

    def single_row(text, color):
        """Build a full-width single-cell row (used for the title and hash labels)."""
        v = _c(box["v"], _BORDER_COLOR, use_color)
        return v + _c(text.ljust(inner_width), color, use_color) + v

    def cell_row(cells, cell_colors):
        """Build a multi-column data row, padding and coloring each cell."""
        v = _c(box["v"], _BORDER_COLOR, use_color)
        parts = []
        for text, width, color in zip(cells, widths, cell_colors):
            padded = text.ljust(width)
            styled = _c(padded, color, use_color) if color else padded
            parts.append(" " * _PAD + styled + " " * _PAD)
        return v + v.join(parts) + v

    lines = []
    lines.append(border(box["tl"], box["tm"], box["tr"], full_width=True))
    lines.append(single_row(title, _TITLE_COLOR))
    lines.append(border(box["ml"], box["tm"], box["mr"]))
    lines.append(cell_row(headers, [_HEADER_COLOR] * len(headers)))

    for hash_text, results, rows in group_rows:
        # With multiple hashes, print a labeled sub-header before each block.
        if len(groups) > 1:
            lines.append(border(box["ml"], box["bm"], box["mr"]))
            lines.append(single_row(f" Hash: {hash_text} ", _TITLE_COLOR))
            lines.append(border(box["ml"], box["tm"], box["mr"]))
        else:
            lines.append(border(box["ml"], box["mm"], box["mr"]))
        if results:
            for r, row in zip(results, rows):
                lines.append(cell_row(row, [_ALGO_COLOR, _CONFIDENCE_COLOR[r.confidence], _ALGO_COLOR, _REASON_COLOR]))
        else:
            lines.append(cell_row(rows[0], [_ERROR_COLOR, _ERROR_COLOR, _ERROR_COLOR, _ERROR_COLOR]))

    lines.append(border(box["bl"], box["bm"], box["br"], full_width=True))
    return lines


def _read_hashes(args):
    """Collect the hash strings to identify from parsed CLI ``args``.

    With ``--file``, reads the file and returns one entry per non-blank line
    (whitespace stripped). Otherwise returns the single positional hash.
    """
    if args.file:
        with open(args.file, "r") as f:
            lines = f.readlines()
        return [line.strip() for line in lines if line.strip()]
    return [args.hash.strip()]


def _default_output_path(file_arg):
    """Return the auto-generated output path for ``--file`` mode: a
    ``result.txt`` written next to the input file, not the current directory.
    """
    return str(Path(file_arg).resolve().parent / "result.txt")


def main():
    """CLI entry point: parse arguments, identify the hash(es), report the results.

    Accepts either a single positional hash or ``--file`` (one hash per line),
    but not both and not neither. The two input modes default to different
    destinations:

    - A single positional hash prints the table to the terminal (colored,
      unless ``--no-color`` or stdout isn't a TTY).
    - ``--file`` writes the table to a ``result.txt`` created next to the
      input file (uncolored, UTF-8) instead of printing — batches are meant
      for a saved report, not a scrollback buffer.

    ``--output`` overrides the destination file path in either mode.
    """
    parser = argparse.ArgumentParser(description="Identify hash types from input text.")
    parser.add_argument("hash", nargs="?", help="The hash to identify.")
    parser.add_argument("--file", help="Path to a text file with one hash per line.")
    parser.add_argument("--output", "-o", help="Write the results table to this file. Defaults to "
                                                "'result.txt' next to --file; has no effect for a single hash "
                                                "unless given explicitly.")
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

    groups = [(h, identify(h)) for h in hash_texts]

    output_path = args.output or (_default_output_path(args.file) if args.file else None)

    if output_path:
        lines = _render_batch(groups, use_color=False, box_encoding="utf-8")
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")
        except OSError as e:
            parser.error(f"could not write to {output_path}: {e}")
    else:
        use_color = not args.no_color and sys.stdout.isatty()
        lines = _render_batch(groups, use_color=use_color)
        print("\n".join(lines))


if __name__ == "__main__":
    main()
