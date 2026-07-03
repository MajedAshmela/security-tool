from dataclasses import dataclass
from typing import Literal
import re
import json
import argparse
#MAJEDALI
#
#
#
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
    # NetNTLM hashes typically have 6 parts separated by ':' and the second part is empty.
    parts = text.split(":")
    return len(parts) == 6 and parts[1] == ""


def _is_descrypt(text):
    # Check whether the string matches the DES-Crypt hash format.
    # DES-Crypt hashes are 13 characters long and use the ./0-9A-Za-z alphabet.
    return bool(re.match(r"^[./0-9a-zA-Z]{13}$", text))


def detect_by_prefix(text, prefix_rules):
    # Detect a hash type based on a predefined prefix rule set.
    # Returns a HashCandidate when the input starts with a known prefix.
    for key, value in prefix_rules.items():
        if text.startswith(key):
            return HashCandidate(
                algorithm=value["algorithm"],
                confidence=value["confidence"],
                reason="matched prefix"
            )
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

def detect_shape_hint(text):
    # Detect non-hash formats by simple shape hints.
    # For example JWT and Base64 strings are often mistaken for hashes.
    if text.startswith("eyJ"):
        return HashCandidate(
            algorithm="JWT",
            confidence="low",
            reason="looks like a JWT, not a hash"
        )
    if "+" in text or "/" in text or "=" in text:
        return HashCandidate(
            algorithm="Base64",
            confidence="low",
            reason="looks like Base64, not a hash"
        )
    return None


def identify(text):
    # Load detection rules and try a sequence of identification methods.
    # Returns either a single HashCandidate, a list of candidates, or an empty list.
    with open("rules.json", "r") as f:
        data = json.load(f)
    prefix_rules = data["prefix_rules"]
    hex_rules = data["hex_rules"]

    result = detect_by_prefix(text, prefix_rules)
    if result is not None:
        return result

    result = detect_special(text)
    if result is not None:
        return result

    results = detect_by_hex_length(text, hex_rules)
    if results:
        return results

    result = detect_generic_phc(text)
    if result is not None:
        return result

    result = detect_shape_hint(text)
    if result is not None:
        return result

    return []


def main():
    # Parse command line input and print the identified hash candidates.
    parser = argparse.ArgumentParser(description="Identify hash types from input text.")
    parser.add_argument("hash", help="The hash to identify.")
    args = parser.parse_args()

    results = identify(args.hash)
    if isinstance(results, list):
        pass
    else:
        results = [results]

    if not results:
        print("No hash type identified.")
        return

    for r in results:
        print(f"Algorithm: {r.algorithm}, confidence: {r.confidence}, reason: {r.reason}")


if __name__ == "__main__":
    main()
