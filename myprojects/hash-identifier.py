from dataclasses import dataclass
from typing import Literal
import re
import json
import argparse
#majed
@dataclass(frozen=True, slots=True)
class HashCandidate:
    algorithm: str
    confidence: Literal["high", "medium", "low"]
    reason: str


def _is_hex(text):
    return bool(re.match(r"^[0-9a-fA-F]+$", text))


def _is_mysql5(text):
    return text.startswith("*") and len(text) == 41 and bool(re.match(r"^[0-9A-F]+$", text[1:]))


def _is_netntlm(text):
    parts = text.split(":")
    return len(parts) == 6 and parts[1] == ""


def _is_descrypt(text):
    return bool(re.match(r"^[./0-9a-zA-Z]{13}$", text))


def detect_by_prefix(text, prefix_rules):
    for key, value in prefix_rules.items():
        if text.startswith(key):
            return HashCandidate(
                algorithm=value["algorithm"],
                confidence=value["confidence"],
                reason="matched prefix"
            )
    return None


def detect_special(text):
    if _is_netntlm(text):
        return HashCandidate(algorithm="NetNTLM", confidence="high", reason="special shape")

    if _is_mysql5(text):
        return HashCandidate(algorithm="MySQL5", confidence="high", reason="special shape")

    if _is_descrypt(text):
        return HashCandidate(algorithm="DES-Crypt", confidence="medium", reason="special shape")

    return None


def detect_by_hex_length(text, hex_rules):
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
    parts = text.split("$")
    if text.startswith("$") and len(parts) >= 3:
        return HashCandidate(
            algorithm="PHC",
            confidence="low",
            reason="PHC-like format, unknown algorithm"
        )
    return None

def detect_shape_hint(text):
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
