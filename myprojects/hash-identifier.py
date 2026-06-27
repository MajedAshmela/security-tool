from dataclasses import dataclass
from typing import Literal
import re

@dataclass(frozen=True, slots=True)

class HashCandidate:
 algorithm : str
 confidence: Literal[ "high" , "medium", "low" ]
 reason : str


def _is_hex(text):
    return bool(re.match(r"^[0-9a-fA-F]+$", text))

def _is_mysql5(text):
 return text.startswith("*") and len(text) == 41 and re.match(r"^[0-9A-F]+$", text[1:])

def _is_netntlm(text):
    parts = text.split(":")
    return len(parts) == 6 and parts[1] == ""

def _is_descrypt(text):
    return bool(re.match(r"^[./0-9a-zA-Z]{13}$", text))

def detect_by_prefix(text,prefix_rules):
    for key, value in prefix_rules.items():
        if text.startswith(key):
            return HashCandidate(
                algorihtm=value["algorithm"],
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

