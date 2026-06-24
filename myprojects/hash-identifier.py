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

def _is_descrypt(text):
    return bool(re.match(r"^[./0-9a-zA-Z]{13}$", text))
