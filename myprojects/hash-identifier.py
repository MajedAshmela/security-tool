from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True, slots=True)

class HashCandidate:
 algorithm : str
 confidence: Literal[ "high" , "medium", "low" ]
 reason : str

