import argparse
import importlib.util
import json
import sys
from pathlib import Path

import pytest

# hash-identifier.py has a hyphen in its name, so it can't be imported with
# a normal `import` statement — load it from its file path instead.
_MODULE_PATH = Path(__file__).resolve().parent / "hash-identifier.py"
_spec = importlib.util.spec_from_file_location("hash_identifier", _MODULE_PATH)
hash_identifier = importlib.util.module_from_spec(_spec)
sys.modules["hash_identifier"] = hash_identifier
_spec.loader.exec_module(hash_identifier)


@pytest.fixture(autouse=True)
def _clear_rules_cache():
    # _load_rules() is lru_cache'd; clear it so tests that monkeypatch
    # RULES_PATH don't leak into other tests (and vice versa).
    hash_identifier._load_rules.cache_clear()
    yield
    hash_identifier._load_rules.cache_clear()


def _write_rules(tmp_path, data):
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(data))
    return path


# =============================================================================
# HashCandidate
# =============================================================================


def test_hash_candidate_is_immutable():
    candidate = hash_identifier.HashCandidate(algorithm="MD5", confidence="high", reason="test")
    with pytest.raises(AttributeError):
        candidate.algorithm = "SHA-1"


# =============================================================================
# Prefix rules
# =============================================================================


def test_bcrypt_prefix_is_recognized():
    sample = "$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW"
    candidates = hash_identifier.identify(sample)
    assert candidates[0].algorithm == "bcrypt"
    assert candidates[0].confidence == "high"


def test_argon2id_prefix_is_recognized():
    sample = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG"
    candidates = hash_identifier.identify(sample)
    assert candidates[0].algorithm == "Argon2id"
    assert candidates[0].confidence == "high"


def test_kerberoast_tgs_rc4_prefix_is_recognized():
    sample = "$krb5tgs$23$*user$REALM.COM$spn/host*$" + "a" * 100
    candidates = hash_identifier.identify(sample)
    assert candidates[0].algorithm == "Kerberoast-TGS-RC4"
    assert candidates[0].confidence == "high"


def test_as_rep_roast_prefix_is_recognized():
    sample = "$krb5asrep$23$user@REALM.COM:" + "a" * 64
    candidates = hash_identifier.identify(sample)
    assert candidates[0].algorithm == "AS-REP-Roast-RC4"
    assert candidates[0].confidence == "high"


def test_bcrypt_below_min_length_downgrades_to_low():
    candidates = hash_identifier.identify("$2b$12$tooshort")
    assert candidates[0].algorithm == "bcrypt"
    assert candidates[0].confidence == "low"
    assert "shorter than the expected minimum" in candidates[0].reason


def test_postgres_md5_prefix_downgrades_when_too_short():
    candidates = hash_identifier.identify("md5abc")
    assert candidates[0].algorithm == "PostgreSQL-MD5"
    assert candidates[0].confidence == "low"


def test_every_prefix_rule_in_rules_json_is_self_consistent():
    # Build a minimal sample for every prefix rule (padded to its own
    # min_length) and check it's classified exactly as the rule declares.
    # This catches typos/inconsistencies in rules.json automatically,
    # without hand-writing one test per rule.
    prefix_rules, _, _ = hash_identifier._load_rules()
    for prefix, rule in prefix_rules.items():
        min_length = rule.get("min_length", len(prefix))
        sample = prefix + "a" * max(0, min_length - len(prefix))
        candidates = hash_identifier.identify(sample)
        assert candidates, f"no candidates for prefix {prefix!r}"
        assert candidates[0].algorithm == rule["algorithm"], prefix
        assert candidates[0].confidence == rule["confidence"], prefix


# =============================================================================
# Special shapes
# =============================================================================


def test_netntlmv1_shape_is_recognized():
    sample = "u4-netntlm::kNS:" + "3" * 48 + ":" + "9" * 48 + ":" + "1" * 16
    candidates = hash_identifier.identify(sample)
    assert candidates[0].algorithm == "NetNTLMv1"
    assert candidates[0].confidence == "high"


def test_netntlmv2_shape_is_recognized():
    sample = "admin::N46iSNekpT:" + "0" * 16 + ":" + "8" * 32 + ":" + "5" * 44
    candidates = hash_identifier.identify(sample)
    assert candidates[0].algorithm == "NetNTLMv2"
    assert candidates[0].confidence == "high"


def test_mysql5_uppercase_is_recognized():
    sample = "*94BDCEBE19083CE2A1F959FD02F964C7AF4CFC29"
    candidates = hash_identifier.identify(sample)
    assert candidates[0].algorithm == "MySQL5"
    assert candidates[0].confidence == "high"


def test_mysql5_lowercase_is_rejected():
    # Real MySQL5 hashes are always uppercase (%02X formatting); a
    # lowercase string of the same shape should NOT be reported as MySQL5.
    sample = "*" + "a" * 40
    candidates = hash_identifier.identify(sample)
    assert not any(c.algorithm == "MySQL5" for c in candidates)


def test_descrypt_shape_is_recognized():
    candidates = hash_identifier.identify("abcdefghijklm")
    assert candidates[0].algorithm == "DES-Crypt"
    assert candidates[0].confidence == "medium"


# =============================================================================
# Hex length rules
# =============================================================================


def test_md5_length_hex_returns_ranked_candidates():
    candidates = hash_identifier.identify("5f4dcc3b5aa765d61d8327deb882cf99")
    assert candidates[0].algorithm == "MD5"
    assert candidates[0].confidence == "medium"
    assert all(c.confidence == "low" for c in candidates[1:])


def test_sha256_length_hex_is_recognized():
    sample = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    candidates = hash_identifier.identify(sample)
    assert candidates[0].algorithm == "SHA-256"


def test_non_hex_string_of_matching_length_is_not_a_hex_match():
    candidates = hash_identifier.identify("g" * 32)
    assert not any(c.reason == "hex length match" for c in candidates)


# =============================================================================
# Fallbacks and shape hints
# =============================================================================


def test_generic_phc_fallback():
    sample = "$unknownalgo$v=1$somesalt$somehash"
    candidates = hash_identifier.identify(sample)
    assert candidates[0].algorithm == "PHC"
    assert candidates[0].confidence == "low"


def test_jwt_shape_hint():
    sample = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc"
    candidates = hash_identifier.identify(sample)
    assert candidates[0].algorithm == "JWT"
    assert candidates[0].confidence == "low"


def test_base64_shape_hint():
    sample = "QUJDREVGRw=="
    candidates = hash_identifier.identify(sample)
    assert candidates[0].algorithm == "Base64"
    assert candidates[0].confidence == "low"


def test_empty_and_garbage_input_returns_empty_list():
    assert hash_identifier.identify("") == []
    assert hash_identifier.identify("not-a-hash-at-all-just-text") == []


def test_identify_always_returns_a_list():
    assert isinstance(hash_identifier.identify("5f4dcc3b5aa765d61d8327deb882cf99"), list)
    assert isinstance(hash_identifier.identify("nonsense"), list)
    assert isinstance(hash_identifier.identify("$2b$12$" + "a" * 53), list)


# =============================================================================
# hashcat_mode_for
# =============================================================================


def test_hashcat_mode_for_known_algorithm():
    assert hash_identifier.hashcat_mode_for("MD5") == "0"
    assert hash_identifier.hashcat_mode_for("bcrypt") == "3200"


def test_hashcat_mode_for_unknown_algorithm():
    assert hash_identifier.hashcat_mode_for("TotallyMadeUp") == "-"


# =============================================================================
# _load_rules validation
# =============================================================================


def test_load_rules_missing_prefix_rules_key(tmp_path, monkeypatch):
    path = _write_rules(tmp_path, {"hex_rules": {}})
    monkeypatch.setattr(hash_identifier, "RULES_PATH", path)
    with pytest.raises(SystemExit):
        hash_identifier._load_rules()


def test_load_rules_invalid_confidence(tmp_path, monkeypatch):
    path = _write_rules(tmp_path, {
        "prefix_rules": {"$x$": {"algorithm": "X", "confidence": "SUPER"}},
        "hex_rules": {},
    })
    monkeypatch.setattr(hash_identifier, "RULES_PATH", path)
    with pytest.raises(SystemExit):
        hash_identifier._load_rules()


def test_load_rules_missing_algorithm(tmp_path, monkeypatch):
    path = _write_rules(tmp_path, {
        "prefix_rules": {"$x$": {"confidence": "high"}},
        "hex_rules": {},
    })
    monkeypatch.setattr(hash_identifier, "RULES_PATH", path)
    with pytest.raises(SystemExit):
        hash_identifier._load_rules()


def test_load_rules_invalid_hashcat_modes_type(tmp_path, monkeypatch):
    path = _write_rules(tmp_path, {
        "prefix_rules": {},
        "hex_rules": {},
        "hashcat_modes": ["not", "a", "dict"],
    })
    monkeypatch.setattr(hash_identifier, "RULES_PATH", path)
    with pytest.raises(SystemExit):
        hash_identifier._load_rules()


def test_load_rules_file_not_found(tmp_path, monkeypatch):
    monkeypatch.setattr(hash_identifier, "RULES_PATH", tmp_path / "does-not-exist.json")
    with pytest.raises(SystemExit):
        hash_identifier._load_rules()


def test_load_rules_invalid_json(tmp_path, monkeypatch):
    path = tmp_path / "rules.json"
    path.write_text("{not valid json")
    monkeypatch.setattr(hash_identifier, "RULES_PATH", path)
    with pytest.raises(SystemExit):
        hash_identifier._load_rules()


# =============================================================================
# Batch input (_read_hashes)
# =============================================================================


def test_read_hashes_from_file(tmp_path):
    path = tmp_path / "hashes.txt"
    path.write_text("5f4dcc3b5aa765d61d8327deb882cf99\n\n  $2b$12$abc  \n")
    args = argparse.Namespace(file=str(path), hash=None)
    assert hash_identifier._read_hashes(args) == [
        "5f4dcc3b5aa765d61d8327deb882cf99",
        "$2b$12$abc",
    ]


def test_read_hashes_single_positional():
    args = argparse.Namespace(file=None, hash="  5f4dcc3b5aa765d61d8327deb882cf99  ")
    assert hash_identifier._read_hashes(args) == ["5f4dcc3b5aa765d61d8327deb882cf99"]
