"""Tests for hash-identifier.py.

Covers every detection path in ``identify()`` (prefix rules, special shapes,
hex-length rules, generic PHC fallback, non-hash shape hints), the
``rules.json`` validation performed by ``_load_rules()``, the hashcat-mode
lookup, batch file reading, and the CLI's output routing (terminal vs.
``--output`` / the default ``result.txt`` for ``--file``).
"""

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
    """Reset the memoized ``_load_rules()`` result before and after every test.

    ``_load_rules()`` is ``lru_cache``'d, so without this, a test that
    monkeypatches ``RULES_PATH`` to a temporary rules file would leak that
    cached result into unrelated tests (and vice versa).
    """
    hash_identifier._load_rules.cache_clear()
    yield
    hash_identifier._load_rules.cache_clear()


def _write_rules(tmp_path, data):
    """Write ``data`` as a ``rules.json`` under ``tmp_path`` and return its path."""
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(data))
    return path


# =============================================================================
# HashCandidate
# =============================================================================


def test_hash_candidate_is_immutable():
    """HashCandidate is frozen — mutating a field after creation must raise."""
    candidate = hash_identifier.HashCandidate(algorithm="MD5", confidence="high", reason="test")
    with pytest.raises(AttributeError):
        candidate.algorithm = "SHA-1"


# =============================================================================
# Prefix rules
# =============================================================================


def test_bcrypt_prefix_is_recognized():
    """A real bcrypt hash (``$2b$``) is identified as bcrypt with high confidence."""
    sample = "$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW"
    candidates = hash_identifier.identify(sample)
    assert candidates[0].algorithm == "bcrypt"
    assert candidates[0].confidence == "high"


def test_argon2id_prefix_is_recognized():
    """A real Argon2id PHC string is identified as Argon2id with high confidence."""
    sample = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG"
    candidates = hash_identifier.identify(sample)
    assert candidates[0].algorithm == "Argon2id"
    assert candidates[0].confidence == "high"


def test_kerberoast_tgs_rc4_prefix_is_recognized():
    """A ``$krb5tgs$23$`` Kerberoasting hash is identified with high confidence."""
    sample = "$krb5tgs$23$*user$REALM.COM$spn/host*$" + "a" * 100
    candidates = hash_identifier.identify(sample)
    assert candidates[0].algorithm == "Kerberoast-TGS-RC4"
    assert candidates[0].confidence == "high"


def test_as_rep_roast_prefix_is_recognized():
    """A ``$krb5asrep$23$`` AS-REP Roasting hash is identified with high confidence."""
    sample = "$krb5asrep$23$user@REALM.COM:" + "a" * 64
    candidates = hash_identifier.identify(sample)
    assert candidates[0].algorithm == "AS-REP-Roast-RC4"
    assert candidates[0].confidence == "high"


def test_bcrypt_below_min_length_downgrades_to_low():
    """A bcrypt-prefixed string shorter than bcrypt's min_length (60) is still
    reported as bcrypt, but downgraded to low confidence with an explanatory reason."""
    candidates = hash_identifier.identify("$2b$12$tooshort")
    assert candidates[0].algorithm == "bcrypt"
    assert candidates[0].confidence == "low"
    assert "shorter than the expected minimum" in candidates[0].reason


def test_postgres_md5_prefix_downgrades_when_too_short():
    """The short/generic ``md5`` prefix (PostgreSQL-MD5) also downgrades to low
    confidence when the input is far shorter than its configured min_length."""
    candidates = hash_identifier.identify("md5abc")
    assert candidates[0].algorithm == "PostgreSQL-MD5"
    assert candidates[0].confidence == "low"


def test_every_prefix_rule_in_rules_json_is_self_consistent():
    """Every prefix rule in rules.json classifies its own minimal sample correctly.

    Builds a sample for each rule (the prefix, padded out to its own
    min_length) and checks identify() reports exactly the algorithm and
    confidence the rule declares. This catches typos/inconsistencies in
    rules.json automatically, without hand-writing one test per rule.
    """
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
    """A NetNTLMv1 record (48-hex LM + 48-hex NT response, 16-hex challenge) is recognized."""
    sample = "u4-netntlm::kNS:" + "3" * 48 + ":" + "9" * 48 + ":" + "1" * 16
    candidates = hash_identifier.identify(sample)
    assert candidates[0].algorithm == "NetNTLMv1"
    assert candidates[0].confidence == "high"


def test_netntlmv2_shape_is_recognized():
    """A NetNTLMv2 record (16-hex challenge, 32-hex HMAC, hex blob) is recognized."""
    sample = "admin::N46iSNekpT:" + "0" * 16 + ":" + "8" * 32 + ":" + "5" * 44
    candidates = hash_identifier.identify(sample)
    assert candidates[0].algorithm == "NetNTLMv2"
    assert candidates[0].confidence == "high"


def test_mysql5_uppercase_is_recognized():
    """A ``*`` + 40 uppercase-hex string is recognized as MySQL5 with high confidence."""
    sample = "*94BDCEBE19083CE2A1F959FD02F964C7AF4CFC29"
    candidates = hash_identifier.identify(sample)
    assert candidates[0].algorithm == "MySQL5"
    assert candidates[0].confidence == "high"


def test_mysql5_lowercase_is_rejected():
    """A lowercase look-alike of the MySQL5 shape must NOT be reported as MySQL5.

    Real MySQL5 hashes are always uppercase (`%02X` formatting), so a
    same-shape lowercase string is a false positive the detector should avoid.
    """
    sample = "*" + "a" * 40
    candidates = hash_identifier.identify(sample)
    assert not any(c.algorithm == "MySQL5" for c in candidates)


def test_descrypt_shape_is_recognized():
    """A 13-char string in the DES-Crypt alphabet is recognized at medium confidence."""
    candidates = hash_identifier.identify("abcdefghijklm")
    assert candidates[0].algorithm == "DES-Crypt"
    assert candidates[0].confidence == "medium"


# =============================================================================
# Hex length rules
# =============================================================================


def test_md5_length_hex_returns_ranked_candidates():
    """A 32-hex string returns MD5 as the top (medium-confidence) candidate,
    with every other same-length algorithm listed at low confidence."""
    candidates = hash_identifier.identify("5f4dcc3b5aa765d61d8327deb882cf99")
    assert candidates[0].algorithm == "MD5"
    assert candidates[0].confidence == "medium"
    assert all(c.confidence == "low" for c in candidates[1:])


def test_sha256_length_hex_is_recognized():
    """A 64-hex string returns SHA-256 as the top candidate for that length."""
    sample = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    candidates = hash_identifier.identify(sample)
    assert candidates[0].algorithm == "SHA-256"


def test_non_hex_string_of_matching_length_is_not_a_hex_match():
    """A 32-char string that isn't valid hex must not be reported via the hex-length path."""
    candidates = hash_identifier.identify("g" * 32)
    assert not any(c.reason == "hex length match" for c in candidates)


# =============================================================================
# Fallbacks and shape hints
# =============================================================================


def test_generic_phc_fallback():
    """A ``$name$...`` string with no matching prefix rule falls back to a
    generic "PHC" candidate at low confidence instead of no match at all."""
    sample = "$unknownalgo$v=1$somesalt$somehash"
    candidates = hash_identifier.identify(sample)
    assert candidates[0].algorithm == "PHC"
    assert candidates[0].confidence == "low"


def test_jwt_shape_hint():
    """A string starting with ``eyJ`` is flagged as a JWT, not a hash."""
    sample = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc"
    candidates = hash_identifier.identify(sample)
    assert candidates[0].algorithm == "JWT"
    assert candidates[0].confidence == "low"


def test_base64_shape_hint():
    """A valid Base64-looking string is flagged as Base64, not a hash."""
    sample = "QUJDREVGRw=="
    candidates = hash_identifier.identify(sample)
    assert candidates[0].algorithm == "Base64"
    assert candidates[0].confidence == "low"


def test_empty_and_garbage_input_returns_empty_list():
    """Empty input and unrecognizable garbage both yield an empty candidate list."""
    assert hash_identifier.identify("") == []
    assert hash_identifier.identify("not-a-hash-at-all-just-text") == []


def test_identify_always_returns_a_list():
    """identify() always returns a list, whether it matched once, ambiguously, or not at all."""
    assert isinstance(hash_identifier.identify("5f4dcc3b5aa765d61d8327deb882cf99"), list)
    assert isinstance(hash_identifier.identify("nonsense"), list)
    assert isinstance(hash_identifier.identify("$2b$12$" + "a" * 53), list)


# =============================================================================
# hashcat_mode_for
# =============================================================================


def test_hashcat_mode_for_known_algorithm():
    """Algorithms present in rules.json's hashcat_modes return their mapped mode number."""
    assert hash_identifier.hashcat_mode_for("MD5") == "0"
    assert hash_identifier.hashcat_mode_for("bcrypt") == "3200"


def test_hashcat_mode_for_unknown_algorithm():
    """An algorithm with no hashcat mode mapping returns the "-" placeholder."""
    assert hash_identifier.hashcat_mode_for("TotallyMadeUp") == "-"


# =============================================================================
# _load_rules validation
# =============================================================================


def test_load_rules_missing_prefix_rules_key(tmp_path, monkeypatch):
    """A rules file missing the required "prefix_rules" key aborts with SystemExit."""
    path = _write_rules(tmp_path, {"hex_rules": {}})
    monkeypatch.setattr(hash_identifier, "RULES_PATH", path)
    with pytest.raises(SystemExit):
        hash_identifier._load_rules()


def test_load_rules_invalid_confidence(tmp_path, monkeypatch):
    """A prefix rule with a confidence value outside {high, medium, low} aborts with SystemExit."""
    path = _write_rules(tmp_path, {
        "prefix_rules": {"$x$": {"algorithm": "X", "confidence": "SUPER"}},
        "hex_rules": {},
    })
    monkeypatch.setattr(hash_identifier, "RULES_PATH", path)
    with pytest.raises(SystemExit):
        hash_identifier._load_rules()


def test_load_rules_missing_algorithm(tmp_path, monkeypatch):
    """A prefix rule missing its "algorithm" name aborts with SystemExit."""
    path = _write_rules(tmp_path, {
        "prefix_rules": {"$x$": {"confidence": "high"}},
        "hex_rules": {},
    })
    monkeypatch.setattr(hash_identifier, "RULES_PATH", path)
    with pytest.raises(SystemExit):
        hash_identifier._load_rules()


def test_load_rules_invalid_hashcat_modes_type(tmp_path, monkeypatch):
    """A non-object "hashcat_modes" value (e.g. a list) aborts with SystemExit."""
    path = _write_rules(tmp_path, {
        "prefix_rules": {},
        "hex_rules": {},
        "hashcat_modes": ["not", "a", "dict"],
    })
    monkeypatch.setattr(hash_identifier, "RULES_PATH", path)
    with pytest.raises(SystemExit):
        hash_identifier._load_rules()


def test_load_rules_file_not_found(tmp_path, monkeypatch):
    """A RULES_PATH pointing at a nonexistent file aborts with SystemExit."""
    monkeypatch.setattr(hash_identifier, "RULES_PATH", tmp_path / "does-not-exist.json")
    with pytest.raises(SystemExit):
        hash_identifier._load_rules()


def test_load_rules_invalid_json(tmp_path, monkeypatch):
    """A rules file containing malformed JSON aborts with SystemExit."""
    path = tmp_path / "rules.json"
    path.write_text("{not valid json")
    monkeypatch.setattr(hash_identifier, "RULES_PATH", path)
    with pytest.raises(SystemExit):
        hash_identifier._load_rules()


# =============================================================================
# Batch input (_read_hashes)
# =============================================================================


def test_read_hashes_from_file(tmp_path):
    """--file mode reads one hash per non-blank line, with whitespace stripped."""
    path = tmp_path / "hashes.txt"
    path.write_text("5f4dcc3b5aa765d61d8327deb882cf99\n\n  $2b$12$abc  \n")
    args = argparse.Namespace(file=str(path), hash=None)
    assert hash_identifier._read_hashes(args) == [
        "5f4dcc3b5aa765d61d8327deb882cf99",
        "$2b$12$abc",
    ]


def test_read_hashes_single_positional():
    """Without --file, _read_hashes returns the single positional hash, stripped."""
    args = argparse.Namespace(file=None, hash="  5f4dcc3b5aa765d61d8327deb882cf99  ")
    assert hash_identifier._read_hashes(args) == ["5f4dcc3b5aa765d61d8327deb882cf99"]


# =============================================================================
# Output rendering (_render_batch) and --output
# =============================================================================


def test_render_batch_returns_plain_lines_without_color():
    """With use_color=False, _render_batch returns plain strings with no ANSI codes."""
    groups = [("5f4dcc3b5aa765d61d8327deb882cf99",
               hash_identifier.identify("5f4dcc3b5aa765d61d8327deb882cf99"))]
    lines = hash_identifier._render_batch(groups, use_color=False, box_encoding="utf-8")
    assert isinstance(lines, list)
    assert all(isinstance(line, str) for line in lines)
    assert not any("\033" in line for line in lines)
    assert any("MD5" in line for line in lines)


def test_main_with_output_writes_file_and_prints_nothing(tmp_path, monkeypatch, capsys):
    """--output writes the uncolored table to that file and prints nothing to the terminal."""
    out_path = tmp_path / "out.txt"
    monkeypatch.setattr(sys, "argv", [
        "hash-identifier.py", "5f4dcc3b5aa765d61d8327deb882cf99", "--output", str(out_path),
    ])
    hash_identifier.main()

    captured = capsys.readouterr()
    assert captured.out == ""

    content = out_path.read_text(encoding="utf-8")
    assert "MD5" in content
    assert "\033" not in content


def test_main_single_hash_without_output_prints_to_terminal(monkeypatch, capsys):
    """A single positional hash with no --output prints the table to the terminal."""
    monkeypatch.setattr(sys, "argv", ["hash-identifier.py", "5f4dcc3b5aa765d61d8327deb882cf99"])
    hash_identifier.main()

    captured = capsys.readouterr()
    assert "MD5" in captured.out


def test_main_with_file_defaults_to_result_txt_next_to_input(tmp_path, monkeypatch, capsys):
    """--file with no --output auto-writes result.txt next to the input file and prints nothing."""
    hashes_path = tmp_path / "hashes.txt"
    hashes_path.write_text("5f4dcc3b5aa765d61d8327deb882cf99\n")
    monkeypatch.setattr(sys, "argv", ["hash-identifier.py", "--file", str(hashes_path)])

    hash_identifier.main()

    captured = capsys.readouterr()
    assert captured.out == ""

    result_path = tmp_path / "result.txt"
    assert result_path.exists()
    assert "MD5" in result_path.read_text(encoding="utf-8")
