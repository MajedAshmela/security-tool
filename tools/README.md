# hash-identifier

A command-line tool that inspects a string and guesses which hashing algorithm
(or hash-like format) produced it. Identification is **purely structural** — it
looks at the prefix, length, and character set of the input. It never tries to
reverse, decrypt, or crack the hash; it only tells you *what kind* of hash you
are looking at, which is the first step before feeding it to a cracker like
hashcat or John the Ripper.

Detection rules live in [`rules.json`](rules.json), so new algorithms can be
added without touching any code.

## Features

- Identifies **50+** hash formats across three detection methods.
- Reports a ranked list of candidates, each with a **confidence** level
  (`high` / `medium` / `low`) and a short **reason**.
- Maps each detected algorithm to its **hashcat `-m` mode number**, so you know
  exactly what to run next.
- Handles a **single hash** or a **batch** from a file (`--file`, one per line).
- Clean, aligned, colored table output — with automatic ASCII fallback for
  terminals that can't render Unicode box characters (e.g. legacy Windows
  consoles), and automatic color-off when piped to a file.
- Data-driven: detection rules are external JSON, not hardcoded.
- Covered by a **pytest** suite (31 tests).

## Requirements

- Python 3.10+ (uses `@dataclass(slots=True)`, added in 3.10). No third-party
  dependencies — standard library only.
- `pytest` is only needed to run the test suite.

## Usage

Identify a single hash (wrap hashes containing `$` in single quotes so the
shell doesn't expand them):

```bash
python hash-identifier.py '5f4dcc3b5aa765d61d8327deb882cf99'
```

Identify many hashes from a file (one per line):

```bash
python hash-identifier.py --file sample-hashes.txt
```

### Options

| Flag | Description |
|------|-------------|
| `hash` | A single hash string to identify (positional). |
| `--file PATH` | Read hashes from a text file, one per line. Blank lines ignored. |
| `--no-color` | Disable ANSI colors (also auto-disabled when output is not a terminal). |

You must pass **either** a positional hash **or** `--file`, not both.

## Example output

```
+------------------------------------------------------------------------+
| Hash Identification Results - 2 hashes                                 |
+--------------+--------------+----------------+-------------------------+
|  Algorithm   |  Confidence  |  Hashcat Mode  |  Reason                 |
+--------------+--------------+----------------+-------------------------+
| Hash: $2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW     |
+--------------+--------------+----------------+-------------------------+
|  bcrypt      |  HIGH        |  3200          |  matched prefix '$2b$'  |
+--------------+--------------+----------------+-------------------------+
| Hash: 5f4dcc3b5aa765d61d8327deb882cf99                                 |
+--------------+--------------+----------------+-------------------------+
|  MD5         |  MEDIUM      |  0             |  hex length match       |
|  NTLM        |  LOW         |  1000          |  hex length match       |
|  MD4         |  LOW         |  900           |  hex length match       |
|  RIPEMD-128  |  LOW         |  -             |  hex length match       |
|  LM          |  LOW         |  3000          |  hex length match       |
+------------------------------------------------------------------------+
```

A dash (`-`) in the Hashcat Mode column means no mode is mapped for that
algorithm.

## How detection works

`identify()` runs five detectors in order and returns as soon as one matches:

| # | Detector | Signal | Confidence |
|---|----------|--------|------------|
| 1 | **Prefix** | Known leading marker, e.g. `$2b$` → bcrypt, `$argon2id$` → Argon2id | `high` (downgraded to `low` if shorter than the format's `min_length`) |
| 2 | **Special shape** | Fixed non-hex structures: NetNTLMv1/v2, MySQL5, DES-Crypt | `high` / `medium` |
| 3 | **Hex length** | Count of hex chars, e.g. 32 → MD5/NTLM/MD4/…; 64 → SHA-256/… | `medium` for the most common, `low` for the rest |
| 4 | **Generic PHC** | Looks like `$name$...` but no specific rule | `low` |
| 5 | **Shape hint** | Not a hash at all — JWT (`eyJ…`) or Base64 | `low` |

### Confidence levels

- **high** — a definitive self-identifying prefix or a distinctive fixed shape.
- **medium** — the single most likely candidate for an otherwise ambiguous
  signal (e.g. the most common algorithm at a given hex length).
- **low** — plausible but ambiguous, or a downgraded/generic/non-hash match.

Because raw hex hashes of the same length are structurally identical (an MD5 and
an NTLM hash are both 32 hex chars), the tool can only *rank* candidates for
those — it cannot pick one with certainty. That is a fundamental limit of
structural identification, not a bug.

## Supported hash types

- **Prefix-based (30 rules):** bcrypt (`$2a$`/`$2b$`/`$y$`), Argon2i/d/id, MD5/
  SHA-256/SHA-512 crypt, Apache-MD5, PBKDF2 (SHA1/256/512), scrypt, phpass
  (`$P$`/`$H$`), LDAP (`{SSHA}`/`{SHA}`), Kerberoast TGS (RC4/AES128/AES256),
  AS-REP Roast, Django PBKDF2/SHA1, Drupal7, MSSQL, PostgreSQL-MD5, Cisco IOS
  (`$8$`/`$9$`), Oracle 11g.
- **Special shapes (4):** NetNTLMv1, NetNTLMv2, MySQL5, DES-Crypt.
- **Hex-length (18 algorithms across lengths 8/16/32/40/56/64/96/128):** CRC32,
  Adler32, MySQL323, MD5, NTLM, MD4, RIPEMD-128, LM, SHA-1, RIPEMD-160, SHA-224,
  SHA-256, SHA3-256, BLAKE2s-256, SHA-384, SHA-512, SHA3-512, BLAKE2b-512.

See [`rules.json`](rules.json) for the authoritative, up-to-date list.

> **Note on hashcat modes:** the mapped mode numbers are provided as a
> convenience. Verify against `hashcat --example-hashes` before relying on them
> in a real engagement, as hashcat occasionally adds or changes modes between
> releases.

## Adding a new hash type

No code changes are needed — edit [`rules.json`](rules.json):

- **Prefix format:** add an entry under `prefix_rules`:
  ```json
  "$newprefix$": { "algorithm": "MyAlgo", "confidence": "high", "min_length": 40 }
  ```
  `min_length` is optional; when set, inputs shorter than it are downgraded to
  `low` confidence.
- **Fixed hex length:** add the algorithm name to the appropriate length list
  under `hex_rules` (the first entry in a list is treated as the most common
  and gets `medium` confidence).
- **Hashcat mode:** add `"MyAlgo": "12345"` under `hashcat_modes`.

The rules file is validated on load: a missing key, invalid confidence value,
missing algorithm name, or malformed JSON aborts with a clear error message.

## Running the tests

```bash
pip install pytest
python -m pytest tools/test_hash_identifier.py -v
```

The suite covers every detection path (prefix, special shapes, hex length,
generic PHC, shape hints), the rules-file validation, the hashcat-mode lookup,
and batch file reading. It also includes a data-driven test that verifies every
prefix rule in `rules.json` classifies its own sample correctly.

## Files

| File | Purpose |
|------|---------|
| [`hash-identifier.py`](hash-identifier.py) | The tool and CLI. |
| [`rules.json`](rules.json) | Detection rules (prefixes, hex lengths, hashcat modes). |
| [`test_hash_identifier.py`](test_hash_identifier.py) | pytest suite. |
| [`sample-hashes.txt`](sample-hashes.txt) | Example hashes for trying `--file`. |

## Limitations

- **Structural only.** It identifies format, not content — it cannot tell you
  the password, nor distinguish two algorithms that share the same length and
  charset (it ranks them instead).
- **Short/generic prefixes** (e.g. `md5`, `S:`, `$8$`) can produce false
  positives; these are given `medium` confidence and `min_length` guards, but
  context still matters.
- **Not exhaustive.** Hundreds of hash formats exist; this covers the common and
  pentest-relevant ones. Formats with no distinctive prefix or unique length
  (many 32-hex vendor hashes) are inherently ambiguous.
```
