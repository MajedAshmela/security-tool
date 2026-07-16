# hash-identifier (Laravel)

A Laravel port of the [Python `hash-identifier`](../Hash%20identifier/README.md). It inspects a
string and guesses which hashing algorithm (or hash-like format) produced it.
Identification is **purely structural** — it looks at the prefix, length, and
character set of the input. It never reverses, decrypts, or cracks the hash; it
only tells you *what kind* of hash you are looking at, which is the first step
before feeding it to a cracker like hashcat or John the Ripper.

The detection engine, rules, and confidence semantics are a faithful
reimplementation of the Python tool. What Laravel adds is **three front-ends over
one shared engine**:

- a **web UI** — paste one hash (or upload a file), one per line for a batch,
  and get an HTML results table with a summary and per-hash copy buttons;
- a **JSON API** — `POST /api/identify`, for scripts and other tools to integrate with;
- an **Artisan command** — `php artisan hash:identify`, mirroring the original CLI,
  with an additional `--stdin` input mode and `--format=json` output.

Detection rules live in [`resources/rules.json`](resources/rules.json), so new
algorithms can be added without touching any code.

No database is required to run this tool — sessions, cache, and the queue all
use non-DB drivers (see `.env`), and requests to `/identify` and
`/api/identify` are rate-limited (`throttle:30,1`).

## Requirements

- PHP 8.3+ and Composer.
- Laravel 13 (installed via Composer). No Node/Vite build step — the web page
  uses plain inline CSS.

## Setup

From this directory:

```bash
composer install
cp .env.example .env      # if .env does not exist yet
php artisan key:generate
```

`composer create-project` already performs these steps, so a freshly scaffolded
copy is ready to run.

## Usage

### Web UI

```bash
php artisan serve
# then open http://127.0.0.1:8000
```

Paste a single hash, or one hash per line for a batch, and submit — or upload
a text file (one hash per line), merged with anything pasted. Each hash gets
a table of ranked candidates with a color-coded confidence badge, the matching
hashcat `-m` mode, and a short reason. Results start with a summary count of
high/medium/low/unmatched, and each hash has a "Copy" button.

Input is capped at 50,000 characters and 500 hashes per request (pasted text
and uploaded file combined); an uploaded file is capped at 512 KB.

### JSON API

```bash
curl -s -X POST http://127.0.0.1:8000/api/identify \
  -H 'Accept: application/json' \
  --data-urlencode 'hashes=5f4dcc3b5aa765d61d8327deb882cf99'
```

```json
{
  "results": [
    {
      "hash": "5f4dcc3b5aa765d61d8327deb882cf99",
      "candidates": [
        { "algorithm": "MD5", "confidence": "medium", "mode": "0", "reason": "hex length match" },
        { "algorithm": "NTLM", "confidence": "low", "mode": "1000", "reason": "hex length match" }
      ]
    }
  ]
}
```

Accepts the same `hashes` (text) and `file` (upload) fields and limits as the
web form, and returns a `422` with a standard Laravel validation-error body if
those limits are exceeded.

### Command line

Identify a single hash — this prints the table to the terminal (wrap hashes
containing `$` in single quotes so the shell doesn't expand them):

```bash
php artisan hash:identify '5f4dcc3b5aa765d61d8327deb882cf99'
```

Identify many hashes from a file (one per line) — this does **not** print to the
terminal. It writes a `result.txt` next to the input file instead (batches are
meant for a saved report, not a scrollback buffer):

```bash
php artisan hash:identify --file sample-hashes.txt
# -> writes sample-hashes.txt's sibling "result.txt", nothing printed
```

Use `--output` to override the destination path in either mode:

```bash
php artisan hash:identify --file sample-hashes.txt --output results.txt
php artisan hash:identify '5f4dcc3b5aa765d61d8327deb882cf99' --output result.txt
```

Pipe hashes in via `--stdin` (one per line) — like a single hash, this prints
to the terminal unless `--output` is given:

```bash
cat sample-hashes.txt | php artisan hash:identify --stdin
```

Get machine-readable JSON instead of the table with `--format=json`, to either
destination:

```bash
php artisan hash:identify '5f4dcc3b5aa765d61d8327deb882cf99' --format=json
```

#### Options

| Argument / flag | Description |
|-----------------|-------------|
| `hash` | A single hash string to identify (positional). Prints to the terminal unless `--output` is given. |
| `--file=PATH` | Read hashes from a text file, one per line. Blank lines ignored. Defaults to writing `result.txt` next to `PATH` instead of printing. |
| `--stdin` | Read hashes (one per line) from standard input instead of a positional hash or `--file`. Opt-in — it never reads stdin unless explicitly passed, so the command can't hang waiting on an unredirected terminal. |
| `--output=PATH` | Write the results to this file (UTF-8, uncolored) instead of the default destination for the input mode. |
| `--format=table\|json` | Output format. Defaults to `table`. |
| `--no-color` | Disable ANSI colors (also auto-disabled when stdout is not a terminal). Has no effect on file or JSON output. |

You must pass exactly **one** of: a positional hash, `--file`, or `--stdin`.

#### Example output

```
┌───────────────────────────────────────────────────────────────────────┐
│ Hash Identification Results — 1 hash                                  │
├─────────────┬──────────────┬────────────────┬─────────────────────────┤
│  Algorithm  │  Confidence  │  Hashcat Mode  │  Reason                 │
├─────────────┼──────────────┼────────────────┼─────────────────────────┤
│  bcrypt     │  HIGH        │  3200          │  matched prefix '$2b$'  │
└───────────────────────────────────────────────────────────────────────┘
```

Legacy Windows consoles that can't render Unicode box characters fall back to an
ASCII table (`+`, `|`, `-`). A dash (`-`) in the Hashcat Mode column means no
mode is mapped for that algorithm.

## How detection works

`HashIdentifier::identify()` runs five detectors in order and returns as soon as
one matches:

| # | Detector | Signal | Confidence |
|---|----------|--------|------------|
| 1 | **Prefix** | Known leading marker, e.g. `$2b$` → bcrypt, `$argon2id$` → Argon2id | `high` (downgraded to `low` if shorter than the format's `min_length`) |
| 2 | **Special shape** | Fixed non-hex structures: NetNTLMv1/v2, MySQL5, DES-Crypt | `high` / `medium` |
| 3 | **Hex length** | Count of hex chars, e.g. 32 → MD5/NTLM/MD4/…; 64 → SHA-256/… | `medium` for the most common, `low` for the rest |
| 4 | **Generic PHC** | Looks like `$name$...` but no specific rule | `low` |
| 5 | **Shape hint** | Not a hash at all — JWT (`eyJ…`) or Base64 | `low` |

Because raw hex hashes of the same length are structurally identical (an MD5 and
an NTLM hash are both 32 hex chars), the tool can only *rank* candidates for
those — it cannot pick one with certainty. That is a fundamental limit of
structural identification, not a bug.

## Adding a new hash type

No code changes are needed — edit [`resources/rules.json`](resources/rules.json):

- **Prefix format:** add an entry under `prefix_rules`:
  ```json
  "$newprefix$": { "algorithm": "MyAlgo", "confidence": "high", "min_length": 40 }
  ```
  `min_length` is optional; inputs shorter than it are downgraded to `low`.
- **Fixed hex length:** add the algorithm name to the appropriate length list
  under `hex_rules` (the first entry gets `medium` confidence, the rest `low`).
- **Hashcat mode:** add `"MyAlgo": "12345"` under `hashcat_modes`.

The rules file is validated on load: a missing key, invalid confidence value,
missing algorithm name, or malformed JSON aborts with a clear
`RuleValidationException`.

## Running the tests

```bash
php artisan test
```

The Pest suite (52 tests) covers every detection path (prefix, special shapes,
hex length, generic PHC, shape hints), the rules-file validation, the
hashcat-mode lookup, confidence sorting, the Artisan command (single hash,
`--file`, `--stdin`, `--output`, `--format=json`, and the usage errors), the
JSON API, and the web routes (file upload, input-size limits, throttling, and
HTML escaping of user input). It includes a data-driven test that verifies
every prefix rule in `rules.json` classifies its own sample correctly, plus a
real subprocess test for `--stdin` (tagged `subprocess`, since it spawns an
actual `php artisan` process with piped input).

## Where things live

| Path | Purpose |
|------|---------|
| [`app/Services/HashIdentifier/HashIdentifier.php`](app/Services/HashIdentifier/HashIdentifier.php) | The detection engine. |
| [`app/Services/HashIdentifier/RuleRepository.php`](app/Services/HashIdentifier/RuleRepository.php) | Loads + validates + caches `rules.json`. |
| [`app/Services/HashIdentifier/HashCandidate.php`](app/Services/HashIdentifier/HashCandidate.php) | Immutable result value object. |
| [`app/Services/HashIdentifier/TableRenderer.php`](app/Services/HashIdentifier/TableRenderer.php) | Bordered console/file table renderer. |
| [`app/Console/Commands/IdentifyHashCommand.php`](app/Console/Commands/IdentifyHashCommand.php) | The `hash:identify` Artisan command. |
| [`app/Http/Controllers/HashIdentifierController.php`](app/Http/Controllers/HashIdentifierController.php) | Web controller. |
| [`app/Http/Controllers/Api/HashIdentifierController.php`](app/Http/Controllers/Api/HashIdentifierController.php) | JSON API controller (`POST /api/identify`). |
| [`app/Http/Requests/IdentifyHashesRequest.php`](app/Http/Requests/IdentifyHashesRequest.php) | Validates pasted text + uploaded file for both the web form and the API (size/line-count caps). |
| [`resources/views/hash-identifier.blade.php`](resources/views/hash-identifier.blade.php) | Web UI. |
| [`resources/rules.json`](resources/rules.json) | Detection rules. |
| [`sample-hashes.txt`](sample-hashes.txt) | Example hashes for trying `--file`. |
| [`tests/`](tests/) | Pest unit + feature tests. |

## Limitations

- **Structural only.** It identifies format, not content — it cannot tell you
  the password, nor distinguish two algorithms that share the same length and
  charset (it ranks them instead).
- **Short/generic prefixes** (e.g. `md5`, `S:`, `$8$`) can produce false
  positives; these are given `medium` confidence and `min_length` guards, but
  context still matters.
- **Not exhaustive.** It covers the common and pentest-relevant formats, the
  same set as the Python original.

> **Note on hashcat modes:** the mapped mode numbers are a convenience. Verify
> against `hashcat --example-hashes` before relying on them in a real engagement.
