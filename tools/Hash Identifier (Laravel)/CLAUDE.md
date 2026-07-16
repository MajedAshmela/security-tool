# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A Laravel 13 (PHP ^8.3) port of the Python `hash-identifier` tool (sibling directory `../Hash identifier`). It inspects a
string and guesses which hashing algorithm produced it, purely structurally (prefix, length, character set) — it never
reverses or cracks hashes. Two front-ends share one detection engine: a web UI and an Artisan command
(`hash:identify`). Detection rules live in data (`resources/rules.json`), not code.

## Toolchain (important — Windows/herd-lite setup)

PHP and Composer are **not on the Git Bash PATH** on this machine (installed via herd-lite). Run `composer` and
`php artisan` commands via the **PowerShell** tool, not Bash.

```powershell
composer install
php artisan test              # full Pest suite (Unit + Feature)
php artisan test --filter=X   # run a single test/group by name
php artisan serve             # web UI at http://127.0.0.1:8000
php artisan hash:identify '5f4dcc3b5aa765d61d8327deb882cf99'
```

No Node/Vite build step is required for this tool — the web page uses plain inline CSS (`vite.config.js` /
`package.json` are Laravel-skeleton leftovers, unused by the hash identifier feature itself).

## Architecture

**One engine, two front-ends.** All detection logic lives in `app/Services/HashIdentifier/`; the Artisan command and
the web controller are both thin adapters over it — never duplicate detection logic into a controller/command.

- `HashIdentifier.php` — the engine. `identify(string $text): list<HashCandidate>` runs five detectors in a fixed
  order and **returns as soon as one matches**:
  1. **Prefix match** (e.g. `$2b$` → bcrypt) — `high`, downgraded to `low` if input is shorter than the rule's
     `min_length`.
  2. **Special fixed shapes** — NetNTLMv1/v2, MySQL5, DES-Crypt (structural checks with no prefix).
  3. **Hex length** — e.g. 32 hex chars → MD5/NTLM/MD4/... Multiple candidates are possible here since same-length
     hex hashes are structurally indistinguishable; the first configured algorithm for a length gets `medium`, the
     rest get `low`.
  4. **Generic PHC** — `$name$...` shape with no specific rule → `low`.
  5. **Shape hint** — not a hash at all (JWT `eyJ...`, Base64) → `low`.
- `RuleRepository.php` — loads, validates, and caches `resources/rules.json`. Deliberately framework-agnostic (no
  Laravel helpers) so the engine and its unit tests can run without booting the app. Throws
  `RuleValidationException` on missing keys, bad JSON, invalid confidence values, or missing algorithm names — rules
  are validated on load, not trusted blindly.
- `HashCandidate.php` — immutable (`readonly`) result value object: `algorithm`, `confidence`, `reason`.
- `TableRenderer.php` — renders the bordered results table for the CLI (Unicode box-drawing with ASCII fallback for
  legacy consoles) and for file output.

**Adding a new hash type requires no code changes** — edit `resources/rules.json`:
- Prefix formats go under `prefix_rules` (optionally with `min_length`).
- Fixed-length hex formats go in the appropriate length list under `hex_rules` (first entry = `medium`, rest = `low`).
- Hashcat mode numbers go under `hashcat_modes`.

**CLI (`app/Console/Commands/IdentifyHashCommand.php`)** mirrors the Python original's I/O behavior exactly — this
asymmetry is intentional, not a bug to "fix":
- A single positional hash argument prints the results table to the terminal (colored unless `--no-color` or stdout
  isn't a TTY).
- `--file PATH` (one hash per line) does **not** print — it writes to `result.txt` next to the input file by default,
  since batch runs are meant to produce a saved report.
- `--output PATH` overrides the destination in either mode.
- Exactly one of the positional hash or `--file` must be given; both or neither is a usage error.

**Web (`app/Http/Controllers/HashIdentifierController.php` + `resources/views/hash-identifier.blade.php`)** accepts
pasted hashes (one per line, same parsing rule as `--file`) via `App\Http\Requests\IdentifyHashesRequest`, which caps
input size (`MAX_INPUT_LENGTH` = 50,000 chars) and line count (`MAX_LINES` = 500) so a single POST can't force
unbounded detection work. The `/identify` route is throttled (`throttle:30,1`). The controller only marshals input
and shapes candidates for the view — all matching happens in `HashIdentifier`.

## Tests

Pest suite (`tests/Unit/HashIdentifierTest.php`, `tests/Feature/HashIdentifierWebTest.php`,
`tests/Feature/IdentifyHashCommandTest.php`) covers every detector path, rules-file validation, hashcat-mode lookup,
confidence sorting, the Artisan command's input modes and usage errors, and the web routes including HTML-escaping of
user input. It includes a data-driven test that walks every prefix rule in `rules.json` and verifies it correctly
classifies its own sample. When adding a new rule, prefer extending that data-driven case over writing a new one-off
test.

Known gotcha: `vendor/bin/pest --init` hangs waiting on a prompt in a non-interactive shell — Pest is already
initialized in this repo, don't re-run it.
