# passgen

A tiny, dependency-free CLI that generates secure passwords and passphrases. Python 3.8+ standard library only — no pip install, no network, no build step.

All output comes from the `secrets` module (a cryptographically secure PRNG). The `random` module is never used for generated output.

## Features

- **Two modes:** diceware-style passphrases (`--words`) and random passwords (`--length`)
- **Curated wordlist:** 4782 lowercase words bundled as `words.txt` (unique, alphabetically sorted, validated at runtime)
- **Correct entropy math:** `--entropy` reports real bits of entropy — `log2(charset^length)` for passwords, `log2(wordlist^words)` for passphrases
- **Simple strength meter:** `--strength` labels entropy as Weak / Fair / Strong / Excellent
- **Hygiene options:** `--symbols` / `--no-symbols`, `--no-ambiguous` (drops `0O1lI`), `--count N` (multiple distinct candidates), `--separator` for passphrases
- **stdout-only secrets:** generated secrets go to stdout; entropy/strength metadata goes to stderr, so stdout stays machine-readable. passgen never writes secrets to disk.
- **Sane errors:** bad arguments exit with code 2 and a clear message.

## Installation

Requires Python 3.8 or newer. No dependencies.

```bash
git clone https://github.com/agenticspring/passgen.git
cd passgen
python3 passgen.py --words 6
```

Optional: make it available on your PATH.

```bash
chmod +x passgen.py
ln -s "$PWD/passgen.py" ~/.local/bin/passgen
```

## Usage

```
usage: passgen [-h] (--words N | --length N) [--separator SEP]
               [--symbols | --no-symbols] [--no-ambiguous]
               [--count N] [--entropy] [--strength] [--version]
```

Passphrase (6 words, default space separator):

```bash
$ python3 passgen.py --words 6
<six random words from the bundled wordlist>
```

Random password (20 characters, symbols included by default):

```bash
$ python3 passgen.py --length 20
<20 random characters>
```

Three alphanumeric-only, unambiguous candidates with entropy + strength:

```bash
$ python3 passgen.py --length 16 --no-symbols --no-ambiguous --count 3 --entropy --strength
<candidate 1>
<candidate 2>
<candidate 3>
entropy: 95.3 bits
strength: Strong
```

*(Example outputs above are illustrative — your output will differ every run.)*

Custom word separator:

```bash
$ python3 passgen.py --words 4 --separator -
<four random words joined by '-'>
```

Entropy and strength go to stderr, so this stays clean in pipelines:

```bash
$ python3 passgen.py --length 32 --entropy 2>/dev/null | pbcopy
```

## Entropy and strength

- Password: `bits = length × log2(len(charset))`. Default charset is 89 characters (26 lower + 26 upper + 10 digits + 27 symbols), so `--length 20` gives ≈ 129.5 bits.
- Passphrase: `bits = words × log2(len(wordlist))`. With 4782 words, `--words 6` gives ≈ 73.3 bits.
- Strength labels (heuristic): `<60` Weak · `60–79` Fair · `80–109` Strong · `≥110` Excellent.

These thresholds are rules of thumb, not a security guarantee — see Limitations.

## Wordlist

`words.txt` is a hand-curated list of 4782 common English words (lowercase a–z, unique, alphabetically sorted). It is **not** the EFF wordlist — no external attribution is required. `tools/build_wordlist.py` contains the raw curated source and regenerates `words.txt` (dedupe + sort + validate); run it if you edit the source list:

```bash
python3 tools/build_wordlist.py
```

The loader finds `words.txt` relative to `passgen.py` (via `importlib.resources`, falling back to `__file__`), so it works from any working directory. If the wordlist is missing or fails validation (fewer than 1024 words, non-lowercase entries, not unique/sorted), passgen exits with an error instead of generating weak output.

## Testing

```bash
python3 -m unittest discover -s tests -v
```

The suite covers: entropy math against independently computed values, charset/format constraints per flag, ambiguous-character filtering, full wordlist validation (count, uniqueness, lowercase, sorted), `--count` uniqueness, consecutive-run non-repetition (real CSPRNG), mocked determinism of the generation path, exit-code-2 handling for bad arguments (`--length 0`, negative values, both modes, no mode), and stdout/stderr separation.

## Limitations

- The strength meter is a simple entropy heuristic; it says nothing about password reuse, phishing, or endpoint compromise.
- Passphrases are only as strong as the wordlist size — this is documented in the entropy report, not hidden.
- This tool generates secrets; it does not store, sync, or manage them. Use a password manager for storage.
- `--count` guarantees uniqueness within one run, not across runs (cross-run collisions are cryptographically negligible).

## Security notes

- Uses `secrets.choice` (OS-provided CSPRNG). No `random` module involvement in output.
- No network access, no telemetry, no disk writes of generated secrets.
- The repository contains no real credentials — example outputs in docs are illustrative placeholders.

## License

MIT — see [LICENSE](LICENSE).
