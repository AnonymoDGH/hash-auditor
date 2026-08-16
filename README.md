<div align="center">

# 🔐 Hash Auditor

<img src="https://raw.githubusercontent.com/AnonymoDGH/hash-auditor/main/logo.png" alt="Hash Auditor" width="180"/>

**Audit your passwords. Hash them. Identify hashes. Crack your own.**

[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![PyPI](https://img.shields.io/badge/PyPI-hash--auditor-orange.svg)](https://pypi.org/project/hash-auditor/)
[![Platform](https://img.shields.io/badge/platform-osx%20%7C%20linux%20%7C%20windows-lightgrey.svg)]()

> *"The password is the lock. Most people use a paper clip."*

</div>

---

## What is it?

A pocket knife for password hygiene: measure how weak your passwords really
are, compute hashes in common formats, identify a hash's algorithm from its
length, and brute-force **your own** hashes with a wordlist and common
mutations. Every cracked hash in your lab is a story your novel's hacker
would tell with a smirk.

## Features

**Core**
- 📏 `check` — length, character classes, entropy, weak-list, patterns, verdict
- 🔑 `hash` — md5, sha1, sha256, sha512
- 🕵️ `identify` — guess the algorithm from hash length
- 💥 `crack` — wordlist attack with mutations (`Cap1tals`, `+123`, `+!`, ...)

**v0.2.0 — the cracking-lab expansion**
- 🧬 `audit` — integrated risk audit: strength + breach exposure + leet +
  date + keyboard-walk + randomness, folded into one 0-100 risk score
- 🎯 `recognize` — ranked hash-format identification with confidence scores
  (bcrypt, argon2, scrypt, PBKDF2, Django, phpass, LDAP, MySQL, ...)
- 🌈 `rainbow` — build, save and query real rainbow tables (reduction chains)
- 🎭 `mask` — hashcat-style mask attacks (`?l?d?s`, custom charsets) with
  keyspace/entropy/time estimates
- 🔀 `combine` — combinator and hybrid word+mask attacks
- 🧩 `pcfg` — probabilistic context-free grammar guesses in probability order
- 📚 `breach` — simulated breach-corpus exposure scoring (Zipf-ranked)
- 📜 `policy` — configurable password policies with presets (basic/corporate/NIST)
- 🔄 `history` — password-rotation enforcement (reuse, similarity, mutation gates)
- 🎲 `generate` — diceware, syllable, leet and PIN generators with entropy
- 📊 `stats` — wordlist statistics incl. Zipf-exponent fit and Markov bigrams
- 🔗 `similarity` — edit distance, mutation classification, clustering
- ⌨️ `keyboard` — QWERTY walk generation and detection
- 📅 `dates` — date-fragment extraction and date-password detection
- 🔤 `fingerprint` — structural shape fingerprints (`Password123!` → `ULDS`)
- 🧮 `entropy` — Shannon, chi-squared, Markov and effective-bit analysis
- 🗂️ `parse` — hash-dump parsing (`user:hash`, CSV, salted) → hashcat format
- ➕ pure-Python `checksums` (CRC32/CRC16/Adler-32/FNV/Luhn), incremental
  `brute` with checkpoint/resume, leet-reversal dictionary matching, and
  wordlist pipeline tools
- 📦 Zero dependencies

## Install

```bash
pip install hash-auditor
```

From source:

```bash
git clone https://github.com/AnonymoDGH/hash-auditor
cd hash-auditor
pip install -e .
```

## Quickstart

```bash
# 1. Audit a password
hashaudit check "password123"
# [*] length:           11
# [*] character classes:2
# [*] entropy (approx): 51.5 bits
# [-] in the known-weak list
# [-] verdict: weak

# 2. Hash something
hashaudit hash --algo md5 "sunshine"
# 3e1d2e2e1e7c7a1c5e2d8f6f1c2e3d4a  (fake value — compute your own)

# 3. Identify a hash by its length
hashaudit identify 5d41402abc4b2a76b9719d911017c592
# md5

# 4. Crack your own hash with a wordlist
hashaudit crack --hash 5d41402abc4b2a76b9719d911017c592 --wordlist rockyou.txt
# [+] FOUND: 'hello'

# 5. v0.2.0: integrated risk audit
hashaudit audit "Summer2024!"
# [*] risk score: 87/100 -> critical
# [-] issues:
#     - found in breach corpus ...

# 6. v0.2.0: identify a hash format with confidence
hashaudit recognize '$2b$12$...'
# 1. bcrypt (confidence: 0.97) -- bcrypt revision 'b'; cost factor 12

# 7. v0.2.0: mask attack on your own hash
hashaudit mask '?d?d?d?d' --hash <md5-of-a-pin>
# [+] FOUND: '1234' after 1,235 attempts
```

## CLI reference

| Command | What it does |
|---|---|
| `hashaudit check <password>` | Full audit report |
| `hashaudit hash <password> --algo <a>` | Compute a hash |
| `hashaudit identify <hex>` | Guess algorithm from length |
| `hashaudit crack --hash <hex> --wordlist <f> [--algo <a>]` | Brute-force with mutations |
| `hashaudit crack --nomutate` | Skip mutation candidates |
| `hashaudit audit <password>` / `--file <f>` | Integrated risk audit (0-100 score) |
| `hashaudit recognize <hash>` | Ranked hash-format identification |
| `hashaudit rainbow --table <f> [--lookup <md5>]` | Build / query a rainbow table |
| `hashaudit mask <mask> --info` / `--hash <hex>` | Mask attack or keyspace info |
| `hashaudit combine --wordlist <f> --mode <m>` | Combinator / hybrid attack |
| `hashaudit pcfg --count <n>` | PCFG guesses in probability order |
| `hashaudit breach <password>` / `--file <f>` | Breach-corpus exposure score |
| `hashaudit policy <password> [--preset <p>]` | Policy check (basic/corporate/nist) |
| `hashaudit history <new> --file <f>` | Rotation-policy check vs history |
| `hashaudit generate --scheme <s>` | diceware / syllable / leet / pin |
| `hashaudit stats --file <f>` | Wordlist statistics + Zipf fit |
| `hashaudit similarity <old> <new>` | How two passwords are related |
| `hashaudit entropy <password>` | Deep randomness analysis |
| `hashaudit parse --file <f> [--hashcat]` | Parse a hash dump |

## How it works

<img src="https://raw.githubusercontent.com/AnonymoDGH/hash-auditor/main/assets/architecture.svg" alt="Architecture" width="820"/>

## Tests

```bash
pip install pytest
pytest
```

## License

[MIT](LICENSE) — audit your own habits, crack your own hashes, and keep the
villain's password cracking on the page.
