# hashident

[![CI](https://github.com/jmendoza167/hash_identifier/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/jmendoza167/hash_identifier/actions/workflows/ci.yml)

hashident is a command-line tool that tells you which algorithm most likely
produced a hash string. For each hash it lists the formats it could be: the
usual ones for its shape under **Possible Hashes**, and the rarer ones under
**Least Possible Hashes**. Ask for more with `-v` and it gives the reasons
behind each match, says how hard the hash is to crack, and prints
ready-to-run Hashcat and John the Ripper commands. It knows 152 formats, and
is built for CTF players, students working through security coursework, and
auditors who find password hashes and need to know what they are looking at.
It runs on Python 3.10+ with no third-party dependencies.

## Why hashident

Many hash identifiers print one flat list of every format with the right
length and leave the rest to you. hashident tries to do better:

- **Two lists, in order of likelihood.** 32 hex characters are MD5 or NTLM
  far more often than Tiger-128 or Snefru-128, so the first two are listed as
  possible and the others as least possible, each list most likely first.
- **A prefix settles it.** When a hash carries a marker such as `$2b$`, `*`
  or `{SSHA}`, hashident reports that format and nothing else: no lookalikes
  of the same length. A salted hash written `hash:salt` is matched as a
  salted format, not as a raw digest.
- **Explains itself when asked.** `-v` prints a detailed report: a ranked
  table with confidence levels, the reasons for each format, a WEAK, MODERATE
  or STRONG rating, the exact Hashcat and John commands to start a wordlist
  attack, and notes where a tool needs the hash in another form.
- **Hashcat and John at a glance.** `--show-modes` adds the Hashcat mode and
  John format to every line of the default view.
- **Context hints.** Tell it where the hash came from (`--from windows`,
  `linux`, `web` or `db`) and the order adapts: 32 hex characters from a
  Windows box are more likely NTLM than MD5.
- **Forgiving input.** Whitespace around or inside a hash is ignored, and
  `0x` in front of hex is handled, so a value copied from a database works.
- **Built for scripts too.** Batches of hashes from files or pipes, a compact
  table with `--table`, meaningful exit codes, and `--json` output with a
  versioned schema.

## Example

Each hash gets a block listing the formats it could be: the usual ones for
its shape first, then the rarer ones.

```sh
hashident 8743b52063cd84097a65d1633f5c74f5
```

<!-- readme-test: output 8743b52063cd84097a65d1633f5c74f5 -->
```text
HASH: 8743b52063cd84097a65d1633f5c74f5

Possible Hashes:
[+] MD5
[+] NTLM

Least Possible Hashes:
[+] LM - LAN Manager
[+] md5(md5($pass))
[+] MD4
[+] md5($pass.$salt)
[+] md5($salt.$pass)
[+] Domain Cached Credentials - DCC, MS Cache, mscash
[+] md5(sha1($pass))
[+] HMAC-MD5 (key = $pass)
[+] HMAC-MD5 (key = $salt)
[+] RIPEMD-128
[+] RAdmin v2.x - MD5 of the password padded to 100 bytes
[+] md5($salt.md5($pass))
[+] HAVAL-128
[+] MD2
[+] Tiger-128 - Tiger-192 cut to 128 bits
[+] MD5(HMAC(Wordpress))
[+] Snefru-128
```

A hash with a prefix is pinned down by it:

<!-- readme-test: output $2a$05$LhayLxezLhK1LhWvKxCyLOj0j1u.Kj0jZ0pEmm134uzrQlFvQJLF6 -->
```text
HASH: $2a$05$LhayLxezLhK1LhWvKxCyLOj0j1u.Kj0jZ0pEmm134uzrQlFvQJLF6

Possible Hashes:
[+] bcrypt
```

`--show-modes` adds each format's Hashcat mode and John format. Here the
hash comes with its salt, so only salted formats are listed:

<!-- readme-test: output --show-modes 01dfae6e5d4d90d9892622325959afbe:7050461 -->
```text
HASH: 01dfae6e5d4d90d9892622325959afbe:7050461

Possible Hashes:
[+] md5($pass.$salt)        (hashcat 10 | john dynamic_1)
[+] md5($salt.$pass)        (hashcat 20 | john dynamic_4)
[+] Domain Cached Credentials - DCC, MS Cache, mscash
    (hashcat 1100 | john mscash)

Least Possible Hashes:
[+] HMAC-MD5 (key = $pass)  (hashcat 50 | john hmac-md5)
[+] HMAC-MD5 (key = $salt)  (hashcat 60)
[+] md5($salt.md5($pass))   (hashcat 3710 | john dynamic_9)
```

`-v` prints a detailed report instead, with the reasons behind each format,
its strength and ready-to-run crack commands. `--possible-only` leaves the
rarer formats out:

```sh
hashident -v --possible-only 8743b52063cd84097a65d1633f5c74f5
```

<!-- readme-test: output -v --possible-only 8743b52063cd84097a65d1633f5c74f5 -->
```text
Input:   8743b52063cd84097a65d1633f5c74f5
Length:  32 characters

#  Format  Confidence  Hashcat  John
-  ------  ----------  -------  -------
1  MD5     MEDIUM      0        raw-md5
2  NTLM    MEDIUM      1000     nt

1. MD5 - medium confidence
   Reasons:
     - 32 hexadecimal characters
     - most common format with this shape
     - also matches NTLM, LM, md5(md5($pass)) and 15 more: same length and
       charset
   Strength: WEAK - Fast and unsalted: GPUs test billions of guesses per second.
   Crack it (save the hash to hash.txt first):
     hashcat -m 0 -a 0 hash.txt wordlist.txt
     john --format=raw-md5 --wordlist=wordlist.txt hash.txt

2. NTLM - medium confidence
   Reasons:
     - 32 hexadecimal characters
     - less common than MD5 with this shape
     - also matches MD5, LM, md5(md5($pass)) and 15 more: same length and
       charset
   Strength: WEAK - Unsalted MD4 of the password: even faster to crack than MD5.
   Crack it (save the hash to hash.txt first):
     hashcat -m 1000 -a 0 hash.txt wordlist.txt
     john --format=nt --wordlist=wordlist.txt hash.txt

Tip: hash from a Windows system? Re-run with --from windows (NTLM ranks first)
```

`--table` prints one row per hash, which suits batches. Given a file
`hashes.txt`:

<!-- readme-test: file hashes.txt -->
```text
# hashes from the lab box
8743b52063cd84097a65d1633f5c74f5
b89eaac7e61417341b710b727768294d0e6a277b
$2a$05$LhayLxezLhK1LhWvKxCyLOj0j1u.Kj0jZ0pEmm134uzrQlFvQJLF6
*FCF7C1B8749CF99D88E5F34271D636178FB5D130
$1$ehAsHC4t$4IbK3fHS/H1YGtNYBrIEB1
not-a-hash
```

```sh
hashident --table -f hashes.txt
```

<!-- readme-test: output --table -f hashes.txt -->
```text
Line    Value                                       Format       Conf    Hashcat
------  ------------------------------------------  -----------  ------  -------
2       8743b52063cd84097a65d1633f5c74f5            MD5          MEDIUM  0
3       b89eaac7e61417341b710b727768294d0e6a277b    SHA-1        MEDIUM  100
4       $2a$05$LhayLxezLhK1L...pEmm134uzrQlFvQJLF6  bcrypt       HIGH    3200
5       *FCF7C1B8749CF99D88E5F34271D636178FB5D130   MySQL 4.1+   HIGH    300
6       $1$ehAsHC4t$4IbK3fHS/H1YGtNYBrIEB1          md5crypt     HIGH    500
7       not-a-hash                                  no match     -       -

6 values: 1 MD5, 1 SHA-1, 1 bcrypt, 1 MySQL 4.1+, 1 md5crypt, 1 no match
Tip: --from windows would change the top format for 1 of 6 values.
Run hashident -v on a value to see its reasons and crack commands.
```

The first column is the line number in the file, so you can find each value
again. Long values are shortened in the middle to keep every line within 80
columns.

Run `hashident` with no arguments for an interactive prompt. In a terminal,
output is colored and starts with a banner:

```text
    _  _     _               _     _     _            _
  _| || |_  | |__   __ _ ___| |__ (_) __| | ___ _ __ | |_
 |_  ..  _| | '_ \ / _` / __| '_ \| |/ _` |/ _ \ '_ \| __|
 |_      _| | | | | (_| \__ \ | | | | (_| |  __/ | | | |_
   |_||_|   |_| |_|\__,_|___/_| |_|_|\__,_|\___|_| |_|\__|
 hashident v0.2.0 :: 152 formats :: identify likely hash algorithms

Enter a hash to identify it. An empty line or Ctrl+C quits.

HASH: *FCF7C1B8749CF99D88E5F34271D636178FB5D130

Possible Hashes:
[+] MySQL 4.1+ - MySQL5, SHA-1(SHA-1($pass))

HASH:
Bye!
```

## Installation

hashident needs Python 3.10 or newer.

### From PyPI

hashident is on [PyPI](https://pypi.org/project/hashident/). The easiest way
to install a command-line tool is [pipx](https://pipx.pypa.io), which gives it
its own environment and puts the `hashident` command on your PATH:

```sh
pipx install hashident
hashident --version
```

Upgrade later with `pipx upgrade hashident`. To install with pip instead, use
a virtual environment and run `python -m pip install hashident`.

### From source

To work on hashident itself, or to run the tests:

```sh
git clone https://github.com/jmendoza167/hash_identifier.git
cd hash_identifier
python -m venv .venv
```

Activate the virtual environment:

| Shell | Command |
| --- | --- |
| PowerShell (Windows) | `.\.venv\Scripts\Activate.ps1` |
| Git Bash (Windows) | `source .venv/Scripts/activate` |
| bash or zsh (Linux, macOS) | `source .venv/bin/activate` |

Then install hashident into it and check that it runs:

```sh
python -m pip install -e .
hashident --version
```

If PowerShell refuses to run `Activate.ps1`, allow scripts for the current
session only with `Set-ExecutionPolicy -Scope Process RemoteSigned`, then
activate again.

To run the tests, install the development extra and run pytest:

```sh
python -m pip install -e ".[dev]"
python -m pytest
```

## Usage

```text
usage: hashident [-h] [--version] [--from {windows,linux,web,db}]
                 [--color {auto,always,never} | --no-color] [-f PATH] [-v |
                 --table] [--possible-only] [--show-modes] [--no-banner]
                 [--json]
                 [hash ...]
```

Run `hashident --help` for the full reference.

| Option | Effect |
| --- | --- |
| `--show-modes` | Add each format's Hashcat mode and John format |
| `--possible-only` | Leave out the least possible formats |
| `-v`, `--verbose` | Detailed report: reasons, strength and crack commands |
| `-vv` | The same, with details for the least possible formats too |
| `--table` | Compact table, one row per hash |
| `--json` | One JSON object per hash, for scripts |
| `--from CONTEXT` | Where the hash came from: `windows`, `linux`, `web` or `db` |
| `-f PATH`, `--file PATH` | Read hashes from a file, one per line |
| `--no-banner` | Do not print the banner |
| `--color MODE`, `--no-color` | When to use color |

### Identify a hash

```sh
hashident 8743b52063cd84097a65d1633f5c74f5
```

Whitespace around the hash is ignored. If nothing matches and the hash has
whitespace inside it, such as a line break from a wrapped copy, hashident
tries again without it and says so. If the input is `0x` followed by hex, as
databases print binary values, the hex after the `0x` is tried as well.

### Interactive mode

Run `hashident` with no arguments in a terminal. It shows its banner and a
`HASH:` prompt, and identifies each hash you enter. An empty line or Ctrl+C
quits. Nothing typed at the prompt goes through the shell, so hashes need no
quoting there. Options still apply: `hashident --show-modes` or
`hashident -v --from windows` start a session with those settings.

### Quoting hashes with `$` or `*`

Wrap hashes that contain `$` (bcrypt, md5crypt, sha512crypt) or start with `*`
(MySQL) in **single quotes**. Otherwise the shell changes them before
hashident sees them: bash and PowerShell both treat `$2a` as a variable, and
bash expands `*` as a filename pattern. Double quotes are not enough, because
both shells still expand `$` inside them.

The same command works in PowerShell and bash:

```sh
hashident '$2a$05$LhayLxezLhK1LhWvKxCyLOj0j1u.Kj0jZ0pEmm134uzrQlFvQJLF6'
hashident '*FCF7C1B8749CF99D88E5F34271D636178FB5D130'
```

In Windows `cmd.exe`, leave the quotes off: cmd does not expand `$`, and it
would pass the single quotes on as part of the hash.

Hashes read from a file, a pipe or the interactive prompt are never touched
by the shell, so they need no quoting.

### Several hashes: arguments, files and stdin

Pass several hashes as arguments, read them from a file with `-f`, or pipe
them in:

```sh
hashident 8743b52063cd84097a65d1633f5c74f5 b89eaac7e61417341b710b727768294d0e6a277b
hashident -f hashes.txt
```

```sh
# bash
cat hashes.txt | hashident
hashident < hashes.txt
```

```powershell
# PowerShell
Get-Content hashes.txt | hashident
```

Each hash gets its own block, under a rule naming it, such as
`== arg 2 ====` or `== line 7 ====`.

- Arguments come first, in order, then the lines of `-f PATH`. `-f -` reads
  standard input. With neither, hashident reads standard input when it is
  piped or redirected, and starts interactive mode otherwise.
- In files and piped input, blank lines and lines starting with `#` are
  skipped, and surrounding whitespace is stripped.
- Files can be UTF-8 or UTF-16 with a byte order mark, so files written by
  `>` in Windows PowerShell 5.1 work as they are.
- A missing or unreadable file, or input with no hashes in it, is an error
  (exit code 2).

### More or less detail: `--show-modes`, `--possible-only`, `-v`

```sh
hashident --show-modes 8743b52063cd84097a65d1633f5c74f5
hashident --possible-only 8743b52063cd84097a65d1633f5c74f5
hashident -v 8743b52063cd84097a65d1633f5c74f5
```

- `--show-modes` adds `(hashcat 0 | john raw-md5)` after each format, with
  only the tools that support it.
- `--possible-only` prints the Possible Hashes list alone.
- `-v` replaces the block with a detailed report: a table of every candidate
  with its confidence, then the reasons, strength, crack commands and notes
  for each possible format. The least possible formats are in the table only;
  `-vv` gives them details too. With several hashes, each report is under a
  rule naming it.

Confidence in the report follows the lists: a format that is the only match
is HIGH, a possible format is MEDIUM, and a least possible one is LOW.

### Batches: `--table`

```sh
hashident --table -f hashes.txt
```

One row per hash: its argument index or line number, the value, the best
format, its confidence and its Hashcat mode. A count per format follows.
`--table` cannot be combined with `-v`.

### Context hints: `--from`

If you know where the hash came from, say so. Formats common in that
environment move up their list:

```sh
hashident --from windows 8743b52063cd84097a65d1633f5c74f5
```

Now NTLM is listed above MD5. The values are `windows`, `linux`, `web` and
`db`. A hint reorders formats within a list; it never moves one from Least
Possible to Possible, and it never makes an ambiguous match certain. With
`-v`, hashident suggests a hint when one would change the top result.

### Banner: `--no-banner`

The banner is printed first when output goes to a terminal, and always in
interactive mode. `--no-banner` hides it. Piped or redirected output and
`--json` never have one, so scripts need not pass the flag.

### Color: `--color`, `--no-color` and `NO_COLOR`

Output is colored only when it goes to a terminal. Piped or redirected output
is plain.

| Option | Effect |
| --- | --- |
| `--color auto` | Default: color in a terminal, unless `NO_COLOR` is set |
| `--color always` | Color even when piped, e.g. into `less -R` |
| `--color never`, `--no-color` | No color |

Setting the [`NO_COLOR`](https://no-color.org) environment variable to any
non-empty value turns color off in `auto` mode. The flags take precedence over
`NO_COLOR`:

```sh
# bash
NO_COLOR=1 hashident 8743b52063cd84097a65d1633f5c74f5
```

```powershell
# PowerShell
$env:NO_COLOR = '1'
hashident 8743b52063cd84097a65d1633f5c74f5
```

### JSON: `--json`

`--json` prints one JSON object per hash, each on its own line
([JSON Lines](https://jsonlines.org)), so large inputs stream and other tools
can process them line by line. It is never colored and has no banner. `-v`,
`--table`, `--show-modes` and `--possible-only` have no effect on it: JSON
always includes everything, and each candidate says which list it is in.

Pretty-print the output with Python:

```sh
hashident --json 8743b52063cd84097a65d1633f5c74f5 | python -m json.tool
hashident --json -f hashes.txt | python -m json.tool --json-lines
```

Print each value's line number and best format:

```sh
hashident --json -f hashes.txt | python -c "import sys, json; [print(r['position'], r['candidates'][0]['format'] if r['matched'] else 'no match') for r in map(json.loads, sys.stdin)]"
```

Or use [jq](https://jqlang.org) to list the possible formats of each value,
or the values that matched nothing:

```sh
hashident --json -f hashes.txt | jq -c '[.candidates[] | select(.tier == "possible") | .format]'
hashident --json -f hashes.txt | jq -r 'select(.matched | not) | .input'
```

In Windows PowerShell 5.1, if piping into Python fails with
`Unexpected UTF-8 BOM`, your console is set to UTF-8 *with* a byte order mark,
which PowerShell adds to everything it pipes into a program. Switch to UTF-8
without one for the session:

```powershell
$OutputEncoding = [Console]::InputEncoding = [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
```

The schema is described under JSON output below.

## How matching works

Every format is one entry in a table: its length and character set or an
anchored pattern, the prefix or structure it has, its tier, and its Hashcat
mode and John format where known. An input must match a pattern from start to
end; there are no partial matches. Then:

1. **The most specific kind of match wins.** A prefix (`$2b$`, `*`, `{SSHA}`,
   `0x0100`) beats a structure (`hash:salt`, `LM:NT`), which beats a bare
   shape (32 hex characters). Only the strongest kind found is listed, so a
   bcrypt hash is never shown next to other 60-character formats.
2. **Each format has a tier.** A format pinned by its prefix is always
   possible. Otherwise the usual formats for a shape are possible and the
   rarer ones least possible. A salted format seen without its salt, such as
   `md5($pass.$salt)` for a bare 32 hex characters, is always least possible.
3. **Within a tier, formats are ordered by how common they are**, and
   `--from` moves the ones typical for that environment up.

Many formats share a shape, which is why hashident lists candidates instead
of naming one: 32 hex characters fit MD5, NTLM, LM, MD4 and several rarer
digests. A few formats are checked beyond their pattern. Cisco type 7 is a
reversible encoding, so a value is only reported as type 7 if it decodes to
printable text, and traditional DES crypt must end in one of the 16
characters its last position can hold.

## Supported formats

hashident knows 152 formats. The tables give the Hashcat mode and John the
Ripper format where the tool supports the format; `--show-modes` prints them
next to each match. For some formats a tool wants the hash in a slightly
different form, and `-v` prints a note saying so. Hashcat modes from 40000 up
were added in hashcat 8.0.0.

<!-- formats-table: start -->
### Raw hashes (46)

| Format | Details | Hashcat mode | John format | Strength |
| --- | --- | --- | --- | --- |
| MD5 | - | 0 | `raw-md5` | Weak |
| NTLM | - | 1000 | `nt` | Weak |
| SHA-1 | - | 100 | `raw-sha1` | Weak |
| SHA-224 | - | 1300 | `raw-sha224` | Moderate |
| SHA-256 | - | 1400 | `raw-sha256` | Moderate |
| SHA-512 | - | 1700 | `raw-sha512` | Moderate |
| MD5(Half) | first 16 characters of an MD5 | 5100 | - | Weak |
| MD5(Middle) | characters 9 to 24 of an MD5 | - | - | Weak |
| LM | LAN Manager | 3000 | `lm` | Weak |
| MD4 | - | 900 | `raw-md4` | Weak |
| RIPEMD-128 | - | 40086 | `ripemd-128` | Weak |
| MD2 | - | 40084 | `md2` | Weak |
| HAVAL-128 | - | 40102 | `haval-128-4` | Weak |
| Tiger-128 | Tiger-192 cut to 128 bits | 40090 | - | Moderate |
| Snefru-128 | - | 40094 | `snefru-128` | Weak |
| RIPEMD-160 | - | 6000 | `ripemd-160` | Moderate |
| Tiger-160 | Tiger-192 cut to 160 bits | 40091 | - | Moderate |
| HAVAL-160 | - | 40105 | - | Weak |
| Tiger-192 | - | 40089 | `tiger` | Moderate |
| HAVAL-192 | - | 40108 | - | Weak |
| SHA3-224 | - | 17300 | - | Moderate |
| HAVAL-224 | - | 40111 | - | Weak |
| SHA3-256 | - | 17400 | - | Moderate |
| BLAKE2s-256 | - | 31000 | - | Moderate |
| GOST R 34.11-94 | - | 6900 | `gost` | Weak |
| RIPEMD-256 | - | 40087 | - | Moderate |
| HAVAL-256 | - | 40114 | `haval-256-3` | Weak |
| Snefru-256 | - | 40095 | `snefru-256` | Weak |
| RIPEMD-320 | - | 33600 | - | Moderate |
| SHA-384 | - | 10800 | `raw-sha384` | Moderate |
| SHA3-384 | - | 17500 | - | Moderate |
| SHA3-512 | - | 17600 | `raw-sha3` | Moderate |
| BLAKE2b-512 | - | 600 | `raw-blake2` | Moderate |
| Whirlpool | - | 6100 | `whirlpool` | Moderate |
| SHA-512/224 | SHA-512 cut to 224 bits | - | - | Moderate |
| SHA-512/256 | SHA-512 cut to 256 bits | - | - | Moderate |
| Keccak-224 | - | 17700 | - | Moderate |
| Keccak-256 | pre-standard SHA-3, used by Ethereum | 17800 | `raw-keccak-256` | Moderate |
| Keccak-384 | - | 17900 | - | Moderate |
| Keccak-512 | - | 18000 | `raw-keccak` | Moderate |
| SM3 | Chinese national standard | 31100 | `raw-sm3` | Moderate |
| Streebog-256 | GOST R 34.11-2012 | 11700 | `stribog-256` | Moderate |
| Streebog-512 | GOST R 34.11-2012 | 11800 | `stribog-512` | Moderate |
| MD5 (Base64) | the raw digest in base64 | - | - | Weak |
| SHA-1 (Base64) | the raw digest in base64 | - | - | Weak |
| SHA-256 (Base64) | the raw digest in base64 | - | - | Moderate |

### Salted, keyed and nested hashes (21)

| Format | Details | Hashcat mode | John format | Strength |
| --- | --- | --- | --- | --- |
| `md5(md5($pass))` | - | 2600 | `dynamic_2` | Weak |
| `md5($pass.$salt)` | - | 10 | `dynamic_1` | Weak |
| `md5($salt.$pass)` | - | 20 | `dynamic_4` | Weak |
| `md5(sha1($pass))` | - | 4400 | `dynamic_22` | Weak |
| `HMAC-MD5 (key = $pass)` | - | 50 | `hmac-md5` | Weak |
| `HMAC-MD5 (key = $salt)` | - | 60 | - | Weak |
| `md5($salt.md5($pass))` | - | 3710 | `dynamic_9` | Weak |
| `sha1($pass.$salt)` | - | 110 | `dynamic_24` | Weak |
| `sha1($salt.$pass)` | - | 120 | `dynamic_25` | Weak |
| `sha1(md5($pass))` | - | 4700 | `dynamic_23` | Weak |
| `sha1(sha1($pass))` | - | 4500 | - | Weak |
| `HMAC-SHA1 (key = $pass)` | - | 150 | `hmac-sha1` | Weak |
| `HMAC-SHA1 (key = $salt)` | - | 160 | - | Weak |
| `sha256($pass.$salt)` | - | 1410 | `dynamic_62` | Moderate |
| `sha256($salt.$pass)` | - | 1420 | `dynamic_61` | Moderate |
| `HMAC-SHA256 (key = $pass)` | - | 1450 | `hmac-sha256` | Moderate |
| `HMAC-SHA256 (key = $salt)` | - | 1460 | - | Moderate |
| `sha512($pass.$salt)` | - | 1710 | `dynamic_82` | Moderate |
| `sha512($salt.$pass)` | - | 1720 | `dynamic_81` | Moderate |
| `HMAC-SHA512 (key = $pass)` | - | 1750 | `hmac-sha512` | Moderate |
| `HMAC-SHA512 (key = $salt)` | - | 1760 | - | Moderate |

### crypt and key-derivation formats (18)

| Format | Details | Hashcat mode | John format | Strength |
| --- | --- | --- | --- | --- |
| md5crypt | MD5(Unix), Cisco-IOS type 5 | 500 | `md5crypt` | Weak |
| sha512crypt | - | 1800 | `sha512crypt` | Strong |
| bcrypt | - | 3200 | `bcrypt` | Strong |
| descrypt | DES(Unix), traditional crypt | 1500 | `descrypt` | Weak |
| MD5(APR) | Apache htpasswd | 1600 | `md5crypt` | Weak |
| sha256crypt | SHA-256(Unix) | 7400 | `sha256crypt` | Strong |
| Argon2 | Argon2i, Argon2d, Argon2id | 34000 | `argon2` | Strong |
| scrypt | SCRYPT:N:r:p:salt:hash | 8900 | - | Strong |
| scrypt (Unix) | `scryptcrypt, $7$` | 36300 | `scrypt` | Strong |
| yescrypt | default in current Debian, Ubuntu and Fedora | 36100 | `crypt` | Strong |
| gost-yescrypt | yescrypt with GOST R 34.11-2012, used by ALT Linux | 36200 | - | Strong |
| passlib PBKDF2-SHA256 | `$pbkdf2-sha256$` | 20300 | `pbkdf2-hmac-sha256` | Strong |
| passlib PBKDF2-SHA512 | `$pbkdf2-sha512$` | 20200 | - | Strong |
| passlib PBKDF2-SHA1 | `$pbkdf2$` | 20400 | - | Strong |
| PBKDF2-HMAC-SHA256 | sha256:rounds:salt:hash | 10900 | - | Strong |
| PBKDF2-HMAC-SHA1 | sha1:rounds:salt:hash | 12000 | - | Strong |
| PBKDF2-HMAC-SHA512 | sha512:rounds:salt:hash | 12100 | - | Strong |
| PBKDF2-HMAC-MD5 | md5:rounds:salt:hash | 11900 | - | Strong |

### Web applications (17)

| Format | Details | Hashcat mode | John format | Strength |
| --- | --- | --- | --- | --- |
| WordPress (phpass) | MD5(Wordpress), also Joomla 2.5.18+ | 400 | `phpass` | Weak |
| phpBB3 (phpass) | MD5(phpBB3) | 400 | `phpass` | Weak |
| MD5(HMAC(Wordpress)) | - | - | - | Weak |
| Joomla | `md5($pass.$salt), before 2.5.18` | 11 | `dynamic_1` | Weak |
| Django SHA-1 | `SHA-1(Django), sha1($salt.$pass)` | 124 | - | Weak |
| Django SHA-256 | `SHA-256(Django), sha256($salt.$pass)` | - | - | Moderate |
| Django SHA-384 | `SHA-384(Django), sha384($salt.$pass)` | - | - | Moderate |
| Django PBKDF2-SHA256 | Django's default since 1.4 | 10000 | `django` | Strong |
| Django bcrypt | a bcrypt hash behind Django's marker | 3200 | `bcrypt` | Strong |
| Django bcrypt-SHA256 | bcrypt of the password's SHA-256 | - | - | Strong |
| Django Argon2 | an Argon2 hash behind Django's marker | 34000 | `argon2` | Strong |
| Drupal 7 | phpass with SHA-512 | 7900 | `drupal7` | Strong |
| osCommerce | `xt:Commerce, md5($salt.$pass), 2-character salt` | 21 | `dynamic_4` | Weak |
| vBulletin < 3.8.5 | `md5(md5($pass).$salt), 3-character salt` | 2611 | `dynamic_7` | Weak |
| vBulletin 3.8.5+ | `md5(md5($pass).$salt), 30-character salt` | 2711 | `dynamic_6` | Weak |
| MyBB / IPB | `md5(md5($salt).md5($pass)), 5 or 8-character salt` | 2811 | `dynamic_12` | Weak |
| JWT | JSON Web Token signed with HMAC | 16500 | `hmac-sha256` | Moderate |

### Databases (9)

| Format | Details | Hashcat mode | John format | Strength |
| --- | --- | --- | --- | --- |
| MySQL323 | MySQL before 4.1, OLD_PASSWORD() | 200 | `mysql` | Weak |
| MySQL 4.1+ | `MySQL5, SHA-1(SHA-1($pass))` | 300 | `mysql-sha1` | Weak |
| MSSQL 2000 | - | 131 | `mssql` | Weak |
| MSSQL 2005 | SQL Server 2005 and 2008 | 132 | `mssql05` | Weak |
| MSSQL 2012 | SQL Server 2012 to 2022 | 1731 | `mssql12` | Moderate |
| Oracle 11g | `the S: verifier, sha1($pass.$salt)` | 112 | `oracle11` | Weak |
| Oracle 12c | the T: verifier, PBKDF2-SHA512 | 12300 | `oracle12c` | Strong |
| PostgreSQL MD5 | `md5($pass.$user), from pg_shadow` | 12 | - | Weak |
| PostgreSQL SCRAM-SHA-256 | default since PostgreSQL 14 | 28600 | `scram-pbkdf2-sha256` | Strong |

### Windows (5)

| Format | Details | Hashcat mode | John format | Strength |
| --- | --- | --- | --- | --- |
| SAM (LM:NT) | LM hash, then NTLM hash | 1000 | `nt` | Weak |
| pwdump | a line of pwdump or secretsdump output | 1000 | `nt` | Weak |
| Domain Cached Credentials | DCC, MS Cache, mscash | 1100 | `mscash` | Weak |
| Domain Cached Credentials 2 | DCC2, MS Cache 2, mscash2 | 2100 | `mscash2` | Moderate |
| RAdmin v2.x | MD5 of the password padded to 100 bytes | 9900 | `radmin` | Weak |

### Network devices and protocols (16)

| Format | Details | Hashcat mode | John format | Strength |
| --- | --- | --- | --- | --- |
| Cisco type 4 | one SHA-256, withdrawn by Cisco | 5700 | - | Weak |
| Cisco type 7 | a reversible encoding, not a hash | - | - | Weak |
| Cisco type 8 | PBKDF2-SHA256 | 9200 | - | Strong |
| Cisco type 9 | scrypt | 9300 | - | Strong |
| Cisco-PIX MD5 | - | 2400 | `pix-md5` | Weak |
| Cisco-ASA MD5 | salted with the start of the user name | 2410 | `asa-md5` | Weak |
| NetNTLMv1 | NTLMv1 challenge and response | 5500 | `netntlm` | Weak |
| NetNTLMv2 | NTLMv2 challenge and response | 5600 | `netntlmv2` | Weak |
| Kerberos 5 TGS-REP etype 23 | Kerberoasting, RC4 | 13100 | `krb5tgs` | Weak |
| Kerberos 5 TGS-REP AES | Kerberoasting, etype 17 or 18 | 19700 | `krb5tgs-sha1` | Moderate |
| Kerberos 5 AS-REP etype 23 | AS-REP roasting, RC4 | 18200 | `krb5asrep` | Weak |
| Kerberos 5 AS-REP AES | AS-REP roasting, etype 17 or 18 | 32200 | `krb5asrep` | Moderate |
| Kerberos 5 Pre-Auth etype 23 | AS-REQ timestamp, RC4 | 7500 | `krb5pa-md5` | Weak |
| Kerberos 5 Pre-Auth AES | AS-REQ timestamp, etype 17 or 18 | 19900 | `krb5pa-sha1` | Moderate |
| WPA PMKID/EAPOL | a line of a .hc22000 file | 22000 | - | Moderate |
| WPA PMKID (legacy) | the format before .hc22000 | 16800 | - | Moderate |

### LDAP (6)

| Format | Details | Hashcat mode | John format | Strength |
| --- | --- | --- | --- | --- |
| LDAP {SHA} | SHA-1 in base64, nsldap | 101 | `raw-sha1` | Weak |
| LDAP {SSHA} | salted SHA-1, nsldaps | 111 | `salted-sha1` | Weak |
| LDAP {SSHA256} | salted SHA-256 | 1411 | - | Moderate |
| LDAP {SSHA512} | salted SHA-512 | 1711 | `ssha512` | Moderate |
| LDAP {MD5} | MD5 in base64 | - | - | Weak |
| LDAP {SMD5} | salted MD5 | - | - | Weak |

### Games (2)

| Format | Details | Hashcat mode | John format | Strength |
| --- | --- | --- | --- | --- |
| Lineage II C4 | - | - | - | Weak |
| SHA-1(MaNGOS) | `sha1(upper($user):upper($pass))` | - | `dynamic_35` | Weak |

### Checksums, not cryptographic hashes (12)

| Format | Details | Hashcat mode | John format | Strength |
| --- | --- | --- | --- | --- |
| CRC-16 | CRC-16/ARC | - | - | Weak |
| CRC-16-CCITT | CRC-16/CCITT-FALSE | - | - | Weak |
| FCS-16 | CRC-16/X-25, used by PPP | - | - | Weak |
| CRC-32B | zlib, PNG, PHP crc32b | 11500 | `crc32` | Weak |
| CRC-32 | CRC-32/BZIP2 | - | - | Weak |
| Adler-32 | zlib | - | - | Weak |
| GHash-32-3 | - | - | - | Weak |
| GHash-32-5 | - | - | - | Weak |
| XOR-32 | - | - | - | Weak |
| FNV-32 | FNV-1 or FNV-1a | - | - | Weak |
| CRC-64 | ECMA-182, Jones | 28000 | - | Weak |
| FNV-64 | FNV-1 or FNV-1a | - | - | Weak |
<!-- formats-table: end -->

Not covered: the formats that `zip2john`, `office2john` and similar tools
extract from files.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Every hash matched a known format; also after interactive mode |
| 1 | No hash matched |
| 2 | Invalid arguments, or input that cannot be read or contains no hashes |
| 3 | Some hashes matched and some did not |

The codes are the same in every view and with `--json`.

## JSON output

Each line of `--json` output is one object for one input value:

| Key | Type | Meaning |
| --- | --- | --- |
| `schema_version` | int | Schema version, currently `1` |
| `input` | string | The value as received |
| `source` | string | `"argument"`, `"<stdin>"` or the path given to `-f` |
| `position` | int | Argument index or line number, starting at 1 |
| `context` | string or null | The `--from` value, or null |
| `matched` | bool | Whether any known format matched |
| `candidates` | list | Matching formats, best first; empty if none |
| `tips` | list | `--from` values that would change the top format |

Each candidate has:

| Key | Type | Meaning |
| --- | --- | --- |
| `rank` | int | 1 for the best candidate |
| `format` | string | Format name, as in the tables above |
| `category` | string | `"raw"`, `"salted"`, `"application"`, `"crypt"` or `"checksum"` |
| `score` | number | Ranking score within the tier |
| `confidence` | string | `"high"`, `"medium"` or `"low"` |
| `tier` | string | `"possible"` or `"least_possible"` |
| `hashcat_mode` | int or null | Hashcat `-m` value |
| `john_format` | string or null | John the Ripper `--format` value |
| `strength` | string | `"weak"`, `"moderate"` or `"strong"` |
| `strength_note` | string | One sentence on why |
| `reasons` | list of string | Why it matched and why it ranks where it does |
| `commands` | list of string | Ready-to-run Hashcat and John commands |
| `notes` | list of string | How to prepare the hash for those tools, if needed |

Each tip has `context` and `top_format`. Absent values, such as a format John
does not support, are `null`. Keys are snake_case, and the output is pure
ASCII: other characters are written as `\uXXXX` escapes.

**Versioning:** new keys may be added within `schema_version` 1, so ignore
keys you don't recognize. `category` and `tier` were added in 0.2.0. Renaming
or removing a key, or changing its type, increases `schema_version`.

## Development

Set up a checkout as described under [From source](#from-source), with the
development extra, and run the tests with `python -m pytest`.

Every format is one `Signature` entry in a module under
`src/hashident/signatures/`. To add a format:

1. Add the entry to the module for its category, and to that module's
   `SIGNATURES` tuple.
2. Add its example to `VECTORS` in `tests/test_vectors.py`, with the tier it
   should land in and where the example comes from.
3. Regenerate the README:

   ```sh
   python scripts/update_readme.py
   ```

The script rewrites the parts of this README that mirror the code: the format
tables, the format count, the banner, and the output under every example.
Review the diff afterwards: a changed example means the program's output
changed. The rest of the README is written by hand and left alone.

`python scripts/update_readme.py --check` changes nothing and exits with 1 if
the README is out of date. The test suite makes the same check, and points
out anything else a new format needs.

## Responsible use

hashident only identifies hashes. It has no cracking built in: the commands
it prints are suggestions for Hashcat or John the Ripper, which you run
yourself. Only analyze hashes you are authorized to work with, such as CTF
challenges, your own systems, coursework material, or systems covered by a
written agreement for a security assessment.

## Credits

The example hashes used in the tests come from the
[Hashcat example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
list wherever it has one, with the plaintext `hashcat`, or are computed from
that same plaintext. One comes from John the Ripper's test vectors. Format
names for John were checked against its source. The two-list layout of the
default view follows the classic hash-identifier tool.

See [CHANGELOG.md](https://github.com/jmendoza167/hash_identifier/blob/main/CHANGELOG.md)
for what changed in each release.

## License

MIT. See [LICENSE](https://github.com/jmendoza167/hash_identifier/blob/main/LICENSE).
