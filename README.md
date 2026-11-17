# hashident

[![CI](https://github.com/jmendoza167/hash_identifier/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/jmendoza167/hash_identifier/actions/workflows/ci.yml)

hashident is a command-line tool that tells you which algorithm most likely
produced a hash string. It ranks every matching format with a confidence
level and the reasons behind it, says how hard the hash is to crack, and
prints ready-to-run Hashcat and John the Ripper commands. It is built for CTF
players, students working through security coursework, and auditors who find
password hashes and need to know what they are looking at. It runs on Python
3.10+ with no third-party dependencies.

## Why hashident

Many hash identifiers print a flat list of every format with the right length
and leave the rest to you. hashident tries to answer the next questions too:

- **Ranked, with reasons.** Candidates are ordered best first and labelled
  HIGH, MEDIUM or LOW confidence, with the reasons for each: the shape that
  matched, why one format outranks another, and what else the input could be.
- **Ready-to-run commands.** Each likely format comes with its Hashcat mode,
  John format and the exact commands to start a wordlist attack, plus notes
  where a tool needs the hash in a slightly different form.
- **Strength ratings.** Every format is rated WEAK, MODERATE or STRONG, with
  a one-line explanation (fast and unsalted, or salted and deliberately slow).
- **Context hints.** Tell it where the hash came from (`--from windows`,
  `linux`, `web` or `db`) and the ranking adapts: 32 hex characters from a
  Windows box are more likely NTLM than MD5. When a hint would change the
  answer, hashident suggests it.
- **Built for scripts too.** Batches of hashes from files or pipes, a compact
  table for many values, meaningful exit codes, and `--json` output with a
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
[+] MD4
[+] RIPEMD-128
[+] HAVAL-128
[+] MD2
[+] Tiger-128 - Tiger-192 cut to 128 bits
[+] Snefru-128
```

`--show-modes` adds each format's Hashcat mode and John format:

<!-- readme-test: output --show-modes b89eaac7e61417341b710b727768294d0e6a277b -->
```text
HASH: b89eaac7e61417341b710b727768294d0e6a277b

Possible Hashes:
[+] SHA-1                                     (hashcat 100 | john raw-sha1)
[+] MySQL 4.1+ - MySQL5, SHA-1(SHA-1($pass))  (hashcat 300 | john mysql-sha1)

Least Possible Hashes:
[+] RIPEMD-160                                (hashcat 6000 | john ripemd-160)
[+] HAVAL-160                                 (hashcat 40105)
[+] Tiger-160 - Tiger-192 cut to 160 bits     (hashcat 40091)
```

`-v` prints a detailed report instead, with the reasons behind each format,
its strength and ready-to-run crack commands:

```sh
hashident -v 8743b52063cd84097a65d1633f5c74f5
```

<!-- readme-test: output -v 8743b52063cd84097a65d1633f5c74f5 -->
```text
Input:   8743b52063cd84097a65d1633f5c74f5
Length:  32 characters

#  Format      Confidence  Hashcat  John
-  ----------  ----------  -------  -----------
1  MD5         MEDIUM      0        raw-md5
2  NTLM        MEDIUM      1000     nt
3  LM          LOW         3000     lm
4  MD4         LOW         900      raw-md4
5  RIPEMD-128  LOW         40086    ripemd-128
6  HAVAL-128   LOW         40102    haval-128-4
7  MD2         LOW         40084    md2
8  Tiger-128   LOW         40090    -
9  Snefru-128  LOW         40094    snefru-128

1. MD5 - medium confidence
   Reasons:
     - 32 hexadecimal characters
     - most common format with this shape
     - also matches NTLM, LM, MD4 and 5 more: same length and charset
   Strength: WEAK - Fast and unsalted: GPUs test billions of guesses per second.
   Crack it (save the hash to hash.txt first):
     hashcat -m 0 -a 0 hash.txt wordlist.txt
     john --format=raw-md5 --wordlist=wordlist.txt hash.txt

2. NTLM - medium confidence
   Reasons:
     - 32 hexadecimal characters
     - less common than MD5 with this shape
     - also matches MD5, LM, MD4 and 5 more: same length and charset
   Strength: WEAK - Unsalted MD4 of the password: even faster to crack than MD5.
   Crack it (save the hash to hash.txt first):
     hashcat -m 1000 -a 0 hash.txt wordlist.txt
     john --format=nt --wordlist=wordlist.txt hash.txt

Low-confidence candidates are shown in the table only.

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
columns. In a terminal, output is colored and starts with a banner;
`--no-banner` hides it. Run `hashident` with no arguments for an interactive
`HASH:` prompt.

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
                 [--color {auto,always,never} | --no-color] [-f PATH] [-v]
                 [--json]
                 [hash ...]
```

Run `hashident --help` for the full reference.

### Identify a hash

```sh
hashident 8743b52063cd84097a65d1633f5c74f5
```

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

Hashes read from a file or a pipe are never touched by the shell, so they need
no quoting.

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

- Arguments come first, in order, then the lines of `-f PATH`. `-f -` reads
  standard input. With neither, hashident reads standard input when it is
  piped or redirected, and shows help otherwise.
- In files and piped input, blank lines and lines starting with `#` are
  skipped, and surrounding whitespace is stripped.
- Files can be UTF-8 or UTF-16 with a byte order mark, so files written by
  `>` in Windows PowerShell 5.1 work as they are.
- A missing or unreadable file, or input with no hashes in it, is an error
  (exit code 2).

### Context hints: `--from`

If you know where the hash came from, say so. Formats common in that
environment are ranked higher:

```sh
hashident --from windows 8743b52063cd84097a65d1633f5c74f5
```

Now NTLM ranks above MD5. The values are `windows`, `linux`, `web` and `db`.
A hint changes which plausible format comes first; it never makes an
ambiguous match certain, so both stay MEDIUM confidence. Without `--from`,
hashident suggests a value when one would change the top result.

### Verbose: `-v`

```sh
hashident -v 8743b52063cd84097a65d1633f5c74f5
hashident -v -f hashes.txt
```

With one hash, `-v` also shows the details and commands of LOW-confidence
candidates, which are normally listed in the table only. With several, it
prints a full report for each value instead of the compact table, each under
a rule such as `== line 3 ====`.

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
can process them line by line. It is never colored, and `-v` has no effect on
it: JSON always includes everything.

Pretty-print the output with Python:

```sh
hashident --json 8743b52063cd84097a65d1633f5c74f5 | python -m json.tool
hashident --json -f hashes.txt | python -m json.tool --json-lines
```

Print each value's line number and best format:

```sh
hashident --json -f hashes.txt | python -c "import sys, json; [print(r['position'], r['candidates'][0]['format'] if r['matched'] else 'no match') for r in map(json.loads, sys.stdin)]"
```

Or use [jq](https://jqlang.org) to list the values that matched nothing:

```sh
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

## Supported formats

hashident lists a format under **Possible Hashes** when it is the usual
answer for the input's shape or is pinned by a prefix, and under **Least
Possible Hashes** when it has the same shape but is rarer. The tables give
the Hashcat mode and John the Ripper format where the tool supports the
format; `--show-modes` prints them next to each match.

<!-- formats-table: start -->
### Raw hashes

| Format | Hashcat mode | John format | Strength |
| --- | --- | --- | --- |
| MD5 | 0 | `raw-md5` | Weak |
| NTLM | 1000 | `nt` | Weak |
| SHA-1 | 100 | `raw-sha1` | Weak |
| SHA-224 | 1300 | `raw-sha224` | Moderate |
| SHA-256 | 1400 | `raw-sha256` | Moderate |
| SHA-512 | 1700 | `raw-sha512` | Moderate |
| MD5(Half) | 5100 | - | Weak |
| MD5(Middle) | - | - | Weak |
| LM | 3000 | `lm` | Weak |
| MD4 | 900 | `raw-md4` | Weak |
| RIPEMD-128 | 40086 | `ripemd-128` | Weak |
| MD2 | 40084 | `md2` | Weak |
| HAVAL-128 | 40102 | `haval-128-4` | Weak |
| Tiger-128 | 40090 | - | Moderate |
| Snefru-128 | 40094 | `snefru-128` | Weak |
| RIPEMD-160 | 6000 | `ripemd-160` | Moderate |
| Tiger-160 | 40091 | - | Moderate |
| HAVAL-160 | 40105 | - | Weak |
| Tiger-192 | 40089 | `tiger` | Moderate |
| HAVAL-192 | 40108 | - | Weak |
| SHA3-224 | 17300 | - | Moderate |
| HAVAL-224 | 40111 | - | Weak |
| SHA3-256 | 17400 | - | Moderate |
| BLAKE2s-256 | 31000 | - | Moderate |
| GOST R 34.11-94 | 6900 | `gost` | Weak |
| RIPEMD-256 | 40087 | - | Moderate |
| HAVAL-256 | 40114 | `haval-256-3` | Weak |
| Snefru-256 | 40095 | `snefru-256` | Weak |
| RIPEMD-320 | 33600 | - | Moderate |
| SHA-384 | 10800 | `raw-sha384` | Moderate |
| SHA3-384 | 17500 | - | Moderate |
| SHA3-512 | 17600 | - | Moderate |
| BLAKE2b-512 | 600 | `raw-blake2` | Moderate |
| Whirlpool | 6100 | `whirlpool` | Moderate |

### Application formats

| Format | Hashcat mode | John format | Strength |
| --- | --- | --- | --- |
| MySQL 4.1+ | 300 | `mysql-sha1` | Weak |

### crypt and key-derivation formats

| Format | Hashcat mode | John format | Strength |
| --- | --- | --- | --- |
| md5crypt | 500 | `md5crypt` | Weak |
| sha512crypt | 1800 | `sha512crypt` | Strong |
| bcrypt | 3200 | `bcrypt` | Strong |

### Checksums (not cryptographic hashes)

| Format | Hashcat mode | John format | Strength |
| --- | --- | --- | --- |
| CRC-16 | - | - | Weak |
| CRC-16-CCITT | - | - | Weak |
| FCS-16 | - | - | Weak |
| CRC-32B | 11500 | `crc32` | Weak |
| CRC-32 | - | - | Weak |
| Adler-32 | - | - | Weak |
| GHash-32-3 | - | - | Weak |
| GHash-32-5 | - | - | Weak |
| XOR-32 | - | - | Weak |
<!-- formats-table: end -->

Many formats share a shape: 32 hex characters fit MD5, NTLM, LM, MD4 and
several rarer digests, and 40 fit SHA-1, RIPEMD-160 and a MySQL 4.1+ hash
without its leading `*`. That is why hashident ranks candidates instead of
naming one.

For some formats a tool wants the hash in a slightly different form, and `-v`
prints a note saying so. For example, Hashcat mode 300 expects a MySQL 4.1+
hash without the `*` while John's `mysql-sha1` format needs it, and Hashcat
wants `$BLAKE2$` in front of a BLAKE2 digest. Hashcat modes from 40000 up
were added in hashcat 8.0.0.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Every hash matched a known format |
| 1 | No hash matched |
| 2 | Invalid arguments, or input that cannot be read or contains no hashes |
| 3 | Some hashes matched and some did not |

The codes are the same with `--json` and `-v`.

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

Each candidate has `rank`, `format`, `score`, `confidence`, `hashcat_mode`,
`john_format`, `strength`, `strength_note`, `reasons`, `commands` and `notes`.
Each tip has `context` and `top_format`. Absent values, such as a format John
does not support, are `null`. Keys are snake_case, and the output is pure
ASCII: other characters are written as `\uXXXX` escapes.

**Versioning:** new keys may be added within `schema_version` 1, so ignore
keys you don't recognize. Renaming or removing a key, or changing its type,
increases `schema_version`.

## Responsible use

hashident only identifies hashes. It has no cracking built in: the commands
it prints are suggestions for Hashcat or John the Ripper, which you run
yourself. Only analyze hashes you are authorized to work with, such as CTF
challenges, your own systems, coursework material, or systems covered by a
written agreement for a security assessment.

## Credits

The example hashes used in the tests and in this README come from the
[Hashcat example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
list. The plaintext for all of them is `hashcat`. The MySQL 4.1+ example is
Hashcat's mode 300 hash written in MySQL's own `*` format.

## License

MIT. See [LICENSE](https://github.com/jmendoza167/hash_identifier/blob/main/LICENSE).
