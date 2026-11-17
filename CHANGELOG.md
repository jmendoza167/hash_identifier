# Changelog

All notable changes to hashident are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-11-16

### Added

- 142 more formats, 152 in all, in five categories: raw hashes, salted and
  nested hashes, application formats, crypt and key-derivation formats, and
  checksums. Among them:
  - raw digests: MD2, MD4, LM, SHA-384, SHA3, Keccak, RIPEMD, Tiger, HAVAL,
    Snefru, GOST R 34.11-94, Streebog, SM3, Whirlpool, BLAKE2, and MD5, SHA-1
    and SHA-256 in base64;
  - salted, HMAC and nested constructions such as `md5($pass.$salt)` and
    `sha1(md5($pass))`;
  - web applications: WordPress and phpBB3 (phpass), Joomla, Drupal 7,
    Django, vBulletin, MyBB, IPB, osCommerce, JWT;
  - Windows: SAM `LM:NT` pairs, pwdump lines, Domain Cached Credentials 1 and
    2, NetNTLMv1 and v2, Kerberos 5 TGS-REP, AS-REP and Pre-Auth;
  - databases: MySQL323, MSSQL 2000 to 2022, Oracle 11g and 12c, PostgreSQL
    MD5 and SCRAM-SHA-256;
  - network: Cisco types 4, 7, 8 and 9, PIX and ASA, WPA PMKID and EAPOL;
  - LDAP `{SHA}`, `{SSHA}`, `{SSHA256}`, `{SSHA512}`, `{MD5}` and `{SMD5}`;
  - crypt and KDF formats: descrypt, `$apr1$`, sha256crypt, Argon2, scrypt,
    yescrypt, PBKDF2;
  - checksums: CRC-16, CRC-32, CRC-64, Adler-32, FCS-16, FNV and others,
    labelled as checksums.
- A new default view: one block per hash, with its formats under "Possible
  Hashes" and "Least Possible Hashes".
- Interactive mode: `hashident` with no input on a terminal shows a banner
  and a `HASH:` prompt.
- `--show-modes` to add Hashcat modes and John formats to the default view,
  `--possible-only` to leave out the least possible formats, `--table` for
  the compact table, and `--no-banner`.
- `-vv` for details of the least possible formats in the detailed report.
- `category` and `tier` for each candidate in `--json` output.
- Notes on how to prepare a hash for Hashcat or John for more formats, and a
  note for Hashcat modes that need hashcat 8.0.0.

### Changed

- The detailed report, which was the default for one hash, is now printed
  with `-v`. The compact table, which was the default for several hashes, is
  now printed with `--table`.
- With no arguments on a terminal, hashident starts interactive mode instead
  of printing its help.
- A prefix match wins outright: a hash with a marker such as `$2b$` or `*` is
  no longer listed next to other formats of the same shape. A structure such
  as `hash:salt` likewise beats a bare shape.
- Confidence follows the two lists: a format that is the only match is high,
  a possible format is medium, and a least possible one is low. NTLM for 32
  hex characters and MySQL 4.1+ for 40 are therefore medium, not low, and
  SHA-224, SHA-256 and SHA-512 are medium, not high, now that other formats
  of their lengths are known.
- `--from` reorders formats within a list; it no longer has any effect across
  them.
- The "also matches" reason names at most three other formats.
- The no-match message no longer lists every known format.

### Fixed

- Whitespace inside a hash, such as a line break from a wrapped copy, no
  longer prevents a match.
- `0x` in front of hex no longer prevents a match: the hex after it is tried
  as well.

## [0.1.0] - 2026-11-13

First release: identification of ten formats (MD5, NTLM, SHA-1, SHA-224,
SHA-256, SHA-512, MySQL 4.1+, md5crypt, sha512crypt and bcrypt) with ranked
candidates, reasons, strength ratings, crack commands, `--from` context
hints, a compact table for several hashes, and `--json` output.

[0.2.0]: https://pypi.org/project/hashident/0.2.0/
[0.1.0]: https://pypi.org/project/hashident/0.1.0/
