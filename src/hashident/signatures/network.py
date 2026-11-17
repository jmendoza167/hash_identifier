"""Network devices and protocols: Cisco, NTLM and Kerberos captures, WPA.

Captured authentication exchanges are long lines with a fixed layout or a
``$tag$`` in front, so they are pinned by structure or prefix.
"""

from __future__ import annotations

from collections.abc import Callable

from hashident.models import Category, Charset, Context, Signature, Strength, Tier
from hashident.signatures import _examples
from hashident.signatures._shared import B64, COLON_FIELD, WINDOWS, hex_chars

_P = Tier.POSSIBLE
_WEAK, _MODERATE, _STRONG = Strength.WEAK, Strength.MODERATE, Strength.STRONG

_HEX = Charset.HEX.char_class


def _net(
    name: str,
    popularity: float,
    example: str,
    *,
    pattern: str,
    strength: Strength,
    note: str,
    length: int | None = None,
    charset: Charset = Charset.MIXED,
    prefixes: tuple[str, ...] = (),
    structure: str | None = None,
    summary: str = "",
    hashcat: int | None = None,
    john: str | None = None,
    notes: tuple[str, ...] = (),
    contexts: frozenset[Context] = frozenset(),
    validator: Callable[[str], bool] | None = None,
) -> Signature:
    return Signature(
        name=name,
        category=Category.APPLICATION,
        tier=_P,
        pattern=pattern,
        length=length,
        charset=charset,
        prefixes=prefixes,
        structure=structure,
        summary=summary,
        strength=strength,
        strength_note=note,
        example=example,
        hashcat_mode=hashcat,
        john_format=john,
        notes=notes,
        popularity=popularity,
        contexts=contexts,
        validator=validator,
    )


# --- Cisco --------------------------------------------------------------------
# Type 5 is md5crypt, in the crypt module.

CISCO4 = _net(
    "Cisco type 4",
    40,
    "2btjjy78REtmYkkW0csHUbJZOstRXoWdX1mGrmmfeHI",
    pattern=rf"{B64}{{43}}",
    length=43,
    charset=Charset.CRYPT64,
    summary="one SHA-256, withdrawn by Cisco",
    strength=_WEAK,
    note="A single unsalted SHA-256, which Cisco withdrew for being too weak.",
    hashcat=5700,
)

# Type 7 is not a hash: each byte is XORed with a fixed key, starting at the
# offset given by the first two digits. A pattern alone would take any hex
# that begins with 00 to 15, so the value is decoded and must come out as
# printable text. At least four bytes are required, which also keeps 4 and 8
# character checksums out.
_CISCO7_KEY = b"dsfd;kfoA,.iyewrkldJKDHSUBsgvca69834ncxv9873254k;fg87"


def _decodes_to_text(value: str) -> bool:
    offset = int(value[:2])
    return all(
        0x20 <= byte ^ _CISCO7_KEY[(offset + i) % len(_CISCO7_KEY)] <= 0x7E
        for i, byte in enumerate(bytes.fromhex(value[2:]))
    )


CISCO7 = _net(
    "Cisco type 7",
    100,
    "08294D5D011A0403",
    pattern=rf"(?:0[0-9]|1[0-5])(?:{_HEX}{{2}}){{4,64}}",
    charset=Charset.HEX,
    summary="a reversible encoding, not a hash",
    strength=_WEAK,
    note="Not a hash: a fixed XOR that any type 7 decoder undoes at once.",
    validator=_decodes_to_text,
)

CISCO8 = _net(
    "Cisco type 8",
    60,
    "$8$TnGX/fE4KGHOVU$pEhnEvxrvaynpi8j4f.EMHr6M.FzU8xnZnBr/tJdFWk",
    pattern=rf"\$8\${B64}{{14}}\${B64}{{43}}",
    length=61,
    charset=Charset.CRYPT64,
    prefixes=("$8$",),
    summary="PBKDF2-SHA256",
    strength=_STRONG,
    note="Salted PBKDF2-SHA256 with 20,000 rounds.",
    hashcat=9200,
)

CISCO9 = _net(
    "Cisco type 9",
    60,
    "$9$2MJBozw/9R3UsU$2lFhcKvpghcyw8deP25GOfyZaagyUOGBymkryvOdfo6",
    pattern=rf"\$9\${B64}{{14}}\${B64}{{43}}",
    length=61,
    charset=Charset.CRYPT64,
    prefixes=("$9$",),
    summary="scrypt",
    strength=_STRONG,
    note="Salted and memory-hard: each guess costs memory as well as time.",
    hashcat=9300,
)

# 16 characters of crypt base64. All 16 being hex digits is next to
# impossible for a real one, so one other character is required; that keeps
# 16-character hex digests (MySQL323) from matching.
CISCO_PIX = _net(
    "Cisco-PIX MD5",
    40,
    "dRRVnUmUHXOTt9nk",
    pattern=rf"(?={B64}*[^0-9a-fA-F]){B64}{{16}}",
    length=16,
    charset=Charset.CRYPT64,
    strength=_WEAK,
    note="One unsalted MD5 of the padded password.",
    hashcat=2400,
    john="pix-md5",
)

CISCO_ASA = _net(
    "Cisco-ASA MD5",
    40,
    "02dMBMYkTdC5Ziyp:36",
    pattern=rf"{B64}{{16}}:[^:\s]{{1,4}}",
    charset=Charset.CRYPT64,
    structure="hash:salt",
    summary="salted with the start of the user name",
    strength=_WEAK,
    note="One MD5 salted with up to four characters of the user name.",
    hashcat=2410,
    john="asa-md5",
)

# --- NTLM challenge and response, as Responder and similar tools capture it ---

NETNTLMV1 = _net(
    "NetNTLMv1",
    60,
    _examples.NETNTLMV1,
    pattern=rf"[^:]*::[^:]*:{_HEX}{{48}}:{_HEX}{{48}}:{_HEX}{{16}}",
    structure="user::domain:lm:nt:challenge",
    summary="NTLMv1 challenge and response",
    strength=_WEAK,
    note="DES-based response to a challenge: quick to crack, whatever the password.",
    hashcat=5500,
    john="netntlm",
    contexts=WINDOWS,
)

NETNTLMV2 = _net(
    "NetNTLMv2",
    80,
    _examples.NETNTLMV2,
    pattern=rf"[^:]*::[^:]*:{_HEX}{{16}}:{_HEX}{{32}}:{_HEX}{{2,}}",
    structure="user::domain:challenge:hmac:blob",
    summary="NTLMv2 challenge and response",
    strength=_WEAK,
    note="One HMAC-MD5 over the NTLM hash: fast to guess on GPUs.",
    hashcat=5600,
    john="netntlmv2",
    contexts=WINDOWS,
)

# --- Kerberos -----------------------------------------------------------------
# $krb5<kind>$<etype>$ ... $<hex>. The fields between differ between the
# tools that write these lines, so only the tag, the encryption type and the
# hex at the end are checked.


def _kerberos(
    name: str,
    tag: str,
    etypes: tuple[int, ...],
    example: str,
    *,
    summary: str,
    hashcat: int,
    john: str | None = None,
    notes: tuple[str, ...] = (),
) -> Signature:
    rc4 = etypes == (23,)
    kinds = "|".join(str(etype) for etype in etypes)
    return _net(
        name,
        80 if rc4 else 60,
        example,
        pattern=rf"\${tag}\$(?:{kinds})\$[!-~]*?[$:]{_HEX}{{64,}}",
        prefixes=tuple(f"${tag}${etype}$" for etype in etypes),
        summary=summary,
        strength=_WEAK if rc4 else _MODERATE,
        note=(
            "Keyed with the unsalted NTLM hash (RC4): fast to guess."
            if rc4
            else "Keyed with a salted PBKDF2-SHA1 of the password, 4,096 rounds."
        ),
        hashcat=hashcat,
        john=john,
        notes=notes,
        contexts=WINDOWS,
    )


def _aes_note(mode_17: int) -> str:
    return f"Hashcat's mode is for etype 18 (AES-256); use {mode_17} for etype 17 (AES-128)."


KRB5_TGS_RC4 = _kerberos(
    "Kerberos 5 TGS-REP etype 23",
    "krb5tgs",
    (23,),
    _examples.KRB5_TGS_23,
    summary="Kerberoasting, RC4",
    hashcat=13100,
    john="krb5tgs",
)

KRB5_TGS_AES = _kerberos(
    "Kerberos 5 TGS-REP AES",
    "krb5tgs",
    (17, 18),
    _examples.KRB5_TGS_18,
    summary="Kerberoasting, etype 17 or 18",
    hashcat=19700,
    notes=(_aes_note(19600),),
)

KRB5_ASREP_RC4 = _kerberos(
    "Kerberos 5 AS-REP etype 23",
    "krb5asrep",
    (23,),
    _examples.KRB5_ASREP_23,
    summary="AS-REP roasting, RC4",
    hashcat=18200,
    john="krb5asrep",
)

KRB5_ASREP_AES = _kerberos(
    "Kerberos 5 AS-REP AES",
    "krb5asrep",
    (17, 18),
    _examples.KRB5_ASREP_18,
    summary="AS-REP roasting, etype 17 or 18",
    hashcat=32200,
    notes=(_aes_note(32100),),
)

KRB5_PA_RC4 = _kerberos(
    "Kerberos 5 Pre-Auth etype 23",
    "krb5pa",
    (23,),
    _examples.KRB5_PA_23,
    summary="AS-REQ timestamp, RC4",
    hashcat=7500,
    john="krb5pa-md5",
)

KRB5_PA_AES = _kerberos(
    "Kerberos 5 Pre-Auth AES",
    "krb5pa",
    (17, 18),
    _examples.KRB5_PA_18,
    summary="AS-REQ timestamp, etype 17 or 18",
    hashcat=19900,
    notes=(_aes_note(19800),),
)

# --- WPA ----------------------------------------------------------------------

_WPA_NOTE = "Salted with the network name, 4,096 PBKDF2-SHA1 rounds: slow, but GPUs manage."

# One line of a .hc22000 file, as hcxpcapngtool writes it: a PMKID (01) or
# an EAPOL handshake (02), then the two MAC addresses and the network name.
WPA = _net(
    "WPA PMKID/EAPOL",
    80,
    _examples.WPA_22000,
    pattern=(
        rf"WPA\*0[12]\*{_HEX}{{32}}\*{_HEX}{{12}}\*{_HEX}{{12}}\*{_HEX}*"
        rf"\*{_HEX}*\*{_HEX}*\*{_HEX}*"
    ),
    charset=Charset.HEX,
    prefixes=("WPA*01*", "WPA*02*"),
    summary="a line of a .hc22000 file",
    strength=_MODERATE,
    note=_WPA_NOTE,
    hashcat=22000,
)

# The format before 22000: pmkid*ap*client*essid, all in hex.
WPA_PMKID = _net(
    "WPA PMKID (legacy)",
    40,
    _examples.WPA_PMKID,
    pattern=rf"{_HEX}{{32}}\*{_HEX}{{12}}\*{_HEX}{{12}}\*{_HEX}{{2,64}}",
    charset=Charset.HEX,
    structure="pmkid*ap*client*essid",
    summary="the format before .hc22000",
    strength=_MODERATE,
    note=_WPA_NOTE,
    hashcat=16800,
    notes=("Current hashcat wants this converted to a .hc22000 line (mode 22000).",),
)

SIGNATURES: tuple[Signature, ...] = (
    CISCO4,
    CISCO7,
    CISCO8,
    CISCO9,
    CISCO_PIX,
    CISCO_ASA,
    NETNTLMV1,
    NETNTLMV2,
    KRB5_TGS_RC4,
    KRB5_TGS_AES,
    KRB5_ASREP_RC4,
    KRB5_ASREP_AES,
    KRB5_PA_RC4,
    KRB5_PA_AES,
    WPA,
    WPA_PMKID,
)
