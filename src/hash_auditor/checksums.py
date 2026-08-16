"""Pure-Python checksums for hash-auditor.

Not cryptographic hashes, but checksums show up constantly in password
storage and breach corpora: CRC32 in legacy systems, Adler-32 in zlib
streams, FNV-1a as a cheap string hash, and the classic Internet checksum
in every IP/TCP header. Implementing them from scratch keeps the module's
educational promise: every bit is visible.

Implemented
-----------
crc32(data)
    CRC-32 (IEEE 802.3), table-driven, matches zlib.crc32.
crc16(data)
    CRC-16/CCITT-FALSE (polynomial 0x1021).
adler32(data)
    Adler-32, matches zlib.adler32.
fnv1a_32(data) / fnv1a_64(data)
    Fowler-Noll-Vo 1a, 32- and 64-bit.
internet_checksum(data)
    the RFC 1071 ones-complement 16-bit sum.
luhn_check(number) / luhn_generate(number)
    the Luhn mod-10 check used by card numbers and some PIN schemes.
checksum_report(data)
    every checksum of one input in a single dict.

Public API is the functions above.

Pure standard library. Deterministic. No network access.
"""

from __future__ import annotations

__all__ = [
    "crc32",
    "crc16",
    "adler32",
    "fnv1a_32",
    "fnv1a_64",
    "internet_checksum",
    "luhn_check",
    "luhn_generate",
    "checksum_report",
]


def _as_bytes(data: bytes | bytearray | str) -> bytes:
    if isinstance(data, str):
        return data.encode("utf-8")
    return bytes(data)


# ---------------------------------------------------------------------------
# CRC-32 (IEEE 802.3): reflected, polynomial 0xEDB88320.
# ---------------------------------------------------------------------------

def _make_crc32_table() -> tuple[int, ...]:
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            crc = (crc >> 1) ^ 0xEDB88320 if crc & 1 else crc >> 1
        table.append(crc)
    return tuple(table)


_CRC32_TABLE = _make_crc32_table()


def crc32(data: bytes | bytearray | str) -> int:
    """CRC-32 of BTQdataBTQ, identical to zlib.crc32 (unsigned)."""
    data = _as_bytes(data)
    crc = 0xFFFFFFFF
    for byte in data:
        crc = _CRC32_TABLE[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


def crc16(data: bytes | bytearray | str) -> int:
    """CRC-16/CCITT-FALSE: polynomial 0x1021, init 0xFFFF, no reflection."""
    data = _as_bytes(data)
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


def adler32(data: bytes | bytearray | str) -> int:
    """Adler-32 of BTQdataBTQ, identical to zlib.adler32."""
    data = _as_bytes(data)
    a, b = 1, 0
    for byte in data:
        a = (a + byte) % 65521
        b = (b + a) % 65521
    return (b << 16) | a


def fnv1a_32(data: bytes | bytearray | str) -> int:
    """32-bit FNV-1a: xor-fold then multiply, per the FNV spec."""
    data = _as_bytes(data)
    h = 0x811C9DC5
    for byte in data:
        h ^= byte
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


def fnv1a_64(data: bytes | bytearray | str) -> int:
    """64-bit FNV-1a."""
    data = _as_bytes(data)
    h = 0xCBF29CE484222325
    for byte in data:
        h ^= byte
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


def internet_checksum(data: bytes | bytearray | str) -> int:
    """RFC 1071 ones-complement 16-bit checksum (as used by IP/TCP)."""
    data = _as_bytes(data)
    if len(data) % 2:
        data = data + b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def luhn_check(number: str) -> bool:
    """Validate a digit string with the Luhn mod-10 algorithm.

    Non-digit characters raise ValueError. The rightmost digit is the check
    digit.
    """
    if not number or not number.isdigit():
        raise ValueError("luhn_check needs a non-empty digit string")
    total = 0
    for i, ch in enumerate(reversed(number)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def luhn_generate(number: str) -> str:
    """Append the Luhn check digit to BTQnumberBTQ."""
    if not number.isdigit():
        raise ValueError("luhn_generate needs a digit string")
    for check in range(10):
        if luhn_check(number + str(check)):
            return number + str(check)
    raise AssertionError("unreachable")  # pragma: no cover


def checksum_report(data: bytes | bytearray | str) -> dict:
    """Every checksum of one input, hex-formatted where natural."""
    return {
        "crc32": f"{crc32(data):08x}",
        "crc16": f"{crc16(data):04x}",
        "adler32": f"{adler32(data):08x}",
        "fnv1a_32": f"{fnv1a_32(data):08x}",
        "fnv1a_64": f"{fnv1a_64(data):016x}",
        "internet_checksum": f"{internet_checksum(data):04x}",
    }
