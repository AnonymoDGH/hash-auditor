"""Pure-Python reference implementations of MD5, SHA-1 and SHA-256.

Educational by design: every round is visible, every constant is named,
and :func:`cross_check` proves the implementations agree with
:mod:`hashlib` byte for byte.  On top of the primitives this module
provides salted and iterated variants, a pure HMAC (RFC 2104) and a
pure PBKDF2-HMAC (RFC 2898) so the whole password-storage stack can be
studied without any C extensions.

Use :mod:`hashlib` in production.  Use this module to *understand*.
"""

from __future__ import annotations

import hashlib
import struct

__all__ = [
    "MD5", "SHA1", "SHA256", "ALGORITHMS", "new", "pure_hexdigest",
    "hmac_digest", "hmac_hex", "pbkdf2_hmac", "salted_hash",
    "iterated_hash", "cross_check",
]

MASK32 = 0xFFFFFFFF


def _rotl(x: int, n: int) -> int:
    """Rotate a 32-bit word left by ``n`` bits."""
    return ((x << n) | (x >> (32 - n))) & MASK32


def _rotr(x: int, n: int) -> int:
    """Rotate a 32-bit word right by ``n`` bits."""
    return ((x >> n) | (x << (32 - n))) & MASK32


def _as_bytes(data: bytes | bytearray | memoryview | str) -> bytes:
    if isinstance(data, str):
        return data.encode("utf-8")
    return bytes(data)


class MD5:
    """RFC 1321 MD5, implemented from the specification.

    Supports incremental :meth:`update`, :meth:`digest` /
    :meth:`hexdigest` and :meth:`copy`.  Digest output is identical to
    :class:`hashlib.md5` for every input (see :func:`cross_check`).
    """

    name = "md5"
    block_size = 64
    digest_size = 16

    # Per-round left-rotate amounts, s[i].
    _S = (
        [7, 12, 17, 22] * 4 + [5, 9, 14, 20] * 4 +
        [4, 11, 16, 23] * 4 + [6, 10, 15, 21] * 4
    )
    # K[i] = floor(2**32 * abs(sin(i + 1))), precomputed.
    _K = (
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    )

    def __init__(self, data: bytes | bytearray | memoryview | str = b"") -> None:
        self._h = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
        self._buffer = b""
        self._msglen = 0
        if data:
            self.update(data)

    def update(self, data: bytes | bytearray | memoryview | str) -> "MD5":
        """Feed more message bytes into the hash."""
        data = _as_bytes(data)
        self._msglen += len(data)
        data = self._buffer + data
        cut = len(data) - len(data) % 64
        for i in range(0, cut, 64):
            self._process_block(data[i:i + 64], self._h)
        self._buffer = data[cut:]
        return self

    @classmethod
    def _process_block(cls, chunk: bytes, h: list[int]) -> None:
        m = list(struct.unpack("<16I", chunk))
        a, b, c, d = h
        for i in range(64):
            if i < 16:
                f = (b & c) | (~b & d)
                g = i
            elif i < 32:
                f = (d & b) | (~d & c)
                g = (5 * i + 1) % 16
            elif i < 48:
                f = b ^ c ^ d
                g = (3 * i + 5) % 16
            else:
                f = c ^ (b | ~d)
                g = (7 * i) % 16
            f = (f + a + cls._K[i] + m[g]) & MASK32
            a = d
            d = c
            c = b
            b = (b + _rotl(f, cls._S[i])) & MASK32
        h[0] = (h[0] + a) & MASK32
        h[1] = (h[1] + b) & MASK32
        h[2] = (h[2] + c) & MASK32
        h[3] = (h[3] + d) & MASK32

    def digest(self) -> bytes:
        """Return the 16-byte digest without disturbing internal state."""
        msg = self._buffer + b"\x80"
        msg += b"\x00" * ((55 - self._msglen % 64) % 64)
        msg += ((self._msglen * 8) & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
        h = list(self._h)
        for i in range(0, len(msg), 64):
            self._process_block(msg[i:i + 64], h)
        return b"".join(w.to_bytes(4, "little") for w in h)

    def hexdigest(self) -> str:
        """Return the digest as a lowercase hex string."""
        return self.digest().hex()

    def copy(self) -> "MD5":
        """Return an independent clone of this hash object."""
        clone = self.__class__.__new__(self.__class__)
        clone._h = list(self._h)
        clone._buffer = self._buffer
        clone._msglen = self._msglen
        return clone


class SHA1:
    """FIPS 180-1 SHA-1, implemented from the specification.

    Same incremental interface as :class:`MD5`.  SHA-1 is broken for
    collision resistance; it remains here because legacy password storage
    (and breach corpora) still use it heavily.
    """

    name = "sha1"
    block_size = 64
    digest_size = 20

    _H0 = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)
    _K = (0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6)

    def __init__(self, data: bytes | bytearray | memoryview | str = b"") -> None:
        self._h = list(self._H0)
        self._buffer = b""
        self._msglen = 0
        if data:
            self.update(data)

    def update(self, data: bytes | bytearray | memoryview | str) -> "SHA1":
        """Feed more message bytes into the hash."""
        data = _as_bytes(data)
        self._msglen += len(data)
        data = self._buffer + data
        cut = len(data) - len(data) % 64
        for i in range(0, cut, 64):
            self._process_block(data[i:i + 64], self._h)
        self._buffer = data[cut:]
        return self

    @classmethod
    def _process_block(cls, chunk: bytes, h: list[int]) -> None:
        w = list(struct.unpack(">16I", chunk))
        for i in range(16, 80):
            w.append(_rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1))
        a, b, c, d, e = h
        for i in range(80):
            if i < 20:
                f = (b & c) | ((~b) & d)
            elif i < 40:
                f = b ^ c ^ d
            elif i < 60:
                f = (b & c) | (b & d) | (c & d)
            else:
                f = b ^ c ^ d
            temp = (_rotl(a, 5) + f + e + cls._K[i // 20] + w[i]) & MASK32
            e = d
            d = c
            c = _rotl(b, 30)
            b = a
            a = temp
        for i, v in enumerate((a, b, c, d, e)):
            h[i] = (h[i] + v) & MASK32

    def digest(self) -> bytes:
        """Return the 20-byte digest without disturbing internal state."""
        msg = self._buffer + b"\x80"
        msg += b"\x00" * ((55 - self._msglen % 64) % 64)
        msg += ((self._msglen * 8) & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "big")
        h = list(self._h)
        for i in range(0, len(msg), 64):
            self._process_block(msg[i:i + 64], h)
        return b"".join(w.to_bytes(4, "big") for w in h)

    def hexdigest(self) -> str:
        """Return the digest as a lowercase hex string."""
        return self.digest().hex()

    def copy(self) -> "SHA1":
        """Return an independent clone of this hash object."""
        clone = self.__class__.__new__(self.__class__)
        clone._h = list(self._h)
        clone._buffer = self._buffer
        clone._msglen = self._msglen
        return clone


class SHA256:
    """FIPS 180-4 SHA-256, implemented from the specification."""

    name = "sha256"
    block_size = 64
    digest_size = 32

    _H0 = (
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    )
    # First 32 bits of the fractional parts of the cube roots of the
    # first 64 primes.
    _K = (
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    )

    def __init__(self, data: bytes | bytearray | memoryview | str = b"") -> None:
        self._h = list(self._H0)
        self._buffer = b""
        self._msglen = 0
        if data:
            self.update(data)

    def update(self, data: bytes | bytearray | memoryview | str) -> "SHA256":
        """Feed more message bytes into the hash."""
        data = _as_bytes(data)
        self._msglen += len(data)
        data = self._buffer + data
        cut = len(data) - len(data) % 64
        for i in range(0, cut, 64):
            self._process_block(data[i:i + 64], self._h)
        self._buffer = data[cut:]
        return self

    @classmethod
    def _process_block(cls, chunk: bytes, h: list[int]) -> None:
        w = list(struct.unpack(">16I", chunk))
        for i in range(16, 64):
            s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w.append((w[i - 16] + s0 + w[i - 7] + s1) & MASK32)
        a, b, c, d, e, f, g, hh = h
        for i in range(64):
            s1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
            ch = (e & f) ^ ((~e) & g)
            temp1 = (hh + s1 + ch + cls._K[i] + w[i]) & MASK32
            s0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (s0 + maj) & MASK32
            hh = g
            g = f
            f = e
            e = (d + temp1) & MASK32
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & MASK32
        for i, v in enumerate((a, b, c, d, e, f, g, hh)):
            h[i] = (h[i] + v) & MASK32

    def digest(self) -> bytes:
        """Return the 32-byte digest without disturbing internal state."""
        msg = self._buffer + b"\x80"
        msg += b"\x00" * ((55 - self._msglen % 64) % 64)
        msg += ((self._msglen * 8) & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "big")
        h = list(self._h)
        for i in range(0, len(msg), 64):
            self._process_block(msg[i:i + 64], h)
        return b"".join(w.to_bytes(4, "big") for w in h)

    def hexdigest(self) -> str:
        """Return the digest as a lowercase hex string."""
        return self.digest().hex()

    def copy(self) -> "SHA256":
        """Return an independent clone of this hash object."""
        clone = self.__class__.__new__(self.__class__)
        clone._h = list(self._h)
        clone._buffer = self._buffer
        clone._msglen = self._msglen
        return clone


ALGORITHMS: dict[str, type] = {"md5": MD5, "sha1": SHA1, "sha256": SHA256}


def new(algo: str, data: bytes | str = b""):
    """Create a pure-Python hash object for ``algo`` (md5/sha1/sha256)."""
    try:
        cls = ALGORITHMS[algo.lower()]
    except KeyError:
        raise ValueError(f"Unknown algorithm: {algo} (use {', '.join(ALGORITHMS)})") from None
    return cls(data)


def pure_hexdigest(algo: str, data: bytes | str) -> str:
    """One-shot pure-Python hex digest."""
    return new(algo, data).hexdigest()


def hmac_digest(algo: str, key: bytes | str, msg: bytes | str) -> bytes:
    """Pure HMAC (RFC 2104) over one of this module's primitives."""
    cls = ALGORITHMS[algo.lower()]
    key = _as_bytes(key)
    msg = _as_bytes(msg)
    if len(key) > cls.block_size:
        key = cls(key).digest()
    key = key.ljust(cls.block_size, b"\x00")
    o_pad = bytes(k ^ 0x5C for k in key)
    i_pad = bytes(k ^ 0x36 for k in key)
    return cls(o_pad + cls(i_pad + msg).digest()).digest()


def hmac_hex(algo: str, key: bytes | str, msg: bytes | str) -> str:
    """Pure HMAC as a lowercase hex string."""
    return hmac_digest(algo, key, msg).hex()


def pbkdf2_hmac(algo: str, password: bytes | str, salt: bytes | str,
                iterations: int, dklen: int | None = None) -> bytes:
    """Pure PBKDF2-HMAC (RFC 2898) built on :func:`hmac_digest`.

    Slow on purpose in pure Python; keep ``iterations`` modest in tests.
    """
    if iterations < 1:
        raise ValueError("iterations must be >= 1")
    cls = ALGORITHMS[algo.lower()]
    password = _as_bytes(password)
    salt = _as_bytes(salt)
    dklen = cls.digest_size if dklen is None else dklen
    if dklen < 1:
        raise ValueError("dklen must be >= 1")
    out = bytearray()
    block_index = 1
    while len(out) < dklen:
        u = hmac_digest(algo, password, salt + block_index.to_bytes(4, "big"))
        acc = u
        for _ in range(iterations - 1):
            u = hmac_digest(algo, password, u)
            acc = bytes(a ^ b for a, b in zip(acc, u))
        out.extend(acc)
        block_index += 1
    return bytes(out[:dklen])


def salted_hash(algo: str, password: str, salt: str, mode: str = "prepend",
                rounds: int = 1) -> str:
    """Hash ``password`` together with ``salt``.

    ``mode`` selects how the salt is combined: ``prepend`` (salt+pw,
    the classic phpBB scheme), ``append`` (pw+salt) or ``colon``
    (``salt:pw``).  ``rounds`` re-hashes the digest that many times.
    """
    if mode == "prepend":
        payload = salt + password
    elif mode == "append":
        payload = password + salt
    elif mode == "colon":
        payload = f"{salt}:{password}"
    else:
        raise ValueError(f"Unknown salt mode: {mode}")
    if rounds < 1:
        raise ValueError("rounds must be >= 1")
    digest = new(algo, payload.encode("utf-8")).digest()
    for _ in range(rounds - 1):
        digest = new(algo, digest).digest()
    return digest.hex()


def iterated_hash(algo: str, password: str, iterations: int) -> str:
    """Repeated hashing: H(pw), then H(previous digest), ``iterations`` times.

    Models legacy "key stretching by re-hashing" schemes that predate
    PBKDF2/bcrypt.  One iteration is the plain hash.
    """
    if iterations < 1:
        raise ValueError("iterations must be >= 1")
    digest = new(algo, password.encode("utf-8")).digest()
    for _ in range(iterations - 1):
        digest = new(algo, digest).digest()
    return digest.hex()


_DEFAULT_SAMPLES = (
    b"",
    b"abc",
    b"a" * 55,
    b"a" * 56,
    b"a" * 63,
    b"a" * 64,
    b"a" * 65,
    b"The quick brown fox jumps over the lazy dog",
    bytes(range(256)) * 3,
)


def cross_check(samples: list[bytes] | tuple[bytes, ...] | None = None) -> dict[str, bool]:
    """Verify every pure implementation against :mod:`hashlib`.

    Returns ``{"md5": True/False, "sha1": ..., "sha256": ...}``.  Used
    by the test-suite and by ``hashaudit hash --selftest``.
    """
    samples = tuple(samples) if samples is not None else _DEFAULT_SAMPLES
    result: dict[str, bool] = {}
    for name, cls in ALGORITHMS.items():
        ok = True
        for sample in samples:
            reference = hashlib.new(name, sample).hexdigest()
            if cls(sample).hexdigest() != reference:
                ok = False
                break
        result[name] = ok
    return result
