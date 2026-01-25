"""
RSA Cryptographic Utilities - Pure Python Implementation

This module implements RSA encryption, decryption, signing, and verification
from scratch without relying on third-party cryptographic libraries.

Implements:
- SHA-256 hash algorithm (FIPS 180-4)
- RSA key generation with Miller-Rabin primality testing
- OAEP padding (PKCS#1 v2.2) for encryption
- PSS padding (PKCS#1 v2.2) for signatures
- PEM key format import/export
"""

import os
import struct
import base64
from typing import Tuple, Optional, Union
import secrets


# =============================================================================
# SHA-256 Implementation (FIPS 180-4)
# =============================================================================

class SHA256:
    """
    Pure Python implementation of SHA-256 hash algorithm.
    Follows FIPS 180-4 specification (ref_docs/NIST.FIPS.180-4.pdf).
    """

    # Initial hash values (first 32 bits of fractional parts of square roots of first 8 primes)
    H0 = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]

    # Round constants (first 32 bits of fractional parts of cube roots of first 64 primes)
    K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]

    def __init__(self, data: bytes = b''):
        self.digest_size = 32
        self.block_size = 64
        self._h = list(self.H0)
        self._buffer = b''
        self._counter = 0

        if data:
            self.update(data)

    @staticmethod
    def _rotr(x: int, n: int) -> int:
        """Right rotate a 32-bit integer."""
        return ((x >> n) | (x << (32 - n))) & 0xffffffff

    @staticmethod
    def _ch(x: int, y: int, z: int) -> int:
        """Choice function."""
        return (x & y) ^ (~x & z)

    @staticmethod
    def _maj(x: int, y: int, z: int) -> int:
        """Majority function."""
        return (x & y) ^ (x & z) ^ (y & z)

    def _sigma0(self, x: int) -> int:
        """Σ0 function."""
        return self._rotr(x, 2) ^ self._rotr(x, 13) ^ self._rotr(x, 22)

    def _sigma1(self, x: int) -> int:
        """Σ1 function."""
        return self._rotr(x, 6) ^ self._rotr(x, 11) ^ self._rotr(x, 25)

    def _gamma0(self, x: int) -> int:
        """σ0 function."""
        return self._rotr(x, 7) ^ self._rotr(x, 18) ^ (x >> 3)

    def _gamma1(self, x: int) -> int:
        """σ1 function."""
        return self._rotr(x, 17) ^ self._rotr(x, 19) ^ (x >> 10)

    def _compress(self, block: bytes):
        """Process a 512-bit block."""
        # Parse block into 16 32-bit words
        w = list(struct.unpack('>16I', block))

        # Extend to 64 words
        for i in range(16, 64):
            w.append((self._gamma1(w[i-2]) + w[i-7] + self._gamma0(w[i-15]) + w[i-16]) & 0xffffffff)

        # Initialize working variables
        a, b, c, d, e, f, g, h = self._h

        # 64 rounds
        for i in range(64):
            t1 = (h + self._sigma1(e) + self._ch(e, f, g) + self.K[i] + w[i]) & 0xffffffff
            t2 = (self._sigma0(a) + self._maj(a, b, c)) & 0xffffffff
            h = g
            g = f
            f = e
            e = (d + t1) & 0xffffffff
            d = c
            c = b
            b = a
            a = (t1 + t2) & 0xffffffff

        # Update hash values
        self._h[0] = (self._h[0] + a) & 0xffffffff
        self._h[1] = (self._h[1] + b) & 0xffffffff
        self._h[2] = (self._h[2] + c) & 0xffffffff
        self._h[3] = (self._h[3] + d) & 0xffffffff
        self._h[4] = (self._h[4] + e) & 0xffffffff
        self._h[5] = (self._h[5] + f) & 0xffffffff
        self._h[6] = (self._h[6] + g) & 0xffffffff
        self._h[7] = (self._h[7] + h) & 0xffffffff

    def update(self, data: bytes) -> 'SHA256':
        """Update hash with additional data."""
        self._buffer += data
        self._counter += len(data)

        while len(self._buffer) >= 64:
            self._compress(self._buffer[:64])
            self._buffer = self._buffer[64:]

        return self

    def digest(self) -> bytes:
        """Return the hash digest."""
        # Create a copy to not affect the internal state
        h = list(self._h)
        buffer = self._buffer
        counter = self._counter

        # Padding
        msg_len = counter * 8  # Length in bits
        buffer += b'\x80'
        buffer += b'\x00' * ((55 - counter) % 64)
        buffer += struct.pack('>Q', msg_len)

        # Process remaining blocks
        for i in range(0, len(buffer), 64):
            block = buffer[i:i+64]
            # Parse block into 16 32-bit words
            w = list(struct.unpack('>16I', block))

            # Extend to 64 words
            for j in range(16, 64):
                w.append(
                    (self._gamma1(w[j-2]) + w[j-7] + self._gamma0(w[j-15]) + w[j-16]) & 0xffffffff)

            # Initialize working variables
            a, b, c, d, e, f, g, hh = h

            # 64 rounds
            for j in range(64):
                t1 = (hh + self._sigma1(e) + self._ch(e, f, g) + self.K[j] + w[j]) & 0xffffffff
                t2 = (self._sigma0(a) + self._maj(a, b, c)) & 0xffffffff
                hh = g
                g = f
                f = e
                e = (d + t1) & 0xffffffff
                d = c
                c = b
                b = a
                a = (t1 + t2) & 0xffffffff

            # Update hash values
            h[0] = (h[0] + a) & 0xffffffff
            h[1] = (h[1] + b) & 0xffffffff
            h[2] = (h[2] + c) & 0xffffffff
            h[3] = (h[3] + d) & 0xffffffff
            h[4] = (h[4] + e) & 0xffffffff
            h[5] = (h[5] + f) & 0xffffffff
            h[6] = (h[6] + g) & 0xffffffff
            h[7] = (h[7] + hh) & 0xffffffff

        return struct.pack('>8I', *h)

    def hexdigest(self) -> str:
        """Return the hash digest as a hex string."""
        return self.digest().hex()

    @classmethod
    def new(cls, data: bytes = b'') -> 'SHA256':
        """Create a new SHA256 hash object."""
        return cls(data)


# =============================================================================
# Mathematical Utilities for RSA
# =============================================================================

def _bytes_to_int(data: bytes) -> int:
    """Convert bytes to integer (big-endian)."""
    return int.from_bytes(data, 'big')


def _int_to_bytes(n: int, length: Optional[int] = None) -> bytes:
    """Convert integer to bytes (big-endian)."""
    if length is None:
        length = (n.bit_length() + 7) // 8
        if length == 0:
            length = 1
    return n.to_bytes(length, 'big')


def _gcd(a: int, b: int) -> int:
    """Compute greatest common divisor using Euclidean algorithm."""
    while b:
        a, b = b, a % b
    return a


def _extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """Extended Euclidean algorithm. Returns (gcd, x, y) where ax + by = gcd."""
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = _extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y


def _mod_inverse(a: int, m: int) -> int:
    """Compute modular multiplicative inverse using extended Euclidean algorithm."""
    gcd, x, _ = _extended_gcd(a % m, m)
    if gcd != 1:
        raise ValueError("Modular inverse does not exist")
    return (x % m + m) % m


def _mod_pow(base: int, exp: int, mod: int) -> int:
    """Modular exponentiation using square-and-multiply algorithm."""
    result = 1
    base = base % mod
    while exp > 0:
        if exp & 1:
            result = (result * base) % mod
        exp >>= 1
        base = (base * base) % mod
    return result


def _miller_rabin(n: int, k: int = 40) -> bool:
    """
    Miller-Rabin primality test.

    Args:
        n: Number to test for primality
        k: Number of rounds (higher = more accurate)

    Returns:
        True if n is probably prime, False if definitely composite
    """
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Witness loop
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2  # Random in [2, n-2]
        x = _mod_pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = _mod_pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True


def _generate_prime(bits: int) -> int:
    """Generate a random prime number with the specified bit length."""
    while True:
        # Generate random odd number with correct bit length
        n = secrets.randbits(bits)
        n |= (1 << (bits - 1)) | 1  # Set MSB and LSB

        if _miller_rabin(n):
            return n


# =============================================================================
# RSA Key Class
# =============================================================================

class RSAKey:
    """
    RSA Key representation supporting both public and private keys.

    Here, the following documentation has been taken as a reference
    for the implementation:
    1. https://datatracker.ietf.org/doc/html/rfc8017
    2. ref_docs/NIST.FIPS.186-5.pdf

    """

    def __init__(self, n: int, e: int, d: Optional[int] = None,
                 p: Optional[int] = None, q: Optional[int] = None):
        """
        Initialize RSA key.

        Args:
            n: Modulus
            e: Public exponent
            d: Private exponent (None for public key only)
            p: First prime factor (optional, for CRT optimization)
            q: Second prime factor (optional, for CRT optimization)
        """
        self.n = n
        self.e = e
        self.d = d
        self.p = p
        self.q = q

        # Precompute CRT values if we have private key components
        if d is not None and p is not None and q is not None:
            self.dp = d % (p - 1)
            self.dq = d % (q - 1)
            self.qinv = _mod_inverse(q, p)
        else:
            self.dp = None
            self.dq = None
            self.qinv = None

    @property
    def key_size(self) -> int:
        """Return key size in bits."""
        return self.n.bit_length()

    def has_private(self) -> bool:
        """Check if this key has private components."""
        return self.d is not None

    def public_key(self) -> 'RSAKey':
        """Return public key portion only."""
        return RSAKey(self.n, self.e)

    def _encrypt_int(self, m: int) -> int:
        """Raw RSA encryption: c = m^e mod n"""
        return _mod_pow(m, self.e, self.n)

    def _decrypt_int(self, c: int) -> int:
        """Raw RSA decryption: m = c^d mod n (with CRT optimization if available)"""
        if not self.has_private():
            raise ValueError("Private key required for decryption")

        # Use CRT optimization if available
        if self.dp is not None and self.dq is not None and self.qinv is not None:
            m1 = _mod_pow(c, self.dp, self.p)
            m2 = _mod_pow(c, self.dq, self.q)
            h = (self.qinv * (m1 - m2)) % self.p
            return m2 + h * self.q
        else:
            return _mod_pow(c, self.d, self.n)

    def export_key(self, format: str = 'PEM') -> bytes:
        """
        Export key in PEM format.

        Args:
            format: Output format ('PEM' supported)

        Returns:
            Key data as bytes
        """
        if self.has_private():
            return self._export_private_pem()
        else:
            return self._export_public_pem()

    def _export_private_pem(self) -> bytes:
        """Export private key in PKCS#1 PEM format."""
        # Build ASN.1 DER structure for RSAPrivateKey
        der = self._build_private_key_der()
        b64 = base64.b64encode(der).decode('ascii')

        # Format with line breaks every 64 characters
        lines = [b64[i:i+64] for i in range(0, len(b64), 64)]
        pem = '-----BEGIN RSA PRIVATE KEY-----\n'
        pem += '\n'.join(lines)
        pem += '\n-----END RSA PRIVATE KEY-----'

        return pem.encode('ascii')

    def _export_public_pem(self) -> bytes:
        """Export public key in PKCS#1 PEM format."""
        # Build ASN.1 DER structure for RSAPublicKey
        der = self._build_public_key_der()
        b64 = base64.b64encode(der).decode('ascii')

        # Format with line breaks every 64 characters
        lines = [b64[i:i+64] for i in range(0, len(b64), 64)]
        pem = '-----BEGIN PUBLIC KEY-----\n'
        pem += '\n'.join(lines)
        pem += '\n-----END PUBLIC KEY-----'

        return pem.encode('ascii')

    def _build_private_key_der(self) -> bytes:
        """Build DER encoding for RSA private key (PKCS#1)."""
        # RSAPrivateKey ::= SEQUENCE {
        #   version           Version,
        #   modulus           INTEGER,
        #   publicExponent    INTEGER,
        #   privateExponent   INTEGER,
        #   prime1            INTEGER,
        #   prime2            INTEGER,
        #   exponent1         INTEGER,
        #   exponent2         INTEGER,
        #   coefficient       INTEGER
        # }

        components = [
            self._der_integer(0),  # version
            self._der_integer(self.n),
            self._der_integer(self.e),
            self._der_integer(self.d),
            self._der_integer(self.p),
            self._der_integer(self.q),
            self._der_integer(self.dp),
            self._der_integer(self.dq),
            self._der_integer(self.qinv)
        ]

        return self._der_sequence(b''.join(components))

    def _build_public_key_der(self) -> bytes:
        """Build DER encoding for RSA public key (SubjectPublicKeyInfo)."""
        # SubjectPublicKeyInfo ::= SEQUENCE {
        #   algorithm         AlgorithmIdentifier,
        #   subjectPublicKey  BIT STRING
        # }

        # RSAPublicKey ::= SEQUENCE {
        #   modulus           INTEGER,
        #   publicExponent    INTEGER
        # }

        # Build RSAPublicKey
        rsa_public_key = self._der_sequence(
            self._der_integer(self.n) + self._der_integer(self.e)
        )

        # Build AlgorithmIdentifier for RSA
        # OID for rsaEncryption: 1.2.840.113549.1.1.1
        rsa_oid = bytes([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01])
        null_param = bytes([0x05, 0x00])
        algorithm_id = self._der_sequence(rsa_oid + null_param)

        # Build BIT STRING containing RSAPublicKey
        # BIT STRING: tag 0x03, length, unused bits (0x00), content
        bit_string_content = b'\x00' + rsa_public_key
        bit_string = bytes([0x03]) + self._der_length(len(bit_string_content)) + bit_string_content

        return self._der_sequence(algorithm_id + bit_string)

    @staticmethod
    def _der_integer(n: int) -> bytes:
        """Encode integer as DER INTEGER."""
        if n == 0:
            data = b'\x00'
        else:
            data = _int_to_bytes(n)
            # Add leading zero if high bit is set (to indicate positive number)
            if data[0] & 0x80:
                data = b'\x00' + data

        return bytes([0x02]) + RSAKey._der_length(len(data)) + data

    @staticmethod
    def _der_sequence(data: bytes) -> bytes:
        """Encode data as DER SEQUENCE."""
        return bytes([0x30]) + RSAKey._der_length(len(data)) + data

    @staticmethod
    def _der_length(length: int) -> bytes:
        """Encode length in DER format."""
        if length < 128:
            return bytes([length])
        elif length < 256:
            return bytes([0x81, length])
        elif length < 65536:
            return bytes([0x82, length >> 8, length & 0xff])
        else:
            raise ValueError("Length too large for DER encoding")

    @classmethod
    def generate(cls, bits: int = 2048, e: int = 65537) -> 'RSAKey':
        """
        Generate a new RSA key pair.

        Args:
            bits: Key size in bits (default 2048)
            e: Public exponent (default 65537)

        Returns:
            RSAKey with both public and private components
        """
        # Generate two distinct primes
        p = _generate_prime(bits // 2)
        q = _generate_prime(bits // 2)

        while p == q:
            q = _generate_prime(bits // 2)

        # Ensure p > q for CRT
        if p < q:
            p, q = q, p

        n = p * q
        phi = (p - 1) * (q - 1)

        # Verify e is coprime to phi
        if _gcd(e, phi) != 1:
            raise ValueError("e is not coprime to phi(n)")

        # Compute private exponent
        d = _mod_inverse(e, phi)

        return cls(n, e, d, p, q)

    @classmethod
    def import_key(cls, key_data: Union[bytes, str]) -> 'RSAKey':
        """
        Import an RSA key from PEM format.

        Args:
            key_data: PEM-encoded key data

        Returns:
            RSAKey object
        """
        if isinstance(key_data, str):
            key_data = key_data.encode('ascii')

        # Decode PEM
        lines = key_data.decode('ascii').strip().split('\n')

        if 'PRIVATE KEY' in lines[0]:
            # Private key
            b64_data = ''.join(lines[1:-1])
            der_data = base64.b64decode(b64_data)
            return cls._parse_private_key_der(der_data)
        elif 'PUBLIC KEY' in lines[0]:
            # Public key
            b64_data = ''.join(lines[1:-1])
            der_data = base64.b64decode(b64_data)
            return cls._parse_public_key_der(der_data)
        else:
            raise ValueError("Unknown key format")

    @classmethod
    def _parse_private_key_der(cls, der: bytes) -> 'RSAKey':
        """Parse DER-encoded RSA private key (PKCS#1)."""
        # Skip SEQUENCE tag and length
        idx = 0
        if der[idx] != 0x30:
            raise ValueError("Expected SEQUENCE")
        idx += 1
        idx, _ = cls._parse_der_length(der, idx)

        # Parse version
        idx, version = cls._parse_der_integer(der, idx)

        # Parse components
        idx, n = cls._parse_der_integer(der, idx)
        idx, e = cls._parse_der_integer(der, idx)
        idx, d = cls._parse_der_integer(der, idx)
        idx, p = cls._parse_der_integer(der, idx)
        idx, q = cls._parse_der_integer(der, idx)
        idx, dp = cls._parse_der_integer(der, idx)
        idx, dq = cls._parse_der_integer(der, idx)
        idx, qinv = cls._parse_der_integer(der, idx)

        return cls(n, e, d, p, q)

    @classmethod
    def _parse_public_key_der(cls, der: bytes) -> 'RSAKey':
        """Parse DER-encoded RSA public key (SubjectPublicKeyInfo)."""
        idx = 0

        # Skip outer SEQUENCE
        if der[idx] != 0x30:
            raise ValueError("Expected SEQUENCE")
        idx += 1
        idx, _ = cls._parse_der_length(der, idx)

        # Skip AlgorithmIdentifier SEQUENCE
        if der[idx] != 0x30:
            raise ValueError("Expected SEQUENCE for AlgorithmIdentifier")
        idx += 1
        idx, algo_len = cls._parse_der_length(der, idx)
        idx += algo_len

        # Parse BIT STRING
        if der[idx] != 0x03:
            raise ValueError("Expected BIT STRING")
        idx += 1
        idx, bit_len = cls._parse_der_length(der, idx)

        # Skip unused bits byte
        idx += 1

        # Parse inner SEQUENCE (RSAPublicKey)
        if der[idx] != 0x30:
            raise ValueError("Expected SEQUENCE for RSAPublicKey")
        idx += 1
        idx, _ = cls._parse_der_length(der, idx)

        # Parse n and e
        idx, n = cls._parse_der_integer(der, idx)
        idx, e = cls._parse_der_integer(der, idx)

        return cls(n, e)

    @staticmethod
    def _parse_der_length(der: bytes, idx: int) -> Tuple[int, int]:
        """Parse DER length and return (new_index, length)."""
        if der[idx] < 128:
            return idx + 1, der[idx]
        elif der[idx] == 0x81:
            return idx + 2, der[idx + 1]
        elif der[idx] == 0x82:
            return idx + 3, (der[idx + 1] << 8) | der[idx + 2]
        else:
            raise ValueError("Unsupported length encoding")

    @classmethod
    def _parse_der_integer(cls, der: bytes, idx: int) -> Tuple[int, int]:
        """Parse DER INTEGER and return (new_index, value)."""
        if der[idx] != 0x02:
            raise ValueError("Expected INTEGER")
        idx += 1
        idx, length = cls._parse_der_length(der, idx)
        value = _bytes_to_int(der[idx:idx + length])
        return idx + length, value


# =============================================================================
# MGF1 (Mask Generation Function)
# =============================================================================

def _mgf1(seed: bytes, length: int, hash_func=SHA256) -> bytes:
    """
    MGF1 mask generation function (PKCS#1 v2.2).

    Args:
        seed: Seed bytes
        length: Desired output length
        hash_func: Hash function class to use

    Returns:
        Mask bytes of specified length
    """
    hash_len = 32  # SHA-256 output length

    if length > (2**32) * hash_len:
        raise ValueError("Mask too long")

    mask = b''
    counter = 0

    while len(mask) < length:
        c = struct.pack('>I', counter)
        mask += hash_func.new(seed + c).digest()
        counter += 1

    return mask[:length]


# =============================================================================
# OAEP Padding (PKCS#1 v2.2)
# =============================================================================

class PKCS1_OAEP:
    """
    PKCS#1 OAEP (Optimal Asymmetric Encryption Padding) implementation.
    Provides probabilistic encryption with semantic security.
    """

    def __init__(self, key: RSAKey, hash_func=SHA256, mgf=_mgf1, label: bytes = b''):
        """
        Initialize OAEP cipher.

        Args:
            key: RSA key to use
            hash_func: Hash function class (default SHA256)
            mgf: Mask generation function (default MGF1)
            label: Optional label (default empty)
        """
        self.key = key
        self.hash_func = hash_func
        self.mgf = mgf
        self.label = label
        self.hash_len = 32  # SHA-256 output length

        # Maximum message length
        k = (key.n.bit_length() + 7) // 8
        self.max_msg_len = k - 2 * self.hash_len - 2

    def encrypt(self, message: bytes) -> bytes:
        """
        Encrypt message using OAEP padding.

        Args:
            message: Plaintext message

        Returns:
            Ciphertext
        """
        k = (self.key.n.bit_length() + 7) // 8
        m_len = len(message)

        if m_len > self.max_msg_len:
            raise ValueError(f"Message too long (max {self.max_msg_len} bytes)")

        # EME-OAEP encoding
        # lHash = Hash(L)
        l_hash = self.hash_func.new(self.label).digest()

        # PS = zero bytes to make DB the right length
        ps_len = k - m_len - 2 * self.hash_len - 2
        ps = b'\x00' * ps_len

        # DB = lHash || PS || 0x01 || M
        db = l_hash + ps + b'\x01' + message

        # Generate random seed
        seed = secrets.token_bytes(self.hash_len)

        # dbMask = MGF(seed, k - hLen - 1)
        db_mask = self.mgf(seed, k - self.hash_len - 1)

        # maskedDB = DB XOR dbMask
        masked_db = bytes(a ^ b for a, b in zip(db, db_mask))

        # seedMask = MGF(maskedDB, hLen)
        seed_mask = self.mgf(masked_db, self.hash_len)

        # maskedSeed = seed XOR seedMask
        masked_seed = bytes(a ^ b for a, b in zip(seed, seed_mask))

        # EM = 0x00 || maskedSeed || maskedDB
        em = b'\x00' + masked_seed + masked_db

        # RSA encryption
        m_int = _bytes_to_int(em)
        c_int = self.key._encrypt_int(m_int)

        return _int_to_bytes(c_int, k)

    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decrypt ciphertext using OAEP padding.

        Args:
            ciphertext: Encrypted message

        Returns:
            Decrypted plaintext
        """
        k = (self.key.n.bit_length() + 7) // 8

        if len(ciphertext) != k:
            raise ValueError("Decryption error")

        if k < 2 * self.hash_len + 2:
            raise ValueError("Decryption error")

        # RSA decryption
        c_int = _bytes_to_int(ciphertext)
        m_int = self.key._decrypt_int(c_int)
        em = _int_to_bytes(m_int, k)

        # EME-OAEP decoding
        # Split EM
        y = em[0]
        masked_seed = em[1:self.hash_len + 1]
        masked_db = em[self.hash_len + 1:]

        # seedMask = MGF(maskedDB, hLen)
        seed_mask = self.mgf(masked_db, self.hash_len)

        # seed = maskedSeed XOR seedMask
        seed = bytes(a ^ b for a, b in zip(masked_seed, seed_mask))

        # dbMask = MGF(seed, k - hLen - 1)
        db_mask = self.mgf(seed, k - self.hash_len - 1)

        # DB = maskedDB XOR dbMask
        db = bytes(a ^ b for a, b in zip(masked_db, db_mask))

        # Verify lHash
        l_hash = self.hash_func.new(self.label).digest()
        l_hash_prime = db[:self.hash_len]

        if l_hash != l_hash_prime:
            raise ValueError("Decryption error")

        if y != 0:
            raise ValueError("Decryption error")

        # Find 0x01 separator
        idx = self.hash_len
        while idx < len(db):
            if db[idx] == 0x01:
                break
            elif db[idx] != 0x00:
                raise ValueError("Decryption error")
            idx += 1

        if idx >= len(db):
            raise ValueError("Decryption error")

        # Return message
        return db[idx + 1:]

    @classmethod
    def new(cls, key: RSAKey) -> 'PKCS1_OAEP':
        """Create a new OAEP cipher instance."""
        return cls(key)


# =============================================================================
# PSS Signature Scheme (PKCS#1 v2.2)
# =============================================================================

class PSS:
    """
    PKCS#1 PSS (Probabilistic Signature Scheme) implementation.
    Provides secure digital signatures with provable security.
    """

    def __init__(self, key: RSAKey, hash_func=SHA256, mgf=_mgf1, salt_len: Optional[int] = None):
        """
        Initialize PSS signer/verifier.

        Args:
            key: RSA key to use
            hash_func: Hash function class (default SHA256)
            mgf: Mask generation function (default MGF1)
            salt_len: Salt length (default: hash length)
        """
        self.key = key
        self.hash_func = hash_func
        self.mgf = mgf
        self.hash_len = 32  # SHA-256 output length
        self.salt_len = salt_len if salt_len is not None else self.hash_len

    def sign(self, msg_hash: SHA256) -> bytes:
        """
        Sign a message hash using PSS padding.

        Args:
            msg_hash: SHA256 hash object of the message

        Returns:
            Signature bytes
        """
        if not self.key.has_private():
            raise ValueError("Private key required for signing")

        em_bits = self.key.n.bit_length() - 1
        em_len = (em_bits + 7) // 8

        m_hash = msg_hash.digest()

        if em_len < self.hash_len + self.salt_len + 2:
            raise ValueError("Encoding error")

        # Generate random salt
        salt = secrets.token_bytes(self.salt_len)

        # M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt
        m_prime = b'\x00' * 8 + m_hash + salt

        # H = Hash(M')
        h = self.hash_func.new(m_prime).digest()

        # PS = zero bytes
        ps_len = em_len - self.salt_len - self.hash_len - 2
        ps = b'\x00' * ps_len

        # DB = PS || 0x01 || salt
        db = ps + b'\x01' + salt

        # dbMask = MGF(H, emLen - hLen - 1)
        db_mask = self.mgf(h, em_len - self.hash_len - 1)

        # maskedDB = DB XOR dbMask
        masked_db = bytes(a ^ b for a, b in zip(db, db_mask))

        # Set leftmost bits to zero
        leading_zero_bits = 8 * em_len - em_bits
        if leading_zero_bits > 0:
            mask = 0xff >> leading_zero_bits
            masked_db = bytes([masked_db[0] & mask]) + masked_db[1:]

        # EM = maskedDB || H || 0xbc
        em = masked_db + h + b'\xbc'

        # RSA signature
        m_int = _bytes_to_int(em)
        s_int = self.key._decrypt_int(m_int)  # Sign uses private key operation

        k = (self.key.n.bit_length() + 7) // 8
        return _int_to_bytes(s_int, k)

    def verify(self, msg_hash: SHA256, signature: bytes) -> bool:
        """
        Verify a PSS signature.

        Args:
            msg_hash: SHA256 hash object of the message
            signature: Signature to verify

        Returns:
            True if valid

        Raises:
            ValueError: If signature is invalid
        """
        k = (self.key.n.bit_length() + 7) // 8
        em_bits = self.key.n.bit_length() - 1
        em_len = (em_bits + 7) // 8

        if len(signature) != k:
            raise ValueError("Invalid signature")

        # RSA verification
        s_int = _bytes_to_int(signature)
        m_int = self.key._encrypt_int(s_int)  # Verify uses public key operation
        em = _int_to_bytes(m_int, em_len)

        m_hash = msg_hash.digest()

        if em_len < self.hash_len + self.salt_len + 2:
            raise ValueError("Invalid signature")

        if em[-1] != 0xbc:
            raise ValueError("Invalid signature")

        # Split EM
        masked_db = em[:em_len - self.hash_len - 1]
        h = em[em_len - self.hash_len - 1:-1]

        # Check leftmost bits
        leading_zero_bits = 8 * em_len - em_bits
        if leading_zero_bits > 0:
            mask = 0xff >> leading_zero_bits
            if masked_db[0] & ~mask:
                raise ValueError("Invalid signature")

        # dbMask = MGF(H, emLen - hLen - 1)
        db_mask = self.mgf(h, em_len - self.hash_len - 1)

        # DB = maskedDB XOR dbMask
        db = bytes(a ^ b for a, b in zip(masked_db, db_mask))

        # Clear leftmost bits
        if leading_zero_bits > 0:
            mask = 0xff >> leading_zero_bits
            db = bytes([db[0] & mask]) + db[1:]

        # Check PS and separator
        ps_len = em_len - self.hash_len - self.salt_len - 2
        for i in range(ps_len):
            if db[i] != 0:
                raise ValueError("Invalid signature")

        if db[ps_len] != 0x01:
            raise ValueError("Invalid signature")

        # Extract salt
        salt = db[ps_len + 1:]

        # M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt
        m_prime = b'\x00' * 8 + m_hash + salt

        # H' = Hash(M')
        h_prime = self.hash_func.new(m_prime).digest()

        if h != h_prime:
            raise ValueError("Invalid signature")

        return True

    @classmethod
    def new(cls, key: RSAKey) -> 'PSS':
        """Create a new PSS signer/verifier instance."""
        return cls(key)


# =============================================================================
# Compatibility Layer (matches original API)
# =============================================================================

# Create module-level aliases for backward compatibility
RSA = type('RSA', (), {
    'generate': staticmethod(lambda bits: RSAKey.generate(bits)),
    'import_key': staticmethod(lambda data: RSAKey.import_key(data)),
    'RsaKey': RSAKey
})()


# =============================================================================
# Public API Functions
# =============================================================================

def generate_keys(key_size: int = 2048) -> Tuple[bytes, bytes]:
    """
    Generates an RSA Public/Private key pair.

    Args:
        key_size (int): The size of the RSA key in bits. Default is 2048.

    Returns:
        Tuple[bytes, bytes]: A tuple containing (private_key_pem, public_key_pem).
    """
    print(f"Generating {key_size}-bit RSA keys...")
    key = RSAKey.generate(key_size)

    private_key = key.export_key()
    public_key = key.public_key().export_key()

    return private_key, public_key


def save_key_to_file(key_data: bytes, filename: str):
    """Saves key data to a file."""
    with open(filename, 'wb') as f:
        f.write(key_data)
    print(f"Key saved to {filename}")


def load_key_from_file(filename: str) -> RSAKey:
    """Loads an RSA key from a file."""
    with open(filename, 'rb') as f:
        key_data = f.read()
    return RSAKey.import_key(key_data)


def encrypt_message(public_key_path: str, message: str) -> bytes:
    """
    Encrypts a message using the recipient's Public Key.
    Uses PKCS1_OAEP padding for confidentiality.

    Args:
        public_key_path (str): Path to the recipient's public key file.
        message (str): The plaintext message to encrypt.

    Returns:
        bytes: The ciphertext.
    """
    recipient_key = load_key_from_file(public_key_path)

    # PKCS1_OAEP is an asymmetric cipher based on RSA and OAEP padding.
    # It provides probabilistic encryption (same text encrypts differently each time)
    # and prevents chosen-ciphertext attacks.
    cipher_rsa = PKCS1_OAEP.new(recipient_key)

    ciphertext = cipher_rsa.encrypt(message.encode('utf-8'))
    return ciphertext


def decrypt_message(private_key_path: str, ciphertext: bytes) -> str:
    """
    Decrypts a message using the recipient's Private Key.

    Args:
        private_key_path (str): Path to the recipient's private key file.
        ciphertext (bytes): The encrypted message.

    Returns:
        str: The decrypted plaintext message.
    """
    private_key = load_key_from_file(private_key_path)

    cipher_rsa = PKCS1_OAEP.new(private_key)

    # Decrypt the message
    decrypted_data = cipher_rsa.decrypt(ciphertext)
    return decrypted_data.decode('utf-8')


def sign_message(private_key_path: str, message: str) -> bytes:
    """
    Signs a message using the sender's Private Key.
    Uses SHA-256 for hashing and PSS padding for signature generation.

    Args:
        private_key_path (str): Path to the sender's private key.
        message (str): The message to sign.

    Returns:
        bytes: The digital signature.
    """
    sender_key = load_key_from_file(private_key_path)

    # Create a hash of the message
    h = SHA256.new(message.encode('utf-8'))

    # PSS (Probabilistic Signature Scheme) is more secure than PKCS#1 v1.5
    signer = PSS.new(sender_key)
    signature = signer.sign(h)

    return signature


def verify_signature(public_key_path: str, message: str, signature: bytes) -> bool:
    """
    Verifies a digital signature using the sender's Public Key.

    Args:
        public_key_path (str): Path to the sender's public key.
        message (str): The original message.
        signature (bytes): The signature to verify.

    Returns:
        bool: True if signature is valid, False otherwise.
    """
    sender_key = load_key_from_file(public_key_path)

    h = SHA256.new(message.encode('utf-8'))
    verifier = PSS.new(sender_key)

    try:
        verifier.verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False
