"""Cryptographic primitives for IPChain.

Provides zero-dependency pure-Python implementations of:
- secp256k1 ECDSA key derivation, RFC 6979 deterministic signing, low-S canonical verification
- Canonical JSON serialization and SHA-256 content/transaction hashing
- Domain-separated SHA-256 Merkle trees and inclusion proof generation/verification
- 64-bit SimHash perceptual fingerprinting for text/plagiarism similarity checks
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from typing import Any

# secp256k1 domain parameters
SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
SECP256K1_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
SECP256K1_G = (SECP256K1_GX, SECP256K1_GY)
SECP256K1_HALF_N = SECP256K1_N // 2

EMPTY_MERKLE_ROOT = hashlib.sha256(b"EMPTY_MERKLE_ROOT").hexdigest()
ZERO_SIMHASH = "0" * 16


def canonical_json(data: Any) -> str:
    """Serialize data into deterministic canonical JSON matching JS canonicalJson."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_bytes(data: bytes | str) -> bytes:
    """Return raw 32-byte SHA-256 digest of bytes or UTF-8 string."""
    raw = data.encode("utf-8") if isinstance(data, str) else data
    return hashlib.sha256(raw).digest()


def sha256_hex(data: bytes | str) -> str:
    """Return 64-char lowercase hex SHA-256 digest of bytes or UTF-8 string."""
    return sha256_bytes(data).hex()


def is_valid_hex(value: str, expected_len: int | None = None) -> bool:
    """Check whether string is valid lowercase/uppercase hex of optional exact length."""
    if not isinstance(value, str):
        return False
    if expected_len is not None and len(value) != expected_len:
        return False
    return bool(re.fullmatch(r"[0-9a-fA-F]+", value))


def is_valid_address(address: str) -> bool:
    """Validate 0x-prefixed 40-hex-character lowercase address."""
    return isinstance(address, str) and bool(re.fullmatch(r"0x[0-9a-f]{40}", address))


# ---------------------------------------------------------------------------
# secp256k1 Jacobian elliptic curve arithmetic
# ---------------------------------------------------------------------------

def _to_jacobian(point: tuple[int, int] | None) -> tuple[int, int, int]:
    if point is None:
        return (0, 1, 0)
    return (point[0], point[1], 1)


def _from_jacobian(jpoint: tuple[int, int, int]) -> tuple[int, int] | None:
    x, y, z = jpoint
    if z == 0:
        return None
    z_inv = pow(z, -1, SECP256K1_P)
    z_inv2 = (z_inv * z_inv) % SECP256K1_P
    z_inv3 = (z_inv2 * z_inv) % SECP256K1_P
    return ((x * z_inv2) % SECP256K1_P, (y * z_inv3) % SECP256K1_P)


def _jacobian_double(jpoint: tuple[int, int, int]) -> tuple[int, int, int]:
    x1, y1, z1 = jpoint
    if y1 == 0 or z1 == 0:
        return (0, 1, 0)
    ysq = (y1 * y1) % SECP256K1_P
    s = (4 * x1 * ysq) % SECP256K1_P
    m = (3 * x1 * x1) % SECP256K1_P  # a = 0 for secp256k1
    nx = (m * m - 2 * s) % SECP256K1_P
    ny = (m * (s - nx) - 8 * ysq * ysq) % SECP256K1_P
    nz = (2 * y1 * z1) % SECP256K1_P
    return (nx, ny, nz)


def _jacobian_add(
    p1: tuple[int, int, int], p2: tuple[int, int, int]
) -> tuple[int, int, int]:
    x1, y1, z1 = p1
    x2, y2, z2 = p2
    if z1 == 0:
        return p2
    if z2 == 0:
        return p1

    z1z1 = (z1 * z1) % SECP256K1_P
    z2z2 = (z2 * z2) % SECP256K1_P
    u1 = (x1 * z2z2) % SECP256K1_P
    u2 = (x2 * z1z1) % SECP256K1_P
    s1 = (y1 * z2 * z2z2) % SECP256K1_P
    s2 = (y2 * z1 * z1z1) % SECP256K1_P

    if u1 == u2:
        if s1 != s2:
            return (0, 1, 0)
        return _jacobian_double(p1)

    h = (u2 - u1) % SECP256K1_P
    r = (s2 - s1) % SECP256K1_P
    h2 = (h * h) % SECP256K1_P
    h3 = (h * h2) % SECP256K1_P
    u1h2 = (u1 * h2) % SECP256K1_P

    nx = (r * r - h3 - 2 * u1h2) % SECP256K1_P
    ny = (r * (u1h2 - nx) - s1 * h3) % SECP256K1_P
    nz = (h * z1 * z2) % SECP256K1_P
    return (nx, ny, nz)


def _jacobian_mul(scalar: int, point: tuple[int, int]) -> tuple[int, int] | None:
    k = scalar % SECP256K1_N
    if k == 0 or point is None:
        return None
    acc = (0, 1, 0)
    addend = _to_jacobian(point)
    while k:
        if k & 1:
            acc = _jacobian_add(acc, addend)
        addend = _jacobian_double(addend)
        k >>= 1
    return _from_jacobian(acc)


def is_on_curve(point: tuple[int, int] | None) -> bool:
    """Return True if affine point lies on secp256k1."""
    if point is None:
        return False
    x, y = point
    if not (0 <= x < SECP256K1_P and 0 <= y < SECP256K1_P):
        return False
    return (y * y - (x * x * x + 7)) % SECP256K1_P == 0


def compress_public_key(point: tuple[int, int]) -> str:
    """Encode affine public key point as 66-hex-char SEC1 compressed key."""
    x, y = point
    prefix = "02" if (y % 2 == 0) else "03"
    return f"{prefix}{x:064x}"


def decompress_public_key(pubkey_hex: str) -> tuple[int, int]:
    """Decode and validate a 66-hex-char SEC1 compressed public key."""
    if not is_valid_hex(pubkey_hex, 66):
        raise ValueError("Public key must be 66 hex characters (compressed SEC1)")
    raw = pubkey_hex.lower()
    prefix = raw[:2]
    if prefix not in ("02", "03"):
        raise ValueError("Compressed public key must start with 02 or 03")
    x = int(raw[2:], 16)
    if x >= SECP256K1_P:
        raise ValueError("Public key x-coordinate out of field range")
    alpha = (pow(x, 3, SECP256K1_P) + 7) % SECP256K1_P
    beta = pow(alpha, (SECP256K1_P + 1) // 4, SECP256K1_P)
    if (beta * beta) % SECP256K1_P != alpha:
        raise ValueError("Public key is not a valid secp256k1 point")
    want_odd = 1 if prefix == "03" else 0
    y = beta if (beta % 2 == want_odd) else (SECP256K1_P - beta)
    return (x, y)


def private_key_to_public_key(privkey_hex: str) -> str:
    """Derive 66-hex-char compressed public key from 64-hex-char private key."""
    if not is_valid_hex(privkey_hex, 64):
        raise ValueError("Private key must be 64 hex characters")
    d = int(privkey_hex, 16)
    if not (1 <= d < SECP256K1_N):
        raise ValueError("Private key scalar out of range [1, N-1]")
    point = _jacobian_mul(d, SECP256K1_G)
    if point is None:
        raise ValueError("Invalid private key")
    return compress_public_key(point)


def public_key_to_address(pubkey_hex: str) -> str:
    """Derive deterministic 0x-prefixed 20-byte address from compressed public key."""
    decompress_public_key(pubkey_hex)
    digest = hashlib.sha256(bytes.fromhex(pubkey_hex.lower())).digest()
    return "0x" + digest[-20:].hex()


def generate_keypair() -> dict[str, str]:
    """Generate a fresh secp256k1 keypair and derived address."""
    d = secrets.randbelow(SECP256K1_N - 1) + 1
    priv_hex = f"{d:064x}"
    pub_hex = private_key_to_public_key(priv_hex)
    return {
        "private_key": priv_hex,
        "public_key": pub_hex,
        "address": public_key_to_address(pub_hex),
    }


def derive_keypair_from_seed(seed: str) -> dict[str, str]:
    """Deterministically derive a secp256k1 keypair from a seed string (for demos/tests)."""
    counter = 0
    while True:
        candidate = sha256_bytes(f"ipchain-seed:{seed}:{counter}")
        d = int.from_bytes(candidate, "big")
        if 1 <= d < SECP256K1_N:
            priv_hex = f"{d:064x}"
            pub_hex = private_key_to_public_key(priv_hex)
            return {
                "private_key": priv_hex,
                "public_key": pub_hex,
                "address": public_key_to_address(pub_hex),
            }
        counter += 1


def _rfc6979_k_and_sign(priv_int: int, digest_bytes: bytes) -> tuple[int, int]:
    """Generate deterministic RFC 6979 nonce k and produce low-S ECDSA signature."""
    if len(digest_bytes) != 32:
        raise ValueError("Digest must be exactly 32 bytes")
    x_bytes = priv_int.to_bytes(32, "big")
    z = int.from_bytes(digest_bytes, "big")
    h_mod = (z % SECP256K1_N).to_bytes(32, "big")

    v = b"\x01" * 32
    k = b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + x_bytes + h_mod, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + x_bytes + h_mod, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()

    while True:
        t = b""
        while len(t) < 32:
            v = hmac.new(k, v, hashlib.sha256).digest()
            t += v
        nonce = int.from_bytes(t[:32], "big")
        if 1 <= nonce < SECP256K1_N:
            point = _jacobian_mul(nonce, SECP256K1_G)
            if point is not None:
                r = point[0] % SECP256K1_N
                if r != 0:
                    k_inv = pow(nonce, -1, SECP256K1_N)
                    s = (k_inv * (z + r * priv_int)) % SECP256K1_N
                    if s != 0:
                        if s > SECP256K1_HALF_N:
                            s = SECP256K1_N - s
                        return (r, s)
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def sign_digest(privkey_hex: str, digest_bytes: bytes) -> str:
    """Sign a 32-byte digest with secp256k1 ECDSA and return 128-hex-char r||s signature."""
    if not is_valid_hex(privkey_hex, 64):
        raise ValueError("Private key must be 64 hex characters")
    d = int(privkey_hex, 16)
    if not (1 <= d < SECP256K1_N):
        raise ValueError("Private key scalar out of range [1, N-1]")
    r, s = _rfc6979_k_and_sign(d, digest_bytes)
    return f"{r:064x}{s:064x}"


def verify_digest_signature(
    pubkey_hex: str, digest_bytes: bytes, signature_hex: str
) -> bool:
    """Verify a 128-hex-char low-S ECDSA signature against compressed public key and 32-byte digest."""
    if len(digest_bytes) != 32 or not is_valid_hex(signature_hex, 128):
        return False
    try:
        q = decompress_public_key(pubkey_hex)
    except ValueError:
        return False

    r = int(signature_hex[:64], 16)
    s = int(signature_hex[64:], 16)
    if not (1 <= r < SECP256K1_N and 1 <= s <= SECP256K1_HALF_N):
        return False

    z = int.from_bytes(digest_bytes, "big")
    w = pow(s, -1, SECP256K1_N)
    u1 = (z * w) % SECP256K1_N
    u2 = (r * w) % SECP256K1_N

    p1 = _to_jacobian(_jacobian_mul(u1, SECP256K1_G)) if u1 else (0, 1, 0)
    p2 = _to_jacobian(_jacobian_mul(u2, q)) if u2 else (0, 1, 0)
    point = _from_jacobian(_jacobian_add(p1, p2))
    if point is None:
        return False
    return (point[0] % SECP256K1_N) == r


# ---------------------------------------------------------------------------
# Merkle Tree & Inclusion Proofs (Domain-separated SHA-256)
# ---------------------------------------------------------------------------

def _merkle_leaf(tx_id: str) -> str:
    return hashlib.sha256(b"\x00" + bytes.fromhex(tx_id)).hexdigest()


def _merkle_node(left_hex: str, right_hex: str) -> str:
    return hashlib.sha256(
        b"\x01" + bytes.fromhex(left_hex) + bytes.fromhex(right_hex)
    ).hexdigest()


class MerkleTree:
    """Domain-separated SHA-256 Merkle tree for block transactions."""

    def __init__(self, tx_ids: list[str]) -> None:
        for tx_id in tx_ids:
            if not is_valid_hex(tx_id, 64):
                raise ValueError(f"Invalid transaction hash for MerkleTree: {tx_id}")
        self.tx_ids = [t.lower() for t in tx_ids]
        self.levels: list[list[str]] = []
        self.root = self._build()

    def _build(self) -> str:
        if not self.tx_ids:
            self.levels = []
            return EMPTY_MERKLE_ROOT

        current = [_merkle_leaf(tx_id) for tx_id in self.tx_ids]
        self.levels = [current]
        while len(current) > 1:
            if len(current) % 2 == 1:
                current = current + [current[-1]]
                self.levels[-1] = current
            next_level = [
                _merkle_node(current[i], current[i + 1])
                for i in range(0, len(current), 2)
            ]
            self.levels.append(next_level)
            current = next_level
        return current[0]

    def get_proof(self, tx_index: int) -> list[dict[str, str]]:
        """Return inclusion proof steps for the transaction at tx_index."""
        if not self.tx_ids or tx_index < 0 or tx_index >= len(self.tx_ids):
            raise IndexError("Transaction index out of range")
        proof: list[dict[str, str]] = []
        idx = tx_index
        for level in self.levels[:-1]:
            if idx % 2 == 0:
                sibling_idx = idx + 1
                position = "right"
            else:
                sibling_idx = idx - 1
                position = "left"
            proof.append({"position": position, "hash": level[sibling_idx]})
            idx //= 2
        return proof


def verify_merkle_proof(
    tx_id: str, proof: list[dict[str, str]], expected_root: str
) -> bool:
    """Verify a Merkle inclusion proof for tx_id against expected_root."""
    if not is_valid_hex(tx_id, 64) or not is_valid_hex(expected_root, 64):
        return False
    current = _merkle_leaf(tx_id.lower())
    for step in proof:
        pos = step.get("position")
        sibling = step.get("hash", "")
        if pos not in ("left", "right") or not is_valid_hex(sibling, 64):
            return False
        if pos == "left":
            current = _merkle_node(sibling.lower(), current)
        else:
            current = _merkle_node(current, sibling.lower())
    return hmac.compare_digest(current, expected_root.lower())


# ---------------------------------------------------------------------------
# 64-bit SimHash for text/abstract similarity & plagiarism detection
# ---------------------------------------------------------------------------

def compute_simhash(text: str) -> str:
    """Compute a 64-bit SimHash fingerprint (16 hex chars) from normalized text."""
    cleaned = re.sub(r"[^a-z0-9\s]", " ", text.lower())
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    if not cleaned:
        return ZERO_SIMHASH

    tokens = cleaned.split(" ")
    features: list[str] = []
    # Combine word unigrams, bigrams, and 4-char shingles for short & long texts
    features.extend(f"w:{tok}" for tok in tokens if tok)
    for i in range(len(tokens) - 1):
        features.append(f"b:{tokens[i]}_{tokens[i + 1]}")
    compact = cleaned.replace(" ", "")
    if len(compact) >= 4:
        for i in range(len(compact) - 3):
            features.append(f"c:{compact[i:i + 4]}")
    elif compact:
        features.append(f"c:{compact}")

    weights = [0] * 64
    for feat in features:
        h = int.from_bytes(sha256_bytes(feat)[:8], "big")
        for bit in range(64):
            if (h >> bit) & 1:
                weights[bit] += 1
            else:
                weights[bit] -= 1

    fingerprint = 0
    for bit in range(64):
        if weights[bit] >= 0:
            fingerprint |= 1 << bit
    return f"{fingerprint:016x}"


def simhash_similarity(hex_a: str, hex_b: str) -> float:
    """Return normalized similarity in [0.0, 1.0] between two 64-bit SimHashes."""
    if (
        not is_valid_hex(hex_a, 16)
        or not is_valid_hex(hex_b, 16)
        or hex_a.lower() == ZERO_SIMHASH
        or hex_b.lower() == ZERO_SIMHASH
    ):
        return 0.0
    xor_val = int(hex_a, 16) ^ int(hex_b, 16)
    distance = xor_val.bit_count()
    return (64 - distance) / 64.0
