"""Data models and canonical serialization for IPChain."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ipchain.crypto import (
    canonical_json,
    is_valid_address,
    is_valid_hex,
    private_key_to_public_key,
    public_key_to_address,
    sha256_bytes,
    sha256_hex,
    sign_digest,
    verify_digest_signature,
)

TX_TYPES = (
    "REGISTER_IP",
    "TRANSFER_IP",
    "GRANT_LICENSE",
    "PURCHASE_LICENSE",
    "REVOKE_LICENSE",
    "FILE_DISPUTE",
    "RESOLVE_DISPUTE",
    "TRANSFER_TOKENS",
)

IP_TYPES = (
    "PATENT",
    "COPYRIGHT",
    "TRADEMARK",
    "TRADE_SECRET",
    "SOFTWARE",
    "DESIGN",
)

IP_STATUSES = ("ACTIVE", "DISPUTED", "REVOKED")

LICENSE_TYPES = (
    "EXCLUSIVE",
    "NON_EXCLUSIVE",
    "COMMERCIAL",
    "ACADEMIC",
    "OPEN_SOURCE",
)

DISPUTE_CLAIMS = (
    "PLAGIARISM",
    "PRIOR_ART",
    "UNAUTHORIZED_FILING",
    "TRADEMARK_CONFLICT",
)

DISPUTE_RULINGS = ("DISMISSED", "UPHELD_REVOKE", "UPHELD_TRANSFER")

MIN_TX_FEE = 1
BLOCK_REWARD = 50
GENESIS_TIMESTAMP = 1700000000
MAX_ROYALTY_BPS = 5000  # 50.00%


def is_strict_int(val: Any) -> bool:
    """Return True if val is an integer and not a boolean."""
    return isinstance(val, int) and not isinstance(val, bool)


@dataclass
class Transaction:
    """Signed blockchain transaction for IP lifecycle or token transfer."""

    tx_type: str
    sender: str
    nonce: int
    fee: int
    timestamp: int
    payload: dict[str, Any]
    public_key: str = ""
    signature: str = ""
    tx_id: str = ""

    def signing_dict(self) -> dict[str, Any]:
        """Return canonical unsigned transaction fields covered by signature."""
        return {
            "type": self.tx_type,
            "sender": self.sender.lower(),
            "nonce": self.nonce,
            "fee": self.fee,
            "timestamp": self.timestamp,
            "payload": self.payload,
        }

    def signing_hash(self) -> bytes:
        """Compute 32-byte SHA-256 hash of canonical unsigned transaction."""
        return sha256_bytes(canonical_json(self.signing_dict()))

    def compute_tx_id(self) -> str:
        """Compute deterministic 64-hex-char transaction ID including signature."""
        full = {
            **self.signing_dict(),
            "public_key": self.public_key.lower(),
            "signature": self.signature.lower(),
        }
        return sha256_hex(canonical_json(full))

    def sign(self, privkey_hex: str) -> "Transaction":
        """Sign transaction with sender's secp256k1 private key."""
        pub = private_key_to_public_key(privkey_hex)
        addr = public_key_to_address(pub)
        if not self.sender:
            self.sender = addr
        elif self.sender.lower() != addr:
            raise ValueError(
                f"Private key address {addr} does not match sender {self.sender}"
            )
        self.sender = addr
        self.public_key = pub
        self.signature = sign_digest(privkey_hex, self.signing_hash())
        self.tx_id = self.compute_tx_id()
        return self

    def verify_signature(self) -> bool:
        """Verify sender address, tx_id integrity, and ECDSA signature."""
        if self.tx_type not in TX_TYPES:
            return False
        if not is_valid_address(self.sender.lower()):
            return False
        if not is_strict_int(self.nonce) or self.nonce < 0:
            return False
        if not is_strict_int(self.fee) or self.fee < MIN_TX_FEE:
            return False
        if not is_strict_int(self.timestamp) or self.timestamp <= 0:
            return False
        if not isinstance(self.payload, dict):
            return False
        if not is_valid_hex(self.public_key, 66) or not is_valid_hex(self.signature, 128):
            return False
        try:
            derived = public_key_to_address(self.public_key)
        except ValueError:
            return False
        if derived != self.sender.lower():
            return False
        if self.tx_id.lower() != self.compute_tx_id():
            return False
        return verify_digest_signature(
            self.public_key, self.signing_hash(), self.signature
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize transaction to JSON-compatible dict."""
        return {
            "tx_id": self.tx_id.lower(),
            "type": self.tx_type,
            "sender": self.sender.lower(),
            "nonce": self.nonce,
            "fee": self.fee,
            "timestamp": self.timestamp,
            "payload": self.payload,
            "public_key": self.public_key.lower(),
            "signature": self.signature.lower(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Transaction":
        """Deserialize transaction dict with structural validation."""
        if not isinstance(data, dict):
            raise ValueError("Transaction must be a JSON object")
        for key in ("type", "sender", "nonce", "fee", "timestamp", "payload"):
            if key not in data:
                raise ValueError(f"Missing transaction field: {key}")
        tx = cls(
            tx_type=str(data["type"]),
            sender=str(data["sender"]).lower(),
            nonce=data["nonce"],
            fee=data["fee"],
            timestamp=data["timestamp"],
            payload=data["payload"],
            public_key=str(data.get("public_key", "")).lower(),
            signature=str(data.get("signature", "")).lower(),
            tx_id=str(data.get("tx_id", "")).lower(),
        )
        return tx


@dataclass
class Block:
    """Blockchain block containing verified IP transactions and cryptographic commitments."""

    index: int
    timestamp: int
    previous_hash: str
    merkle_root: str
    state_root: str
    nonce: int
    difficulty: int
    miner: str
    transactions: list[Transaction] = field(default_factory=list)
    hash: str = ""

    def header_dict(self) -> dict[str, Any]:
        """Return canonical block header fields hashed for Proof-of-Work."""
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "previous_hash": self.previous_hash.lower(),
            "merkle_root": self.merkle_root.lower(),
            "state_root": self.state_root.lower(),
            "nonce": self.nonce,
            "difficulty": self.difficulty,
            "miner": self.miner.lower(),
        }

    def compute_hash(self) -> str:
        """Compute SHA-256 block header hash."""
        return sha256_hex(canonical_json(self.header_dict()))

    def meets_difficulty(self) -> bool:
        """Check whether block hash meets leading-zero PoW target."""
        if self.index == 0:
            return True
        return self.hash.startswith("0" * self.difficulty)

    def to_dict(self) -> dict[str, Any]:
        """Serialize block and transactions to JSON-compatible dict."""
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "previous_hash": self.previous_hash.lower(),
            "merkle_root": self.merkle_root.lower(),
            "state_root": self.state_root.lower(),
            "nonce": self.nonce,
            "difficulty": self.difficulty,
            "miner": self.miner.lower(),
            "hash": self.hash.lower(),
            "transactions": [tx.to_dict() for tx in self.transactions],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Block":
        """Deserialize block dict with structural validation."""
        if not isinstance(data, dict):
            raise ValueError("Block must be a JSON object")
        required = (
            "index",
            "timestamp",
            "previous_hash",
            "merkle_root",
            "state_root",
            "nonce",
            "difficulty",
            "miner",
            "transactions",
            "hash",
        )
        for key in required:
            if key not in data:
                raise ValueError(f"Missing block field: {key}")
        txs = [Transaction.from_dict(item) for item in data["transactions"]]
        return cls(
            index=data["index"],
            timestamp=data["timestamp"],
            previous_hash=str(data["previous_hash"]).lower(),
            merkle_root=str(data["merkle_root"]).lower(),
            state_root=str(data["state_root"]).lower(),
            nonce=data["nonce"],
            difficulty=data["difficulty"],
            miner=str(data["miner"]).lower(),
            transactions=txs,
            hash=str(data["hash"]).lower(),
        )


@dataclass
class AccountState:
    """On-chain account balance and replay-protection nonce."""

    address: str
    balance: int = 0
    nonce: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "balance": self.balance,
            "nonce": self.nonce,
        }


@dataclass
class IPAsset:
    """Registered Intellectual Property asset stored in ledger state."""

    ip_id: str
    title: str
    ip_type: str
    description: str
    content_hash: str
    simhash: str
    jurisdiction: str
    original_creator: str
    owner: str
    status: str
    royalty_bps: int
    license_price: int
    allow_public_license: bool
    default_license_type: str
    tags: list[str]
    registered_block: int
    registered_tx: str
    registered_at: int
    provenance: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip_id": self.ip_id,
            "title": self.title,
            "ip_type": self.ip_type,
            "description": self.description,
            "content_hash": self.content_hash,
            "simhash": self.simhash,
            "jurisdiction": self.jurisdiction,
            "original_creator": self.original_creator,
            "owner": self.owner,
            "status": self.status,
            "royalty_bps": self.royalty_bps,
            "license_price": self.license_price,
            "allow_public_license": self.allow_public_license,
            "default_license_type": self.default_license_type,
            "tags": list(self.tags),
            "registered_block": self.registered_block,
            "registered_tx": self.registered_tx,
            "registered_at": self.registered_at,
            "provenance": list(self.provenance),
        }


@dataclass
class LicenseRecord:
    """Smart-contract license granted or purchased against an IP asset."""

    license_id: str
    ip_id: str
    licensor: str
    licensee: str
    license_type: str
    scope: str
    granted_block: int
    expires_block: int
    royalty_bps: int
    paid_amount: int
    creator_royalty_paid: int
    status: str
    granted_tx: str
    revoked_tx: str = ""
    revoke_reason: str = ""

    def is_effective_at(self, block_index: int) -> bool:
        """Return True if license is ACTIVE and not expired at block_index."""
        if self.status != "ACTIVE":
            return False
        if self.expires_block > 0 and block_index >= self.expires_block:
            return False
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "license_id": self.license_id,
            "ip_id": self.ip_id,
            "licensor": self.licensor,
            "licensee": self.licensee,
            "license_type": self.license_type,
            "scope": self.scope,
            "granted_block": self.granted_block,
            "expires_block": self.expires_block,
            "royalty_bps": self.royalty_bps,
            "paid_amount": self.paid_amount,
            "creator_royalty_paid": self.creator_royalty_paid,
            "status": self.status,
            "granted_tx": self.granted_tx,
            "revoked_tx": self.revoked_tx,
            "revoke_reason": self.revoke_reason,
        }


@dataclass
class DisputeRecord:
    """Prior-art / plagiarism dispute record against an IP asset."""

    dispute_id: str
    accused_ip_id: str
    prior_art_ip_id: str
    challenger: str
    claim_type: str
    evidence_hash: str
    description: str
    filed_block: int
    filed_tx: str
    status: str
    ruling: str = ""
    ruling_notes: str = ""
    resolved_block: int = 0
    resolved_tx: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "dispute_id": self.dispute_id,
            "accused_ip_id": self.accused_ip_id,
            "prior_art_ip_id": self.prior_art_ip_id,
            "challenger": self.challenger,
            "claim_type": self.claim_type,
            "evidence_hash": self.evidence_hash,
            "description": self.description,
            "filed_block": self.filed_block,
            "filed_tx": self.filed_tx,
            "status": self.status,
            "ruling": self.ruling,
            "ruling_notes": self.ruling_notes,
            "resolved_block": self.resolved_block,
            "resolved_tx": self.resolved_tx,
        }
