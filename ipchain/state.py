"""Deterministic IP Protection state machine for IPChain."""

from __future__ import annotations

import copy
from typing import Any

from ipchain.crypto import (
    ZERO_SIMHASH,
    canonical_json,
    is_valid_address,
    is_valid_hex,
    sha256_hex,
    simhash_similarity,
)
from ipchain.models import (
    BLOCK_REWARD,
    DISPUTE_CLAIMS,
    DISPUTE_RULINGS,
    IP_TYPES,
    LICENSE_TYPES,
    MAX_ROYALTY_BPS,
    AccountState,
    Block,
    DisputeRecord,
    IPAsset,
    LicenseRecord,
    Transaction,
    is_strict_int,
)


class StateTransitionError(ValueError):
    """Raised when a transaction or block violates protocol/IP state rules."""


class LedgerState:
    """In-memory deterministic state for accounts, IP assets, licenses, and disputes."""

    def __init__(self, arbitrator: str) -> None:
        if not is_valid_address(arbitrator.lower()):
            raise ValueError("Arbitrator must be a valid 0x address")
        self.arbitrator: str = arbitrator.lower()
        self.accounts: dict[str, AccountState] = {}
        self.assets: dict[str, IPAsset] = {}
        self.content_hash_index: dict[str, str] = {}
        self.licenses: dict[str, LicenseRecord] = {}
        self.disputes: dict[str, DisputeRecord] = {}

    def clone(self) -> "LedgerState":
        """Return an independent deep copy of the ledger state."""
        return copy.deepcopy(self)

    def get_account(self, address: str) -> AccountState:
        """Return existing AccountState or default zero-balance account."""
        addr = address.lower()
        acct = self.accounts.get(addr)
        if acct is None:
            return AccountState(address=addr, balance=0, nonce=0)
        return acct

    def get_or_create_account(self, address: str) -> AccountState:
        """Return existing AccountState or insert a new zero-balance account."""
        addr = address.lower()
        if addr not in self.accounts:
            self.accounts[addr] = AccountState(address=addr, balance=0, nonce=0)
        return self.accounts[addr]

    def set_genesis_balances(self, balances: dict[str, int]) -> None:
        """Initialize genesis balances before Block #0 commitment."""
        for addr, amount in balances.items():
            norm = addr.lower()
            if not is_valid_address(norm) or not is_strict_int(amount) or amount < 0:
                raise StateTransitionError(f"Invalid genesis balance entry for {addr}")
            acct = self.get_or_create_account(norm)
            acct.balance = amount

    def compute_state_root(self) -> str:
        """Compute canonical SHA-256 commitment over entire ledger state."""
        snapshot = {
            "arbitrator": self.arbitrator,
            "accounts": {
                addr: self.accounts[addr].to_dict()
                for addr in sorted(self.accounts.keys())
            },
            "assets": {
                ip_id: self.assets[ip_id].to_dict()
                for ip_id in sorted(self.assets.keys())
            },
            "content_hash_index": {
                ch: self.content_hash_index[ch]
                for ch in sorted(self.content_hash_index.keys())
            },
            "licenses": {
                lid: self.licenses[lid].to_dict()
                for lid in sorted(self.licenses.keys())
            },
            "disputes": {
                did: self.disputes[did].to_dict()
                for did in sorted(self.disputes.keys())
            },
        }
        return sha256_hex(canonical_json(snapshot))

    def find_similar_ips(
        self, simhash: str, threshold: float = 0.80, exclude_ip_id: str = ""
    ) -> list[dict[str, Any]]:
        """Find registered IP assets with SimHash similarity >= threshold."""
        if not is_valid_hex(simhash, 16) or simhash.lower() == ZERO_SIMHASH:
            return []
        matches: list[dict[str, Any]] = []
        for asset in self.assets.values():
            if exclude_ip_id and asset.ip_id == exclude_ip_id:
                continue
            sim = simhash_similarity(simhash, asset.simhash)
            if sim >= threshold:
                matches.append(
                    {
                        "ip_id": asset.ip_id,
                        "title": asset.title,
                        "owner": asset.owner,
                        "status": asset.status,
                        "similarity": round(sim, 4),
                        "similarity_pct": round(sim * 100.0, 2),
                        "registered_block": asset.registered_block,
                    }
                )
        matches.sort(key=lambda m: (-m["similarity"], m["registered_block"]))
        return matches

    def active_licenses_for_ip(
        self, ip_id: str, block_index: int
    ) -> list[LicenseRecord]:
        """Return effective active licenses for ip_id at block_index."""
        return [
            lic
            for lic in self.licenses.values()
            if lic.ip_id == ip_id and lic.is_effective_at(block_index)
        ]

    def open_disputes_for_ip(self, ip_id: str) -> list[DisputeRecord]:
        """Return open disputes targeting ip_id."""
        return [
            d
            for d in self.disputes.values()
            if d.accused_ip_id == ip_id and d.status == "OPEN"
        ]

    def apply_transaction(self, tx: Transaction, block_index: int) -> dict[str, Any]:
        """Validate and execute one signed transaction against state."""
        if not tx.verify_signature():
            raise StateTransitionError(
                f"Invalid cryptographic signature or tx_id on {tx.tx_id}"
            )

        sender_acct = self.get_or_create_account(tx.sender)
        if tx.nonce != sender_acct.nonce:
            raise StateTransitionError(
                f"Nonce mismatch for {tx.sender}: expected {sender_acct.nonce}, got {tx.nonce}"
            )
        if sender_acct.balance < tx.fee:
            raise StateTransitionError(
                f"Insufficient balance for fee: has {sender_acct.balance}, needs {tx.fee}"
            )

        handlers = {
            "REGISTER_IP": self._apply_register_ip,
            "TRANSFER_IP": self._apply_transfer_ip,
            "GRANT_LICENSE": self._apply_grant_license,
            "PURCHASE_LICENSE": self._apply_purchase_license,
            "REVOKE_LICENSE": self._apply_revoke_license,
            "FILE_DISPUTE": self._apply_file_dispute,
            "RESOLVE_DISPUTE": self._apply_resolve_dispute,
            "TRANSFER_TOKENS": self._apply_transfer_tokens,
        }
        handler = handlers.get(tx.tx_type)
        if handler is None:
            raise StateTransitionError(f"Unsupported transaction type: {tx.tx_type}")

        event = handler(tx, sender_acct, block_index)
        sender_acct.balance -= tx.fee
        sender_acct.nonce += 1
        return event

    def apply_block(self, block: Block) -> None:
        """Apply all transactions in block and credit miner reward + fees."""
        if not is_valid_address(block.miner):
            raise StateTransitionError("Block miner must be a valid 0x address")
        total_fees = 0
        for tx in block.transactions:
            self.apply_transaction(tx, block.index)
            total_fees += tx.fee
        if block.index > 0:
            miner_acct = self.get_or_create_account(block.miner)
            miner_acct.balance += BLOCK_REWARD + total_fees

    # ------------------------------------------------------------------
    # Transaction handlers
    # ------------------------------------------------------------------

    def _apply_register_ip(
        self, tx: Transaction, _sender_acct: AccountState, block_index: int
    ) -> dict[str, Any]:
        p = tx.payload
        title = str(p.get("title", "")).strip()
        if not (3 <= len(title) <= 140):
            raise StateTransitionError("Title must be 3..140 characters")

        ip_type = str(p.get("ip_type", "")).upper()
        if ip_type not in IP_TYPES:
            raise StateTransitionError(f"Invalid ip_type: {ip_type}")

        description = str(p.get("description", "")).strip()
        if len(description) > 2000:
            raise StateTransitionError("Description exceeds 2000 characters")

        content_hash = str(p.get("content_hash", "")).lower()
        if not is_valid_hex(content_hash, 64):
            raise StateTransitionError("content_hash must be 64 hex chars (SHA-256)")
        if content_hash in self.content_hash_index:
            existing_id = self.content_hash_index[content_hash]
            raise StateTransitionError(
                f"Duplicate content_hash already registered under {existing_id}"
            )

        simhash = str(p.get("simhash", ZERO_SIMHASH)).lower() or ZERO_SIMHASH
        if not is_valid_hex(simhash, 16):
            raise StateTransitionError("simhash must be 16 hex chars")

        jurisdiction = str(p.get("jurisdiction", "GLOBAL")).strip().upper() or "GLOBAL"
        if not (2 <= len(jurisdiction) <= 32):
            raise StateTransitionError("Jurisdiction must be 2..32 characters")

        royalty_bps = p.get("royalty_bps", 0)
        if not is_strict_int(royalty_bps) or not (0 <= royalty_bps <= MAX_ROYALTY_BPS):
            raise StateTransitionError(
                f"royalty_bps must be integer 0..{MAX_ROYALTY_BPS}"
            )

        license_price = p.get("license_price", 0)
        if not is_strict_int(license_price) or license_price < 0:
            raise StateTransitionError("license_price must be non-negative integer")

        allow_public = p.get("allow_public_license", False)
        if not isinstance(allow_public, bool):
            raise StateTransitionError("allow_public_license must be boolean")

        default_lic = str(p.get("default_license_type", "NON_EXCLUSIVE")).upper()
        if default_lic not in LICENSE_TYPES:
            raise StateTransitionError(f"Invalid default_license_type: {default_lic}")
        if allow_public and default_lic == "EXCLUSIVE":
            raise StateTransitionError(
                "Publicly purchasable default license cannot be EXCLUSIVE"
            )

        raw_tags = p.get("tags", [])
        if not isinstance(raw_tags, list) or len(raw_tags) > 8:
            raise StateTransitionError("tags must be a list of at most 8 items")
        tags = [str(t).strip()[:32] for t in raw_tags if str(t).strip()]

        ip_id = (
            "IP-"
            + sha256_hex(f"{tx.sender}:{content_hash}:{tx.nonce}")[:16].upper()
        )
        asset = IPAsset(
            ip_id=ip_id,
            title=title,
            ip_type=ip_type,
            description=description,
            content_hash=content_hash,
            simhash=simhash,
            jurisdiction=jurisdiction,
            original_creator=tx.sender,
            owner=tx.sender,
            status="ACTIVE",
            royalty_bps=royalty_bps,
            license_price=license_price,
            allow_public_license=allow_public,
            default_license_type=default_lic,
            tags=tags,
            registered_block=block_index,
            registered_tx=tx.tx_id,
            registered_at=tx.timestamp,
            provenance=[
                {
                    "event": "REGISTERED",
                    "actor": tx.sender,
                    "block_index": block_index,
                    "tx_id": tx.tx_id,
                    "timestamp": tx.timestamp,
                    "details": f"Registered {ip_type} in {jurisdiction}",
                }
            ],
        )
        self.assets[ip_id] = asset
        self.content_hash_index[content_hash] = ip_id
        return {"event": "IP_REGISTERED", "ip_id": ip_id}

    def _apply_transfer_ip(
        self, tx: Transaction, _sender_acct: AccountState, block_index: int
    ) -> dict[str, Any]:
        p = tx.payload
        ip_id = str(p.get("ip_id", ""))
        asset = self.assets.get(ip_id)
        if asset is None:
            raise StateTransitionError(f"Unknown IP asset: {ip_id}")
        if asset.owner != tx.sender:
            raise StateTransitionError("Only current IP owner can transfer ownership")
        if asset.status != "ACTIVE":
            raise StateTransitionError(
                f"Cannot transfer IP while status is {asset.status}"
            )

        to_address = str(p.get("to_address", "")).lower()
        if not is_valid_address(to_address):
            raise StateTransitionError("Invalid recipient address")
        if to_address == asset.owner:
            raise StateTransitionError("Recipient is already the current owner")

        note = str(p.get("note", "")).strip()
        if len(note) > 300:
            raise StateTransitionError("Transfer note exceeds 300 characters")

        prev_owner = asset.owner
        asset.owner = to_address
        self.get_or_create_account(to_address)
        asset.provenance.append(
            {
                "event": "TRANSFERRED",
                "from": prev_owner,
                "to": to_address,
                "block_index": block_index,
                "tx_id": tx.tx_id,
                "timestamp": tx.timestamp,
                "details": note or "Ownership transferred",
            }
        )
        return {"event": "IP_TRANSFERRED", "ip_id": ip_id, "to": to_address}

    def _apply_grant_license(
        self, tx: Transaction, _sender_acct: AccountState, block_index: int
    ) -> dict[str, Any]:
        p = tx.payload
        ip_id = str(p.get("ip_id", ""))
        asset = self.assets.get(ip_id)
        if asset is None:
            raise StateTransitionError(f"Unknown IP asset: {ip_id}")
        if asset.owner != tx.sender:
            raise StateTransitionError("Only IP owner can grant a license")
        if asset.status != "ACTIVE":
            raise StateTransitionError(
                f"Cannot grant license while IP status is {asset.status}"
            )

        licensee = str(p.get("licensee", "")).lower()
        if not is_valid_address(licensee) or licensee == asset.owner:
            raise StateTransitionError("Invalid licensee address")

        license_type = str(p.get("license_type", "")).upper()
        if license_type not in LICENSE_TYPES:
            raise StateTransitionError(f"Invalid license_type: {license_type}")

        scope = str(p.get("scope", "")).strip()
        if not (1 <= len(scope) <= 300):
            raise StateTransitionError("License scope must be 1..300 characters")

        duration_blocks = p.get("duration_blocks", 0)
        if not is_strict_int(duration_blocks) or duration_blocks < 0:
            raise StateTransitionError("duration_blocks must be >= 0")

        royalty_bps = p.get("royalty_bps", asset.royalty_bps)
        if not is_strict_int(royalty_bps) or not (0 <= royalty_bps <= MAX_ROYALTY_BPS):
            raise StateTransitionError("Invalid royalty_bps")

        active = self.active_licenses_for_ip(ip_id, block_index)
        if any(lic.license_type == "EXCLUSIVE" for lic in active):
            raise StateTransitionError(
                "An active EXCLUSIVE license already blocks new licenses"
            )
        if license_type == "EXCLUSIVE" and active:
            raise StateTransitionError(
                "Cannot grant EXCLUSIVE license while other licenses are active"
            )

        expires_block = (block_index + duration_blocks) if duration_blocks > 0 else 0
        license_id = (
            "LIC-"
            + sha256_hex(f"{ip_id}:{licensee}:{tx.nonce}")[:14].upper()
        )
        record = LicenseRecord(
            license_id=license_id,
            ip_id=ip_id,
            licensor=asset.owner,
            licensee=licensee,
            license_type=license_type,
            scope=scope,
            granted_block=block_index,
            expires_block=expires_block,
            royalty_bps=royalty_bps,
            paid_amount=0,
            creator_royalty_paid=0,
            status="ACTIVE",
            granted_tx=tx.tx_id,
        )
        self.licenses[license_id] = record
        self.get_or_create_account(licensee)
        asset.provenance.append(
            {
                "event": "LICENSE_GRANTED",
                "license_id": license_id,
                "licensee": licensee,
                "license_type": license_type,
                "block_index": block_index,
                "tx_id": tx.tx_id,
                "timestamp": tx.timestamp,
                "details": scope,
            }
        )
        return {"event": "LICENSE_GRANTED", "license_id": license_id}

    def _apply_purchase_license(
        self, tx: Transaction, sender_acct: AccountState, block_index: int
    ) -> dict[str, Any]:
        p = tx.payload
        ip_id = str(p.get("ip_id", ""))
        asset = self.assets.get(ip_id)
        if asset is None:
            raise StateTransitionError(f"Unknown IP asset: {ip_id}")
        if asset.status != "ACTIVE":
            raise StateTransitionError(
                f"Cannot purchase license while IP status is {asset.status}"
            )
        if not asset.allow_public_license:
            raise StateTransitionError("IP asset does not allow public self-licensing")
        if tx.sender == asset.owner:
            raise StateTransitionError("Owner cannot purchase a license from themselves")

        license_type = str(p.get("license_type", asset.default_license_type)).upper()
        if license_type not in (
            "NON_EXCLUSIVE",
            "COMMERCIAL",
            "ACADEMIC",
            "OPEN_SOURCE",
        ):
            raise StateTransitionError(
                f"Public purchase does not allow license_type {license_type}"
            )

        scope = str(p.get("scope", "Standard public license terms")).strip()
        if not (1 <= len(scope) <= 300):
            raise StateTransitionError("License scope must be 1..300 characters")

        duration_blocks = p.get("duration_blocks", 0)
        if not is_strict_int(duration_blocks) or duration_blocks < 0:
            raise StateTransitionError("duration_blocks must be >= 0")

        active = self.active_licenses_for_ip(ip_id, block_index)
        if any(lic.license_type == "EXCLUSIVE" for lic in active):
            raise StateTransitionError("Active EXCLUSIVE license prevents purchase")

        price = asset.license_price
        if sender_acct.balance < tx.fee + price:
            raise StateTransitionError(
                f"Insufficient balance for license purchase: needs {tx.fee + price}, has {sender_acct.balance}"
            )

        creator_royalty = 0
        if price > 0:
            sender_acct.balance -= price
            if asset.owner != asset.original_creator:
                creator_royalty = (price * asset.royalty_bps) // 10000
                owner_share = price - creator_royalty
                if creator_royalty > 0:
                    self.get_or_create_account(asset.original_creator).balance += creator_royalty
                if owner_share > 0:
                    self.get_or_create_account(asset.owner).balance += owner_share
            else:
                self.get_or_create_account(asset.owner).balance += price

        expires_block = (block_index + duration_blocks) if duration_blocks > 0 else 0
        license_id = (
            "LIC-"
            + sha256_hex(f"{ip_id}:{tx.sender}:{tx.nonce}")[:14].upper()
        )
        record = LicenseRecord(
            license_id=license_id,
            ip_id=ip_id,
            licensor=asset.owner,
            licensee=tx.sender,
            license_type=license_type,
            scope=scope,
            granted_block=block_index,
            expires_block=expires_block,
            royalty_bps=asset.royalty_bps,
            paid_amount=price,
            creator_royalty_paid=creator_royalty,
            status="ACTIVE",
            granted_tx=tx.tx_id,
        )
        self.licenses[license_id] = record
        asset.provenance.append(
            {
                "event": "LICENSE_PURCHASED",
                "license_id": license_id,
                "licensee": tx.sender,
                "paid_amount": price,
                "creator_royalty_paid": creator_royalty,
                "block_index": block_index,
                "tx_id": tx.tx_id,
                "timestamp": tx.timestamp,
                "details": f"Purchased {license_type} license ({price} IPC, royalty {creator_royalty} IPC)",
            }
        )
        return {
            "event": "LICENSE_PURCHASED",
            "license_id": license_id,
            "paid_amount": price,
            "creator_royalty_paid": creator_royalty,
        }

    def _apply_revoke_license(
        self, tx: Transaction, _sender_acct: AccountState, block_index: int
    ) -> dict[str, Any]:
        p = tx.payload
        license_id = str(p.get("license_id", ""))
        lic = self.licenses.get(license_id)
        if lic is None:
            raise StateTransitionError(f"Unknown license: {license_id}")
        if lic.status != "ACTIVE":
            raise StateTransitionError("License is not active")

        asset = self.assets[lic.ip_id]
        if tx.sender not in (asset.owner, self.arbitrator):
            raise StateTransitionError("Only IP owner or arbitrator can revoke license")

        reason = str(p.get("reason", "")).strip()
        if not (1 <= len(reason) <= 300):
            raise StateTransitionError("Revoke reason must be 1..300 characters")

        lic.status = "REVOKED"
        lic.revoked_tx = tx.tx_id
        lic.revoke_reason = reason
        asset.provenance.append(
            {
                "event": "LICENSE_REVOKED",
                "license_id": license_id,
                "actor": tx.sender,
                "block_index": block_index,
                "tx_id": tx.tx_id,
                "timestamp": tx.timestamp,
                "details": reason,
            }
        )
        return {"event": "LICENSE_REVOKED", "license_id": license_id}

    def _apply_file_dispute(
        self, tx: Transaction, _sender_acct: AccountState, block_index: int
    ) -> dict[str, Any]:
        p = tx.payload
        accused_ip_id = str(p.get("accused_ip_id", ""))
        accused = self.assets.get(accused_ip_id)
        if accused is None:
            raise StateTransitionError(f"Unknown accused IP: {accused_ip_id}")
        if accused.status == "REVOKED":
            raise StateTransitionError("Accused IP is already REVOKED")
        if accused.owner == tx.sender:
            raise StateTransitionError("Owner cannot file a dispute against their own IP")

        prior_art_ip_id = str(p.get("prior_art_ip_id", "")).strip()
        if prior_art_ip_id:
            if prior_art_ip_id == accused_ip_id:
                raise StateTransitionError("prior_art_ip_id cannot equal accused_ip_id")
            prior_art = self.assets.get(prior_art_ip_id)
            if prior_art is None:
                raise StateTransitionError(f"Unknown prior_art_ip_id: {prior_art_ip_id}")
            if prior_art.status == "REVOKED":
                raise StateTransitionError("Cannot cite a REVOKED IP as prior art")
            if prior_art.registered_block > accused.registered_block:
                raise StateTransitionError(
                    "Cited prior art IP was registered after the accused IP"
                )

        claim_type = str(p.get("claim_type", "")).upper()
        if claim_type not in DISPUTE_CLAIMS:
            raise StateTransitionError(f"Invalid claim_type: {claim_type}")

        evidence_hash = str(p.get("evidence_hash", "")).lower().strip()
        if evidence_hash and not is_valid_hex(evidence_hash, 64):
            raise StateTransitionError("evidence_hash must be empty or 64 hex chars")

        description = str(p.get("description", "")).strip()
        if not (5 <= len(description) <= 1000):
            raise StateTransitionError("Dispute description must be 5..1000 characters")

        for existing in self.disputes.values():
            if (
                existing.accused_ip_id == accused_ip_id
                and existing.challenger == tx.sender
                and existing.status == "OPEN"
            ):
                raise StateTransitionError(
                    "Challenger already has an open dispute on this IP"
                )

        dispute_id = (
            "DSP-"
            + sha256_hex(f"{accused_ip_id}:{tx.sender}:{tx.nonce}")[:14].upper()
        )
        record = DisputeRecord(
            dispute_id=dispute_id,
            accused_ip_id=accused_ip_id,
            prior_art_ip_id=prior_art_ip_id,
            challenger=tx.sender,
            claim_type=claim_type,
            evidence_hash=evidence_hash,
            description=description,
            filed_block=block_index,
            filed_tx=tx.tx_id,
            status="OPEN",
        )
        self.disputes[dispute_id] = record
        accused.status = "DISPUTED"
        accused.provenance.append(
            {
                "event": "DISPUTE_FILED",
                "dispute_id": dispute_id,
                "challenger": tx.sender,
                "claim_type": claim_type,
                "block_index": block_index,
                "tx_id": tx.tx_id,
                "timestamp": tx.timestamp,
                "details": description,
            }
        )
        return {"event": "DISPUTE_FILED", "dispute_id": dispute_id}

    def _apply_resolve_dispute(
        self, tx: Transaction, _sender_acct: AccountState, block_index: int
    ) -> dict[str, Any]:
        if tx.sender != self.arbitrator:
            raise StateTransitionError(
                "Only the designated Arbitrator Authority can resolve disputes"
            )
        p = tx.payload
        dispute_id = str(p.get("dispute_id", ""))
        dispute = self.disputes.get(dispute_id)
        if dispute is None:
            raise StateTransitionError(f"Unknown dispute: {dispute_id}")
        if dispute.status != "OPEN":
            raise StateTransitionError("Dispute is already resolved")

        ruling = str(p.get("ruling", "")).upper()
        if ruling not in DISPUTE_RULINGS:
            raise StateTransitionError(f"Invalid ruling: {ruling}")

        ruling_notes = str(p.get("ruling_notes", "")).strip()
        if not (1 <= len(ruling_notes) <= 500):
            raise StateTransitionError("ruling_notes must be 1..500 characters")

        accused = self.assets[dispute.accused_ip_id]
        dispute.status = "RESOLVED"
        dispute.ruling = ruling
        dispute.ruling_notes = ruling_notes
        dispute.resolved_block = block_index
        dispute.resolved_tx = tx.tx_id

        remaining_open = self.open_disputes_for_ip(accused.ip_id)
        if ruling == "UPHELD_REVOKE":
            accused.status = "REVOKED"
            for lic in self.licenses.values():
                if lic.ip_id == accused.ip_id and lic.status == "ACTIVE":
                    lic.status = "REVOKED"
                    lic.revoked_tx = tx.tx_id
                    lic.revoke_reason = f"IP revoked by dispute ruling {dispute_id}"
        elif ruling == "UPHELD_TRANSFER":
            accused.owner = dispute.challenger
            accused.status = "DISPUTED" if remaining_open else "ACTIVE"
        else:  # DISMISSED
            if accused.status != "REVOKED":
                accused.status = "DISPUTED" if remaining_open else "ACTIVE"

        accused.provenance.append(
            {
                "event": "DISPUTE_RESOLVED",
                "dispute_id": dispute_id,
                "ruling": ruling,
                "block_index": block_index,
                "tx_id": tx.tx_id,
                "timestamp": tx.timestamp,
                "details": ruling_notes,
            }
        )
        return {"event": "DISPUTE_RESOLVED", "dispute_id": dispute_id, "ruling": ruling}

    def _apply_transfer_tokens(
        self, tx: Transaction, sender_acct: AccountState, _block_index: int
    ) -> dict[str, Any]:
        p = tx.payload
        to_address = str(p.get("to_address", "")).lower()
        if not is_valid_address(to_address) or to_address == tx.sender:
            raise StateTransitionError("Invalid token recipient address")

        amount = p.get("amount")
        if not is_strict_int(amount) or amount <= 0:
            raise StateTransitionError("Transfer amount must be positive integer")

        if sender_acct.balance < tx.fee + amount:
            raise StateTransitionError(
                f"Insufficient balance: needs {tx.fee + amount}, has {sender_acct.balance}"
            )
        sender_acct.balance -= amount
        self.get_or_create_account(to_address).balance += amount
        return {"event": "TOKENS_TRANSFERRED", "to": to_address, "amount": amount}
