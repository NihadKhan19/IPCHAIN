"""Core IPChain blockchain engine: genesis, mempool, PoW mining, verification, and P2P sync."""

from __future__ import annotations

import copy
import json
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from ipchain.crypto import (
    EMPTY_MERKLE_ROOT,
    MerkleTree,
    compute_simhash,
    is_valid_address,
    is_valid_hex,
    sha256_hex,
    verify_merkle_proof,
)
from ipchain.models import (
    BLOCK_REWARD,
    GENESIS_TIMESTAMP,
    Block,
    Transaction,
)
from ipchain.state import LedgerState, StateTransitionError
from ipchain.storage import ChainStorage


class BlockchainError(ValueError):
    """Raised on invalid blockchain operations, mining failures, or sync rejections."""


class Blockchain:
    """Thread-safe Proof-of-Work blockchain specialized for Intellectual Property Protection."""

    def __init__(
        self,
        arbitrator: str,
        genesis_balances: dict[str, int] | None = None,
        difficulty: int = 2,
        data_dir: str | Path | None = None,
    ) -> None:
        if difficulty < 1 or difficulty > 6:
            raise ValueError("Difficulty must be between 1 and 6")
        if not is_valid_address(arbitrator.lower()):
            raise ValueError("Arbitrator must be a valid 0x address")

        self._lock = threading.RLock()
        self.arbitrator = arbitrator.lower()
        self.genesis_balances = {
            addr.lower(): int(bal)
            for addr, bal in (genesis_balances or {}).items()
        }
        self.difficulty = difficulty
        self.storage = ChainStorage(data_dir) if data_dir is not None else None

        self.chain: list[Block] = []
        self.mempool: list[Transaction] = []
        self.peers: set[str] = set()
        self.tx_index: dict[str, tuple[int, int]] = {}
        self.state = self._new_genesis_state()

        if self.storage is not None and self.storage.exists():
            self._load_from_storage()
        else:
            genesis_block = self._create_genesis_block()
            self.chain = [genesis_block]
            self._persist()

    def _new_genesis_state(self) -> LedgerState:
        state = LedgerState(arbitrator=self.arbitrator)
        state.set_genesis_balances(self.genesis_balances)
        return state

    def _create_genesis_block(self) -> Block:
        state_root = self._new_genesis_state().compute_state_root()
        genesis = Block(
            index=0,
            timestamp=GENESIS_TIMESTAMP,
            previous_hash="0" * 64,
            merkle_root=EMPTY_MERKLE_ROOT,
            state_root=state_root,
            nonce=0,
            difficulty=self.difficulty,
            miner=self.arbitrator,
            transactions=[],
        )
        genesis.hash = genesis.compute_hash()
        return genesis

    def _persist(self) -> None:
        if self.storage is not None:
            self.storage.save(
                blocks=self.chain,
                mempool=self.mempool,
                peers=sorted(self.peers),
                difficulty=self.difficulty,
            )

    def _load_from_storage(self) -> None:
        assert self.storage is not None
        loaded = self.storage.load()
        blocks: list[Block] = loaded["blocks"]
        expected_genesis = self._create_genesis_block()
        valid, final_state, report = self.validate_chain(
            blocks, expected_genesis=expected_genesis
        )
        if not valid or final_state is None:
            raise BlockchainError(
                f"Persisted ledger failed integrity verification: {report.get('error')}"
            )
        self.chain = blocks
        self.state = final_state
        self.peers = set(loaded["peers"])
        self._rebuild_tx_index()

        # Re-validate persisted mempool transactions against current state
        self.mempool = []
        for tx in loaded["mempool"]:
            try:
                self.submit_transaction(tx, persist=False)
            except (BlockchainError, StateTransitionError):
                continue

    def _rebuild_tx_index(self) -> None:
        self.tx_index = {}
        for block in self.chain:
            for idx, tx in enumerate(block.transactions):
                self.tx_index[tx.tx_id] = (block.index, idx)

    @property
    def height(self) -> int:
        with self._lock:
            return len(self.chain) - 1

    @property
    def latest_block(self) -> Block:
        with self._lock:
            return self.chain[-1]

    def _projected_state_locked(self) -> LedgerState:
        """Clone committed state and apply current mempool txs at next block index."""
        proj = self.state.clone()
        next_idx = len(self.chain)
        for pending in self.mempool:
            proj.apply_transaction(pending, next_idx)
        return proj

    def get_projected_account(self, address: str) -> dict[str, Any]:
        """Return committed and pending (mempool-projected) balance and nonce."""
        addr = address.lower()
        with self._lock:
            committed = self.state.get_account(addr)
            projected = self._projected_state_locked().get_account(addr)
            return {
                "address": addr,
                "balance": committed.balance,
                "nonce": committed.nonce,
                "pending_balance": projected.balance,
                "pending_nonce": projected.nonce,
            }

    def submit_transaction(
        self, tx: Transaction, persist: bool = True
    ) -> dict[str, Any]:
        """Validate transaction signature, IP rules, and pending nonce, then queue in mempool."""
        with self._lock:
            if not tx.verify_signature():
                raise BlockchainError("Invalid transaction signature or tx_id")
            if tx.tx_id in self.tx_index:
                raise BlockchainError(f"Transaction {tx.tx_id} is already confirmed")
            if any(m.tx_id == tx.tx_id for m in self.mempool):
                raise BlockchainError(f"Transaction {tx.tx_id} is already in mempool")

            proj = self._projected_state_locked()
            event = proj.apply_transaction(tx, len(self.chain))
            self.mempool.append(tx)
            if persist:
                self._persist()
            return {
                "tx_id": tx.tx_id,
                "status": "PENDING",
                "mempool_size": len(self.mempool),
                "event": event,
            }

    def mine_block(
        self, miner_address: str, max_txs: int = 50
    ) -> dict[str, Any]:
        """Mine a new PoW block containing valid queued transactions."""
        miner = miner_address.lower()
        if not is_valid_address(miner):
            raise BlockchainError("Invalid miner address")

        with self._lock:
            prev_block = self.chain[-1]
            next_index = prev_block.index + 1
            timestamp = max(int(time.time()), prev_block.timestamp)

            candidate_state = self.state.clone()
            included: list[Transaction] = []
            included_ids: set[str] = set()
            events: list[dict[str, Any]] = []

            for tx in self.mempool:
                if len(included) >= max_txs:
                    break
                try:
                    ev = candidate_state.apply_transaction(tx, next_index)
                    included.append(tx)
                    included_ids.add(tx.tx_id)
                    events.append({"tx_id": tx.tx_id, **ev})
                except StateTransitionError:
                    # Drop stale/conflicting pending txs cleanly
                    continue

            total_fees = sum(t.fee for t in included)
            candidate_state.get_or_create_account(miner).balance += (
                BLOCK_REWARD + total_fees
            )
            merkle_root = MerkleTree([t.tx_id for t in included]).root
            state_root = candidate_state.compute_state_root()

            block = Block(
                index=next_index,
                timestamp=timestamp,
                previous_hash=prev_block.hash,
                merkle_root=merkle_root,
                state_root=state_root,
                nonce=0,
                difficulty=self.difficulty,
                miner=miner,
                transactions=included,
            )

            target_prefix = "0" * self.difficulty
            start_ns = time.perf_counter_ns()
            while True:
                candidate_hash = block.compute_hash()
                if candidate_hash.startswith(target_prefix):
                    block.hash = candidate_hash
                    break
                block.nonce += 1
            elapsed_ms = round((time.perf_counter_ns() - start_ns) / 1_000_000, 2)

            self.chain.append(block)
            self.state = candidate_state
            for idx, tx in enumerate(included):
                self.tx_index[tx.tx_id] = (block.index, idx)
            self.mempool = [
                tx for tx in self.mempool if tx.tx_id not in included_ids
            ]
            # Filter any remaining mempool txs that became invalid after block inclusion
            surviving: list[Transaction] = []
            proj = self.state.clone()
            next_height = len(self.chain)
            for tx in self.mempool:
                try:
                    proj.apply_transaction(tx, next_height)
                    surviving.append(tx)
                except StateTransitionError:
                    continue
            self.mempool = surviving
            self._persist()

            return {
                "block": block.to_dict(),
                "reward": BLOCK_REWARD,
                "fees": total_fees,
                "elapsed_ms": elapsed_ms,
                "events": events,
            }

    def validate_chain(
        self,
        blocks: list[Block],
        expected_genesis: Block | None = None,
        min_difficulty: int | None = None,
    ) -> tuple[bool, LedgerState | None, dict[str, Any]]:
        """Verify entire chain: PoW, links, Merkle roots, ECDSA signatures, and state roots."""
        if not blocks:
            return (
                False,
                None,
                {"valid": False, "error": "Chain is empty", "blocks": []},
            )

        required_diff = min_difficulty if min_difficulty is not None else self.difficulty
        sim_state = self._new_genesis_state()
        block_reports: list[dict[str, Any]] = []

        for idx, block in enumerate(blocks):
            checks = {
                "index_valid": block.index == idx,
                "hash_valid": block.hash == block.compute_hash(),
                "pow_valid": True,
                "link_valid": True,
                "merkle_valid": True,
                "signatures_valid": True,
                "state_root_valid": True,
            }
            error_msg = ""

            if idx == 0:
                checks["link_valid"] = block.previous_hash == "0" * 64
                if block.transactions:
                    checks["signatures_valid"] = False
                    error_msg = "Genesis block cannot contain transactions"
                if block.merkle_root != EMPTY_MERKLE_ROOT:
                    checks["merkle_valid"] = False
                if expected_genesis is not None and block.hash != expected_genesis.hash:
                    checks["hash_valid"] = False
                    error_msg = "Genesis block hash mismatch"
                if sim_state.compute_state_root() != block.state_root:
                    checks["state_root_valid"] = False
            else:
                prev = blocks[idx - 1]
                checks["link_valid"] = (
                    block.previous_hash == prev.hash
                    and block.timestamp >= prev.timestamp
                )
                checks["pow_valid"] = (
                    block.difficulty >= required_diff and block.meets_difficulty()
                )
                try:
                    computed_merkle = MerkleTree(
                        [t.tx_id for t in block.transactions]
                    ).root
                    checks["merkle_valid"] = computed_merkle == block.merkle_root
                except ValueError as exc:
                    checks["merkle_valid"] = False
                    error_msg = str(exc)

                try:
                    for tx in block.transactions:
                        if not tx.verify_signature():
                            checks["signatures_valid"] = False
                            error_msg = f"Invalid signature on tx {tx.tx_id}"
                            break
                    if checks["signatures_valid"]:
                        sim_state.apply_block(block)
                        checks["state_root_valid"] = (
                            sim_state.compute_state_root() == block.state_root
                        )
                        if not checks["state_root_valid"]:
                            error_msg = "State root mismatch after replaying block"
                except StateTransitionError as exc:
                    checks["state_root_valid"] = False
                    error_msg = str(exc)

            block_ok = all(checks.values()) and not error_msg
            if not block_ok and not error_msg:
                failed = [k for k, v in checks.items() if not v]
                error_msg = f"Failed checks: {', '.join(failed)}"

            block_reports.append(
                {
                    "index": block.index,
                    "hash": block.hash,
                    "tx_count": len(block.transactions),
                    "valid": block_ok,
                    "checks": checks,
                    "error": error_msg,
                }
            )
            if not block_ok:
                return (
                    False,
                    None,
                    {
                        "valid": False,
                        "failed_block": block.index,
                        "error": f"Block #{block.index}: {error_msg}",
                        "blocks": block_reports,
                    },
                )

        return (
            True,
            sim_state,
            {
                "valid": True,
                "checked_blocks": len(blocks),
                "latest_hash": blocks[-1].hash,
                "latest_state_root": blocks[-1].state_root,
                "blocks": block_reports,
            },
        )

    def verify_integrity(self) -> dict[str, Any]:
        """Run full cryptographic audit on the local committed chain."""
        with self._lock:
            expected_genesis = self._create_genesis_block()
            _, _, report = self.validate_chain(
                self.chain, expected_genesis=expected_genesis
            )
            return report

    def simulate_tamper(
        self,
        block_index: int,
        target: str = "tx_title",
        replacement: str = "Tampered IP Title",
    ) -> dict[str, Any]:
        """Non-destructively mutate an in-memory copy of the chain to demonstrate tamper detection."""
        with self._lock:
            if block_index < 0 or block_index >= len(self.chain):
                raise BlockchainError(f"Block index {block_index} out of range")
            tampered = copy.deepcopy(self.chain)
            blk = tampered[block_index]

            description = ""
            if target == "block_timestamp":
                blk.timestamp += 1234
                description = f"Modified Block #{block_index} timestamp (+1234s)"
            elif target == "block_miner":
                blk.miner = "0x" + ("deadbeef" * 5)
                description = f"Changed Block #{block_index} miner address"
            elif target == "tx_title" and blk.transactions:
                tx = blk.transactions[0]
                if "title" in tx.payload:
                    tx.payload["title"] = replacement
                    description = (
                        f"Altered tx[0] payload title in Block #{block_index} to '{replacement}'"
                    )
                else:
                    tx.payload["tampered"] = replacement
                    description = f"Injected payload field in Block #{block_index} tx[0]"
            elif target == "tx_owner_payload" and blk.transactions:
                tx = blk.transactions[0]
                tx.sender = "0x" + ("cafe" * 10)
                description = f"Spoofed tx[0] sender in Block #{block_index}"
            else:
                blk.state_root = "0" * 64
                description = f"Corrupted Block #{block_index} state_root"

            expected_genesis = self._create_genesis_block()
            valid, _, report = self.validate_chain(
                tampered, expected_genesis=expected_genesis
            )
            return {
                "simulation": description,
                "live_chain_untouched": True,
                "tampered_chain_valid": valid,
                "audit_report": report,
            }

    def get_tx_proof(self, tx_id: str) -> dict[str, Any]:
        """Return transaction details and cryptographic Merkle inclusion proof."""
        norm_id = tx_id.lower()
        with self._lock:
            loc = self.tx_index.get(norm_id)
            if loc is None:
                raise BlockchainError(f"Confirmed transaction not found: {tx_id}")
            block_idx, tx_idx = loc
            block = self.chain[block_idx]
            tree = MerkleTree([t.tx_id for t in block.transactions])
            proof = tree.get_proof(tx_idx)
            verified = verify_merkle_proof(norm_id, proof, block.merkle_root)
            return {
                "tx_id": norm_id,
                "transaction": block.transactions[tx_idx].to_dict(),
                "block_index": block.index,
                "block_hash": block.hash,
                "block_timestamp": block.timestamp,
                "merkle_root": block.merkle_root,
                "tx_index": tx_idx,
                "proof": proof,
                "verified": verified,
            }

    def verify_content(
        self,
        content_hash: str = "",
        text: str = "",
        ip_id: str = "",
    ) -> dict[str, Any]:
        """Verify an artifact hash, text, or ip_id against registered IP + SimHash prior art."""
        with self._lock:
            norm_hash = content_hash.lower().strip()
            if not norm_hash and text:
                norm_hash = sha256_hex(text)

            simhash = compute_simhash(text) if text else ""

            matched_asset = None
            if ip_id:
                matched_asset = self.state.assets.get(ip_id)
            if matched_asset is None and norm_hash:
                if not is_valid_hex(norm_hash, 64):
                    raise BlockchainError("content_hash must be 64 hex chars")
                found_id = self.state.content_hash_index.get(norm_hash)
                if found_id:
                    matched_asset = self.state.assets.get(found_id)

            similar = (
                self.state.find_similar_ips(
                    simhash,
                    threshold=0.78,
                    exclude_ip_id=matched_asset.ip_id if matched_asset else "",
                )
                if simhash
                else []
            )

            certificate = None
            if matched_asset is not None:
                proof_bundle = self.get_tx_proof(matched_asset.registered_tx)
                licenses = [
                    lic.to_dict()
                    for lic in self.state.licenses.values()
                    if lic.ip_id == matched_asset.ip_id
                ]
                disputes = [
                    d.to_dict()
                    for d in self.state.disputes.values()
                    if d.accused_ip_id == matched_asset.ip_id
                ]
                certificate = {
                    "ip_asset": matched_asset.to_dict(),
                    "merkle_proof": proof_bundle,
                    "licenses": licenses,
                    "disputes": disputes,
                }

            return {
                "exact_match": matched_asset is not None,
                "queried_hash": norm_hash,
                "queried_simhash": simhash,
                "certificate": certificate,
                "similar_prior_art": similar,
            }

    # ------------------------------------------------------------------
    # P2P peer management & longest-valid-chain sync
    # ------------------------------------------------------------------

    def register_peer(self, peer_url: str) -> list[str]:
        """Normalize and add a peer node HTTP base URL."""
        cleaned = peer_url.strip().rstrip("/")
        if not (cleaned.startswith("http://") or cleaned.startswith("https://")):
            raise BlockchainError("Peer URL must start with http:// or https://")
        with self._lock:
            self.peers.add(cleaned)
            self._persist()
            return sorted(self.peers)

    def resolve_conflicts(self, timeout_sec: float = 4.0) -> dict[str, Any]:
        """Query registered peers and adopt longest cryptographically valid chain."""
        with self._lock:
            peer_list = sorted(self.peers)
            best_chain = self.chain
            best_state = self.state
            best_peer = None
            errors: list[dict[str, str]] = []
            expected_genesis = self._create_genesis_block()

        for peer in peer_list:
            try:
                req = urllib.request.Request(f"{peer}/api/chain", method="GET")
                with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
                    payload = json.loads(resp.read().decode("utf-8"))
                raw_blocks = payload.get("chain", [])
                candidate_blocks = [Block.from_dict(b) for b in raw_blocks]
            except (urllib.error.URLError, ValueError, KeyError, TimeoutError) as exc:
                errors.append({"peer": peer, "error": str(exc)})
                continue

            if len(candidate_blocks) <= len(best_chain):
                continue

            valid, cand_state, report = self.validate_chain(
                candidate_blocks, expected_genesis=expected_genesis
            )
            if valid and cand_state is not None:
                best_chain = candidate_blocks
                best_state = cand_state
                best_peer = peer
            else:
                errors.append(
                    {"peer": peer, "error": f"Rejected invalid chain: {report.get('error')}"}
                )

        with self._lock:
            replaced = False
            if best_peer is not None and len(best_chain) > len(self.chain):
                self.chain = best_chain
                self.state = best_state
                self._rebuild_tx_index()
                # Prune confirmed or invalidated txs from mempool
                surviving: list[Transaction] = []
                proj = self.state.clone()
                next_idx = len(self.chain)
                for tx in self.mempool:
                    if tx.tx_id in self.tx_index:
                        continue
                    try:
                        proj.apply_transaction(tx, next_idx)
                        surviving.append(tx)
                    except StateTransitionError:
                        continue
                self.mempool = surviving
                self._persist()
                replaced = True

            return {
                "replaced": replaced,
                "adopted_from": best_peer,
                "height": len(self.chain) - 1,
                "latest_hash": self.chain[-1].hash,
                "errors": errors,
            }
