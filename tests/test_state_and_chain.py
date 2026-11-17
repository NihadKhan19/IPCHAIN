"""Tests for IPChain state transitions, PoW mining, tamper detection, and persistence."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ipchain.blockchain import Blockchain, BlockchainError
from ipchain.crypto import compute_simhash, sha256_hex
from ipchain.demo import default_genesis_config, get_demo_personas, seed_demo_scenario
from ipchain.models import BLOCK_REWARD, Transaction
from ipchain.state import StateTransitionError


def _make_tx(
    chain: Blockchain,
    persona: dict[str, str],
    tx_type: str,
    payload: dict,
    fee: int = 1,
    nonce_override: int | None = None,
) -> Transaction:
    acct = chain.get_projected_account(persona["address"])
    nonce = acct["pending_nonce"] if nonce_override is None else nonce_override
    return Transaction(
        tx_type=tx_type,
        sender=persona["address"],
        nonce=nonce,
        fee=fee,
        timestamp=1700001000 + nonce,
        payload=payload,
    ).sign(persona["private_key"])


class StateAndChainTests(unittest.TestCase):
    def setUp(self) -> None:
        self.personas = get_demo_personas()
        self.arb, self.balances = default_genesis_config()
        self.chain = Blockchain(
            arbitrator=self.arb,
            genesis_balances=self.balances,
            difficulty=2,
        )

    def test_register_duplicate_hash_and_nonce_replay_rejected(self) -> None:
        alice = self.personas["alice"]
        bob = self.personas["bob"]
        content = "Original Quantum Invention Blueprint"
        ch = sha256_hex(content)

        tx1 = _make_tx(
            self.chain,
            alice,
            "REGISTER_IP",
            {
                "title": "Quantum Blueprint",
                "ip_type": "PATENT",
                "description": content,
                "content_hash": ch,
                "simhash": compute_simhash(content),
                "jurisdiction": "GLOBAL",
                "royalty_bps": 1000,
                "license_price": 100,
                "allow_public_license": True,
                "default_license_type": "COMMERCIAL",
                "tags": ["quantum"],
            },
        )
        self.chain.submit_transaction(tx1)
        self.chain.mine_block(self.arb)

        # Exact duplicate content hash from Bob must be rejected
        dup_tx = _make_tx(
            self.chain,
            bob,
            "REGISTER_IP",
            {
                "title": "Stolen Quantum Blueprint",
                "ip_type": "PATENT",
                "description": content,
                "content_hash": ch,
                "simhash": compute_simhash(content),
                "jurisdiction": "US",
                "royalty_bps": 0,
                "license_price": 0,
                "allow_public_license": False,
                "default_license_type": "NON_EXCLUSIVE",
                "tags": [],
            },
        )
        with self.assertRaises(StateTransitionError):
            self.chain.submit_transaction(dup_tx)

        # Replay with stale nonce=0 for Alice must be rejected
        replay_tx = _make_tx(
            self.chain,
            alice,
            "TRANSFER_TOKENS",
            {"to_address": bob["address"], "amount": 10},
            nonce_override=0,
        )
        with self.assertRaises(StateTransitionError):
            self.chain.submit_transaction(replay_tx)

    def test_transfer_and_automated_creator_royalty_split(self) -> None:
        alice = self.personas["alice"]
        bob = self.personas["bob"]
        carol = self.personas["carol"]

        alice_start = self.chain.state.get_account(alice["address"]).balance
        bob_start = self.chain.state.get_account(bob["address"]).balance
        carol_start = self.chain.state.get_account(carol["address"]).balance

        # 1. Alice registers software with 10% (1000 bps) creator royalty & 100 IPC license price
        doc = "High-Speed Neural Audio Codec Source Code v1"
        reg = _make_tx(
            self.chain,
            alice,
            "REGISTER_IP",
            {
                "title": "Neural Audio Codec",
                "ip_type": "SOFTWARE",
                "description": doc,
                "content_hash": sha256_hex(doc),
                "simhash": compute_simhash(doc),
                "jurisdiction": "GLOBAL",
                "royalty_bps": 1000,
                "license_price": 100,
                "allow_public_license": True,
                "default_license_type": "COMMERCIAL",
                "tags": ["audio"],
            },
        )
        ip_id = self.chain.submit_transaction(reg)["event"]["ip_id"]
        self.chain.mine_block(self.arb)

        # 2. Alice transfers ownership to Bob
        tr = _make_tx(
            self.chain,
            alice,
            "TRANSFER_IP",
            {"ip_id": ip_id, "to_address": bob["address"], "note": "Sold IP rights"},
        )
        self.chain.submit_transaction(tr)
        self.chain.mine_block(self.arb)
        self.assertEqual(self.chain.state.assets[ip_id].owner, bob["address"])
        self.assertEqual(self.chain.state.assets[ip_id].original_creator, alice["address"])

        # Non-owner (Alice) can no longer transfer
        unauth_tr = _make_tx(
            self.chain,
            alice,
            "TRANSFER_IP",
            {"ip_id": ip_id, "to_address": carol["address"], "note": "Unauthorized"},
        )
        with self.assertRaises(StateTransitionError):
            self.chain.submit_transaction(unauth_tr)

        # 3. Carol purchases a 100 IPC commercial license -> 10 IPC royalty to Alice, 90 IPC to Bob
        buy = _make_tx(
            self.chain,
            carol,
            "PURCHASE_LICENSE",
            {
                "ip_id": ip_id,
                "license_type": "COMMERCIAL",
                "scope": "SaaS product usage",
                "duration_blocks": 100,
            },
        )
        buy_res = self.chain.submit_transaction(buy)
        self.assertEqual(buy_res["event"]["creator_royalty_paid"], 10)
        self.chain.mine_block(self.arb)

        self.assertEqual(
            self.chain.state.get_account(alice["address"]).balance,
            alice_start - 2 + 10,  # 2 tx fees + 10 IPC royalty
        )
        self.assertEqual(
            self.chain.state.get_account(bob["address"]).balance,
            bob_start + 90,
        )
        self.assertEqual(
            self.chain.state.get_account(carol["address"]).balance,
            carol_start - 1 - 100,
        )

    def test_exclusive_license_guard_and_revocation(self) -> None:
        alice = self.personas["alice"]
        bob = self.personas["bob"]
        carol = self.personas["carol"]

        doc = "Exclusive Industrial Turbine Design"
        reg = _make_tx(
            self.chain,
            alice,
            "REGISTER_IP",
            {
                "title": "Turbine CAD",
                "ip_type": "DESIGN",
                "description": doc,
                "content_hash": sha256_hex(doc),
                "simhash": compute_simhash(doc),
                "jurisdiction": "EU",
                "royalty_bps": 500,
                "license_price": 0,
                "allow_public_license": False,
                "default_license_type": "NON_EXCLUSIVE",
                "tags": ["cad"],
            },
        )
        ip_id = self.chain.submit_transaction(reg)["event"]["ip_id"]
        self.chain.mine_block(self.arb)

        # Grant exclusive license to Bob
        ex_tx = _make_tx(
            self.chain,
            alice,
            "GRANT_LICENSE",
            {
                "ip_id": ip_id,
                "licensee": bob["address"],
                "license_type": "EXCLUSIVE",
                "scope": "Exclusive EU manufacturing",
                "duration_blocks": 50,
            },
        )
        lic_id = self.chain.submit_transaction(ex_tx)["event"]["license_id"]
        self.chain.mine_block(self.arb)

        # Second license to Carol must be blocked while exclusive license is active
        second_tx = _make_tx(
            self.chain,
            alice,
            "GRANT_LICENSE",
            {
                "ip_id": ip_id,
                "licensee": carol["address"],
                "license_type": "NON_EXCLUSIVE",
                "scope": "Secondary manufacturing",
                "duration_blocks": 10,
            },
        )
        with self.assertRaises(StateTransitionError):
            self.chain.submit_transaction(second_tx)

        # Revoke Bob's license, then Carol can be licensed
        rev_tx = _make_tx(
            self.chain,
            alice,
            "REVOKE_LICENSE",
            {"license_id": lic_id, "reason": "Mutual termination"},
        )
        self.chain.submit_transaction(rev_tx)
        self.chain.mine_block(self.arb)

        second_tx_ok = _make_tx(
            self.chain,
            alice,
            "GRANT_LICENSE",
            {
                "ip_id": ip_id,
                "licensee": carol["address"],
                "license_type": "NON_EXCLUSIVE",
                "scope": "Authorized manufacturing",
                "duration_blocks": 10,
            },
        )
        self.chain.submit_transaction(second_tx_ok)
        self.chain.mine_block(self.arb)

    def test_demo_seed_dispute_resolution_and_tamper_detection(self) -> None:
        seed_info = seed_demo_scenario(self.chain)
        self.assertTrue(seed_info["seeded"])
        self.assertEqual(self.chain.height, 4)

        audit = self.chain.verify_integrity()
        self.assertTrue(audit["valid"])
        self.assertEqual(audit["checked_blocks"], 5)

        dispute_id = seed_info["open_dispute_id"]
        accused_ip_id = seed_info["ip_ids"][3]
        self.assertEqual(self.chain.state.assets[accused_ip_id].status, "DISPUTED")

        # Non-arbitrator cannot resolve dispute
        bob = self.personas["bob"]
        bad_resolve = _make_tx(
            self.chain,
            bob,
            "RESOLVE_DISPUTE",
            {
                "dispute_id": dispute_id,
                "ruling": "DISMISSED",
                "ruling_notes": "Unauthorized attempt",
            },
        )
        with self.assertRaises(StateTransitionError):
            self.chain.submit_transaction(bad_resolve)

        # Arbitrator upholds plagiarism claim and revokes copycat IP
        arb_p = self.personas["arbitrator"]
        ok_resolve = _make_tx(
            self.chain,
            arb_p,
            "RESOLVE_DISPUTE",
            {
                "dispute_id": dispute_id,
                "ruling": "UPHELD_REVOKE",
                "ruling_notes": "Prior art verified at Block #1",
            },
        )
        self.chain.submit_transaction(ok_resolve)
        self.chain.mine_block(arb_p["address"])
        self.assertEqual(self.chain.state.assets[accused_ip_id].status, "REVOKED")

        # Tamper simulation catches every attack while leaving live chain valid
        for vector in ("tx_title", "tx_owner_payload", "block_timestamp", "block_miner", "state_root"):
            sim = self.chain.simulate_tamper(1, target=vector, replacement="Evil Hack")
            self.assertFalse(sim["tampered_chain_valid"])
            self.assertFalse(sim["audit_report"]["valid"])
        self.assertTrue(self.chain.verify_integrity()["valid"])

    def test_disk_persistence_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp) / "ledger"
            c1 = Blockchain(
                arbitrator=self.arb,
                genesis_balances=self.balances,
                difficulty=2,
                data_dir=data_dir,
            )
            seed_demo_scenario(c1)
            expected_root = c1.state.compute_state_root()
            expected_height = c1.height

            c2 = Blockchain(
                arbitrator=self.arb,
                genesis_balances=self.balances,
                difficulty=2,
                data_dir=data_dir,
            )
            self.assertEqual(c2.height, expected_height)
            self.assertEqual(c2.state.compute_state_root(), expected_root)
            self.assertEqual(
                c2.verify_content(ip_id=list(c2.state.assets.keys())[0])["exact_match"],
                True,
            )


if __name__ == "__main__":
    unittest.main()
