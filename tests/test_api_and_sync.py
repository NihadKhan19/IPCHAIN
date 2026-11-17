"""End-to-end HTTP REST API, Web UI static serving, and 2-node P2P sync tests."""

from __future__ import annotations

import json
import threading
import time
import unittest
import urllib.error
import urllib.request
from typing import Any

from ipchain.blockchain import Blockchain
from ipchain.crypto import compute_simhash, generate_keypair, sha256_hex
from ipchain.demo import default_genesis_config, get_demo_personas, seed_demo_scenario
from ipchain.models import Transaction
from ipchain.server import create_server


def _http(url: str, method: str = "GET", body: dict[str, Any] | None = None) -> tuple[int, Any]:
    data = None if body is None else json.dumps(body).encode("utf-8")
    headers = {"Content-Type": "application/json"} if data is not None else {}
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read().decode("utf-8")
            ctype = resp.headers.get("Content-Type", "")
            if "application/json" in ctype:
                return resp.status, json.loads(raw)
            return resp.status, raw
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


class ApiAndSyncTests(unittest.TestCase):
    def _start_node(self, seed: bool = False) -> tuple[Blockchain, Any, str, threading.Thread]:
        arb, balances = default_genesis_config()
        chain = Blockchain(arbitrator=arb, genesis_balances=balances, difficulty=2)
        if seed:
            seed_demo_scenario(chain)
        server = create_server(chain, host="127.0.0.1", port=0)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return chain, server, f"http://127.0.0.1:{port}", thread

    def test_full_rest_api_and_static_assets(self) -> None:
        chain, server, base_url, thread = self._start_node(seed=True)
        try:
            for route in ("/", "/styles.css", "/app.js"):
                code, body = _http(f"{base_url}{route}")
                self.assertEqual(code, 200)
                self.assertGreater(len(body), 100)

            code, status = _http(f"{base_url}/api/status")
            self.assertEqual(code, 200)
            self.assertEqual(status["height"], 4)
            self.assertEqual(status["total_ips"], 4)
            self.assertEqual(status["open_disputes"], 1)

            # Generate fresh wallet, claim faucet tokens, sign & register IP, verify + Merkle proof
            fresh = generate_keypair()
            code, faucet_res = _http(
                f"{base_url}/api/faucet",
                "POST",
                {"address": fresh["address"], "amount": 250, "auto_mine": True},
            )
            self.assertEqual(code, 201)

            code, acct = _http(f"{base_url}/api/accounts/{fresh['address']}")
            self.assertEqual(code, 200)
            self.assertEqual(acct["balance"], 250)

            work = "Novel decentralized federated genomic training weights hash commitment."
            tx = Transaction(
                tx_type="REGISTER_IP",
                sender=fresh["address"],
                nonce=acct["pending_nonce"],
                fee=1,
                timestamp=int(time.time()),
                payload={
                    "title": "Federated Genomic Weights",
                    "ip_type": "TRADE_SECRET",
                    "description": "Confidential model weights fingerprint",
                    "content_hash": sha256_hex(work),
                    "simhash": compute_simhash(work),
                    "jurisdiction": "GLOBAL",
                    "royalty_bps": 750,
                    "license_price": 40,
                    "allow_public_license": True,
                    "default_license_type": "COMMERCIAL",
                    "tags": ["genomics", "ai"],
                },
            ).sign(fresh["private_key"])

            code, sub = _http(f"{base_url}/api/transactions", "POST", tx.to_dict())
            self.assertEqual(code, 201)
            ip_id = sub["event"]["ip_id"]

            code, mined = _http(
                f"{base_url}/api/mine", "POST", {"miner_address": fresh["address"]}
            )
            self.assertEqual(code, 201)
            self.assertEqual(mined["block"]["index"], 6)

            code, ver = _http(
                f"{base_url}/api/verify",
                "POST",
                {"content_hash": sha256_hex(work), "text": work},
            )
            self.assertEqual(code, 200)
            self.assertTrue(ver["exact_match"])
            self.assertEqual(ver["certificate"]["ip_asset"]["ip_id"], ip_id)
            self.assertTrue(ver["certificate"]["merkle_proof"]["verified"])

            # Tamper simulation via API
            code, sim = _http(
                f"{base_url}/api/audit/simulate-tamper",
                "POST",
                {"block_index": 1, "target": "tx_title", "replacement": "Hacked"},
            )
            self.assertEqual(code, 200)
            self.assertFalse(sim["tampered_chain_valid"])

            # Chain audit remains 100% valid
            code, audit = _http(f"{base_url}/api/audit")
            self.assertEqual(code, 200)
            self.assertTrue(audit["valid"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_two_node_p2p_sync_adopts_longer_valid_chain(self) -> None:
        _, srv_a, url_a, thr_a = self._start_node(seed=True)
        chain_b, srv_b, url_b, thr_b = self._start_node(seed=False)
        try:
            self.assertEqual(chain_b.height, 0)

            code, reg_res = _http(
                f"{url_b}/api/peers/register", "POST", {"peer_url": url_a}
            )
            self.assertEqual(code, 200)
            self.assertIn(url_a, reg_res["peers"])

            code, sync_res = _http(f"{url_b}/api/peers/sync", "POST", {})
            self.assertEqual(code, 200)
            self.assertTrue(sync_res["replaced"])
            self.assertEqual(sync_res["adopted_from"], url_a)
            self.assertEqual(sync_res["height"], 4)
            self.assertEqual(len(chain_b.state.assets), 4)

            # Verify Node B passes full cryptographic audit after sync
            code, audit_b = _http(f"{url_b}/api/audit")
            self.assertEqual(code, 200)
            self.assertTrue(audit_b["valid"])
        finally:
            srv_a.shutdown()
            srv_a.server_close()
            srv_b.shutdown()
            srv_b.server_close()
            thr_a.join(timeout=2)
            thr_b.join(timeout=2)

    def test_p2p_sync_rejects_tampered_longer_peer_chain(self) -> None:
        chain_evil, srv_evil, url_evil, thr_evil = self._start_node(seed=True)
        chain_clean, srv_clean, url_clean, thr_clean = self._start_node(seed=False)
        try:
            # Corrupt block #1 title on evil node without valid signature/PoW recomputation
            chain_evil.chain[1].transactions[0].payload["title"] = "Tampered Evil Title"

            _http(f"{url_clean}/api/peers/register", "POST", {"peer_url": url_evil})
            code, sync_res = _http(f"{url_clean}/api/peers/sync", "POST", {})
            self.assertEqual(code, 200)
            self.assertFalse(sync_res["replaced"])
            self.assertEqual(chain_clean.height, 0)
            self.assertTrue(sync_res["errors"])
        finally:
            srv_evil.shutdown()
            srv_evil.server_close()
            srv_clean.shutdown()
            srv_clean.server_close()
            thr_evil.join(timeout=2)
            thr_clean.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
