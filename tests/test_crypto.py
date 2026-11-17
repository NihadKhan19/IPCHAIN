"""Tests for secp256k1 ECDSA, RFC 6979, Merkle proofs, SimHash, and JS interoperability."""

from __future__ import annotations

import json
import subprocess
import unittest
from pathlib import Path

from ipchain.crypto import (
    EMPTY_MERKLE_ROOT,
    SECP256K1_HALF_N,
    SECP256K1_N,
    MerkleTree,
    canonical_json,
    compute_simhash,
    decompress_public_key,
    derive_keypair_from_seed,
    generate_keypair,
    is_on_curve,
    private_key_to_public_key,
    public_key_to_address,
    sha256_bytes,
    sha256_hex,
    sign_digest,
    simhash_similarity,
    verify_digest_signature,
    verify_merkle_proof,
)
from ipchain.models import Transaction


class CryptoTests(unittest.TestCase):
    def test_keypair_curve_and_address(self) -> None:
        kp = generate_keypair()
        self.assertEqual(len(kp["private_key"]), 64)
        self.assertEqual(len(kp["public_key"]), 66)
        self.assertTrue(kp["address"].startswith("0x") and len(kp["address"]) == 42)
        pt = decompress_public_key(kp["public_key"])
        self.assertTrue(is_on_curve(pt))
        self.assertEqual(private_key_to_public_key(kp["private_key"]), kp["public_key"])
        self.assertEqual(public_key_to_address(kp["public_key"]), kp["address"])

    def test_rfc6979_deterministic_and_low_s(self) -> None:
        kp = derive_keypair_from_seed("test-seed-1")
        digest = sha256_bytes("intellectual property prior art commitment")
        sig1 = sign_digest(kp["private_key"], digest)
        sig2 = sign_digest(kp["private_key"], digest)
        self.assertEqual(sig1, sig2)
        self.assertTrue(verify_digest_signature(kp["public_key"], digest, sig1))

        # Verify low-S enforcement rejects malleable high-S signatures
        r_hex, s_hex = sig1[:64], sig1[64:]
        s_int = int(s_hex, 16)
        self.assertLessEqual(s_int, SECP256K1_HALF_N)
        high_s = SECP256K1_N - s_int
        malleated_sig = f"{r_hex}{high_s:064x}"
        self.assertFalse(verify_digest_signature(kp["public_key"], digest, malleated_sig))

        # Tampered digest fails verification
        bad_digest = sha256_bytes("intellectual property prior art commitmenT")
        self.assertFalse(verify_digest_signature(kp["public_key"], bad_digest, sig1))

    def test_merkle_tree_and_inclusion_proofs(self) -> None:
        empty = MerkleTree([])
        self.assertEqual(empty.root, EMPTY_MERKLE_ROOT)

        for count in (1, 2, 3, 5, 8):
            tx_ids = [sha256_hex(f"tx-{count}-{i}") for i in range(count)]
            tree = MerkleTree(tx_ids)
            for idx, tx_id in enumerate(tx_ids):
                proof = tree.get_proof(idx)
                self.assertTrue(verify_merkle_proof(tx_id, proof, tree.root))
                self.assertFalse(
                    verify_merkle_proof(sha256_hex("wrong"), proof, tree.root)
                )
                self.assertFalse(
                    verify_merkle_proof(tx_id, proof, sha256_hex("wrong-root"))
                )

    def test_simhash_similarity_detects_near_duplicates(self) -> None:
        original = (
            "A quantum-resistant zero-knowledge identity verification protocol using "
            "lattice-based commitments and Merkle inclusion proofs."
        )
        paraphrase = (
            "A quantum-resistant zero-knowledge identity verification protocol using "
            "lattice-based commitments and Merkle inclusion proofs!"
        )
        unrelated = "Recipe for sourdough artisan bread with high hydration starter."

        h_orig = compute_simhash(original)
        h_para = compute_simhash(paraphrase)
        h_unrel = compute_simhash(unrelated)

        self.assertGreater(simhash_similarity(h_orig, h_para), 0.90)
        self.assertLess(simhash_similarity(h_orig, h_unrel), 0.75)

    def test_js_crypto_matches_python_exactly(self) -> None:
        jsc = Path("/System/Library/Frameworks/JavaScriptCore.framework/Versions/Current/Helpers/jsc")
        if not jsc.is_file():
            self.skipTest("JavaScriptCore jsc binary not available")

        app_js = Path(__file__).resolve().parent.parent / "web" / "app.js"
        kp = derive_keypair_from_seed("js-python-interop-wallet")
        sample_text = "Decentralized IP protection — café π 🚀 prior art"
        unsigned_tx = {
            "type": "REGISTER_IP",
            "sender": kp["address"],
            "nonce": 3,
            "fee": 1,
            "timestamp": 1700001234,
            "payload": {
                "title": "Cross-Runtime Test IP",
                "ip_type": "SOFTWARE",
                "tags": ["z", "a"],
                "allow_public_license": True,
                "royalty_bps": 500,
            },
        }
        tx_ids = [sha256_hex(f"leaf-{i}") for i in range(5)]
        tree = MerkleTree(tx_ids)
        proof = tree.get_proof(2)

        driver = f"""
        const text = {json.dumps(sample_text, ensure_ascii=False)};
        const priv = {json.dumps(kp["private_key"])};
        const unsignedTx = {json.dumps(unsigned_tx, ensure_ascii=False)};
        const proofData = {json.dumps({"txId": tx_ids[2], "proof": proof, "root": tree.root})};
        const signedTx = IPChainCrypto.signTransactionJS(unsignedTx, priv);
        print(JSON.stringify({{
          sha: IPChainCrypto.sha256Hex(text),
          simhash: IPChainCrypto.computeSimhashJS(text),
          pub: IPChainCrypto.privToPubHex(priv),
          addr: IPChainCrypto.pubToAddress(IPChainCrypto.privToPubHex(priv)),
          canon: IPChainCrypto.canonicalJson(unsignedTx),
          signedTx: signedTx,
          merkleOk: IPChainCrypto.verifyMerkleProofJS(proofData.txId, proofData.proof, proofData.root)
        }}));
        """
        proc = subprocess.run(
            [str(jsc), str(app_js), "-e", driver],
            check=True,
            capture_output=True,
            text=True,
        )
        js_out = json.loads(proc.stdout.strip().splitlines()[-1])

        self.assertEqual(js_out["sha"], sha256_hex(sample_text))
        self.assertEqual(js_out["simhash"], compute_simhash(sample_text))
        self.assertEqual(js_out["pub"], kp["public_key"])
        self.assertEqual(js_out["addr"], kp["address"])
        self.assertEqual(js_out["canon"], canonical_json(unsigned_tx))
        self.assertTrue(js_out["merkleOk"])

        # Python Transaction verifier must accept the browser-signed transaction directly!
        py_tx = Transaction.from_dict(js_out["signedTx"])
        self.assertTrue(py_tx.verify_signature())


if __name__ == "__main__":
    unittest.main()
