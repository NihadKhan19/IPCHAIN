"""Deterministic demo personas and Topic 12 IP Protection seed scenario."""

from __future__ import annotations

import time
from typing import Any

from ipchain.blockchain import Blockchain
from ipchain.crypto import compute_simhash, derive_keypair_from_seed, sha256_hex
from ipchain.models import GENESIS_TIMESTAMP, Transaction


def get_demo_personas() -> dict[str, dict[str, str]]:
    """Return deterministic testnet/demo personas for walkthroughs and P2P genesis alignment."""
    specs = [
        ("treasury", "IPChain Genesis Treasury & Faucet", "TREASURY"),
        ("arbitrator", "Global IP Arbitrator Authority", "ARBITRATOR"),
        ("alice", "Dr. Alice Chen (Inventor & Researcher)", "CREATOR"),
        ("bob", "Bob Vance (Digital Media Studio)", "STUDIO"),
        ("carol", "Carol Rivera (Enterprise Licensee)", "LICENSEE"),
        ("dave", "Dave Mercer (Disputed Filer Demo)", "CHALLENGER"),
    ]
    personas: dict[str, dict[str, str]] = {}
    for key, label, role in specs:
        kp = derive_keypair_from_seed(f"ipchain-topic12-{key}")
        personas[key] = {
            "id": key,
            "label": label,
            "role": role,
            "address": kp["address"],
            "public_key": kp["public_key"],
            "private_key": kp["private_key"],
        }
    return personas


def default_genesis_config() -> tuple[str, dict[str, int]]:
    """Return deterministic arbitrator address and genesis IPC balances."""
    personas = get_demo_personas()
    balances = {
        personas["treasury"]["address"]: 1_000_000,
        personas["arbitrator"]["address"]: 50_000,
        personas["alice"]["address"]: 10_000,
        personas["bob"]["address"]: 10_000,
        personas["carol"]["address"]: 10_000,
        personas["dave"]["address"]: 2_000,
    }
    return personas["arbitrator"]["address"], balances


def _build_signed_tx(
    chain: Blockchain,
    persona: dict[str, str],
    tx_type: str,
    payload: dict[str, Any],
    timestamp: int,
    fee: int = 1,
) -> Transaction:
    acct = chain.get_projected_account(persona["address"])
    tx = Transaction(
        tx_type=tx_type,
        sender=persona["address"],
        nonce=acct["pending_nonce"],
        fee=fee,
        timestamp=timestamp,
        payload=payload,
    )
    return tx.sign(persona["private_key"])


def seed_demo_scenario(chain: Blockchain) -> dict[str, Any]:
    """Populate a realistic multi-block Topic 12 IP Protection scenario if chain is at genesis."""
    if chain.height > 0:
        return {"seeded": False, "reason": "Chain already has mined blocks"}

    personas = get_demo_personas()
    alice = personas["alice"]
    bob = personas["bob"]
    carol = personas["carol"]
    dave = personas["dave"]
    arb = personas["arbitrator"]

    base_ts = max(int(time.time()) - 300, GENESIS_TIMESTAMP + 60)

    # --- Block 1: Initial Patent, Software, and Trademark Registrations ---
    patent_doc = (
        "A quantum-resistant zero-knowledge identity verification protocol using "
        "lattice-based commitments and Merkle inclusion proofs for decentralized "
        "intellectual property timestamping without exposing underlying trade secrets."
    )
    software_src = (
        "fn verify_merkle_inclusion(leaf: [u8; 32], proof: &[(bool, [u8; 32])], "
        "root: [u8; 32]) -> bool { /* ZeroCopy consensus verifier v1.0 */ true }"
    )
    trademark_spec = (
        "NOVASYNTH AUDIO — Stylized hexagonal waveform emblem and acoustic chime "
        "registered under Class 9 and Class 42 digital synthesis software."
    )

    tx1 = _build_signed_tx(
        chain,
        alice,
        "REGISTER_IP",
        {
            "title": "Quantum-Resistant ZK Identity Protocol",
            "ip_type": "PATENT",
            "description": patent_doc,
            "content_hash": sha256_hex(patent_doc),
            "simhash": compute_simhash(patent_doc),
            "jurisdiction": "WIPO",
            "royalty_bps": 1000,  # 10.00%
            "license_price": 120,
            "allow_public_license": True,
            "default_license_type": "COMMERCIAL",
            "tags": ["cryptography", "zkp", "post-quantum"],
        },
        base_ts + 10,
    )
    res1 = chain.submit_transaction(tx1)

    tx2 = _build_signed_tx(
        chain,
        alice,
        "REGISTER_IP",
        {
            "title": "ZeroCopy Merkle Consensus Engine v1.0",
            "ip_type": "SOFTWARE",
            "description": software_src,
            "content_hash": sha256_hex(software_src),
            "simhash": compute_simhash(software_src),
            "jurisdiction": "GLOBAL",
            "royalty_bps": 500,  # 5.00%
            "license_price": 80,
            "allow_public_license": True,
            "default_license_type": "COMMERCIAL",
            "tags": ["rust", "consensus", "merkle"],
        },
        base_ts + 12,
    )
    res2 = chain.submit_transaction(tx2)

    tx3 = _build_signed_tx(
        chain,
        bob,
        "REGISTER_IP",
        {
            "title": "NovaSynth Audio™ Brand Mark & Sonic Logo",
            "ip_type": "TRADEMARK",
            "description": trademark_spec,
            "content_hash": sha256_hex(trademark_spec),
            "simhash": compute_simhash(trademark_spec),
            "jurisdiction": "US",
            "royalty_bps": 1500,  # 15.00%
            "license_price": 0,
            "allow_public_license": False,
            "default_license_type": "NON_EXCLUSIVE",
            "tags": ["brand", "audio", "trademark"],
        },
        base_ts + 14,
    )
    res3 = chain.submit_transaction(tx3)
    chain.mine_block(arb["address"])

    patent_ip_id = res1["event"]["ip_id"]
    software_ip_id = res2["event"]["ip_id"]
    trademark_ip_id = res3["event"]["ip_id"]

    # --- Block 2: Ownership Transfer (Alice -> Bob) + Direct Academic License ---
    tx4 = _build_signed_tx(
        chain,
        alice,
        "TRANSFER_IP",
        {
            "ip_id": software_ip_id,
            "to_address": bob["address"],
            "note": "Assigned commercial distribution rights to Studio Bob while retaining 5% creator royalty",
        },
        base_ts + 30,
    )
    tx5 = _build_signed_tx(
        chain,
        bob,
        "GRANT_LICENSE",
        {
            "ip_id": trademark_ip_id,
            "licensee": carol["address"],
            "license_type": "ACADEMIC",
            "scope": "University DSP research showcase and non-commercial audio demos",
            "duration_blocks": 500,
            "royalty_bps": 0,
        },
        base_ts + 32,
    )
    chain.submit_transaction(tx4)
    chain.submit_transaction(tx5)
    chain.mine_block(alice["address"])

    # --- Block 3: Public License Purchase (Automated Royalty Split) + Near-Duplicate Copycat Filing ---
    tx6 = _build_signed_tx(
        chain,
        carol,
        "PURCHASE_LICENSE",
        {
            "ip_id": software_ip_id,
            "license_type": "COMMERCIAL",
            "scope": "Enterprise cloud validator deployment (multi-region)",
            "duration_blocks": 1000,
        },
        base_ts + 60,
    )

    copycat_doc = (
        "A quantum-resistant zero-knowledge identity verification protocol using "
        "lattice-based commitments and Merkle inclusion proofs for decentralized "
        "intellectual property timestamping without exposing underlying trade secrets!"
    )
    tx7 = _build_signed_tx(
        chain,
        dave,
        "REGISTER_IP",
        {
            "title": "ZK Lattice Identity Timestamp Whitepaper (Copycat Filing)",
            "ip_type": "COPYRIGHT",
            "description": copycat_doc,
            "content_hash": sha256_hex(copycat_doc),
            "simhash": compute_simhash(copycat_doc),
            "jurisdiction": "EU",
            "royalty_bps": 2000,
            "license_price": 200,
            "allow_public_license": True,
            "default_license_type": "COMMERCIAL",
            "tags": ["zkp", "whitepaper"],
        },
        base_ts + 62,
    )
    chain.submit_transaction(tx6)
    res7 = chain.submit_transaction(tx7)
    chain.mine_block(bob["address"])

    copycat_ip_id = res7["event"]["ip_id"]

    # --- Block 4: Alice Files Prior-Art Plagiarism Dispute Against Copycat ---
    tx8 = _build_signed_tx(
        chain,
        alice,
        "FILE_DISPUTE",
        {
            "accused_ip_id": copycat_ip_id,
            "prior_art_ip_id": patent_ip_id,
            "claim_type": "PRIOR_ART",
            "evidence_hash": sha256_hex(patent_doc),
            "description": (
                "Accused filing reproduces Alice's Block #1 patent abstract nearly verbatim "
                "(SimHash match >95%) after prior-art commitment was already mined."
            ),
        },
        base_ts + 90,
    )
    res8 = chain.submit_transaction(tx8)
    chain.mine_block(arb["address"])

    return {
        "seeded": True,
        "height": chain.height,
        "ip_ids": [patent_ip_id, software_ip_id, trademark_ip_id, copycat_ip_id],
        "open_dispute_id": res8["event"]["dispute_id"],
    }
