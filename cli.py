#!/usr/bin/env python3
"""Command-line client for interacting with a running IPChain node."""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from ipchain.crypto import (
    ZERO_SIMHASH,
    compute_simhash,
    generate_keypair,
    private_key_to_public_key,
    public_key_to_address,
    sha256_hex,
    verify_merkle_proof,
)
from ipchain.demo import get_demo_personas
from ipchain.models import Transaction


def _http_json(url: str, method: str = "GET", body: dict[str, Any] | None = None) -> Any:
    data = None if body is None else json.dumps(body).encode("utf-8")
    headers = {"Content-Type": "application/json"} if data is not None else {}
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode("utf-8", errors="replace")
        print(f"HTTP {exc.code}: {err_body}", file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as exc:
        print(f"Connection error: {exc.reason}", file=sys.stderr)
        sys.exit(1)


def _resolve_privkey(key_or_persona: str) -> tuple[str, str]:
    personas = get_demo_personas()
    if key_or_persona in personas:
        p = personas[key_or_persona]
        return p["private_key"], p["address"]
    pub = private_key_to_public_key(key_or_persona)
    return key_or_persona, public_key_to_address(pub)


def _sign_and_submit(
    node: str,
    key_or_persona: str,
    tx_type: str,
    payload: dict[str, Any],
    fee: int = 1,
) -> Any:
    privkey, addr = _resolve_privkey(key_or_persona)
    acct = _http_json(f"{node}/api/accounts/{addr}")
    tx = Transaction(
        tx_type=tx_type,
        sender=addr,
        nonce=acct["pending_nonce"],
        fee=fee,
        timestamp=int(time.time()),
        payload=payload,
    ).sign(privkey)
    return _http_json(f"{node}/api/transactions", method="POST", body=tx.to_dict())


def _hash_input(file_path: str | None, text: str | None) -> tuple[str, str]:
    if file_path:
        raw = Path(file_path).read_bytes()
        content_hash = sha256_hex(raw)
        try:
            decoded = raw.decode("utf-8")
            simhash = compute_simhash(decoded)
        except UnicodeDecodeError:
            simhash = ZERO_SIMHASH
        return content_hash, simhash
    if text is not None:
        return sha256_hex(text), compute_simhash(text)
    raise ValueError("Provide either --file or --text")


def main() -> None:
    parser = argparse.ArgumentParser(description="IPChain CLI")
    parser.add_argument(
        "--node", default="http://127.0.0.1:8080", help="Node base URL"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("status", help="Show node status")
    sub.add_parser("keygen", help="Generate a new secp256k1 wallet keypair")
    sub.add_parser("personas", help="Show demo persona addresses")
    sub.add_parser("audit", help="Run full chain integrity audit")
    sub.add_parser("list-ips", help="List registered IP assets")

    p_faucet = sub.add_parser("faucet", help="Claim test IPC tokens")
    p_faucet.add_argument("--address", required=True)
    p_faucet.add_argument("--amount", type=int, default=250)

    p_reg = sub.add_parser("register", help="Register a file or text as IP")
    p_reg.add_argument("--key", required=True, help="Private key hex or demo persona (alice/bob/carol)")
    p_reg.add_argument("--title", required=True)
    p_reg.add_argument("--type", dest="ip_type", default="COPYRIGHT")
    p_reg.add_argument("--file", default="")
    p_reg.add_argument("--text", default=None)
    p_reg.add_argument("--description", default="")
    p_reg.add_argument("--jurisdiction", default="GLOBAL")
    p_reg.add_argument("--royalty-bps", type=int, default=500)
    p_reg.add_argument("--license-price", type=int, default=50)
    p_reg.add_argument("--public-license", action="store_true")

    p_transfer = sub.add_parser("transfer", help="Transfer IP ownership")
    p_transfer.add_argument("--key", required=True)
    p_transfer.add_argument("--ip-id", required=True)
    p_transfer.add_argument("--to", required=True)
    p_transfer.add_argument("--note", default="")

    p_mine = sub.add_parser("mine", help="Mine a block")
    p_mine.add_argument("--miner", default="arbitrator", help="Address or persona")

    p_verify = sub.add_parser("verify", help="Verify file, text, hash, or IP ID")
    p_verify.add_argument("--file", default="")
    p_verify.add_argument("--text", default="")
    p_verify.add_argument("--hash", dest="content_hash", default="")
    p_verify.add_argument("--ip-id", default="")

    p_proof = sub.add_parser("proof", help="Fetch and verify Merkle proof for tx_id")
    p_proof.add_argument("tx_id")

    args = parser.parse_args()
    node = args.node.rstrip("/")

    if args.cmd == "status":
        out = _http_json(f"{node}/api/status")
    elif args.cmd == "keygen":
        out = generate_keypair()
    elif args.cmd == "personas":
        out = _http_json(f"{node}/api/demo/personas")
    elif args.cmd == "audit":
        out = _http_json(f"{node}/api/audit")
    elif args.cmd == "list-ips":
        out = _http_json(f"{node}/api/ips")
    elif args.cmd == "faucet":
        out = _http_json(
            f"{node}/api/faucet",
            method="POST",
            body={"address": args.address, "amount": args.amount, "auto_mine": True},
        )
    elif args.cmd == "register":
        content_hash, simhash = _hash_input(args.file or None, args.text)
        desc = args.description or (args.text or f"File hash registration: {args.file}")
        out = _sign_and_submit(
            node,
            args.key,
            "REGISTER_IP",
            {
                "title": args.title,
                "ip_type": args.ip_type.upper(),
                "description": desc[:2000],
                "content_hash": content_hash,
                "simhash": simhash,
                "jurisdiction": args.jurisdiction,
                "royalty_bps": args.royalty_bps,
                "license_price": args.license_price,
                "allow_public_license": bool(args.public_license),
                "default_license_type": "COMMERCIAL",
                "tags": [],
            },
        )
    elif args.cmd == "transfer":
        _, to_addr = (
            (None, args.to)
            if args.to.startswith("0x")
            else _resolve_privkey(args.to)
        )
        out = _sign_and_submit(
            node,
            args.key,
            "TRANSFER_IP",
            {"ip_id": args.ip_id, "to_address": to_addr, "note": args.note},
        )
    elif args.cmd == "mine":
        miner_addr = (
            args.miner
            if args.miner.startswith("0x")
            else _resolve_privkey(args.miner)[1]
        )
        out = _http_json(
            f"{node}/api/mine", method="POST", body={"miner_address": miner_addr}
        )
    elif args.cmd == "verify":
        ch = args.content_hash
        text = args.text
        if args.file:
            ch, _ = _hash_input(args.file, None)
            try:
                text = Path(args.file).read_text(encoding="utf-8")
            except UnicodeDecodeError:
                text = ""
        out = _http_json(
            f"{node}/api/verify",
            method="POST",
            body={"content_hash": ch, "text": text, "ip_id": args.ip_id},
        )
    elif args.cmd == "proof":
        bundle = _http_json(f"{node}/api/tx/{args.tx_id}/proof")
        client_ok = verify_merkle_proof(
            bundle["tx_id"], bundle["proof"], bundle["merkle_root"]
        )
        bundle["client_verified"] = client_ok
        out = bundle
    else:
        raise AssertionError("Unhandled command")

    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
