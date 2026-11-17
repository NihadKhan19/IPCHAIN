#!/usr/bin/env python3
"""Run an IPChain Topic-12 Intellectual Property Protection blockchain node & Web UI."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from ipchain.blockchain import Blockchain
from ipchain.demo import default_genesis_config, get_demo_personas, seed_demo_scenario
from ipchain.server import create_server


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="IPChain Node — Decentralized Intellectual Property Protection"
    )
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    default_port = int(os.environ.get("PORT", "8080"))
    parser.add_argument("--port", type=int, default=default_port, help=f"HTTP port (default: {default_port})")
    parser.add_argument(
        "--data-dir",
        default="",
        help="Directory for persistent ledger.json (default: ./data/node_<port>)",
    )
    parser.add_argument(
        "--difficulty",
        type=int,
        default=2,
        help="Proof-of-Work leading hex zeros 1..6 (default: 2)",
    )
    parser.add_argument(
        "--no-seed",
        action="store_true",
        help="Do not auto-seed the Topic 12 demo IP scenario on a fresh chain",
    )
    parser.add_argument(
        "--no-faucet",
        action="store_true",
        help="Disable the /api/faucet endpoint",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    base_dir = Path(__file__).resolve().parent
    data_dir = (
        Path(args.data_dir)
        if args.data_dir
        else base_dir / "data" / f"node_{args.port}"
    )

    arbitrator, genesis_balances = default_genesis_config()
    chain = Blockchain(
        arbitrator=arbitrator,
        genesis_balances=genesis_balances,
        difficulty=args.difficulty,
        data_dir=data_dir,
    )

    if not args.no_seed and chain.height == 0:
        seed_info = seed_demo_scenario(chain)
        if seed_info.get("seeded"):
            print(f"[seed] Seeded Topic 12 IP scenario ({len(seed_info['ip_ids'])} IP assets across {chain.height} blocks)")

    server = create_server(
        chain=chain,
        host=args.host,
        port=args.port,
        web_dir=base_dir / "web",
        enable_faucet=not args.no_faucet,
    )

    personas = get_demo_personas()
    print("=" * 68)
    print("  IPChain — Topic 12: Intellectual Property Protection Blockchain")
    print("=" * 68)
    print(f"  Web UI & API   : http://{args.host}:{args.port}")
    print(f"  Data Directory : {data_dir}")
    print(f"  Chain Height   : {chain.height} blocks | Difficulty: {chain.difficulty}")
    print(f"  Registered IPs : {len(chain.state.assets)}")
    print(f"  Arbitrator     : {personas['arbitrator']['address']}")
    print("  Press Ctrl+C to stop the node cleanly.")
    print("=" * 68)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down IPChain node...")
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
