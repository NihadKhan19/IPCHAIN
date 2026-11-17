"""Atomic JSON file persistence for IPChain node state."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from ipchain.models import Block, Transaction


class ChainStorage:
    """Persists chain blocks, mempool, and peer list atomically to disk."""

    def __init__(self, data_dir: str | Path) -> None:
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.ledger_file = self.data_dir / "ledger.json"

    def exists(self) -> bool:
        """Return True if a persisted ledger file already exists."""
        return self.ledger_file.is_file()

    def save(
        self,
        blocks: list[Block],
        mempool: list[Transaction],
        peers: list[str],
        difficulty: int,
    ) -> None:
        """Atomically write chain, mempool, and peer metadata to disk."""
        payload = {
            "version": 1,
            "difficulty": difficulty,
            "peers": sorted(set(peers)),
            "chain": [b.to_dict() for b in blocks],
            "mempool": [tx.to_dict() for tx in mempool],
        }
        tmp_path = self.data_dir / "ledger.json.tmp"
        with tmp_path.open("w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, self.ledger_file)

    def load(self) -> dict[str, Any]:
        """Load persisted ledger JSON from disk."""
        with self.ledger_file.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        blocks = [Block.from_dict(b) for b in data.get("chain", [])]
        mempool = [Transaction.from_dict(tx) for tx in data.get("mempool", [])]
        peers = [str(p) for p in data.get("peers", [])]
        difficulty = int(data.get("difficulty", 2))
        return {
            "blocks": blocks,
            "mempool": mempool,
            "peers": peers,
            "difficulty": difficulty,
        }
