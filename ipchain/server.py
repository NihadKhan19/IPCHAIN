"""Thread-safe REST API and static Web UI server for IPChain."""

from __future__ import annotations

import json
import mimetypes
from functools import partial
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from ipchain.blockchain import Blockchain, BlockchainError
from ipchain.crypto import is_valid_address
from ipchain.demo import get_demo_personas, seed_demo_scenario
from ipchain.models import Transaction
from ipchain.state import StateTransitionError

MAX_BODY_BYTES = 1_048_576  # 1 MiB
DEFAULT_WEB_DIR = Path(__file__).resolve().parent.parent / "web"

STATIC_ALLOWLIST = {
    "/": "index.html",
    "/index.html": "index.html",
    "/styles.css": "styles.css",
    "/app.js": "app.js",
}


class IPChainRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler backed by a shared Blockchain instance."""

    def __init__(
        self,
        *args: Any,
        chain: Blockchain,
        web_dir: Path,
        enable_faucet: bool = True,
        **kwargs: Any,
    ) -> None:
        self.chain = chain
        self.web_dir = web_dir
        self.enable_faucet = enable_faucet
        super().__init__(*args, **kwargs)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        # Suppress noisy stdout access logs during automated tests unless overridden
        return

    def _send_json(self, status: int, payload: Any) -> None:
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def _send_static(self, filename: str) -> None:
        target = self.web_dir / filename
        if not target.is_file():
            self._send_json(HTTPStatus.NOT_FOUND, {"error": f"Asset {filename} missing"})
            return
        data = target.read_bytes()
        ctype, _ = mimetypes.guess_type(str(target))
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", f"{ctype or 'application/octet-stream'}; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _read_json_body(self) -> dict[str, Any]:
        raw_len = self.headers.get("Content-Length")
        if raw_len is None:
            return {}
        try:
            length = int(raw_len)
        except ValueError as exc:
            raise ValueError("Invalid Content-Length header") from exc
        if length < 0 or length > MAX_BODY_BYTES:
            raise ValueError("Request body exceeds maximum allowed size")
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("Request body must be a JSON object")
        return data

    # ------------------------------------------------------------------
    # GET routes
    # ------------------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        if path in STATIC_ALLOWLIST:
            self._send_static(STATIC_ALLOWLIST[path])
            return

        try:
            if path == "/api/status":
                self._handle_status()
            elif path == "/api/demo/personas":
                self._handle_demo_personas()
            elif path == "/api/chain":
                self._handle_get_chain()
            elif path.startswith("/api/blocks/"):
                self._handle_get_block(path.removeprefix("/api/blocks/"))
            elif path == "/api/mempool":
                self._handle_get_mempool()
            elif path.startswith("/api/accounts/"):
                self._handle_get_account(path.removeprefix("/api/accounts/"))
            elif path == "/api/ips":
                self._handle_list_ips(qs)
            elif path.startswith("/api/ips/"):
                self._handle_get_ip(path.removeprefix("/api/ips/"))
            elif path == "/api/licenses":
                self._handle_list_licenses(qs)
            elif path == "/api/disputes":
                self._handle_list_disputes(qs)
            elif path.startswith("/api/tx/") and path.endswith("/proof"):
                tx_id = path[len("/api/tx/") : -len("/proof")]
                self._handle_tx_proof(tx_id)
            elif path == "/api/audit":
                self._send_json(HTTPStatus.OK, self.chain.verify_integrity())
            elif path == "/api/peers":
                with self.chain._lock:
                    self._send_json(HTTPStatus.OK, {"peers": sorted(self.chain.peers)})
            else:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "Endpoint not found"})
        except (BlockchainError, StateTransitionError, ValueError) as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
        except Exception as exc:  # pragma: no cover - defensive fallback
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(exc)})

    # ------------------------------------------------------------------
    # POST routes
    # ------------------------------------------------------------------

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path

        try:
            body = self._read_json_body()
            if path == "/api/transactions":
                self._handle_submit_tx(body)
            elif path == "/api/mine":
                self._handle_mine(body)
            elif path == "/api/verify":
                self._handle_verify(body)
            elif path == "/api/faucet":
                self._handle_faucet(body)
            elif path == "/api/demo/seed":
                result = seed_demo_scenario(self.chain)
                self._send_json(HTTPStatus.OK, result)
            elif path == "/api/audit/simulate-tamper":
                self._handle_simulate_tamper(body)
            elif path == "/api/peers/register":
                peer_url = str(body.get("peer_url", ""))
                peers = self.chain.register_peer(peer_url)
                self._send_json(HTTPStatus.OK, {"peers": peers})
            elif path == "/api/peers/sync":
                result = self.chain.resolve_conflicts()
                self._send_json(HTTPStatus.OK, result)
            else:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "Endpoint not found"})
        except (BlockchainError, StateTransitionError, ValueError, json.JSONDecodeError) as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
        except Exception as exc:  # pragma: no cover
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(exc)})

    # ------------------------------------------------------------------
    # Handlers
    # ------------------------------------------------------------------

    def _handle_status(self) -> None:
        with self.chain._lock:
            assets = self.chain.state.assets.values()
            licenses = self.chain.state.licenses.values()
            disputes = self.chain.state.disputes.values()
            latest = self.chain.chain[-1]
            self._send_json(
                HTTPStatus.OK,
                {
                    "network": "IPChain Topic-12 Mainnet",
                    "height": len(self.chain.chain) - 1,
                    "blocks": len(self.chain.chain),
                    "difficulty": self.chain.difficulty,
                    "latest_hash": latest.hash,
                    "latest_state_root": latest.state_root,
                    "mempool_size": len(self.chain.mempool),
                    "arbitrator": self.chain.arbitrator,
                    "total_ips": len(self.chain.state.assets),
                    "active_ips": sum(1 for a in assets if a.status == "ACTIVE"),
                    "disputed_ips": sum(1 for a in assets if a.status == "DISPUTED"),
                    "revoked_ips": sum(1 for a in assets if a.status == "REVOKED"),
                    "active_licenses": sum(
                        1
                        for lic in licenses
                        if lic.is_effective_at(len(self.chain.chain) - 1)
                    ),
                    "open_disputes": sum(1 for d in disputes if d.status == "OPEN"),
                    "peers": sorted(self.chain.peers),
                },
            )

    def _handle_demo_personas(self) -> None:
        personas = get_demo_personas()
        with self.chain._lock:
            enriched = []
            for p in personas.values():
                acct = self.chain.get_projected_account(p["address"])
                enriched.append({**p, **acct})
        self._send_json(
            HTTPStatus.OK,
            {
                "demo_notice": "Deterministic test accounts for local classroom/capstone evaluation only.",
                "personas": enriched,
            },
        )

    def _handle_get_chain(self) -> None:
        with self.chain._lock:
            self._send_json(
                HTTPStatus.OK,
                {
                    "height": len(self.chain.chain) - 1,
                    "difficulty": self.chain.difficulty,
                    "chain": [b.to_dict() for b in self.chain.chain],
                },
            )

    def _handle_get_block(self, raw_idx: str) -> None:
        try:
            idx = int(raw_idx)
        except ValueError as exc:
            raise ValueError("Block index must be an integer") from exc
        with self.chain._lock:
            if idx < 0 or idx >= len(self.chain.chain):
                self._send_json(HTTPStatus.NOT_FOUND, {"error": f"Block #{idx} not found"})
                return
            self._send_json(HTTPStatus.OK, self.chain.chain[idx].to_dict())

    def _handle_get_mempool(self) -> None:
        with self.chain._lock:
            self._send_json(
                HTTPStatus.OK,
                {
                    "count": len(self.chain.mempool),
                    "transactions": [tx.to_dict() for tx in self.chain.mempool],
                },
            )

    def _handle_get_account(self, address: str) -> None:
        norm = address.lower().strip()
        if not is_valid_address(norm):
            raise ValueError("Invalid 0x account address")
        with self.chain._lock:
            acct = self.chain.get_projected_account(norm)
            owned_ips = [
                a.ip_id for a in self.chain.state.assets.values() if a.owner == norm
            ]
            created_ips = [
                a.ip_id
                for a in self.chain.state.assets.values()
                if a.original_creator == norm
            ]
            held_licenses = [
                lic.license_id
                for lic in self.chain.state.licenses.values()
                if lic.licensee == norm
            ]
            self._send_json(
                HTTPStatus.OK,
                {
                    **acct,
                    "owned_ips": owned_ips,
                    "created_ips": created_ips,
                    "held_licenses": held_licenses,
                },
            )

    def _handle_list_ips(self, qs: dict[str, list[str]]) -> None:
        ip_type = qs.get("type", [""])[0].upper().strip()
        status = qs.get("status", [""])[0].upper().strip()
        owner = qs.get("owner", [""])[0].lower().strip()
        query = qs.get("q", [""])[0].lower().strip()

        with self.chain._lock:
            items = []
            for asset in self.chain.state.assets.values():
                if ip_type and asset.ip_type != ip_type:
                    continue
                if status and asset.status != status:
                    continue
                if owner and asset.owner != owner:
                    continue
                if query:
                    haystack = " ".join(
                        [
                            asset.ip_id,
                            asset.title,
                            asset.description,
                            asset.content_hash,
                            asset.owner,
                            asset.original_creator,
                            " ".join(asset.tags),
                        ]
                    ).lower()
                    if query not in haystack:
                        continue
                d = asset.to_dict()
                d["license_count"] = sum(
                    1
                    for lic in self.chain.state.licenses.values()
                    if lic.ip_id == asset.ip_id and lic.status == "ACTIVE"
                )
                d["open_dispute_count"] = len(
                    self.chain.state.open_disputes_for_ip(asset.ip_id)
                )
                items.append(d)
            items.sort(key=lambda x: (-x["registered_block"], x["ip_id"]))
            self._send_json(HTTPStatus.OK, {"count": len(items), "assets": items})

    def _handle_get_ip(self, ip_id: str) -> None:
        with self.chain._lock:
            asset = self.chain.state.assets.get(ip_id)
            if asset is None:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": f"IP {ip_id} not found"})
                return
            bundle = self.chain.verify_content(ip_id=ip_id)
            self._send_json(HTTPStatus.OK, bundle["certificate"])

    def _handle_list_licenses(self, qs: dict[str, list[str]]) -> None:
        ip_id = qs.get("ip_id", [""])[0].strip()
        licensee = qs.get("licensee", [""])[0].lower().strip()
        status = qs.get("status", [""])[0].upper().strip()

        with self.chain._lock:
            items = []
            for lic in self.chain.state.licenses.values():
                if ip_id and lic.ip_id != ip_id:
                    continue
                if licensee and lic.licensee != licensee:
                    continue
                if status and lic.status != status:
                    continue
                asset = self.chain.state.assets.get(lic.ip_id)
                row = lic.to_dict()
                row["ip_title"] = asset.title if asset else ""
                items.append(row)
            items.sort(key=lambda x: (-x["granted_block"], x["license_id"]))
            self._send_json(HTTPStatus.OK, {"count": len(items), "licenses": items})

    def _handle_list_disputes(self, qs: dict[str, list[str]]) -> None:
        status = qs.get("status", [""])[0].upper().strip()
        accused = qs.get("accused_ip_id", [""])[0].strip()

        with self.chain._lock:
            items = []
            for disp in self.chain.state.disputes.values():
                if status and disp.status != status:
                    continue
                if accused and disp.accused_ip_id != accused:
                    continue
                asset = self.chain.state.assets.get(disp.accused_ip_id)
                row = disp.to_dict()
                row["accused_title"] = asset.title if asset else ""
                row["accused_owner"] = asset.owner if asset else ""
                items.append(row)
            items.sort(key=lambda x: (-x["filed_block"], x["dispute_id"]))
            self._send_json(HTTPStatus.OK, {"count": len(items), "disputes": items})

    def _handle_tx_proof(self, tx_id: str) -> None:
        proof = self.chain.get_tx_proof(tx_id)
        self._send_json(HTTPStatus.OK, proof)

    def _handle_submit_tx(self, body: dict[str, Any]) -> None:
        tx = Transaction.from_dict(body)
        result = self.chain.submit_transaction(tx)
        self._send_json(HTTPStatus.CREATED, result)

    def _handle_mine(self, body: dict[str, Any]) -> None:
        miner = str(body.get("miner_address", "")).strip() or self.chain.arbitrator
        result = self.chain.mine_block(miner)
        self._send_json(HTTPStatus.CREATED, result)

    def _handle_verify(self, body: dict[str, Any]) -> None:
        result = self.chain.verify_content(
            content_hash=str(body.get("content_hash", "")),
            text=str(body.get("text", "")),
            ip_id=str(body.get("ip_id", "")),
        )
        self._send_json(HTTPStatus.OK, result)

    def _handle_faucet(self, body: dict[str, Any]) -> None:
        if not self.enable_faucet:
            raise ValueError("Faucet is disabled on this node")
        target = str(body.get("address", "")).lower().strip()
        if not is_valid_address(target):
            raise ValueError("Invalid target 0x address")
        amount = body.get("amount", 250)
        if not isinstance(amount, int) or isinstance(amount, bool) or not (1 <= amount <= 1000):
            raise ValueError("Faucet amount must be integer 1..1000")
        auto_mine = bool(body.get("auto_mine", True))

        treasury = get_demo_personas()["treasury"]
        if target == treasury["address"]:
            raise ValueError("Cannot send faucet funds to treasury itself")

        import time as _time

        acct = self.chain.get_projected_account(treasury["address"])
        tx = Transaction(
            tx_type="TRANSFER_TOKENS",
            sender=treasury["address"],
            nonce=acct["pending_nonce"],
            fee=1,
            timestamp=int(_time.time()),
            payload={"to_address": target, "amount": amount},
        ).sign(treasury["private_key"])
        res = self.chain.submit_transaction(tx)
        mined = None
        if auto_mine:
            mined = self.chain.mine_block(treasury["address"])
        self._send_json(
            HTTPStatus.CREATED,
            {"faucet_tx": res, "mined_block": mined},
        )

    def _handle_simulate_tamper(self, body: dict[str, Any]) -> None:
        block_index = body.get("block_index", 1 if self.chain.height >= 1 else 0)
        if not isinstance(block_index, int) or isinstance(block_index, bool):
            raise ValueError("block_index must be an integer")
        target = str(body.get("target", "tx_title"))
        replacement = str(body.get("replacement", "Tampered IP Title"))
        report = self.chain.simulate_tamper(block_index, target, replacement)
        self._send_json(HTTPStatus.OK, report)


def create_server(
    chain: Blockchain,
    host: str = "127.0.0.1",
    port: int = 8080,
    web_dir: Path | None = None,
    enable_faucet: bool = True,
) -> ThreadingHTTPServer:
    """Create configured ThreadingHTTPServer for IPChain."""
    handler = partial(
        IPChainRequestHandler,
        chain=chain,
        web_dir=web_dir or DEFAULT_WEB_DIR,
        enable_faucet=enable_faucet,
    )
    server = ThreadingHTTPServer((host, port), handler)
    server.daemon_threads = True
    return server
