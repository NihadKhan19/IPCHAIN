# IPChain — Topic 12: Intellectual Property Protection Blockchain

A full-stack, zero-dependency working blockchain implementation for **Intellectual Property (IP) Protection**, built with Python 3 standard library and a pure-JavaScript Web3 client UI.

---

## Core Capabilities

- **Immutable Proof-of-Creation & Timestamping (`REGISTER_IP`)**
  - Files and works are hashed locally via **SHA-256** (`content_hash`) so confidential IP never needs to leave the creator's device.
  - Consensus state rejects duplicate `content_hash` registrations (`StateTransitionError`) while recording deterministic `ip_id`, block height, timestamp, jurisdiction, and creator address.
- **Real Client-Side & Node-Verified Cryptography (`secp256k1` + RFC 6979)**
  - Pure-Python (`ipchain/crypto.py`) and matching pure-JS (`web/app.js`) **secp256k1 ECDSA** wallets, deterministic RFC 6979 nonces, low-$S$ canonicalization, and `0x...` address derivation.
  - Browser signs transactions client-side; private keys never traverse `POST /api/transactions`.
- **Perceptual Plagiarism & Prior-Art Detection (`SimHash`)**
  - Computes a 64-bit **SimHash** fingerprint over text/source shingles to flag near-duplicate filings and potential plagiarism during pre-checks and verification.
- **Chain of Custody, Licensing & Automated Creator Royalties**
  - `TRANSFER_IP`: Transfers ownership while preserving `original_creator` and full provenance timeline.
  - `GRANT_LICENSE` / `REVOKE_LICENSE`: Supports `EXCLUSIVE`, `NON_EXCLUSIVE`, `COMMERCIAL`, `ACADEMIC`, and `OPEN_SOURCE` licenses with block-duration expiry and exclusivity enforcement.
  - `PURCHASE_LICENSE`: Self-service license checkout that deterministically splits payment between `original_creator` (`royalty_bps`) and the current `owner`.
- **On-Chain Dispute Filing & Arbitrator Governance**
  - `FILE_DISPUTE`: Freezes transfers and new licenses on disputed IP (`DISPUTED`) while citing prior-art IP and evidence hashes.
  - `RESOLVE_DISPUTE`: Signed exclusively by the genesis-designated **Arbitrator Authority** (`DISMISSED`, `UPHELD_REVOKE`, or `UPHELD_TRANSFER`).
- **Merkle Inclusion Proofs, State Roots, PoW & P2P Sync**
  - Every block header commits to `previous_hash`, `merkle_root` (domain-separated SHA-256), `state_root`, `nonce`, and `difficulty` Proof-of-Work.
  - Built-in **Chain Integrity Auditor**, **Non-Destructive Tamper Attack Simulator**, **JSON IP Certificates**, and **multi-node HTTP longest-valid-chain sync**.

---

## Project Structure

```text
ip-blockchain/
├── run_node.py             # Node & Web UI entrypoint (ThreadingHTTPServer)
├── cli.py                  # Command-line client (wallets, register, transfer, verify, proof, audit)
├── README.md
├── ipchain/
│   ├── __init__.py
│   ├── crypto.py           # secp256k1 ECDSA (RFC 6979), SHA-256, MerkleTree, SimHash
│   ├── models.py           # Transaction, Block, AccountState, IPAsset, LicenseRecord, DisputeRecord
│   ├── state.py            # Deterministic IP state machine & automated royalty split logic
│   ├── blockchain.py       # PoW mining, mempool projection, full chain replay audit, P2P sync
│   ├── storage.py          # Atomic JSON ledger persistence
│   ├── demo.py             # Deterministic demo personas & 4-block Topic 12 seed scenario
│   └── server.py           # REST API & static Web UI server
├── web/
│   ├── index.html          # Interactive IP Protection Studio & Explorer
│   ├── styles.css
│   └── app.js              # Browser SHA-256, SimHash, secp256k1 wallet signing & Merkle verifier
└── tests/
    ├── test_crypto.py      # Curve math, RFC 6979, Merkle proofs, SimHash & JS-vs-Python parity
    ├── test_state_and_chain.py
    └── test_api_and_sync.py
```

---

## Quick Start

### 1. Run the Blockchain Node & Web UI

```bash
cd /Users/nihadkhan/.gemini/antigravity/scratch/ip-blockchain
python3 run_node.py --port 8080
```

Open **http://127.0.0.1:8080** in your browser.

On a fresh database, `run_node.py` automatically seeds a 4-block Topic 12 walkthrough (Patent, Software, Trademark, Ownership Transfer, Royalty Split License, Copycat Filing, and an Open Prior-Art Dispute ready for Arbitrator review). Pass `--no-seed` to start from Genesis Block `#0`.

### 2. Multi-Node P2P Consensus Demo

Terminal 1 (seeded primary node):
```bash
python3 run_node.py --port 8080
```

Terminal 2 (fresh peer node starting at Genesis `#0`):
```bash
python3 run_node.py --port 8081 --no-seed
```

In the Web UI on `http://127.0.0.1:8081` → **Audit, Tamper Lab & P2P** tab, register `http://127.0.0.1:8080` and click **Sync Chain**. Node 8081 verifies every block's PoW, signatures, Merkle root, and state root before adopting the longer chain.

### 3. CLI Usage

```bash
python3 cli.py status
python3 cli.py keygen
python3 cli.py list-ips
python3 cli.py register --key alice --title "My Invention" --type PATENT --text "Novel circuit design..." --public-license
python3 cli.py mine --miner alice
python3 cli.py verify --text "Novel circuit design..."
python3 cli.py audit
```

---

## REST API Endpoints

| Method | Path | Description |
| :--- | :--- | :--- |
| `GET` | `/api/status` | Node height, difficulty, mempool size, IP/license/dispute counts |
| `GET` | `/api/demo/personas` | Deterministic demo accounts (local evaluation only) |
| `GET` | `/api/chain` | Full serialized blockchain blocks |
| `GET` | `/api/blocks/<index>` | Inspect single block by height |
| `GET` | `/api/mempool` | List pending signed transactions |
| `GET` | `/api/accounts/<address>` | Committed & pending balance, nonce, owned IPs, licenses |
| `GET` | `/api/ips` | List/filter IP assets (`?type=`, `?status=`, `?owner=`, `?q=`) |
| `GET` | `/api/ips/<ip_id>` | Full IP certificate, provenance, licenses, disputes & Merkle proof |
| `GET` | `/api/licenses` | List licenses (`?ip_id=`, `?licensee=`, `?status=`) |
| `GET` | `/api/disputes` | List disputes (`?status=`, `?accused_ip_id=`) |
| `GET` | `/api/tx/<tx_id>/proof` | Cryptographic Merkle inclusion proof for transaction |
| `POST` | `/api/transactions` | Submit a client-signed transaction to the mempool |
| `POST` | `/api/mine` | Mine pending mempool transactions into a new PoW block |
| `POST` | `/api/verify` | Verify exact content hash, IP ID, Merkle proof, and SimHash prior art |
| `POST` | `/api/faucet` | Credit test `IPC` tokens from Genesis Treasury |
| `GET` | `/api/audit` | Replay & verify entire chain from Genesis `#0` |
| `POST` | `/api/audit/simulate-tamper` | Non-destructive in-memory tamper detection test |
| `POST` | `/api/peers/register` | Register peer node URL |
| `POST` | `/api/peers/sync` | Fetch and adopt longest cryptographically valid peer chain |

---

## Running Automated Tests

```bash
python3 -m unittest discover -s tests -v
```
