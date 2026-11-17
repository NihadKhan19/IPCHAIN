/* IPChain Client — Zero-dependency browser secp256k1, SHA-256, SimHash, Merkle verifier & UI */
(() => {
  "use strict";

  // =========================================================================
  // 1. Pure-JS UTF-8, SHA-256, HMAC-SHA256, Canonical JSON, SimHash, Merkle
  // =========================================================================

  const SHA256_K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ]);

  function utf8Encode(str) {
    const out = [];
    for (let i = 0; i < str.length; i++) {
      let cp = str.codePointAt(i);
      if (cp > 0xffff) i++;
      if (cp < 0x80) {
        out.push(cp);
      } else if (cp < 0x800) {
        out.push(0xc0 | (cp >> 6), 0x80 | (cp & 0x3f));
      } else if (cp < 0x10000) {
        out.push(0xe0 | (cp >> 12), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
      } else {
        out.push(
          0xf0 | (cp >> 18),
          0x80 | ((cp >> 12) & 0x3f),
          0x80 | ((cp >> 6) & 0x3f),
          0x80 | (cp & 0x3f)
        );
      }
    }
    return new Uint8Array(out);
  }

  function rotr(x, n) {
    return (x >>> n) | (x << (32 - n));
  }

  function sha256Bytes(input) {
    const msg = typeof input === "string" ? utf8Encode(input) : input;
    const bitLen = BigInt(msg.length) * 8n;
    const padLen = ((56 - ((msg.length + 1) % 64)) + 64) % 64;
    const padded = new Uint8Array(msg.length + 1 + padLen + 8);
    padded.set(msg, 0);
    padded[msg.length] = 0x80;
    const view = new DataView(padded.buffer);
    view.setBigUint64(padded.length - 8, bitLen, false);

    let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
    let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
    const w = new Uint32Array(64);

    for (let offset = 0; offset < padded.length; offset += 64) {
      for (let i = 0; i < 16; i++) {
        w[i] = view.getUint32(offset + i * 4, false);
      }
      for (let i = 16; i < 64; i++) {
        const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
        const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
      }
      let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
      for (let i = 0; i < 64; i++) {
        const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const ch = (e & f) ^ ((~e) & g);
        const temp1 = (h + S1 + ch + SHA256_K[i] + w[i]) >>> 0;
        const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const temp2 = (S0 + maj) >>> 0;
        h = g; g = f; f = e; e = (d + temp1) >>> 0;
        d = c; c = b; b = a; a = (temp1 + temp2) >>> 0;
      }
      h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
      h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + h) >>> 0;
    }

    const out = new Uint8Array(32);
    const ov = new DataView(out.buffer);
    [h0, h1, h2, h3, h4, h5, h6, h7].forEach((val, idx) => ov.setUint32(idx * 4, val, false));
    return out;
  }

  function bytesToHex(bytes) {
    let hex = "";
    for (let i = 0; i < bytes.length; i++) {
      hex += bytes[i].toString(16).padStart(2, "0");
    }
    return hex;
  }

  function hexToBytes(hex) {
    const clean = hex.toLowerCase();
    const out = new Uint8Array(clean.length / 2);
    for (let i = 0; i < out.length; i++) {
      out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
  }

  function sha256Hex(input) {
    return bytesToHex(sha256Bytes(input));
  }

  function hmacSha256(keyBytes, msgBytes) {
    let key = keyBytes;
    if (key.length > 64) key = sha256Bytes(key);
    const kPad = new Uint8Array(64);
    kPad.set(key, 0);
    const oKey = new Uint8Array(64);
    const iKey = new Uint8Array(64);
    for (let i = 0; i < 64; i++) {
      oKey[i] = kPad[i] ^ 0x5c;
      iKey[i] = kPad[i] ^ 0x36;
    }
    const inner = new Uint8Array(64 + msgBytes.length);
    inner.set(iKey, 0);
    inner.set(msgBytes, 64);
    const innerHash = sha256Bytes(inner);
    const outer = new Uint8Array(64 + 32);
    outer.set(oKey, 0);
    outer.set(innerHash, 64);
    return sha256Bytes(outer);
  }

  function concatBytes(...arrays) {
    const total = arrays.reduce((acc, a) => acc + a.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const a of arrays) {
      out.set(a, offset);
      offset += a.length;
    }
    return out;
  }

  function canonicalJson(val) {
    if (val === null || typeof val !== "object") {
      return JSON.stringify(val);
    }
    if (Array.isArray(val)) {
      return "[" + val.map((item) => canonicalJson(item)).join(",") + "]";
    }
    const keys = Object.keys(val).sort();
    return (
      "{" +
      keys.map((k) => JSON.stringify(k) + ":" + canonicalJson(val[k])).join(",") +
      "}"
    );
  }

  function computeSimhashJS(text) {
    let cleaned = text.toLowerCase().replace(/[^a-z0-9\s]/g, " ").replace(/\s+/g, " ").trim();
    if (!cleaned) return "0000000000000000";
    const tokens = cleaned.split(" ");
    const features = [];
    for (const tok of tokens) {
      if (tok) features.push("w:" + tok);
    }
    for (let i = 0; i < tokens.length - 1; i++) {
      features.push("b:" + tokens[i] + "_" + tokens[i + 1]);
    }
    const compact = cleaned.replace(/ /g, "");
    if (compact.length >= 4) {
      for (let i = 0; i < compact.length - 3; i++) {
        features.push("c:" + compact.slice(i, i + 4));
      }
    } else if (compact) {
      features.push("c:" + compact);
    }

    const weights = new Int32Array(64);
    for (const feat of features) {
      const digest = sha256Bytes(feat);
      let h = 0n;
      for (let i = 0; i < 8; i++) {
        h = (h << 8n) | BigInt(digest[i]);
      }
      for (let bit = 0; bit < 64; bit++) {
        if ((h >> BigInt(bit)) & 1n) weights[bit] += 1;
        else weights[bit] -= 1;
      }
    }
    let fp = 0n;
    for (let bit = 0; bit < 64; bit++) {
      if (weights[bit] >= 0) fp |= 1n << BigInt(bit);
    }
    return fp.toString(16).padStart(16, "0");
  }

  function verifyMerkleProofJS(txId, proof, expectedRoot) {
    if (!/^[0-9a-f]{64}$/i.test(txId) || !/^[0-9a-f]{64}$/i.test(expectedRoot)) {
      return false;
    }
    let current = sha256Hex(concatBytes(new Uint8Array([0x00]), hexToBytes(txId)));
    for (const step of proof) {
      if (!step || (step.position !== "left" && step.position !== "right")) return false;
      if (!/^[0-9a-f]{64}$/i.test(step.hash || "")) return false;
      const left = step.position === "left" ? step.hash : current;
      const right = step.position === "left" ? current : step.hash;
      current = sha256Hex(concatBytes(new Uint8Array([0x01]), hexToBytes(left), hexToBytes(right)));
    }
    return current.toLowerCase() === expectedRoot.toLowerCase();
  }

  // =========================================================================
  // 2. Pure-JS secp256k1 BigInt ECDSA (RFC 6979 + Low-S)
  // =========================================================================

  const SECP_P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
  const SECP_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
  const SECP_HALF_N = SECP_N >> 1n;
  const SECP_GX = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
  const SECP_GY = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;

  function mod(a, m) {
    const r = a % m;
    return r >= 0n ? r : r + m;
  }

  function modInv(a, m) {
    let lm = 1n, hm = 0n;
    let low = mod(a, m), high = m;
    while (low > 1n) {
      const ratio = high / low;
      const nm = hm - lm * ratio;
      const next = high - low * ratio;
      hm = lm; high = low;
      lm = nm; low = next;
    }
    return mod(lm, m);
  }

  function jDouble(p) {
    const [x1, y1, z1] = p;
    if (y1 === 0n || z1 === 0n) return [0n, 1n, 0n];
    const ysq = mod(y1 * y1, SECP_P);
    const s = mod(4n * x1 * ysq, SECP_P);
    const m = mod(3n * x1 * x1, SECP_P);
    const nx = mod(m * m - 2n * s, SECP_P);
    const ny = mod(m * (s - nx) - 8n * ysq * ysq, SECP_P);
    const nz = mod(2n * y1 * z1, SECP_P);
    return [nx, ny, nz];
  }

  function jAdd(p1, p2) {
    const [x1, y1, z1] = p1;
    const [x2, y2, z2] = p2;
    if (z1 === 0n) return p2;
    if (z2 === 0n) return p1;
    const z1z1 = mod(z1 * z1, SECP_P);
    const z2z2 = mod(z2 * z2, SECP_P);
    const u1 = mod(x1 * z2z2, SECP_P);
    const u2 = mod(x2 * z1z1, SECP_P);
    const s1 = mod(y1 * z2 * z2z2, SECP_P);
    const s2 = mod(y2 * z1 * z1z1, SECP_P);
    if (u1 === u2) return s1 !== s2 ? [0n, 1n, 0n] : jDouble(p1);
    const h = mod(u2 - u1, SECP_P);
    const r = mod(s2 - s1, SECP_P);
    const h2 = mod(h * h, SECP_P);
    const h3 = mod(h * h2, SECP_P);
    const u1h2 = mod(u1 * h2, SECP_P);
    const nx = mod(r * r - h3 - 2n * u1h2, SECP_P);
    const ny = mod(r * (u1h2 - nx) - s1 * h3, SECP_P);
    const nz = mod(h * z1 * z2, SECP_P);
    return [nx, ny, nz];
  }

  function scalarMulG(scalar) {
    let k = mod(scalar, SECP_N);
    if (k === 0n) return null;
    let acc = [0n, 1n, 0n];
    let addend = [SECP_GX, SECP_GY, 1n];
    while (k > 0n) {
      if (k & 1n) acc = jAdd(acc, addend);
      addend = jDouble(addend);
      k >>= 1n;
    }
    const [x, y, z] = acc;
    if (z === 0n) return null;
    const zi = modInv(z, SECP_P);
    const zi2 = mod(zi * zi, SECP_P);
    const zi3 = mod(zi2 * zi, SECP_P);
    return [mod(x * zi2, SECP_P), mod(y * zi3, SECP_P)];
  }

  function bigIntToBytes32(n) {
    return hexToBytes(n.toString(16).padStart(64, "0"));
  }

  function bytesToBigInt(bytes) {
    return BigInt("0x" + bytesToHex(bytes));
  }

  function privToPubHex(privHex) {
    const d = BigInt("0x" + privHex);
    if (d < 1n || d >= SECP_N) throw new Error("Private key out of range");
    const pt = scalarMulG(d);
    const prefix = pt[1] % 2n === 0n ? "02" : "03";
    return prefix + pt[0].toString(16).padStart(64, "0");
  }

  function pubToAddress(pubHex) {
    const digest = sha256Bytes(hexToBytes(pubHex));
    return "0x" + bytesToHex(digest.slice(12));
  }

  function generateKeypairJS() {
    const buf = new Uint8Array(32);
    while (true) {
      crypto.getRandomValues(buf);
      const d = bytesToBigInt(buf);
      if (d >= 1n && d < SECP_N) {
        const priv = d.toString(16).padStart(64, "0");
        const pub = privToPubHex(priv);
        return { private_key: priv, public_key: pub, address: pubToAddress(pub) };
      }
    }
  }

  function signDigestJS(privHex, digestBytes) {
    const d = BigInt("0x" + privHex);
    const xBytes = bigIntToBytes32(d);
    const z = bytesToBigInt(digestBytes);
    const hMod = bigIntToBytes32(z % SECP_N);

    let v = new Uint8Array(32).fill(0x01);
    let k = new Uint8Array(32).fill(0x00);
    k = hmacSha256(k, concatBytes(v, new Uint8Array([0x00]), xBytes, hMod));
    v = hmacSha256(k, v);
    k = hmacSha256(k, concatBytes(v, new Uint8Array([0x01]), xBytes, hMod));
    v = hmacSha256(k, v);

    while (true) {
      let t = new Uint8Array(0);
      while (t.length < 32) {
        v = hmacSha256(k, v);
        t = concatBytes(t, v);
      }
      const nonce = bytesToBigInt(t.slice(0, 32));
      if (nonce >= 1n && nonce < SECP_N) {
        const pt = scalarMulG(nonce);
        if (pt) {
          const r = pt[0] % SECP_N;
          if (r !== 0n) {
            const kInv = modInv(nonce, SECP_N);
            let s = mod(kInv * (z + r * d), SECP_N);
            if (s !== 0n) {
              if (s > SECP_HALF_N) s = SECP_N - s;
              return r.toString(16).padStart(64, "0") + s.toString(16).padStart(64, "0");
            }
          }
        }
      }
      k = hmacSha256(k, concatBytes(v, new Uint8Array([0x00])));
      v = hmacSha256(k, v);
    }
  }

  function signTransactionJS(unsignedTx, privHex) {
    const pub = privToPubHex(privHex);
    const addr = pubToAddress(pub);
    const signingObj = {
      type: unsignedTx.type,
      sender: addr,
      nonce: unsignedTx.nonce,
      fee: unsignedTx.fee,
      timestamp: unsignedTx.timestamp,
      payload: unsignedTx.payload,
    };
    const digest = sha256Bytes(canonicalJson(signingObj));
    const sig = signDigestJS(privHex, digest);
    const full = { ...signingObj, public_key: pub, signature: sig };
    const txId = sha256Hex(canonicalJson(full));
    return { ...full, tx_id: txId };
  }

  // Expose crypto helpers only in non-DOM test engines (jsc) if needed
  if (typeof window === "undefined") {
    globalThis.IPChainCrypto = {
      sha256Hex,
      canonicalJson,
      computeSimhashJS,
      privToPubHex,
      pubToAddress,
      signTransactionJS,
      verifyMerkleProofJS,
    };
    return;
  }

  // =========================================================================
  // 3. UI Application State & API Helpers
  // =========================================================================

  const STORAGE_KEY_WALLETS = "ipchain_custom_wallets_v1";
  const STORAGE_KEY_ACTIVE = "ipchain_active_wallet_v1";
  const STORAGE_KEY_PREFS = "ipchain_wallet_prefs_v1";
  const STORAGE_KEY_CACHE = "ipchain_offline_cache_v1";

  const state = {
    status: null,
    personas: [],
    customWallets: [],
    walletPrefs: { aliases: {}, hidden: [] },
    activeAddress: "",
    assets: [],
    licenses: [],
    disputes: [],
    blocks: [],
    mempool: [],
    chartMetric: "cumulative_ips",
    registryView: "table",
    livePolling: true,
    pollInFlight: false,
    offlineMode: false,
    cachedAt: null,
    lastWalletsKey: "",
  };

  function escapeHtml(str) {
    return String(str ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function shortAddr(addr) {
    if (!addr || addr.length < 12) return addr || "—";
    return addr.slice(0, 8) + "..." + addr.slice(-6);
  }

  function labelForAddr(addr) {
    if (!addr) return "—";
    const norm = addr.toLowerCase();
    const alias = state.walletPrefs.aliases[norm];
    if (alias) return `${alias} (${shortAddr(norm)})`;
    const all = [...state.personas, ...state.customWallets];
    const match = all.find((w) => w.address.toLowerCase() === norm);
    return match ? `${match.label.split("(")[0].trim()} (${shortAddr(norm)})` : shortAddr(norm);
  }

  function formatTs(ts) {
    if (!ts) return "—";
    return new Date(ts * 1000).toLocaleString();
  }

  const STATUS_SYMBOLS = {
    ACTIVE: "&#10003;",
    RESOLVED: "&#10003;",
    DISPUTED: "&#9888;",
    OPEN: "&#9873;",
    REVOKED: "&#10005;",
  };

  function renderStatusPill(status) {
    const raw = String(status || "UNKNOWN");
    const sym = STATUS_SYMBOLS[raw] || "&bull;";
    return `<span class="pill pill-${escapeHtml(raw)}"><span aria-hidden="true">${sym}</span> ${escapeHtml(raw)}</span>`;
  }

  function toast(msg, kind = "info") {
    const box = document.getElementById("toastContainer");
    const el = document.createElement("div");
    el.className = `toast ${kind === "ok" ? "ok" : kind === "err" ? "err" : ""}`;
    el.textContent = msg;
    box.appendChild(el);
    setTimeout(() => el.remove(), 4600);
  }

  async function api(path, method = "GET", body = null) {
    const opts = { method, headers: {} };
    if (body !== null) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    const res = await fetch(path, opts);
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      throw new Error(data.error || `Request failed (${res.status})`);
    }
    return data;
  }

  function loadCustomWallets() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY_WALLETS);
      state.customWallets = raw ? JSON.parse(raw) : [];
    } catch {
      state.customWallets = [];
    }
    try {
      const rawPrefs = localStorage.getItem(STORAGE_KEY_PREFS);
      const parsed = rawPrefs ? JSON.parse(rawPrefs) : {};
      state.walletPrefs = {
        aliases: parsed.aliases && typeof parsed.aliases === "object" ? parsed.aliases : {},
        hidden: Array.isArray(parsed.hidden) ? parsed.hidden.map((a) => String(a).toLowerCase()) : [],
      };
    } catch {
      state.walletPrefs = { aliases: {}, hidden: [] };
    }
  }

  function saveCustomWallets() {
    localStorage.setItem(STORAGE_KEY_WALLETS, JSON.stringify(state.customWallets));
  }

  function saveWalletPrefs() {
    localStorage.setItem(STORAGE_KEY_PREFS, JSON.stringify(state.walletPrefs));
  }

  function applyWalletAlias(wallet) {
    const addr = wallet.address.toLowerCase();
    const alias = state.walletPrefs.aliases[addr];
    return alias ? { ...wallet, label: alias, originalLabel: wallet.label } : { ...wallet, originalLabel: wallet.label };
  }

  function getAllWallets(includeHidden = false) {
    const hiddenSet = new Set(state.walletPrefs.hidden);
    const orderedPersonas = state.personas.filter((p) => p.id !== "treasury");
    const treasury = state.personas.filter((p) => p.id === "treasury");
    const combined = [...orderedPersonas, ...state.customWallets, ...treasury].map(applyWalletAlias);
    if (includeHidden) return combined;
    const visible = combined.filter((w) => !hiddenSet.has(w.address.toLowerCase()));
    return visible.length ? visible : combined;
  }

  function getActiveWallet() {
    const all = getAllWallets();
    return all.find((w) => w.address.toLowerCase() === state.activeAddress.toLowerCase()) || all[0] || null;
  }

  function nextCustomWalletNumber() {
    const used = new Set(
      state.customWallets.map((w) => {
        const m = /^Custom Wallet #(\d+)$/.exec(w.label || "");
        return m ? Number(m[1]) : 0;
      })
    );
    let n = 1;
    while (used.has(n)) n += 1;
    return n;
  }

  function switchTab(tabName) {
    document.querySelectorAll(".tab-btn").forEach((b) => {
      b.classList.toggle("active", b.dataset.tab === tabName);
    });
    document.querySelectorAll(".tab-panel").forEach((p) => {
      p.classList.toggle("active", p.id === `tab-${tabName}`);
    });
  }

  async function signAndSubmitTx(txType, payload, autoMine = false) {
    const wallet = getActiveWallet();
    if (!wallet) throw new Error("No active wallet selected");
    const acct = await api(`/api/accounts/${wallet.address}`);
    const unsigned = {
      type: txType,
      sender: wallet.address,
      nonce: acct.pending_nonce,
      fee: 1,
      timestamp: Math.floor(Date.now() / 1000),
      payload,
    };
    const signed = signTransactionJS(unsigned, wallet.private_key);
    const submitted = await api("/api/transactions", "POST", signed);
    let mined = null;
    if (autoMine) {
      mined = await api("/api/mine", "POST", { miner_address: wallet.address });
    }
    await refreshAll();
    await runAndRenderAudit();
    return { submitted, mined };
  }

  // =========================================================================
  // 4. Data Loading, Telemetry Chart & Dynamic Rendering
  // =========================================================================

  function saveOfflineSnapshot() {
    try {
      const savedAt = Date.now();
      state.cachedAt = savedAt;
      localStorage.setItem(
        STORAGE_KEY_CACHE,
        JSON.stringify({
          savedAt,
          status: state.status,
          personas: state.personas,
          assets: state.assets,
          licenses: state.licenses,
          disputes: state.disputes,
          blocks: state.blocks,
          mempool: state.mempool,
        })
      );
    } catch {
      // Ignore storage quota limitations
    }
  }

  function loadOfflineSnapshot() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY_CACHE);
      return raw ? JSON.parse(raw) : null;
    } catch {
      return null;
    }
  }

  function applySnapshot(snapshot) {
    state.status = snapshot.status || null;
    state.personas = snapshot.personas || [];
    state.assets = snapshot.assets || [];
    state.licenses = snapshot.licenses || [];
    state.disputes = snapshot.disputes || [];
    state.blocks = snapshot.blocks || [];
    state.mempool = snapshot.mempool || [];
    if (snapshot.savedAt) state.cachedAt = snapshot.savedAt;
    if (!state.activeAddress && state.personas.length) {
      const saved = localStorage.getItem(STORAGE_KEY_ACTIVE);
      const alice = state.personas.find((p) => p.id === "alice");
      state.activeAddress = saved || (alice ? alice.address : state.personas[0].address);
    }
  }

  function setOfflineBanner(isOffline, message = "") {
    state.offlineMode = isOffline;
    const banner = document.getElementById("offlineBanner");
    const textEl = document.getElementById("offlineBannerText");
    const liveBtn = document.getElementById("livePulseBtn");
    const liveLbl = document.getElementById("livePulseLabel");
    if (banner) banner.classList.toggle("hidden", !isOffline);
    if (textEl && message) textEl.textContent = message;
    if (liveBtn && liveLbl) {
      liveBtn.classList.toggle("offline", isOffline);
      liveLbl.textContent = isOffline ? "OFFLINE" : state.livePolling ? "LIVE" : "PAUSED";
    }
  }

  async function renderAllViews(isOffline = false) {
    renderHeader();
    if (!isOffline) {
      await renderActiveWalletStats();
    } else {
      renderSavedWalletsList();
    }
    renderKPIs();
    renderTelemetryChart();
    renderAlertsPanel();
    renderRegistry();
    renderGovernance();
    renderExplorer();
    renderPeers();
    const regEl = document.getElementById("registryGrid");
    if (regEl) regEl.removeAttribute("aria-busy");
  }

  async function handleOfflineFallback(err) {
    const cached = loadOfflineSnapshot();
    if (!state.status && cached) {
      applySnapshot(cached);
      await renderAllViews(true);
    }
    const ts = state.cachedAt || (cached && cached.savedAt);
    const tsText = ts ? ` from ${new Date(ts).toLocaleTimeString()}` : "";
    setOfflineBanner(
      true,
      ts
        ? `Offline mode · Showing cached ledger snapshot${tsText} while reconnecting.`
        : `Offline mode · Waiting for node connection (${err ? err.message : "unreachable"}).`
    );
  }

  async function refreshAll() {
    const [status, personasRes, ipsRes, licRes, dispRes, chainRes, mempoolRes] = await Promise.all([
      api("/api/status"),
      api("/api/demo/personas"),
      api("/api/ips"),
      api("/api/licenses"),
      api("/api/disputes"),
      api("/api/chain"),
      api("/api/mempool"),
    ]);

    applySnapshot({
      status,
      personas: personasRes.personas || [],
      assets: ipsRes.assets || [],
      licenses: licRes.licenses || [],
      disputes: dispRes.disputes || [],
      blocks: chainRes.chain || [],
      mempool: mempoolRes.transactions || [],
    });

    saveOfflineSnapshot();
    setOfflineBanner(false);
    await renderAllViews(false);

    document.getElementById("lastSyncTime").textContent = new Date().toLocaleTimeString();
  }

  function renderHeader() {
    const s = state.status;
    if (!s) return;
    document.getElementById("statHeight").textContent = s.height;
    document.getElementById("statDifficulty").textContent = s.difficulty;
    document.getElementById("statMempool").textContent = s.mempool_size;
    document.getElementById("hdrMempool").textContent = s.mempool_size;
    document.getElementById("statIPs").textContent = s.active_ips;
    document.getElementById("statLicenses").textContent = s.active_licenses;
    document.getElementById("statDisputes").textContent = s.open_disputes;
    document.getElementById("arbitratorAddrLabel").textContent = s.arbitrator;

    const select = document.getElementById("walletSelect");
    const wallets = getAllWallets();
    const walletsKey = wallets.map((w) => `${w.address}:${w.label}`).join("|");
    if (walletsKey !== state.lastWalletsKey) {
      select.innerHTML = wallets
        .map(
          (w) =>
            `<option value="${escapeHtml(w.address)}">${escapeHtml(w.label)} — ${shortAddr(w.address)}</option>`
        )
        .join("");
      state.lastWalletsKey = walletsKey;
    }
    const active = getActiveWallet();
    if (active) {
      select.value = active.address;
      state.activeAddress = active.address;
    }
  }

  function renderKPIs() {
    const s = state.status;
    if (!s) return;
    document.getElementById("kpiTotalIPs").textContent = s.total_ips;

    let totalPaid = 0;
    let totalSplits = 0;
    for (const lic of state.licenses) {
      totalPaid += Number(lic.paid_amount || 0);
      totalSplits += Number(lic.creator_royalty_paid || 0);
    }
    document.getElementById("kpiRoyaltyVolume").innerHTML = `${totalPaid} <span class="kpi-unit">IPC</span>`;
    document.getElementById("kpiCreatorSplits").textContent = `${totalSplits} IPC`;
  }

  function buildChartSeries() {
    let cumIps = 0;
    const licByBlock = {};
    for (const lic of state.licenses) {
      licByBlock[lic.granted_block] = (licByBlock[lic.granted_block] || 0) + Number(lic.paid_amount || 0);
    }

    return state.blocks.map((blk) => {
      let regCount = 0;
      let txVol = blk.index > 0 ? 50 : 0; // block reward
      for (const tx of blk.transactions || []) {
        txVol += Number(tx.fee || 0);
        if (tx.type === "REGISTER_IP") regCount += 1;
        if (tx.type === "TRANSFER_TOKENS") txVol += Number((tx.payload && tx.payload.amount) || 0);
      }
      txVol += licByBlock[blk.index] || 0;
      cumIps += regCount;

      let value = cumIps;
      if (state.chartMetric === "tx_activity") value = (blk.transactions || []).length;
      else if (state.chartMetric === "ipc_volume") value = txVol;

      return {
        index: blk.index,
        label: `B#${blk.index}`,
        value,
        txCount: (blk.transactions || []).length,
        cumIps,
        ipcFlow: txVol,
        timestamp: blk.timestamp,
        miner: blk.miner,
      };
    });
  }

  function smoothSplinePath(pts) {
    if (!pts.length) return "";
    if (pts.length === 1) return `M ${pts[0].x} ${pts[0].y}`;
    let d = `M ${pts[0].x.toFixed(1)} ${pts[0].y.toFixed(1)}`;
    for (let i = 0; i < pts.length - 1; i++) {
      const p0 = pts[i];
      const p1 = pts[i + 1];
      const cx = ((p0.x + p1.x) / 2).toFixed(1);
      d += ` C ${cx} ${p0.y.toFixed(1)}, ${cx} ${p1.y.toFixed(1)}, ${p1.x.toFixed(1)} ${p1.y.toFixed(1)}`;
    }
    return d;
  }

  function renderTelemetryChart() {
    const svg = document.getElementById("telemetryChartSvg");
    const stage = document.getElementById("telemetryChartStage");
    const tooltip = document.getElementById("chartTooltip");
    const series = buildChartSeries();
    if (!svg) return;

    const W = 760;
    const H = 240;
    const padL = 44;
    const padR = 20;
    const padT = 18;
    const padB = 34;
    const plotW = W - padL - padR;
    const plotH = H - padT - padB;

    if (!series.length) {
      svg.innerHTML = "";
      return;
    }

    const maxVal = Math.max(1, ...series.map((d) => d.value));
    const yTicks = 4;
    const pts = series.map((d, i) => {
      const x = series.length === 1 ? padL + plotW / 2 : padL + (i / (series.length - 1)) * plotW;
      const y = padT + plotH - (d.value / maxVal) * plotH;
      return { ...d, x, y };
    });

    let gridHtml = "";
    for (let t = 0; t <= yTicks; t++) {
      const val = Math.round((maxVal / yTicks) * t);
      const y = padT + plotH - (t / yTicks) * plotH;
      gridHtml += `<line x1="${padL}" y1="${y.toFixed(1)}" x2="${W - padR}" y2="${y.toFixed(1)}" stroke="#E7E5E4" stroke-width="1"/>`;
      gridHtml += `<text x="${padL - 8}" y="${(y + 4).toFixed(1)}" fill="#A8A29E" font-size="11" font-family="'Fira Code', monospace" text-anchor="end">${val}</text>`;
    }

    const linePath = smoothSplinePath(pts);
    const first = pts[0];
    const last = pts[pts.length - 1];
    const areaPath = `${linePath} L ${last.x.toFixed(1)} ${(padT + plotH).toFixed(1)} L ${first.x.toFixed(1)} ${(padT + plotH).toFixed(1)} Z`;

    const xLabels = pts
      .map(
        (p) =>
          `<text x="${p.x.toFixed(1)}" y="${H - 10}" fill="#A8A29E" font-size="11" font-family="'Fira Code', monospace" text-anchor="middle">${p.label}</text>`
      )
      .join("");

    const pointsHtml = pts
      .map(
        (p, idx) => `
      <circle cx="${p.x.toFixed(1)}" cy="${p.y.toFixed(1)}" r="4" fill="#78716C" stroke="#FFFFFF" stroke-width="2"/>
      <circle class="chart-hit" data-idx="${idx}" cx="${p.x.toFixed(1)}" cy="${p.y.toFixed(1)}" r="16" fill="transparent" style="cursor:pointer;"/>`
      )
      .join("");

    svg.innerHTML = `
      <defs>
        <linearGradient id="ipAreaGrad" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="#78716C" stop-opacity="0.16"/>
          <stop offset="100%" stop-color="#FAF9F6" stop-opacity="0.02"/>
        </linearGradient>
      </defs>
      ${gridHtml}
      <path d="${areaPath}" fill="url(#ipAreaGrad)"/>
      <path d="${linePath}" fill="none" stroke="#78716C" stroke-width="2" stroke-linecap="round"/>
      ${xLabels}
      ${pointsHtml}
    `;

    svg.querySelectorAll(".chart-hit").forEach((dot) => {
      dot.addEventListener("mouseenter", () => {
        const p = pts[Number(dot.dataset.idx)];
        const unitLabel =
          state.chartMetric === "cumulative_ips"
            ? `${p.cumIps} total IPs`
            : state.chartMetric === "tx_activity"
            ? `${p.txCount} transactions`
            : `${p.ipcFlow} IPC volume`;
        tooltip.innerHTML = `
          <strong>Block #${p.index}</strong> · <span style="color:#FAF9F6;font-weight:500;">${unitLabel}</span><br/>
          <span style="color:#A8A29E;">Txs: ${p.txCount} · Miner: ${escapeHtml(shortAddr(p.miner))}</span>
        `;
        const rect = stage.getBoundingClientRect();
        const px = (p.x / W) * rect.width;
        const py = (p.y / H) * rect.height;
        tooltip.style.left = `${Math.min(Math.max(px - 60, 8), rect.width - 210)}px`;
        tooltip.style.top = `${Math.max(py - 54, 6)}px`;
        tooltip.classList.remove("hidden");
      });
      dot.addEventListener("mouseleave", () => tooltip.classList.add("hidden"));
    });
  }

  function renderAlertsPanel() {
    const panel = document.getElementById("alertsPanel");
    const badge = document.getElementById("alertCountBadge");
    const alerts = [];

    const openDisputes = state.disputes.filter((d) => d.status === "OPEN");
    for (const d of openDisputes) {
      alerts.push(`
        <div class="alert-item">
          <strong><span aria-hidden="true">&#9873;</span> Open Dispute: ${escapeHtml(d.accused_title || d.accused_ip_id)}</strong>
          <div>${escapeHtml(d.claim_type)} · <code>${escapeHtml(d.dispute_id)}</code></div>
          <div class="alert-meta" style="margin-top:6px;">
            <button type="button" class="btn btn-danger btn-sm" data-jump-tab="governance">Review &amp; Arbitrate</button>
          </div>
        </div>
      `);
    }

    if (state.mempool.length > 0) {
      alerts.push(`
        <div class="alert-item">
          <strong><span aria-hidden="true">&#9203;</span> ${state.mempool.length} Pending Transaction(s) in Mempool</strong>
          <div class="alert-meta">Waiting for Proof-of-Work block sealing.</div>
          <div style="margin-top:6px;">
            <button type="button" class="btn btn-primary btn-sm" id="alertMineBtn">Mine Block Now</button>
          </div>
        </div>
      `);
    }

    const revokedCount = state.assets.filter((a) => a.status === "REVOKED").length;
    if (revokedCount > 0) {
      alerts.push(`
        <div class="alert-item">
          <strong><span aria-hidden="true">&#10005;</span> ${revokedCount} Revoked IP Asset(s)</strong>
          <div class="alert-meta">Invalidated by arbitrator ruling and permanently locked.</div>
        </div>
      `);
    }

    badge.textContent = openDisputes.length + state.mempool.length;
    badge.classList.toggle("has-alerts", openDisputes.length > 0 || state.mempool.length > 0);

    const nominalHtml = !alerts.length
      ? `<div class="alert-item normal"><strong><span aria-hidden="true">&#10003;</span> All Systems Nominal</strong><div class="alert-meta">No open disputes or pending congestion.</div></div>`
      : alerts.join("");

    const recentBlocks = [...state.blocks]
      .reverse()
      .slice(0, 3)
      .map(
        (b) => `
      <div class="alert-item feed">
        <strong><span aria-hidden="true">&#9635;</span> Block #${b.index} Sealed (${b.transactions.length} txs)</strong>
        <div class="alert-meta">Hash <code>${shortAddr(b.hash)}</code> · ${formatTs(b.timestamp)}</div>
      </div>`
      )
      .join("");

    panel.innerHTML = nominalHtml + recentBlocks;
    panel.removeAttribute("aria-busy");

    panel.querySelectorAll("[data-jump-tab]").forEach((btn) => {
      btn.addEventListener("click", () => switchTab(btn.dataset.jumpTab));
    });
    const mineBtn = document.getElementById("alertMineBtn");
    if (mineBtn) {
      mineBtn.addEventListener("click", () => document.getElementById("btnMineHeader").click());
    }
  }

  async function renderActiveWalletStats() {
    const active = getActiveWallet();
    if (!active) return;
    const acct = await api(`/api/accounts/${active.address}`);
    document.getElementById("walletBalance").textContent = `${acct.pending_balance} IPC`;
    document.getElementById("walletNonce").textContent = acct.pending_nonce;

    const details = document.getElementById("activeWalletDetails");
    details.innerHTML = `
      <div><strong>Label:</strong> ${escapeHtml(active.label)}</div>
      <div><strong>Address:</strong> <code>${escapeHtml(active.address)}</code></div>
      <div><strong>Public Key:</strong> <code>${escapeHtml(active.public_key)}</code></div>
      <div><strong>Private Key:</strong> <code>${escapeHtml(active.private_key)}</code></div>
      <div><strong>Balance:</strong> ${acct.balance} IPC (pending: ${acct.pending_balance} IPC) | <strong>Nonce:</strong> ${acct.nonce}</div>
    `;
    renderSavedWalletsList();
  }

  async function syncWalletUIAfterChange() {
    state.lastWalletsKey = "";
    const active = getActiveWallet();
    if (active) {
      state.activeAddress = active.address;
      localStorage.setItem(STORAGE_KEY_ACTIVE, state.activeAddress);
    }
    renderHeader();
    await renderActiveWalletStats();
    renderRegistry();
    renderGovernance();
  }

  async function renameWallet(address, newLabel) {
    const clean = String(newLabel || "").trim();
    if (!clean) throw new Error("Wallet name cannot be empty");
    const norm = address.toLowerCase();
    const custom = state.customWallets.find((w) => w.address.toLowerCase() === norm);
    if (custom) {
      custom.label = clean;
      saveCustomWallets();
    } else {
      state.walletPrefs.aliases[norm] = clean;
      saveWalletPrefs();
    }
    await syncWalletUIAfterChange();
    toast(`Renamed wallet to "${clean}"`, "ok");
  }

  async function removeCustomWallet(address) {
    const norm = address.toLowerCase();
    state.customWallets = state.customWallets.filter((w) => w.address.toLowerCase() !== norm);
    delete state.walletPrefs.aliases[norm];
    state.walletPrefs.hidden = state.walletPrefs.hidden.filter((a) => a !== norm);
    saveCustomWallets();
    saveWalletPrefs();
    if (state.activeAddress.toLowerCase() === norm) {
      state.activeAddress = "";
    }
    await syncWalletUIAfterChange();
    toast(`Removed custom wallet ${shortAddr(norm)}`, "ok");
  }

  async function removeAllCustomWallets() {
    const count = state.customWallets.length;
    if (!count) return;
    const customSet = new Set(state.customWallets.map((w) => w.address.toLowerCase()));
    state.customWallets = [];
    saveCustomWallets();
    if (customSet.has(state.activeAddress.toLowerCase())) {
      state.activeAddress = "";
    }
    await syncWalletUIAfterChange();
    toast(`Removed ${count} custom wallet(s)`, "ok");
  }

  async function toggleHidePersona(address) {
    const norm = address.toLowerCase();
    const hiddenSet = new Set(state.walletPrefs.hidden);
    if (hiddenSet.has(norm)) {
      hiddenSet.delete(norm);
    } else {
      const remainingVisible = getAllWallets().filter((w) => w.address.toLowerCase() !== norm);
      if (!remainingVisible.length) {
        throw new Error("At least one wallet must stay visible in the dropdown");
      }
      hiddenSet.add(norm);
      if (state.activeAddress.toLowerCase() === norm) {
        state.activeAddress = remainingVisible[0].address;
      }
    }
    state.walletPrefs.hidden = [...hiddenSet];
    saveWalletPrefs();
    await syncWalletUIAfterChange();
  }

  async function restoreHiddenPersonas() {
    state.walletPrefs.hidden = [];
    saveWalletPrefs();
    await syncWalletUIAfterChange();
    toast("Restored all built-in demo wallets", "ok");
  }

  function renderSavedWalletsList() {
    const box = document.getElementById("savedWalletsList");
    if (!box) return;
    if (!state.customWallets.length) {
      box.innerHTML = `<div class="muted" style="font-size:12px;">No custom wallets saved yet. Click <strong>+ Wallet</strong> to generate one or <strong>Edit / Remove Wallets</strong> to manage demo accounts.</div>`;
      return;
    }
    box.innerHTML = state.customWallets
      .map((w) => {
        const isAct = w.address.toLowerCase() === state.activeAddress.toLowerCase();
        return `
        <div class="row-card" style="display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center;gap:8px;padding:10px 12px;">
          <div>
            <strong>${escapeHtml(w.label)}</strong> ${isAct ? renderStatusPill("ACTIVE") : ""}
            <div class="muted" style="margin:0;font-size:12px;"><code>${escapeHtml(w.address)}</code></div>
          </div>
          <div style="display:flex;gap:6px;">
            <button type="button" class="btn btn-secondary btn-sm" data-wallet-edit="${escapeHtml(w.address)}">Edit</button>
            <button type="button" class="btn btn-danger btn-sm" data-wallet-del="${escapeHtml(w.address)}">Remove</button>
          </div>
        </div>`;
      })
      .join("");
  }

  function openWalletManagerModal() {
    const hiddenSet = new Set(state.walletPrefs.hidden);
    const customHtml = state.customWallets.length
      ? state.customWallets
          .map((w) => {
            const isAct = w.address.toLowerCase() === state.activeAddress.toLowerCase();
            return `
            <div class="row-card" style="display:grid;gap:8px;">
              <div style="display:flex;flex-wrap:wrap;gap:8px;align-items:center;">
                <input type="text" class="wallet-rename-input" data-addr="${escapeHtml(w.address)}" value="${escapeHtml(w.label)}" style="flex:1;min-width:180px;" />
                <button type="button" class="btn btn-secondary btn-sm" data-wm-action="save" data-addr="${escapeHtml(w.address)}">Save Name</button>
                <button type="button" class="btn ${isAct ? "btn-accent" : "btn-primary"} btn-sm" data-wm-action="use" data-addr="${escapeHtml(w.address)}">${isAct ? "Active ✓" : "Use"}</button>
                <button type="button" class="btn btn-danger btn-sm" data-wm-action="delete" data-addr="${escapeHtml(w.address)}">Remove</button>
              </div>
              <div class="muted" style="margin:0;font-size:12px;">Address: <code>${escapeHtml(w.address)}</code></div>
            </div>`;
          })
          .join("")
      : `<p class="muted">No custom wallets created or imported.</p>`;

    const demoHtml = state.personas
      .map((p) => {
        const norm = p.address.toLowerCase();
        const isHidden = hiddenSet.has(norm);
        const isAct = norm === state.activeAddress.toLowerCase();
        const currentLabel = state.walletPrefs.aliases[norm] || p.label;
        return `
        <div class="row-card" style="display:grid;gap:8px;opacity:${isHidden ? "0.65" : "1"};">
          <div style="display:flex;flex-wrap:wrap;gap:8px;align-items:center;">
            <input type="text" class="wallet-rename-input" data-addr="${escapeHtml(p.address)}" value="${escapeHtml(currentLabel)}" style="flex:1;min-width:180px;" />
            <button type="button" class="btn btn-secondary btn-sm" data-wm-action="save" data-addr="${escapeHtml(p.address)}">Save Name</button>
            ${!isHidden ? `<button type="button" class="btn ${isAct ? "btn-accent" : "btn-primary"} btn-sm" data-wm-action="use" data-addr="${escapeHtml(p.address)}">${isAct ? "Active ✓" : "Use"}</button>` : ""}
            <button type="button" class="btn ${isHidden ? "btn-secondary" : "btn-danger"} btn-sm" data-wm-action="toggle-hide" data-addr="${escapeHtml(p.address)}">${isHidden ? "Show" : "Remove from List"}</button>
          </div>
          <div class="muted" style="margin:0;font-size:12px;">Built-in ${escapeHtml(p.role)} · <code>${escapeHtml(p.address)}</code></div>
        </div>`;
      })
      .join("");

    openModal(
      "Edit or Remove Wallets",
      `
      <div class="stack-form" id="walletManagerRoot">
        <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap;">
          <h4 style="margin:0;">Custom Wallets (${state.customWallets.length})</h4>
          ${state.customWallets.length ? `<button type="button" class="btn btn-danger btn-sm" data-wm-action="delete-all-custom">Remove All Custom Wallets</button>` : ""}
        </div>
        <div class="stack-list">${customHtml}</div>

        <hr class="sep" />
        <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap;">
          <h4 style="margin:0;">Built-in Demo Wallets</h4>
          ${state.walletPrefs.hidden.length ? `<button type="button" class="btn btn-secondary btn-sm" data-wm-action="restore-all">Restore Hidden (${state.walletPrefs.hidden.length})</button>` : ""}
        </div>
        <div class="stack-list">${demoHtml}</div>
      </div>`
    );

    document.getElementById("walletManagerRoot").addEventListener("click", async (e) => {
      const btn = e.target.closest("button[data-wm-action]");
      if (!btn) return;
      const action = btn.dataset.wmAction;
      const addr = btn.dataset.addr || "";
      try {
        if (action === "save") {
          const input = [...document.querySelectorAll(".wallet-rename-input")].find(
            (el) => el.dataset.addr.toLowerCase() === addr.toLowerCase()
          );
          await renameWallet(addr, input ? input.value : "");
          openWalletManagerModal();
        } else if (action === "use") {
          state.activeAddress = addr;
          await syncWalletUIAfterChange();
          openWalletManagerModal();
        } else if (action === "delete") {
          await removeCustomWallet(addr);
          openWalletManagerModal();
        } else if (action === "delete-all-custom") {
          await removeAllCustomWallets();
          openWalletManagerModal();
        } else if (action === "toggle-hide") {
          await toggleHidePersona(addr);
          openWalletManagerModal();
        } else if (action === "restore-all") {
          await restoreHiddenPersonas();
          openWalletManagerModal();
        }
      } catch (err) {
        toast(err.message, "err");
      }
    });
  }

  async function runAndRenderAudit() {
    const report = await api("/api/audit");
    const pill = document.getElementById("statIntegrityPill");
    const lbl = document.getElementById("statIntegrity");
    const icon = document.getElementById("kpiIntegrityIcon");
    pill.classList.remove("ok", "bad");
    lbl.classList.remove("ok", "bad");
    icon.classList.remove("green", "red");

    if (report.valid) {
      pill.classList.add("ok");
      pill.textContent = `✓ ${report.checked_blocks} blocks OK`;
      lbl.classList.add("ok");
      lbl.textContent = "VERIFIED";
      icon.classList.add("green");
    } else {
      pill.classList.add("bad");
      pill.textContent = `✕ Block #${report.failed_block} FAIL`;
      lbl.classList.add("bad");
      lbl.textContent = "TAMPERED";
      icon.classList.add("red");
    }

    const box = document.getElementById("auditReportBox");
    const rows = (report.blocks || [])
      .map(
        (b) => `
      <tr>
        <td>#${b.index}</td>
        <td><code>${shortAddr(b.hash)}</code></td>
        <td>${b.tx_count}</td>
        <td>${b.checks.pow_valid ? "&#10003; OK" : "&#10005; FAIL"}</td>
        <td>${b.checks.merkle_valid ? "&#10003; OK" : "&#10005; FAIL"}</td>
        <td>${b.checks.signatures_valid ? "&#10003; OK" : "&#10005; FAIL"}</td>
        <td>${b.checks.state_root_valid ? "&#10003; OK" : "&#10005; FAIL"}</td>
      </tr>`
      )
      .join("");
    box.innerHTML = `
      <div class="alert ${report.valid ? "alert-ok" : "alert-bad"}">
        ${report.valid ? `&#10003; All ${report.checked_blocks} blocks passed cryptographic validation.` : `&#10005; ${escapeHtml(report.error)}`}
      </div>
      <table class="audit-table">
        <thead><tr><th>Block</th><th>Hash</th><th>Txs</th><th>PoW</th><th>Merkle</th><th>ECDSA</th><th>State</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    `;
  }

  function renderRegistry() {
    const q = document.getElementById("regSearch").value.trim().toLowerCase();
    const t = document.getElementById("regTypeFilter").value;
    const st = document.getElementById("regStatusFilter").value;
    const active = getActiveWallet();
    const myAddr = active ? active.address.toLowerCase() : "";

    const filtered = state.assets.filter((a) => {
      if (t && a.ip_type !== t) return false;
      if (st && a.status !== st) return false;
      if (q) {
        const hay = `${a.ip_id} ${a.title} ${a.description} ${a.content_hash} ${a.owner} ${a.original_creator} ${(a.tags || []).join(" ")}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });

    const grid = document.getElementById("registryGrid");
    if (!filtered.length) {
      grid.className = "";
      grid.innerHTML = `<p class="muted">No matching IP assets found.</p>`;
      return;
    }

    if (state.registryView === "table") {
      grid.className = "table-wrap";
      const rowsHtml = filtered
        .map((a) => {
          const isOwner = a.owner.toLowerCase() === myAddr;
          const canBuy = !isOwner && a.status === "ACTIVE" && a.allow_public_license;
          const canTransfer = isOwner && a.status === "ACTIVE";
          const canDispute = !isOwner && a.status !== "REVOKED";
          return `
          <tr>
            <td><code>${escapeHtml(a.ip_id)}</code><div class="muted" style="margin:2px 0 0;font-size:11px;">Block #${a.registered_block}</div></td>
            <td>
              <strong>${escapeHtml(a.title)}</strong>
              <div style="margin-top:4px;"><span class="pill pill-type">${escapeHtml(a.ip_type)}</span> <span class="muted">${escapeHtml(a.jurisdiction)}</span></div>
            </td>
            <td>${renderStatusPill(a.status)}</td>
            <td>
              <div>${escapeHtml(labelForAddr(a.owner))}</div>
              <div class="muted" style="margin:0;font-size:11px;">Creator: ${escapeHtml(labelForAddr(a.original_creator))}</div>
            </td>
            <td class="mono-num">
              <div>${(a.royalty_bps / 100).toFixed(2)}% royalty</div>
              <div class="muted" style="margin:0;font-size:11px;">${a.allow_public_license ? `${a.license_price} IPC` : "Private"}</div>
            </td>
            <td>
              <div class="ip-actions">
                <button class="btn btn-secondary btn-sm" data-action="inspect" data-ip="${escapeHtml(a.ip_id)}">Inspect</button>
                ${canBuy ? `<button class="btn btn-accent btn-sm" data-action="buy-license" data-ip="${escapeHtml(a.ip_id)}">Buy</button>` : ""}
                ${canTransfer ? `<button class="btn btn-secondary btn-sm" data-action="transfer" data-ip="${escapeHtml(a.ip_id)}">Transfer</button>` : ""}
                ${canTransfer ? `<button class="btn btn-secondary btn-sm" data-action="grant" data-ip="${escapeHtml(a.ip_id)}">License</button>` : ""}
                ${canDispute ? `<button class="btn btn-danger btn-sm" data-action="dispute" data-ip="${escapeHtml(a.ip_id)}">Dispute</button>` : ""}
              </div>
            </td>
          </tr>`;
        })
        .join("");

      grid.innerHTML = `
        <table class="data-table">
          <thead>
            <tr>
              <th>IP ID</th>
              <th>Asset Title &amp; Type</th>
              <th>Status</th>
              <th>Owner &amp; Creator</th>
              <th>Royalty / Price</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>${rowsHtml}</tbody>
        </table>
      `;
      return;
    }

    grid.className = "cards-grid";
    grid.innerHTML = filtered
      .map((a) => {
        const isOwner = a.owner.toLowerCase() === myAddr;
        const canBuy = !isOwner && a.status === "ACTIVE" && a.allow_public_license;
        const canTransfer = isOwner && a.status === "ACTIVE";
        const canDispute = !isOwner && a.status !== "REVOKED";
        return `
        <article class="ip-card">
          <div class="ip-card-top">
            <span class="pill pill-type">${escapeHtml(a.ip_type)}</span>
            ${renderStatusPill(a.status)}
          </div>
          <div>
            <h3 style="margin:0 0 4px;font-size:16px;">${escapeHtml(a.title)}</h3>
            <div class="muted" style="font-size:12px;"><code>${escapeHtml(a.ip_id)}</code> · Block #${a.registered_block} · ${escapeHtml(a.jurisdiction)}</div>
          </div>
          <p class="muted" style="margin:0;">${escapeHtml(a.description.slice(0, 140))}${a.description.length > 140 ? "..." : ""}</p>
          <div class="ip-meta-grid">
            <div><span class="meta-label">Current Owner</span>${escapeHtml(labelForAddr(a.owner))}</div>
            <div><span class="meta-label">Original Creator</span>${escapeHtml(labelForAddr(a.original_creator))}</div>
            <div><span class="meta-label">Creator Royalty</span>${(a.royalty_bps / 100).toFixed(2)}%</div>
            <div><span class="meta-label">Public License</span>${a.allow_public_license ? `${a.license_price} IPC` : "Private Only"}</div>
          </div>
          <div><span class="meta-label">Content SHA-256</span><code>${escapeHtml(a.content_hash.slice(0, 28))}...</code></div>
          <div class="ip-actions">
            <button class="btn btn-secondary btn-sm" data-action="inspect" data-ip="${escapeHtml(a.ip_id)}">Inspect &amp; Proof</button>
            ${canBuy ? `<button class="btn btn-accent btn-sm" data-action="buy-license" data-ip="${escapeHtml(a.ip_id)}">Buy License (${a.license_price} IPC)</button>` : ""}
            ${canTransfer ? `<button class="btn btn-secondary btn-sm" data-action="transfer" data-ip="${escapeHtml(a.ip_id)}">Transfer</button>` : ""}
            ${canTransfer ? `<button class="btn btn-secondary btn-sm" data-action="grant" data-ip="${escapeHtml(a.ip_id)}">Grant License</button>` : ""}
            ${canDispute ? `<button class="btn btn-danger btn-sm" data-action="dispute" data-ip="${escapeHtml(a.ip_id)}">Challenge / Dispute</button>` : ""}
          </div>
        </article>`;
      })
      .join("");
  }

  function renderGovernance() {
    const active = getActiveWallet();
    const myAddr = active ? active.address.toLowerCase() : "";
    const isArb = state.status && myAddr === state.status.arbitrator.toLowerCase();

    const licEl = document.getElementById("licensesList");
    if (!state.licenses.length) {
      licEl.innerHTML = `<p class="muted">No licenses issued yet.</p>`;
    } else {
      licEl.innerHTML = state.licenses
        .map((lic) => {
          const canRevoke = lic.status === "ACTIVE" && (lic.licensor.toLowerCase() === myAddr || isArb);
          return `
          <div class="row-card">
            <div class="ip-card-top">
              <strong>${escapeHtml(lic.ip_title || lic.ip_id)}</strong>
              ${renderStatusPill(lic.status)}
            </div>
            <div class="muted" style="margin:4px 0;"><code>${escapeHtml(lic.license_id)}</code> · ${escapeHtml(lic.license_type)} · Block #${lic.granted_block} ${lic.expires_block ? `→ #${lic.expires_block}` : "(Perpetual)"}</div>
            <div><strong>Licensor:</strong> ${escapeHtml(labelForAddr(lic.licensor))} → <strong>Licensee:</strong> ${escapeHtml(labelForAddr(lic.licensee))}</div>
            <div><strong>Scope:</strong> ${escapeHtml(lic.scope)}</div>
            <div><strong>Paid:</strong> <span class="mono-num">${lic.paid_amount} IPC</span> | <strong>Creator Royalty Paid:</strong> <span class="mono-num">${lic.creator_royalty_paid} IPC</span></div>
            ${lic.revoke_reason ? `<div class="muted">Revoked: ${escapeHtml(lic.revoke_reason)}</div>` : ""}
            ${canRevoke ? `<div style="margin-top:8px;"><button class="btn btn-danger btn-sm" data-action="revoke-license" data-lic="${escapeHtml(lic.license_id)}">Revoke License</button></div>` : ""}
          </div>`;
        })
        .join("");
    }

    const dispEl = document.getElementById("disputesList");
    if (!state.disputes.length) {
      dispEl.innerHTML = `<p class="muted">No IP disputes filed.</p>`;
    } else {
      dispEl.innerHTML = state.disputes
        .map((d) => {
          return `
          <div class="row-card">
            <div class="ip-card-top">
              <strong>${escapeHtml(d.accused_title || d.accused_ip_id)}</strong>
              ${renderStatusPill(d.status)}
            </div>
            <div class="muted" style="margin:4px 0;"><code>${escapeHtml(d.dispute_id)}</code> · Claim: <strong>${escapeHtml(d.claim_type)}</strong> · Filed Block #${d.filed_block}</div>
            <div><strong>Challenger:</strong> ${escapeHtml(labelForAddr(d.challenger))} | <strong>Prior Art:</strong> ${d.prior_art_ip_id ? `<code>${escapeHtml(d.prior_art_ip_id)}</code>` : "External"}</div>
            <p style="margin:6px 0;">${escapeHtml(d.description)}</p>
            ${d.ruling ? `<div class="alert alert-ok" style="margin-top:6px;"><strong>Ruling: ${escapeHtml(d.ruling)}</strong> — ${escapeHtml(d.ruling_notes)} (Block #${d.resolved_block})</div>` : ""}
            ${
              d.status === "OPEN"
                ? isArb
                  ? `<div class="ip-actions" style="margin-top:8px;">
                      <button class="btn btn-danger btn-sm" data-action="rule" data-dispute="${escapeHtml(d.dispute_id)}" data-ruling="UPHELD_REVOKE">Uphold &amp; Revoke</button>
                      <button class="btn btn-accent btn-sm" data-action="rule" data-dispute="${escapeHtml(d.dispute_id)}" data-ruling="UPHELD_TRANSFER">Uphold &amp; Transfer</button>
                      <button class="btn btn-secondary btn-sm" data-action="rule" data-dispute="${escapeHtml(d.dispute_id)}" data-ruling="DISMISSED">Dismiss</button>
                    </div>`
                  : `<div class="muted" style="margin-top:6px;">Switch Active Wallet to <strong>Global IP Arbitrator Authority</strong> to rule on this dispute.</div>`
                : ""
            }
          </div>`;
        })
        .join("");
    }
  }

  function renderExplorer() {
    const memEl = document.getElementById("mempoolList");
    if (!state.mempool.length) {
      memEl.innerHTML = `<p class="muted">Mempool is empty. Any newly signed transactions will appear here before mining.</p>`;
    } else {
      memEl.innerHTML = state.mempool
        .map(
          (tx) => `
        <div class="row-card">
          <div class="ip-card-top">
            <strong>${escapeHtml(tx.type)}</strong>
            <code>${escapeHtml(tx.tx_id)}</code>
          </div>
          <div>Sender: ${escapeHtml(labelForAddr(tx.sender))} | Nonce: ${tx.nonce} | Fee: ${tx.fee} IPC</div>
        </div>`
        )
        .join("");
    }

    const blkEl = document.getElementById("blocksList");
    blkEl.innerHTML = [...state.blocks]
      .reverse()
      .map(
        (b) => `
      <div class="row-card">
        <div class="ip-card-top">
          <strong>Block #${b.index} ${b.index === 0 ? "(Genesis)" : ""}</strong>
          <span class="muted">${formatTs(b.timestamp)} · ${b.transactions.length} txs · Nonce ${b.nonce} · Diff ${b.difficulty}</span>
        </div>
        <div style="display:grid;gap:4px;margin:6px 0;">
          <div><span class="meta-label">Hash</span> <code>${escapeHtml(b.hash)}</code></div>
          <div><span class="meta-label">Prev Hash</span> <code>${escapeHtml(b.previous_hash)}</code></div>
          <div><span class="meta-label">Merkle Root</span> <code>${escapeHtml(b.merkle_root)}</code></div>
          <div><span class="meta-label">State Root</span> <code>${escapeHtml(b.state_root)}</code></div>
          <div><span class="meta-label">Miner</span> ${escapeHtml(labelForAddr(b.miner))}</div>
        </div>
        ${
          b.transactions.length
            ? `<div style="margin-top:8px;display:grid;gap:6px;">
                ${b.transactions
                  .map(
                    (tx) => `
                  <div class="proof-step" style="justify-content:space-between;">
                    <span><strong>${escapeHtml(tx.type)}</strong> by ${escapeHtml(labelForAddr(tx.sender))} · <code>${shortAddr(tx.tx_id)}</code></span>
                    <button class="btn btn-secondary btn-sm" data-action="tx-proof" data-tx="${escapeHtml(tx.tx_id)}">Verify Merkle Proof</button>
                  </div>`
                  )
                  .join("")}
              </div>`
            : ""
        }
      </div>`
      )
      .join("");
  }

  function renderPeers() {
    const box = document.getElementById("peersListBox");
    const peers = (state.status && state.status.peers) || [];
    if (!peers.length) {
      box.innerHTML = `<p class="muted">No peer nodes registered yet.</p>`;
      return;
    }
    box.innerHTML = peers.map((p) => `<div class="row-card"><code>${escapeHtml(p)}</code></div>`).join("");
  }

  // =========================================================================
  // 5. Modals & Verification Views
  // =========================================================================

  function openModal(title, htmlContent) {
    document.getElementById("modalTitle").textContent = title;
    document.getElementById("modalBody").innerHTML = htmlContent;
    document.getElementById("modalBackdrop").classList.remove("hidden");
  }

  function closeModal() {
    document.getElementById("modalBackdrop").classList.add("hidden");
  }

  async function inspectIpModal(ipId) {
    const cert = await api(`/api/ips/${ipId}`);
    const a = cert.ip_asset;
    const mp = cert.merkle_proof;
    const clientVerified = verifyMerkleProofJS(mp.tx_id, mp.proof, mp.merkle_root);

    const timelineHtml = (a.provenance || [])
      .map(
        (ev) => `
      <div class="timeline-item">
        <strong>${escapeHtml(ev.event)}</strong> (Block #${ev.block_index}) — ${escapeHtml(ev.details || "")}
        <div class="muted">Tx: <code>${shortAddr(ev.tx_id)}</code> · ${formatTs(ev.timestamp)}</div>
      </div>`
      )
      .join("");

    const proofStepsHtml = (mp.proof || []).length
      ? mp.proof
          .map(
            (st, idx) =>
              `<div class="proof-step">Step ${idx + 1}: sibling (${escapeHtml(st.position)}) <code>${escapeHtml(st.hash)}</code></div>`
          )
          .join("")
      : `<div class="proof-step">Single-transaction block (leaf hash directly forms root)</div>`;

    openModal(
      `IP Certificate — ${a.ip_id}`,
      `
      <div class="stack-form">
        <div class="alert alert-ok">
          <strong>Verified On-Chain Registration</strong> · Client-Side Merkle Proof Check: <strong>${clientVerified ? "PASSED ✓" : "FAILED"}</strong>
        </div>
        <div class="wallet-details-box">
          <div><strong>Title:</strong> ${escapeHtml(a.title)} (${escapeHtml(a.ip_type)})</div>
          <div><strong>Status:</strong> ${renderStatusPill(a.status)} · Jurisdiction: ${escapeHtml(a.jurisdiction)}</div>
          <div><strong>Original Creator:</strong> <code>${escapeHtml(a.original_creator)}</code> (${escapeHtml(labelForAddr(a.original_creator))})</div>
          <div><strong>Current Owner:</strong> <code>${escapeHtml(a.owner)}</code> (${escapeHtml(labelForAddr(a.owner))})</div>
          <div><strong>Content SHA-256:</strong> <code>${escapeHtml(a.content_hash)}</code></div>
          <div><strong>SimHash Fingerprint:</strong> <code>${escapeHtml(a.simhash)}</code></div>
          <div><strong>Block #${mp.block_index}:</strong> <code>${escapeHtml(mp.block_hash)}</code></div>
          <div><strong>Merkle Root:</strong> <code>${escapeHtml(mp.merkle_root)}</code></div>
          <div><strong>Registration Tx:</strong> <code>${escapeHtml(mp.tx_id)}</code></div>
        </div>
        <div>
          <h4>Provenance &amp; Chain of Custody</h4>
          <div class="timeline">${timelineHtml}</div>
        </div>
        <div>
          <h4>Merkle Inclusion Proof Path</h4>
          ${proofStepsHtml}
        </div>
        <div class="form-actions">
          <button class="btn btn-primary btn-sm" id="btnDownloadCert">Download JSON Certificate</button>
        </div>
      </div>`
    );

    document.getElementById("btnDownloadCert").onclick = () => {
      const blob = new Blob([JSON.stringify(cert, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `${a.ip_id}-certificate.json`;
      link.click();
      URL.revokeObjectURL(url);
    };
  }

  function renderVerifyResult(res) {
    const pane = document.getElementById("verifyResultPane");
    let html = "";

    if (res.exact_match && res.certificate) {
      const a = res.certificate.ip_asset;
      const mp = res.certificate.merkle_proof;
      const clientOk = verifyMerkleProofJS(mp.tx_id, mp.proof, mp.merkle_root);
      html += `
        <div class="alert alert-ok">
          <strong>&#10003; Exact Prior-Art Match Found!</strong><br/>
          Registered as <code>${escapeHtml(a.ip_id)}</code> (<strong>${escapeHtml(a.title)}</strong>) at Block #${mp.block_index} on ${formatTs(a.registered_at)}.
          <br/>Client-side Merkle Inclusion Proof: <strong>${clientOk ? "CRYPTOGRAPHICALLY VERIFIED &#10003;" : "INVALID &#10005;"}</strong>
        </div>
        <div class="wallet-details-box" style="margin-top:10px;">
          <div><strong>Status:</strong> ${renderStatusPill(a.status)} | <strong>Type:</strong> ${escapeHtml(a.ip_type)}</div>
          <div><strong>Original Creator:</strong> ${escapeHtml(labelForAddr(a.original_creator))}</div>
          <div><strong>Current Owner:</strong> ${escapeHtml(labelForAddr(a.owner))}</div>
          <div><strong>Content Hash:</strong> <code>${escapeHtml(a.content_hash)}</code></div>
          <div><strong>Merkle Root:</strong> <code>${escapeHtml(mp.merkle_root)}</code></div>
        </div>`;
    } else {
      html += `
        <div class="alert alert-warn">
          <strong>&#9888; No Exact Content-Hash Match on Chain.</strong><br/>
          Queried SHA-256: <code>${escapeHtml(res.queried_hash || "—")}</code>
        </div>`;
    }

    if (res.similar_prior_art && res.similar_prior_art.length) {
      html += `
        <div class="alert alert-bad" style="margin-top:10px;">
          <strong>&#10005; Potential Plagiarism / Prior-Art Similarity Detected (SimHash):</strong>
          ${res.similar_prior_art
            .map(
              (m) =>
                `<div style="margin-top:6px;">• <strong>${m.similarity_pct}% similar</strong> to <code>${escapeHtml(m.ip_id)}</code> ("${escapeHtml(m.title)}", Block #${m.registered_block}, ${escapeHtml(m.status)})</div>`
            )
            .join("")}
        </div>`;
    } else if (res.queried_simhash && res.queried_simhash !== "0000000000000000") {
      html += `<div class="muted" style="margin-top:10px;">SimHash plagiarism check: no near-duplicate prior art found (&ge; 78% threshold).</div>`;
    }

    pane.innerHTML = html;
  }

  // =========================================================================
  // 6. File Hashing, Live Auto-Polling & Event Bindings
  // =========================================================================

  let regFileBytes = null;
  let verFileBytes = null;

  function updateRegisterHashes() {
    const text = document.getElementById("regText").value;
    let cHash = "—";
    let sHash = "0000000000000000";
    if (regFileBytes) {
      cHash = sha256Hex(regFileBytes);
      try {
        const decoded = new TextDecoder("utf-8", { fatal: true }).decode(regFileBytes);
        sHash = computeSimhashJS(decoded);
      } catch {
        sHash = text.trim() ? computeSimhashJS(text) : "0000000000000000";
      }
    } else if (text.length > 0) {
      cHash = sha256Hex(text);
      sHash = computeSimhashJS(text);
    }
    document.getElementById("regContentHash").textContent = cHash;
    document.getElementById("regSimhash").textContent = sHash;
  }

  function setupDropzone(dropEl, inputEl, metaEl, onFile) {
    dropEl.addEventListener("dragover", (e) => {
      e.preventDefault();
      dropEl.classList.add("dragover");
    });
    dropEl.addEventListener("dragleave", () => dropEl.classList.remove("dragover"));
    dropEl.addEventListener("drop", async (e) => {
      e.preventDefault();
      dropEl.classList.remove("dragover");
      const file = e.dataTransfer.files[0];
      if (file) await onFile(file, metaEl);
    });
    inputEl.addEventListener("change", async () => {
      const file = inputEl.files[0];
      if (file) await onFile(file, metaEl);
    });
  }

  function startLivePolling() {
    setInterval(async () => {
      const modalOpen = !document.getElementById("modalBackdrop").classList.contains("hidden");
      const selectFocused = document.activeElement && document.activeElement.tagName === "SELECT";
      if (!state.livePolling || state.pollInFlight || document.hidden || modalOpen || selectFocused) return;
      state.pollInFlight = true;
      try {
        await refreshAll();
        await runAndRenderAudit();
      } catch (err) {
        await handleOfflineFallback(err);
      } finally {
        state.pollInFlight = false;
      }
    }, 3000);
  }

  function initEvents() {
    // Live polling toggle
    const liveBtn = document.getElementById("livePulseBtn");
    liveBtn.addEventListener("click", () => {
      state.livePolling = !state.livePolling;
      liveBtn.classList.toggle("paused", !state.livePolling);
      if (!state.offlineMode) {
        document.getElementById("livePulseLabel").textContent = state.livePolling ? "LIVE" : "PAUSED";
      }
      toast(state.livePolling ? "Live 3s telemetry enabled" : "Live auto-refresh paused", "info");
    });

    // Offline banner manual retry sync
    const retryBtn = document.getElementById("btnRetrySync");
    if (retryBtn) {
      retryBtn.addEventListener("click", async () => {
        try {
          await refreshAll();
          await runAndRenderAudit();
          toast("Reconnected and synced with blockchain node", "ok");
        } catch (err) {
          await handleOfflineFallback(err);
          toast(`Still offline: ${err.message}`, "err");
        }
      });
    }

    // Chart metric toggles
    document.querySelectorAll("[data-chart-metric]").forEach((btn) => {
      btn.addEventListener("click", () => {
        document.querySelectorAll("[data-chart-metric]").forEach((b) => b.classList.remove("active"));
        btn.classList.add("active");
        state.chartMetric = btn.dataset.chartMetric;
        renderTelemetryChart();
      });
    });

    // Registry Table/Card view toggles
    const tableBtn = document.getElementById("viewTableBtn");
    const cardsBtn = document.getElementById("viewCardsBtn");
    tableBtn.addEventListener("click", () => {
      state.registryView = "table";
      tableBtn.classList.add("active");
      cardsBtn.classList.remove("active");
      renderRegistry();
    });
    cardsBtn.addEventListener("click", () => {
      state.registryView = "cards";
      cardsBtn.classList.add("active");
      tableBtn.classList.remove("active");
      renderRegistry();
    });

    // Tabs
    document.querySelectorAll(".tab-btn").forEach((btn) => {
      btn.addEventListener("click", async () => {
        switchTab(btn.dataset.tab);
        if (btn.dataset.tab === "audit") await runAndRenderAudit();
      });
    });

    // Wallet switch
    document.getElementById("walletSelect").addEventListener("change", async (e) => {
      state.activeAddress = e.target.value;
      localStorage.setItem(STORAGE_KEY_ACTIVE, state.activeAddress);
      await renderActiveWalletStats();
      renderRegistry();
      renderGovernance();
    });

    // New wallet
    document.getElementById("btnNewWallet").addEventListener("click", async () => {
      const kp = generateKeypairJS();
      const idx = nextCustomWalletNumber();
      state.customWallets.push({
        id: `custom-${Date.now()}-${idx}`,
        label: `Custom Wallet #${idx}`,
        role: "USER",
        ...kp,
      });
      saveCustomWallets();
      state.activeAddress = kp.address;
      await syncWalletUIAfterChange();
      toast(`Generated Custom Wallet #${idx} (${shortAddr(kp.address)})`, "ok");
    });

    // Manage / Edit / Remove wallets
    document.getElementById("btnManageWallets").addEventListener("click", openWalletManagerModal);
    document.getElementById("btnManageWalletsTab").addEventListener("click", openWalletManagerModal);
    document.getElementById("savedWalletsList").addEventListener("click", async (e) => {
      const editBtn = e.target.closest("button[data-wallet-edit]");
      const delBtn = e.target.closest("button[data-wallet-del]");
      if (editBtn) {
        openWalletManagerModal();
      } else if (delBtn) {
        await removeCustomWallet(delBtn.dataset.walletDel);
      }
    });

    // Faucet
    document.getElementById("btnFaucet").addEventListener("click", async () => {
      try {
        const active = getActiveWallet();
        if (!active) return;
        await api("/api/faucet", "POST", { address: active.address, amount: 250, auto_mine: true });
        await refreshAll();
        await runAndRenderAudit();
        toast(`Credited 250 IPC to ${shortAddr(active.address)}`, "ok");
      } catch (err) {
        toast(err.message, "err");
      }
    });

    // Mining
    const doMine = async () => {
      try {
        const active = getActiveWallet();
        const res = await api("/api/mine", "POST", { miner_address: active ? active.address : "" });
        await refreshAll();
        await runAndRenderAudit();
        toast(
          `Mined Block #${res.block.index} (${res.block.transactions.length} txs, nonce ${res.block.nonce}, ${res.elapsed_ms}ms)`,
          "ok"
        );
      } catch (err) {
        toast(err.message, "err");
      }
    };
    document.getElementById("btnMineHeader").addEventListener("click", doMine);
    document.getElementById("btnMineExplorer").addEventListener("click", doMine);

    // Registry filters
    ["regSearch", "regTypeFilter", "regStatusFilter"].forEach((id) => {
      document.getElementById(id).addEventListener("input", renderRegistry);
      document.getElementById(id).addEventListener("change", renderRegistry);
    });

    // Register file + text hashing
    document.getElementById("regBrowseBtn").addEventListener("click", () => {
      document.getElementById("regFileInput").click();
    });
    setupDropzone(
      document.getElementById("regDropzone"),
      document.getElementById("regFileInput"),
      document.getElementById("regFileMeta"),
      async (file, meta) => {
        regFileBytes = new Uint8Array(await file.arrayBuffer());
        meta.textContent = `Loaded ${file.name} (${file.size} bytes) — hashed locally`;
        if (!document.getElementById("regTitle").value.trim()) {
          document.getElementById("regTitle").value = file.name.slice(0, 120);
        }
        updateRegisterHashes();
      }
    );
    document.getElementById("regText").addEventListener("input", () => {
      if (!document.getElementById("regFileInput").files.length) regFileBytes = null;
      updateRegisterHashes();
    });

    // Prior-art precheck
    document.getElementById("btnPrecheck").addEventListener("click", async () => {
      try {
        const contentHash = document.getElementById("regContentHash").textContent.trim();
        const text = document.getElementById("regText").value;
        if (contentHash === "—") {
          toast("Provide a file or text first", "err");
          return;
        }
        const res = await api("/api/verify", "POST", { content_hash: contentHash, text });
        const box = document.getElementById("regPrecheckBox");
        box.classList.remove("hidden", "alert-ok", "alert-warn", "alert-bad");
        if (res.exact_match) {
          box.classList.add("alert-bad");
          box.textContent = `Blocked: Exact content_hash is already registered under ${res.certificate.ip_asset.ip_id} ("${res.certificate.ip_asset.title}").`;
        } else if (res.similar_prior_art.length) {
          box.classList.add("alert-warn");
          const top = res.similar_prior_art[0];
          box.textContent = `Warning: ${top.similarity_pct}% SimHash similarity to existing IP ${top.ip_id} ("${top.title}").`;
        } else {
          box.classList.add("alert-ok");
          box.textContent = "Clear: No exact collision or SimHash prior-art overlap detected.";
        }
      } catch (err) {
        toast(err.message, "err");
      }
    });

    // Register submit
    document.getElementById("registerForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      try {
        const contentHash = document.getElementById("regContentHash").textContent.trim();
        if (!/^[0-9a-f]{64}$/.test(contentHash)) {
          throw new Error("Drop a file or enter work text to generate SHA-256 content_hash");
        }
        const simhash = document.getElementById("regSimhash").textContent.trim();
        const tags = document
          .getElementById("regTags")
          .value.split(",")
          .map((t) => t.trim())
          .filter(Boolean)
          .slice(0, 8);
        const autoMine = document.getElementById("regAutoMine").checked;
        const payload = {
          title: document.getElementById("regTitle").value.trim(),
          ip_type: document.getElementById("regType").value,
          description:
            document.getElementById("regDescription").value.trim() ||
            document.getElementById("regText").value.trim().slice(0, 500),
          content_hash: contentHash,
          simhash,
          jurisdiction: document.getElementById("regJurisdiction").value.trim() || "GLOBAL",
          royalty_bps: Number(document.getElementById("regRoyalty").value),
          license_price: Number(document.getElementById("regPrice").value),
          allow_public_license: document.getElementById("regPublicLicense").checked,
          default_license_type: document.getElementById("regLicType").value,
          tags,
        };
        const { submitted, mined } = await signAndSubmitTx("REGISTER_IP", payload, autoMine);
        const ipId = submitted.event.ip_id;
        toast(
          mined
            ? `Registered & mined ${ipId} in Block #${mined.block.index}`
            : `Queued registration ${ipId} in mempool`,
          "ok"
        );
      } catch (err) {
        toast(err.message, "err");
      }
    });

    // Verify tab
    document.getElementById("verBrowseBtn").addEventListener("click", () => {
      document.getElementById("verFileInput").click();
    });
    setupDropzone(
      document.getElementById("verDropzone"),
      document.getElementById("verFileInput"),
      document.getElementById("verFileMeta"),
      async (file, meta) => {
        verFileBytes = new Uint8Array(await file.arrayBuffer());
        const hash = sha256Hex(verFileBytes);
        document.getElementById("verHashInput").value = hash;
        try {
          const txt = new TextDecoder("utf-8", { fatal: true }).decode(verFileBytes);
          document.getElementById("verText").value = txt.slice(0, 10000);
        } catch {
          // binary file
        }
        meta.textContent = `Hashed ${file.name} (${shortAddr(hash)})`;
      }
    );
    document.getElementById("btnRunVerify").addEventListener("click", async () => {
      try {
        const res = await api("/api/verify", "POST", {
          content_hash: document.getElementById("verHashInput").value.trim(),
          text: document.getElementById("verText").value,
          ip_id: document.getElementById("verIpIdInput").value.trim(),
        });
        renderVerifyResult(res);
      } catch (err) {
        toast(err.message, "err");
      }
    });

    // Registry action delegation
    document.getElementById("registryGrid").addEventListener("click", async (e) => {
      const btn = e.target.closest("button[data-action]");
      if (!btn) return;
      const action = btn.dataset.action;
      const ipId = btn.dataset.ip;
      const asset = state.assets.find((x) => x.ip_id === ipId);
      if (!asset) return;

      try {
        if (action === "inspect") {
          await inspectIpModal(ipId);
        } else if (action === "buy-license") {
          openModal(
            `Purchase License — ${asset.ip_id}`,
            `
            <form id="modalTxForm" class="stack-form">
              <p>Acquiring <strong>${escapeHtml(asset.default_license_type)}</strong> license for <strong>${escapeHtml(asset.title)}</strong> at <strong>${asset.license_price} IPC</strong> (${(asset.royalty_bps / 100).toFixed(2)}% creator royalty split).</p>
              <label>License Scope<input type="text" id="mScope" required value="Commercial integration & usage rights" /></label>
              <label>Duration (blocks, 0 = perpetual)<input type="number" id="mDur" value="500" min="0" /></label>
              <button type="submit" class="btn btn-accent">Sign, Pay ${asset.license_price} IPC &amp; Mine</button>
            </form>`
          );
          document.getElementById("modalTxForm").onsubmit = async (ev) => {
            ev.preventDefault();
            try {
              await signAndSubmitTx(
                "PURCHASE_LICENSE",
                {
                  ip_id: ipId,
                  license_type: asset.default_license_type === "EXCLUSIVE" ? "COMMERCIAL" : asset.default_license_type,
                  scope: document.getElementById("mScope").value.trim(),
                  duration_blocks: Number(document.getElementById("mDur").value),
                },
                true
              );
              closeModal();
              toast("License purchased & royalty settled on-chain", "ok");
            } catch (err) {
              toast(err.message, "err");
            }
          };
        } else if (action === "transfer") {
          openModal(
            `Transfer IP Ownership — ${asset.ip_id}`,
            `
            <form id="modalTxForm" class="stack-form">
              <label>Recipient Address (0x...)<input type="text" id="mTo" required placeholder="0x..." /></label>
              <label>Transfer Note<input type="text" id="mNote" placeholder="Assignment agreement reference" /></label>
              <button type="submit" class="btn btn-primary">Sign Ownership Transfer &amp; Mine</button>
            </form>`
          );
          document.getElementById("modalTxForm").onsubmit = async (ev) => {
            ev.preventDefault();
            try {
              await signAndSubmitTx(
                "TRANSFER_IP",
                {
                  ip_id: ipId,
                  to_address: document.getElementById("mTo").value.trim().toLowerCase(),
                  note: document.getElementById("mNote").value.trim(),
                },
                true
              );
              closeModal();
              toast(`Transferred ${ipId} ownership`, "ok");
            } catch (err) {
              toast(err.message, "err");
            }
          };
        } else if (action === "grant") {
          openModal(
            `Grant License — ${asset.ip_id}`,
            `
            <form id="modalTxForm" class="stack-form">
              <label>Licensee Address (0x...)<input type="text" id="mLicensee" required placeholder="0x..." /></label>
              <label>License Type
                <select id="mLicType">
                  <option value="NON_EXCLUSIVE">NON_EXCLUSIVE</option>
                  <option value="EXCLUSIVE">EXCLUSIVE</option>
                  <option value="COMMERCIAL">COMMERCIAL</option>
                  <option value="ACADEMIC">ACADEMIC</option>
                  <option value="OPEN_SOURCE">OPEN_SOURCE</option>
                </select>
              </label>
              <label>Scope<input type="text" id="mScope" required value="Authorized licensee usage" /></label>
              <label>Duration (blocks, 0 = perpetual)<input type="number" id="mDur" value="500" min="0" /></label>
              <button type="submit" class="btn btn-primary">Sign Grant &amp; Mine</button>
            </form>`
          );
          document.getElementById("modalTxForm").onsubmit = async (ev) => {
            ev.preventDefault();
            try {
              await signAndSubmitTx(
                "GRANT_LICENSE",
                {
                  ip_id: ipId,
                  licensee: document.getElementById("mLicensee").value.trim().toLowerCase(),
                  license_type: document.getElementById("mLicType").value,
                  scope: document.getElementById("mScope").value.trim(),
                  duration_blocks: Number(document.getElementById("mDur").value),
                  royalty_bps: asset.royalty_bps,
                },
                true
              );
              closeModal();
              toast("License granted & mined", "ok");
            } catch (err) {
              toast(err.message, "err");
            }
          };
        } else if (action === "dispute") {
          openModal(
            `File Prior-Art / Plagiarism Dispute — ${asset.ip_id}`,
            `
            <form id="modalTxForm" class="stack-form">
              <label>Claim Type
                <select id="mClaim">
                  <option value="PRIOR_ART">PRIOR_ART</option>
                  <option value="PLAGIARISM">PLAGIARISM</option>
                  <option value="UNAUTHORIZED_FILING">UNAUTHORIZED_FILING</option>
                  <option value="TRADEMARK_CONFLICT">TRADEMARK_CONFLICT</option>
                </select>
              </label>
              <label>Cited Prior-Art IP ID (optional)<input type="text" id="mPriorArt" placeholder="IP-..." /></label>
              <label>Evidence Description *<textarea id="mDesc" rows="3" required minlength="5" placeholder="Describe prior creation evidence..."></textarea></label>
              <button type="submit" class="btn btn-danger">Sign Dispute Filing &amp; Mine</button>
            </form>`
          );
          document.getElementById("modalTxForm").onsubmit = async (ev) => {
            ev.preventDefault();
            try {
              await signAndSubmitTx(
                "FILE_DISPUTE",
                {
                  accused_ip_id: ipId,
                  prior_art_ip_id: document.getElementById("mPriorArt").value.trim(),
                  claim_type: document.getElementById("mClaim").value,
                  evidence_hash: "",
                  description: document.getElementById("mDesc").value.trim(),
                },
                true
              );
              closeModal();
              toast(`Filed dispute against ${ipId}`, "ok");
            } catch (err) {
              toast(err.message, "err");
            }
          };
        }
      } catch (err) {
        toast(err.message, "err");
      }
    });

    // Governance actions (revoke / arbitrator rule)
    document.getElementById("tab-governance").addEventListener("click", async (e) => {
      const btn = e.target.closest("button[data-action]");
      if (!btn) return;
      const action = btn.dataset.action;
      try {
        if (action === "revoke-license") {
          await signAndSubmitTx(
            "REVOKE_LICENSE",
            { license_id: btn.dataset.lic, reason: "Revoked by IP owner via governance console" },
            true
          );
          toast(`Revoked license ${btn.dataset.lic}`, "ok");
        } else if (action === "rule") {
          await signAndSubmitTx(
            "RESOLVE_DISPUTE",
            {
              dispute_id: btn.dataset.dispute,
              ruling: btn.dataset.ruling,
              ruling_notes: `Arbitrator ruling: ${btn.dataset.ruling}`,
            },
            true
          );
          toast(`Resolved dispute ${btn.dataset.dispute} (${btn.dataset.ruling})`, "ok");
        }
      } catch (err) {
        toast(err.message, "err");
      }
    });

    // Explorer Merkle proof button
    document.getElementById("blocksList").addEventListener("click", async (e) => {
      const btn = e.target.closest("button[data-action='tx-proof']");
      if (!btn) return;
      try {
        const bundle = await api(`/api/tx/${btn.dataset.tx}/proof`);
        const clientOk = verifyMerkleProofJS(bundle.tx_id, bundle.proof, bundle.merkle_root);
        openModal(
          `Merkle Inclusion Proof — ${shortAddr(bundle.tx_id)}`,
          `
          <div class="stack-form">
            <div class="alert ${clientOk ? "alert-ok" : "alert-bad"}">
              Client-side Merkle verification: <strong>${clientOk ? "VALID ✓" : "INVALID"}</strong> (Block #${bundle.block_index})
            </div>
            <div><strong>Tx ID:</strong> <code>${escapeHtml(bundle.tx_id)}</code></div>
            <div><strong>Merkle Root:</strong> <code>${escapeHtml(bundle.merkle_root)}</code></div>
            <div><strong>Steps:</strong>
              ${(bundle.proof || []).length
                ? bundle.proof.map((s, i) => `<div class="proof-step">#${i + 1} (${escapeHtml(s.position)}): <code>${escapeHtml(s.hash)}</code></div>`).join("")
                : `<div class="proof-step">Single transaction in block</div>`}
            </div>
          </div>`
        );
      } catch (err) {
        toast(err.message, "err");
      }
    });

    // Audit & Tamper simulator
    document.getElementById("btnRunAudit").addEventListener("click", runAndRenderAudit);
    document.getElementById("btnSimulateTamper").addEventListener("click", async () => {
      try {
        const block_index = Number(document.getElementById("tamperBlockIdx").value);
        const target = document.getElementById("tamperTarget").value;
        const replacement = document.getElementById("tamperReplacement").value;
        const res = await api("/api/audit/simulate-tamper", "POST", { block_index, target, replacement });
        document.getElementById("tamperResultBox").innerHTML = `
          <div class="alert alert-bad">
            <strong>Attack Detected &amp; Rejected!</strong><br/>
            Simulation: ${escapeHtml(res.simulation)}<br/>
            Failure Caught: <strong>${escapeHtml(res.audit_report.error)}</strong><br/>
            <small>Live persisted ledger remains untouched and valid.</small>
          </div>`;
      } catch (err) {
        toast(err.message, "err");
      }
    });

    // Import wallet & Send IPC
    document.getElementById("btnImportWallet").addEventListener("click", async () => {
      try {
        const priv = document.getElementById("importPrivKey").value.trim().toLowerCase();
        if (!/^[0-9a-f]{64}$/.test(priv)) throw new Error("Private key must be 64 hex chars");
        const pub = privToPubHex(priv);
        const addr = pubToAddress(pub);
        const label = document.getElementById("importLabel").value.trim() || `Imported (${shortAddr(addr)})`;
        if (!getAllWallets(true).some((w) => w.address.toLowerCase() === addr)) {
          state.customWallets.push({ id: `imp-${Date.now()}`, label, role: "USER", private_key: priv, public_key: pub, address: addr });
          saveCustomWallets();
        }
        state.walletPrefs.hidden = state.walletPrefs.hidden.filter((a) => a !== addr);
        saveWalletPrefs();
        state.activeAddress = addr;
        await syncWalletUIAfterChange();
        toast(`Imported wallet ${shortAddr(addr)}`, "ok");
      } catch (err) {
        toast(err.message, "err");
      }
    });

    document.getElementById("btnSendTokens").addEventListener("click", async () => {
      try {
        const to_address = document.getElementById("sendToAddr").value.trim().toLowerCase();
        const amount = Number(document.getElementById("sendAmount").value);
        await signAndSubmitTx("TRANSFER_TOKENS", { to_address, amount }, true);
        toast(`Sent ${amount} IPC to ${shortAddr(to_address)}`, "ok");
      } catch (err) {
        toast(err.message, "err");
      }
    });

    // P2P Peers
    document.getElementById("btnAddPeer").addEventListener("click", async () => {
      try {
        const peer_url = document.getElementById("peerUrlInput").value.trim();
        await api("/api/peers/register", "POST", { peer_url });
        await refreshAll();
        toast(`Registered peer ${peer_url}`, "ok");
      } catch (err) {
        toast(err.message, "err");
      }
    });

    document.getElementById("btnSyncPeers").addEventListener("click", async () => {
      try {
        const res = await api("/api/peers/sync", "POST", {});
        await refreshAll();
        await runAndRenderAudit();
        toast(
          res.replaced
            ? `Synced longer valid chain from ${res.adopted_from} (height #${res.height})`
            : `Local chain is already up to date (height #${res.height})`,
          "ok"
        );
      } catch (err) {
        toast(err.message, "err");
      }
    });

    // Modal close
    document.getElementById("modalClose").addEventListener("click", closeModal);
    document.getElementById("modalBackdrop").addEventListener("click", (e) => {
      if (e.target.id === "modalBackdrop") closeModal();
    });
  }

  // Boot
  window.addEventListener("DOMContentLoaded", async () => {
    loadCustomWallets();
    initEvents();
    try {
      await refreshAll();
      await runAndRenderAudit();
    } catch (err) {
      await handleOfflineFallback(err);
      toast(`Node offline or unreachable: ${err.message}`, "err");
    } finally {
      startLivePolling();
    }
  });
})();
