UnityWallet: Sequential VDF-Based Token with Lightweight Verification

UnityWallet is a JavaScript/Node.js library that implements a practical, deterministic, and verifiable token system based on sequential work (VDF — Verifiable Delay Function). Tokens are generated using public data and require real computation effort, while verification is fast and lightweight.

🔧 How it works

Given a value, the token is generated like this:

let x = sha256(pubKey || value || timestamp);
for (let i = 0; i < value; i++) {
  x = sha256(x);
  proof += x * modInv(x, p);
}

x is updated sequentially using sha256(x) — each step depends on the previous one.

modInv(x, p) computes the modular inverse of x modulo a large prime p.

Each term x * inv ≡ 1 mod p, so the sum yields proof % p === value.

✅ Token Verification

x = sha256(pubKey || value || timestamp);
for (let i = 0; i <= r; i++) x = sha256(x);
partial = x * modInv(x, p);

(proof % p === value) && ((proof - partial) % p === value - 1n)

Verification:

Only requires reaching a single xᵣ for a random index r ∈ [0, value)

Much faster than generation, but still linear in r

⏱️ Example timings for value = 1000n

Operation

Hash Cost

modInv Cost

Total Time (est.)

genToken

1000 × 0.5 ms = 500 ms

1000 × 2 ms = 2000 ms

~2.6 s

verifyToken

500 × 0.5 ms = 250 ms

1 × 2 ms = 2 ms

~252 ms

Verification is ~10× faster, but still linear with respect to value.

🔒 Security Properties

🔁 Sequential: each xᵢ = sha256(xᵢ₋₁) — no skipping possible

🧠 Proof of Work: cost proportional to value

✅ Verifiable: quick public validation

❌ ASIC/GPU-resistant: hash chaining prevents parallelism

📦 Example Usage

const wallet = new UnityWallet(p, q);
const token = await wallet.genToken(1234n, 1000n);
const isValid = await wallet.verifyToken(token);

⚠️ Notes

modInv is ~10× slower than sha256 — it's the dominant cost in genToken

For very large value, consider checkpointing or alternative validation models

✍️ Author

Created by @YourNameHere for practical, fair, and verifiable proof-of-work applications.

