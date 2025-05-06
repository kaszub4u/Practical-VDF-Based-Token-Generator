# 🔐 UnityWallet — Cryptographic Token Wallet with NTRU & Pietrzak VDF

**UnityWallet** is a JavaScript-based cryptographic token system that includes:

- Asymmetric encryption and signatures using **NTRU** (Post-Quantum safe),
- A time-delay mechanism using **Pietrzak's Verifiable Delay Function (VDF)**,
- Transaction tracking and DAG-based ownership transfer,
- Full serialization/deserialization support for advanced types (`BigInt`, `Map`, `Date`, etc.).

---

## 🚀 Features

- 🧮 Deterministic token identity with timestamp
- ⏳ Proof-of-delay via VDF (Pietrzak)
- 🔐 NTRU-based asymmetric encryption & signing
- ✅ Fast token and transaction verification
- 🔁 Token transfers with full traceability

---

## 📦 Usage

### 1. Generate keys and a token
```js
const wallet = new UnityWallet(p, q);
const [privKey, pubKey] = await wallet.ntru.genKeys();
const token = await wallet.genToken(pubKey, 100n);
2. Verify the token
js
Kopiuj
Edytuj
const isValid = await wallet.verifyToken(token);
3. Create a transaction
js
Kopiuj
Edytuj
const tx = await wallet.genTransaction(tokenId, prevTxId, privKey, {
  from: pubKey,
  to: recipientPubKey,
  type: "spend",
  data: { value: 25n }
});
4. Verify the transaction
js
Kopiuj
Edytuj
const valid = await UnityWallet.verifyTransaction(tx, wallet.ntru);
⏳ VDF Performance
UnityWallet uses a recursive implementation of Pietrzak’s VDF, offering a strong separation between computation and verification time:

T (delay steps)	Proving Time (O(T))	Verifying Time (O(log² T))	Speedup
2⁸ (256)	~256 ops	~88 ops	~3×
2¹² (4096)	~4096 ops	~132 ops	~30×
2¹⁶ (65,536)	~65k ops	~176 ops	~370×
2²⁰ (1,048,576)	~1M ops	~220 ops	~5,000×
2²⁴ (16M)	~16M ops	~264 ops	~70,000×

This makes it ideal for delay-based randomness, anti-front-running, or decentralized time locks.

🔐 NTRU-based Encryption
js
Kopiuj
Edytuj
const encrypted = await wallet.ntru.encrypt(data, password);
const decrypted = await wallet.ntru.decrypt(encrypted, password);
Supports:

Fast key generation

Asymmetric encryption & decryption

Deterministic VRF

Post-quantum safety (NTRU lattice-based)

📂 Serialization
Custom serialize / deserialize functions allow the encoding of:

BigInt, Set, Map, Symbol, Date, RegExp, File, etc.

Fully deterministic object ordering (for hashing & signing)

🔧 Installation
No bundler required. You can use it in the browser or import as an ES module.

📈 Future Plans
Full DAG ownership model

Token metadata and lock-in rules

Transaction weighting / fee system

Aggregate signatures

Created by @YourNameHere for practical, fair, and verifiable proof-of-work applications.

MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the “Software”), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
