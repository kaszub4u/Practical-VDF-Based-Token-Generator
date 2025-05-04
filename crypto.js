class EventEmitter {
	constructor() {
		this.events = {};
	}
	on(event, listener) {
		if (!this.events[event]) this.events[event] = [];
		this.events[event].push(listener);
	}
	emit(event, data) {
		if (this.events[event]) {
			this.events[event].forEach(fn => fn(data));
		}
	}
}

class UnityWallet extends EventEmitter {
  constructor(p, q) {
    super();
    this.ntru = new NTRU(p, q);
    this.p = p;
  }

  powmod(base, exponent, mod) {
    let result = 1n;
    base = base % mod;
    while (exponent > 0n) {
      if (exponent % 2n === 1n) {
        result = (result * base) % mod;
      }
      exponent = exponent >> 1n;
      base = (base * base) % mod;
    }
    return result;
  }

  async getTokenId(token) {
    return await this.ntru.hashn({
      pubKey: token.pubKey,
      value: token.value,
      timestamp: token.timestamp,
      proof: token.proof
    });
  }

  async genToken(pubKey, value) {
    const timestamp = Date.now();
    const input = pubKey.toString(16) + value.toString(16) + timestamp.toString(16);
    let x = await this.ntru.sha256n(input);

    let proof = 0n;
    for (let i = 0n; i < value; i++) {
      x = await this.ntru.sha256n(x);
      const inv = this.ntru.modInv(x, this.p);
      proof += x * inv;
    }

    return {
      pubKey,
      value,
      timestamp,
      proof,
      transactions: []
    };
    
  }

  async verifyToken(token) {
    const input = token.pubKey.toString(16) + token.value.toString(16) + token.timestamp.toString(16);
    let x = await this.ntru.sha256n(input);

    const r = BigInt(this.ntru.randr(0, Number(token.value - 1n)));
    for (let i = 0n; i <= r; i++) {
      x = await this.ntru.sha256n(x);
    }

    const partial = x * this.ntru.modInv(x, this.p);
    return (token.proof % this.p === token.value) &&
           ((token.proof - partial) % this.p === token.value - 1n);
  }

  async getDepthByTxId(token, txId) {
    let depth = 0n;
    let currentId = txId;

    while (true) {
      const current = await this.findTransactionById(token, currentId);
      if (!current || !current.prevTxId) break;
      currentId = current.prevTxId;
      depth++;
    }

    return depth;
  }

  async findTransactionById(token, targetId) {
    for (const tx of token.transactions) {
      const id = await this.getTxId(tx);
      if (id === targetId) return tx;
    }
    return null;
  }

  getReceivedValue(token, pubKey) {
    return token.transactions
      .filter(tx => tx.data.config.type === "spend" && tx.data.config.to === pubKey)
      .reduce((sum, tx) => sum + tx.data.config.data.value, 0n);
  }

  getSpentValue(token, pubKey) {
    return token.transactions
      .filter(tx => tx.data.config.type === "spend" && tx.data.config.from === pubKey)
      .reduce((sum, tx) => sum + tx.data.config.data.value, 0n);
  }

  getSpendableValue(token, pubKey) {
    const received = (pubKey === token.pubKey) ? token.value : this.getReceivedValue(token, pubKey);
    return received - this.getSpentValue(token, pubKey);
  }

  static async verifyTransaction(tx, ntru) {
    const message = {
      tokenId: tx.tokenId,
      prevTxId: tx.prevTxId,
      data: tx.data
    };
    return await ntru.NTRUVerifySign(message, tx.signature, tx.data.config.from);
  }

  async genTransaction(tokenId, prevTxId, privKey, config) {
    const { from, type = "spend" } = config;

    if (type === "spend") {
      if (typeof config.data?.value !== "bigint") {
        throw new Error("Missing or invalid 'value' in config.data");
      }
      if (!prevTxId) {
        throw new Error("Missing prevTxId for spend transaction");
      }
    }

    const timestamp = Date.now();
    const data = { config, timestamp };
    const message = { tokenId, prevTxId, data };
    const signature = await this.ntru.NTRUSign(message, privKey);

    return {
      tokenId,
      prevTxId,
      data,
      signature
    };
  }

  async getTxId(tx) {
    return await this.ntru.hashn(tx);
  }

  getCurrentOwners(token) {
    const fromSet = new Set(token.transactions.map(tx => tx.data.config.from.toString()));
    const toSet = new Set(token.transactions.map(tx => tx.data.config.to.toString()));
    const leaves = [...toSet].filter(to => !fromSet.has(to));
    return leaves.length ? leaves.map(s => BigInt(s)) : [token.pubKey];
  }
}


const p = 2n**256n - 189n;
const q = 2n**1279n - 1n;

class NTRU {
  constructor(p, q) {
    this.p = p;
    this.q = q;
  }

  randr(min, max) {
    min = Math.ceil(min);
    max = Math.floor(max);
    return Math.floor(Math.random() * (max - min + 1) + min);
  }

  async serialize(data) {
    return await serialize(data);
  }

  async deserialize(data) {
    return await deserialize(data);
  }

	async sha256(data)
	{
		const buffer = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(await this.serialize(data)));
		return [...new Uint8Array(buffer)].map(b => b.toString(16).padStart(2, "0")).join("");		
	}

  async sha256n(data) {
    const hex = (await this.sha256(data));
    return BigInt('0x' + hex);
  }

  str2n(str) {
    const encoded = new TextEncoder().encode(str);
    return this.uint8array2n(encoded);
  }

  n2base64(n) {
    return this.uint8array2base64(this.n2uint8array(n));
  }

  base642n(base64) {
    return this.uint8array2n(this.base642uint8array(base64));
  }

  modInv(a, b) {
    let b0 = b, t, q;
    let x0 = 0n, x1 = 1n;
    if (b == 1n) return 1n;
    while (a > 1n) {
      if (b == 0n) return 1n;
      q = a / b;
      [a, b] = [b, a % b];
      [x0, x1] = [x1 - q * x0, x0];
    }
    if (x1 < 0n) x1 += b0;
    return x1;
  }

  powMod(base, exponent, modulus) {
    if (modulus === 1n) return 0n;
    let result = 1n;
    base = base % modulus;
    while (exponent > 0n) {
      if (exponent % 2n === 1n) result = (result * base) % modulus;
      exponent = exponent >> 1n;
      base = (base * base) % modulus;
    }
    return result;
  }

  async hashn(data, mod = this.p) {
    return this.modInv(await this.sha256n(data), mod);
  }

  genRand(bits = 256n) {
    const bytes = Math.ceil(Number(bits) / 8);
    const uint8arr = crypto.getRandomValues(new Uint8Array(bytes));
    return this.uint8array2n(uint8arr) & this.mask(bits);
  }

  async genHKey(f) {
    f ||= this.genRand(this.msb(this.p));
    f &= this.mask(this.msb(this.p));
    const fh = await this.hashn((f % this.p).toString(16), this.p);
    const fq = this.modInv((f % this.p), this.q);
    return (fh * fq) % this.q;
  }

  async genKeys(f) {
    f ||= this.genRand(this.msb(this.p));
    f &= this.mask(this.msb(this.p));
    return [f, await this.genHKey(f)];
  }

  NTRUEncrypt(m, h, seed = 0n) {
    seed ||= this.genRand(this.msb(this.p));
    seed &= this.mask(this.msb(this.p));
    return (seed * this.p * (h % this.q) + m) % this.q;
  }

  async NTRUDecrypt(e, f) {
    return (((e * f) % this.q) * this.modInv(f, this.p)) % this.p;
  }

  async NTRUSign(msg, f) {
    const m = await this.hashn(msg, this.p);
    const fh = await this.hashn((f % this.p).toString(16), this.p);
    const fhp = this.modInv(fh, this.p);
    return (m * f * fhp);
  }

  async NTRUVerifySign(msg, sign, h) {
    const m = await this.hashn(msg, this.p);
    const d = (sign * h) % this.q % this.p;
    return (m == d) && (!((m * this.modInv(h, this.q)) == sign));
  }

  async NTRUEncode(data, seed) {
    const uint8 = new TextEncoder().encode(await this.serialize(data));
    for (let i = 0n; i < BigInt(uint8.length); i++)
      uint8[i] ^= Number((await this.hashn((seed + i).toString(16), this.p)) & 255n);
    return this.uint8array2base64(uint8);
  }

  async NTRUDecode(base64, seed) {
    const uint8 = this.base642uint8array(base64);
    for (let i = 0n; i < BigInt(uint8.length); i++)
      uint8[i] ^= Number((await this.hashn((seed + i).toString(16), this.p)) & 255n);
    return await this.deserialize(new TextDecoder().decode(uint8));
  }

  async encryptNTRU(data, h, seed = 0n) {
    seed ||= this.genRand(256n);
    seed &= this.mask(this.msb(this.p));
    const ivn = await this.hashn(seed.toString(16), this.p);
    const e = await this.NTRUEncrypt(seed, h, ivn);
    return btoa(this.n2base64(e) + ':' + await this.NTRUEncode(data, ivn));
  }

  async decryptNTRU(encrypted, f) 
  {
		const [e, encoded] = atob(encrypted).split(':');
    let seed = await this.NTRUDecrypt(this.base642n(e), f);
    seed &= this.mask(this.msb(this.p));
    const ivn = await this.hashn(seed.toString(16), this.p);
    return await this.NTRUDecode(encoded, ivn);
  }

  async encrypt(data, password, seed = 0n) 
  {
    const passwordn = this.str2n(await this.serialize(password));
    const [f, h] = await this.genKeys(passwordn);
    return await this.encryptNTRU(data, h, seed);
  }

  async decrypt(encrypted, password) 
  {
    const passwordn = this.str2n(await this.serialize(password));
    const [f, h] = await this.genKeys(passwordn);
    return await this.decryptNTRU(encrypted, f);
  }

  uint8array2n(uint8array) {
    let n = 0n;
    for (let i = uint8array.length - 1; i >= 0; i--)
      n = (n << 8n) | BigInt(uint8array[i]);
    return n;
  }

  n2uint8array(n) {
    let decoded = [];
    let i = 0n;
    while ((n >> (8n * i)) > 0n) {
      decoded.push(Number((n >> (8n * i)) & 255n));
      i += 1n;
    }
    return new Uint8Array(decoded);
  }

  n2str(n) {
    return new TextDecoder().decode(this.n2uint8array(n));
  }

  uint8array2base64(uint8array) {
    return btoa(String.fromCharCode(...uint8array));
  }

  base642uint8array(base64) {
    return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
  }

  mask(n) {
    return (1n << n) - 1n;
  }

  msb(n) {
    let i = 0n;
    while (n > 0n) {
      n >>= 1n;
      i++;
    }
    return i;
  }
} 
