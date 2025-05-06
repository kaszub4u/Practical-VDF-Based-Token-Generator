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
    const output = (await this.ntru.vdf(input, value));

    return {
      pubKey,
      value,
      timestamp,
      output,
      transactions: []
    };
    
  }

	async verifyToken(token) {
		const { pubKey, value, timestamp, output } = token;
		const input = pubKey.toString(16) + value.toString(16) + timestamp.toString(16);
		return (await this.ntru.verifyVdf(input, value, output.y, output.proof));
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

const p = 2n**256n - 587n;
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

	powMod(base, exp, mod) 
	{
		let res = 1n;
		base %= mod;
		while (exp > 0n) {
			if (exp & 1n) res = (res * base) % mod;
			base = (base * base) % mod;
			exp >>= 1n;
		}
		return res;
	}

	async hashn(data, mod = this.p) 
	{
		return ((await this.sha256n(data)) % mod) || 1n;
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

	//VRF
	async vrf(msg, privKey) {
		const output = await this.hashn(msg);                  // pseudolosowy hash
		const signature = await this.NTRUSign(output, privKey); // dowód = podpis
		return { output, signature };
	}

	async verifyVrf(msg, output, signature, pubKey) {
		const expected = await this.hashn(msg); // musimy znać, co podpisano
		if (expected !== output) return false;
		return await this.NTRUVerifySign(output, signature, pubKey);
	}
  
	/*
	async vdf(msg, value)
	{
		const x = await this.hashn(msg);

		let proof = 0n;
		for (let i = 0n; i < value; i++) 
		{
			const inv = this.modInv((x + i), this.p);
			proof += (x + i) * inv;
		}
		return proof;
	}
	
	async verifyVdf(msg, value, proof)
	{
		const x = await this.hashn(msg);

		const r = BigInt(this.randr(0, Number(value - 1n)));
		const partial = (x + r) * this.modInv((x + r), this.p);

		return (proof % this.p === value) &&
			((proof - partial) % this.p === value - 1n);
	
	}
	*/

	//VDF pietrzak
  async vdf(msg, T, N = this.p) {
	  const x = await this.hashn(msg, N);
    if (T === 1n) return { y: this.powMod(x, 2n, N), proof: [] };

    const k = T / 2n;
    const x_k = this.powMod(x, 1n << k, N);
    const r = (await this.hashn(`${x}:${x_k}:${T}`)) % N;

    const x1 = (x_k * this.powMod(x, r, N)) % N;
    const { y, proof } = await this.vdf(x1, k, N);
    return { y, proof: [{ x_k, r }, ...proof] };
  }

  async verifyVdf(msg, T, y, proof, N = this.p) {
	  const x = await this.hashn(msg, N);
    if (T === 1n) return this.powMod(x, 2n, N) === y;

    const k = T / 2n;
    const { x_k, r } = proof[0];
    const r_check = (await this.hashn(`${x}:${x_k}:${T}`)) % N;
    if (r !== r_check) return false;

    const x1 = (x_k * this.powMod(x, r, N)) % N;
    return await this.verifyVdf(x1, k, y, proof.slice(1), N);
  }

	//VDF
	// Funkcja VDF — kosztowna generacja dowodu
	/*
	async vdf(msg, t, mod = this.p) {
	
		const rootExp = (2n * mod - 1n) / 3n; // (2p-1)/3
		let y = await this.hashn(msg, mod);   // x
		for (let i = 0n; i < t; i++)          // t × pierwiastek³
			y = this.powMod(y, rootExp, mod);
		return y;                             // proof
	}

	async verifyVdf(msg, t, y, mod = this.p) {
		const x = await this.hashn(msg, mod);
		let z = y;
		for (let i = 0n; i < t; i++)          // t × kubowanie
			z = this.powMod(z, 3n, mod);        // z ← z³ mod p
		return z === x;
	}
	*/
} 
//NTRU END

// Funkcja serializująca
async function serialize(value) {
  // Obsługa null i undefined
  if (value === null || value === undefined) {
    // Uwaga: JSON.stringify(undefined) zwraca 'undefined' (typ string) 
    // lub może zwrócić samo `undefined` (co nie jest poprawnym JSON-em).
    // Jeśli chcesz mieć pewność, że dla `undefined` zwróci się np. "null", 
    // możesz to zmienić wedle potrzeb.
    return JSON.stringify(value);
  }

  // Obsługuje typy proste (string, boolean)
  if (typeof value === 'string' || typeof value === 'boolean') {
    return JSON.stringify(value);
  }

  // Obsługuje BigInt
  if (typeof value === 'bigint') {
    return JSON.stringify({ type: 'BigInt', value: value.toString() });
  }

  // Obsługuje NaN, Infinity, -Infinity
  if (typeof value === 'number') {
    if (Number.isNaN(value)) {
      return JSON.stringify({ type: 'NaN' });
    }
    if (value === Infinity) {
      return JSON.stringify({ type: 'Infinity' });
    }
    if (value === -Infinity) {
      return JSON.stringify({ type: '-Infinity' });
    }
    return JSON.stringify(value);
  }

  // Obsługuje Date
  if (value instanceof Date) {
    return JSON.stringify({ type: 'Date', value: value.toISOString() });
  }

  // Obsługuje RegExp
  if (value instanceof RegExp) {
    return JSON.stringify({ type: 'RegExp', value: value.toString() });
  }

  // Obsługuje Symbol
  if (typeof value === 'symbol') {
    return JSON.stringify({ type: 'Symbol', value: value.toString() });
  }

  // Obsługuje Map
  if (value instanceof Map) {
    const mapObj = {};
    for (let [k, v] of value.entries()) {
      mapObj[k] = await serialize(v);
    }
    return JSON.stringify({ type: 'Map', value: mapObj });
  }

  // Obsługuje Set
  if (value instanceof Set) {
    const setArray = [];
    for (let v of value) {
      setArray.push(await serialize(v));
    }
    return JSON.stringify({ type: 'Set', value: setArray });
  }

  // Obsługuje WeakMap i WeakSet (nieserializowalne)
  if (value instanceof WeakMap || value instanceof WeakSet) {
    return JSON.stringify({ type: value.constructor.name, value: 'Cannot serialize WeakMap/WeakSet' });
  }

  // Obsługuje File i Blob
  if (value instanceof File || value instanceof Blob) {
    const reader = new FileReader();
    return new Promise((resolve, reject) => {
      reader.onloadend = () => {
        const base64String = reader.result;
        resolve(JSON.stringify({
          type: 'File/Blob',
          name: value.name,
          size: value.size,
          typeMime: value.type,
          content: base64String
        }));
      };
      reader.onerror = reject;
      reader.readAsDataURL(value); // Asynchronicznie konwertujemy zawartość pliku na base64
    });
  }

  // Obsługuje ArrayBuffer
  if (value instanceof ArrayBuffer) {
    return JSON.stringify({ type: 'ArrayBuffer', value: Array.from(new Uint8Array(value)) });
  }

  // Obsługuje TypedArrays (np. Uint8Array, Int8Array itp.)
  if (
    value instanceof Uint8Array ||
    value instanceof Int8Array ||
    value instanceof Int16Array ||
    value instanceof Int32Array ||
    value instanceof Uint16Array ||
    value instanceof Uint32Array ||
    value instanceof Uint8ClampedArray
  ) {
    return JSON.stringify({ type: value.constructor.name, value: Array.from(value) });
  }

  // Obsługuje SharedArrayBuffer (jeśli dostępne)
  if (typeof SharedArrayBuffer !== 'undefined' && value instanceof SharedArrayBuffer) {
    return JSON.stringify({ type: 'SharedArrayBuffer', value: Array.from(new Uint8Array(value)) });
  }

  // Obsługuje funkcje (Function)
  if (typeof value === 'function') {
    return JSON.stringify({ type: 'Function', value: value.toString() });
  }

  // Obsługuje tablice
  if (Array.isArray(value)) {
    const serializedArray = [];
    for (let item of value) {
      serializedArray.push(await serialize(item));
    }
    return JSON.stringify(serializedArray);
  }

  // Obsługuje ogólne obiekty
  if (typeof value === 'object') {
    const obj = {};
	const keys = Object.keys(value).sort(); // 👈 deterministyczna kolejność
	for (let key of keys) {
		obj[key] = await serialize(value[key]);
	}
    return JSON.stringify(obj);
  }

  // Jeśli żadna z powyższych opcji nie pasuje, zwróć oryginalną wartość
  return JSON.stringify(value);
}

// Funkcja deserializująca
async function deserialize(serializedData) {
  const data = JSON.parse(serializedData);

  // *** Obsługa wartości null (kluczowe!) ***
  if (data === null) {
    return null;
  }

  // Obsługuje BigInt
  if (data.type === 'BigInt') {
    return BigInt(data.value);
  }

  // Obsługuje NaN, Infinity, -Infinity
  if (data.type === 'NaN') {
    return NaN;
  }
  if (data.type === 'Infinity') {
    return Infinity;
  }
  if (data.type === '-Infinity') {
    return -Infinity;
  }

  // Obsługuje Symbol
  if (data.type === 'Symbol') {
    return Symbol(data.value);
  }

  // Obsługuje ArrayBuffer
  if (data.type === 'ArrayBuffer') {
    const buffer = new ArrayBuffer(data.value.length);
    new Uint8Array(buffer).set(data.value);
    return buffer;
  }

  // Obsługuje TypedArrays
  if (
    data.type === 'Uint8Array' ||
    data.type === 'Int8Array' ||
    data.type === 'Int16Array' ||
    data.type === 'Int32Array' ||
    data.type === 'Uint16Array' ||
    data.type === 'Uint32Array' ||
    data.type === 'Uint8ClampedArray'
  ) {
    return new globalThis[data.type](data.value);
  }

  // Obsługuje SharedArrayBuffer
  if (data.type === 'SharedArrayBuffer') {
    const buffer = new SharedArrayBuffer(data.value.length);
    new Uint8Array(buffer).set(data.value);
    return buffer;
  }

  // Obsługuje funkcje (Function)
  if (data.type === 'Function') {
    return new Function('return ' + data.value)();
  }

  // Obsługuje File/Blob
  if (data.type === 'File/Blob') {
    const base64Content = data.content;
    const byteCharacters = atob(base64Content.split(',')[1]);
    const byteArrays = new Uint8Array(byteCharacters.length);

    for (let i = 0; i < byteCharacters.length; i++) {
      byteArrays[i] = byteCharacters.charCodeAt(i);
    }

    const blob = new Blob([byteArrays], { type: data.typeMime });
    return new File([blob], data.name, { type: data.typeMime, lastModified: Date.now() });
  }

  // Obsługuje Date
  if (data.type === 'Date') {
    return new Date(data.value);
  }

  // Obsługuje RegExp
  if (data.type === 'RegExp') {
    const match = data.value.match(/^\/(.*)\/([gimsuy]*)$/);
    if (match) {
      return new RegExp(match[1], match[2]);
    }
  }

  // Obsługuje Map
  if (data.type === 'Map') {
    const map = new Map();
    for (let [key, value] of Object.entries(data.value)) {
      map.set(key, await deserialize(value));
    }
    return map;
  }

  // Obsługuje Set
  if (data.type === 'Set') {
    const set = new Set();
    for (let value of data.value) {
      set.add(await deserialize(value));
    }
    return set;
  }

  // Obsługuje WeakMap i WeakSet
  if (data.type === 'WeakMap' || data.type === 'WeakSet') {
    // Nie można ich zserializować i zdeserializować w standardowy sposób
    return data.value;
  }

  // Obsługuje ogólne obiekty (w tym tablice)
  if (typeof data === 'object') {
    // Jeśli to jest tablica, tworzymy nową tablicę:
    const obj = Array.isArray(data) ? [] : {};
    for (let key in data) {
      if (data.hasOwnProperty(key)) {
        obj[key] = await deserialize(data[key]);
      }
    }
    return obj;
  }

  // W innych przypadkach (typ prosty itp.) – zwracamy wprost
  return data;
}
