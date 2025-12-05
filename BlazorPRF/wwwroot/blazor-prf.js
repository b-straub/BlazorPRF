// src/utils.ts
function zeroFill(buffer) {
  buffer.fill(0);
}
function toBase64(data) {
  return btoa(String.fromCharCode(...data));
}
function fromBase64(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
function arrayBufferToBase64(buffer) {
  return toBase64(new Uint8Array(buffer));
}
function base64ToArrayBuffer(base64) {
  return fromBase64(base64).buffer;
}

// src/webauthn.ts
async function checkPrfSupport() {
  if (!window.PublicKeyCredential) {
    return false;
  }
  if (typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === "function") {
    const available = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    if (!available) {
      return false;
    }
  }
  return true;
}
async function registerCredentialWithPrf(displayName, options) {
  try {
    const userId = crypto.getRandomValues(new Uint8Array(16));
    const effectiveDisplayName = displayName ?? options.rpName;
    const authenticatorAttachment = options.authenticatorAttachment === "platform" ? "platform" : "cross-platform";
    const publicKeyCredentialCreationOptions = {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rp: {
        name: options.rpName,
        id: options.rpId ?? window.location.hostname
      },
      user: {
        id: userId,
        name: effectiveDisplayName,
        // Required by spec
        displayName: effectiveDisplayName
      },
      pubKeyCredParams: [
        { alg: -7, type: "public-key" },
        // ES256 (P-256)
        { alg: -257, type: "public-key" }
        // RS256
      ],
      authenticatorSelection: {
        authenticatorAttachment,
        residentKey: "required",
        userVerification: "discouraged"
      },
      timeout: options.timeoutMs,
      attestation: "none",
      extensions: {
        prf: {}
      }
    };
    const credential = await navigator.credentials.create({
      publicKey: publicKeyCredentialCreationOptions
    });
    if (credential === null) {
      return {
        success: false,
        cancelled: true
      };
    }
    const extensionResults = credential.getClientExtensionResults();
    if (!extensionResults.prf?.enabled) {
      return {
        success: false,
        errorCode: "PrfNotSupported" /* PrfNotSupported */
      };
    }
    return {
      success: true,
      value: {
        id: credential.id,
        rawId: arrayBufferToBase64(credential.rawId)
      }
    };
  } catch (error) {
    if (error instanceof DOMException && error.name === "NotAllowedError") {
      return {
        success: false,
        cancelled: true
      };
    }
    return {
      success: false,
      errorCode: "RegistrationFailed" /* RegistrationFailed */
    };
  }
}

// node_modules/@noble/hashes/esm/crypto.js
var crypto2 = typeof globalThis === "object" && "crypto" in globalThis ? globalThis.crypto : void 0;

// node_modules/@noble/hashes/esm/utils.js
function isBytes(a) {
  return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array";
}
function anumber(n) {
  if (!Number.isSafeInteger(n) || n < 0)
    throw new Error("positive integer expected, got " + n);
}
function abytes(b, ...lengths) {
  if (!isBytes(b))
    throw new Error("Uint8Array expected");
  if (lengths.length > 0 && !lengths.includes(b.length))
    throw new Error("Uint8Array expected of length " + lengths + ", got length=" + b.length);
}
function ahash(h) {
  if (typeof h !== "function" || typeof h.create !== "function")
    throw new Error("Hash should be wrapped by utils.createHasher");
  anumber(h.outputLen);
  anumber(h.blockLen);
}
function aexists(instance, checkFinished = true) {
  if (instance.destroyed)
    throw new Error("Hash instance has been destroyed");
  if (checkFinished && instance.finished)
    throw new Error("Hash#digest() has already been called");
}
function aoutput(out, instance) {
  abytes(out);
  const min = instance.outputLen;
  if (out.length < min) {
    throw new Error("digestInto() expects output buffer of length at least " + min);
  }
}
function clean(...arrays) {
  for (let i = 0; i < arrays.length; i++) {
    arrays[i].fill(0);
  }
}
function createView(arr) {
  return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
}
function rotr(word, shift) {
  return word << 32 - shift | word >>> shift;
}
var hasHexBuiltin = /* @__PURE__ */ (() => (
  // @ts-ignore
  typeof Uint8Array.from([]).toHex === "function" && typeof Uint8Array.fromHex === "function"
))();
var hexes = /* @__PURE__ */ Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, "0"));
function bytesToHex(bytes) {
  abytes(bytes);
  if (hasHexBuiltin)
    return bytes.toHex();
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += hexes[bytes[i]];
  }
  return hex;
}
var asciis = { _0: 48, _9: 57, A: 65, F: 70, a: 97, f: 102 };
function asciiToBase16(ch) {
  if (ch >= asciis._0 && ch <= asciis._9)
    return ch - asciis._0;
  if (ch >= asciis.A && ch <= asciis.F)
    return ch - (asciis.A - 10);
  if (ch >= asciis.a && ch <= asciis.f)
    return ch - (asciis.a - 10);
  return;
}
function hexToBytes(hex) {
  if (typeof hex !== "string")
    throw new Error("hex string expected, got " + typeof hex);
  if (hasHexBuiltin)
    return Uint8Array.fromHex(hex);
  const hl = hex.length;
  const al = hl / 2;
  if (hl % 2)
    throw new Error("hex string expected, got unpadded hex of length " + hl);
  const array = new Uint8Array(al);
  for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
    const n1 = asciiToBase16(hex.charCodeAt(hi));
    const n2 = asciiToBase16(hex.charCodeAt(hi + 1));
    if (n1 === void 0 || n2 === void 0) {
      const char = hex[hi] + hex[hi + 1];
      throw new Error('hex string expected, got non-hex character "' + char + '" at index ' + hi);
    }
    array[ai] = n1 * 16 + n2;
  }
  return array;
}
function utf8ToBytes(str) {
  if (typeof str !== "string")
    throw new Error("string expected");
  return new Uint8Array(new TextEncoder().encode(str));
}
function toBytes(data) {
  if (typeof data === "string")
    data = utf8ToBytes(data);
  abytes(data);
  return data;
}
function concatBytes(...arrays) {
  let sum = 0;
  for (let i = 0; i < arrays.length; i++) {
    const a = arrays[i];
    abytes(a);
    sum += a.length;
  }
  const res = new Uint8Array(sum);
  for (let i = 0, pad = 0; i < arrays.length; i++) {
    const a = arrays[i];
    res.set(a, pad);
    pad += a.length;
  }
  return res;
}
var Hash = class {
};
function createHasher(hashCons) {
  const hashC = (msg) => hashCons().update(toBytes(msg)).digest();
  const tmp = hashCons();
  hashC.outputLen = tmp.outputLen;
  hashC.blockLen = tmp.blockLen;
  hashC.create = () => hashCons();
  return hashC;
}
function randomBytes(bytesLength = 32) {
  if (crypto2 && typeof crypto2.getRandomValues === "function") {
    return crypto2.getRandomValues(new Uint8Array(bytesLength));
  }
  if (crypto2 && typeof crypto2.randomBytes === "function") {
    return Uint8Array.from(crypto2.randomBytes(bytesLength));
  }
  throw new Error("crypto.getRandomValues must be defined");
}

// node_modules/@noble/hashes/esm/_md.js
function setBigUint64(view, byteOffset, value, isLE2) {
  if (typeof view.setBigUint64 === "function")
    return view.setBigUint64(byteOffset, value, isLE2);
  const _32n2 = BigInt(32);
  const _u32_max = BigInt(4294967295);
  const wh = Number(value >> _32n2 & _u32_max);
  const wl = Number(value & _u32_max);
  const h = isLE2 ? 4 : 0;
  const l = isLE2 ? 0 : 4;
  view.setUint32(byteOffset + h, wh, isLE2);
  view.setUint32(byteOffset + l, wl, isLE2);
}
function Chi(a, b, c) {
  return a & b ^ ~a & c;
}
function Maj(a, b, c) {
  return a & b ^ a & c ^ b & c;
}
var HashMD = class extends Hash {
  constructor(blockLen, outputLen, padOffset, isLE2) {
    super();
    this.finished = false;
    this.length = 0;
    this.pos = 0;
    this.destroyed = false;
    this.blockLen = blockLen;
    this.outputLen = outputLen;
    this.padOffset = padOffset;
    this.isLE = isLE2;
    this.buffer = new Uint8Array(blockLen);
    this.view = createView(this.buffer);
  }
  update(data) {
    aexists(this);
    data = toBytes(data);
    abytes(data);
    const { view, buffer, blockLen } = this;
    const len = data.length;
    for (let pos = 0; pos < len; ) {
      const take = Math.min(blockLen - this.pos, len - pos);
      if (take === blockLen) {
        const dataView = createView(data);
        for (; blockLen <= len - pos; pos += blockLen)
          this.process(dataView, pos);
        continue;
      }
      buffer.set(data.subarray(pos, pos + take), this.pos);
      this.pos += take;
      pos += take;
      if (this.pos === blockLen) {
        this.process(view, 0);
        this.pos = 0;
      }
    }
    this.length += data.length;
    this.roundClean();
    return this;
  }
  digestInto(out) {
    aexists(this);
    aoutput(out, this);
    this.finished = true;
    const { buffer, view, blockLen, isLE: isLE2 } = this;
    let { pos } = this;
    buffer[pos++] = 128;
    clean(this.buffer.subarray(pos));
    if (this.padOffset > blockLen - pos) {
      this.process(view, 0);
      pos = 0;
    }
    for (let i = pos; i < blockLen; i++)
      buffer[i] = 0;
    setBigUint64(view, blockLen - 8, BigInt(this.length * 8), isLE2);
    this.process(view, 0);
    const oview = createView(out);
    const len = this.outputLen;
    if (len % 4)
      throw new Error("_sha2: outputLen should be aligned to 32bit");
    const outLen = len / 4;
    const state = this.get();
    if (outLen > state.length)
      throw new Error("_sha2: outputLen bigger than state");
    for (let i = 0; i < outLen; i++)
      oview.setUint32(4 * i, state[i], isLE2);
  }
  digest() {
    const { buffer, outputLen } = this;
    this.digestInto(buffer);
    const res = buffer.slice(0, outputLen);
    this.destroy();
    return res;
  }
  _cloneInto(to) {
    to || (to = new this.constructor());
    to.set(...this.get());
    const { blockLen, buffer, length, finished, destroyed, pos } = this;
    to.destroyed = destroyed;
    to.finished = finished;
    to.length = length;
    to.pos = pos;
    if (length % blockLen)
      to.buffer.set(buffer);
    return to;
  }
  clone() {
    return this._cloneInto();
  }
};
var SHA256_IV = /* @__PURE__ */ Uint32Array.from([
  1779033703,
  3144134277,
  1013904242,
  2773480762,
  1359893119,
  2600822924,
  528734635,
  1541459225
]);
var SHA512_IV = /* @__PURE__ */ Uint32Array.from([
  1779033703,
  4089235720,
  3144134277,
  2227873595,
  1013904242,
  4271175723,
  2773480762,
  1595750129,
  1359893119,
  2917565137,
  2600822924,
  725511199,
  528734635,
  4215389547,
  1541459225,
  327033209
]);

// node_modules/@noble/hashes/esm/_u64.js
var U32_MASK64 = /* @__PURE__ */ BigInt(2 ** 32 - 1);
var _32n = /* @__PURE__ */ BigInt(32);
function fromBig(n, le = false) {
  if (le)
    return { h: Number(n & U32_MASK64), l: Number(n >> _32n & U32_MASK64) };
  return { h: Number(n >> _32n & U32_MASK64) | 0, l: Number(n & U32_MASK64) | 0 };
}
function split(lst, le = false) {
  const len = lst.length;
  let Ah = new Uint32Array(len);
  let Al = new Uint32Array(len);
  for (let i = 0; i < len; i++) {
    const { h, l } = fromBig(lst[i], le);
    [Ah[i], Al[i]] = [h, l];
  }
  return [Ah, Al];
}
var shrSH = (h, _l, s) => h >>> s;
var shrSL = (h, l, s) => h << 32 - s | l >>> s;
var rotrSH = (h, l, s) => h >>> s | l << 32 - s;
var rotrSL = (h, l, s) => h << 32 - s | l >>> s;
var rotrBH = (h, l, s) => h << 64 - s | l >>> s - 32;
var rotrBL = (h, l, s) => h >>> s - 32 | l << 64 - s;
function add(Ah, Al, Bh, Bl) {
  const l = (Al >>> 0) + (Bl >>> 0);
  return { h: Ah + Bh + (l / 2 ** 32 | 0) | 0, l: l | 0 };
}
var add3L = (Al, Bl, Cl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0);
var add3H = (low, Ah, Bh, Ch) => Ah + Bh + Ch + (low / 2 ** 32 | 0) | 0;
var add4L = (Al, Bl, Cl, Dl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0);
var add4H = (low, Ah, Bh, Ch, Dh) => Ah + Bh + Ch + Dh + (low / 2 ** 32 | 0) | 0;
var add5L = (Al, Bl, Cl, Dl, El) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0) + (El >>> 0);
var add5H = (low, Ah, Bh, Ch, Dh, Eh) => Ah + Bh + Ch + Dh + Eh + (low / 2 ** 32 | 0) | 0;

// node_modules/@noble/hashes/esm/sha2.js
var SHA256_K = /* @__PURE__ */ Uint32Array.from([
  1116352408,
  1899447441,
  3049323471,
  3921009573,
  961987163,
  1508970993,
  2453635748,
  2870763221,
  3624381080,
  310598401,
  607225278,
  1426881987,
  1925078388,
  2162078206,
  2614888103,
  3248222580,
  3835390401,
  4022224774,
  264347078,
  604807628,
  770255983,
  1249150122,
  1555081692,
  1996064986,
  2554220882,
  2821834349,
  2952996808,
  3210313671,
  3336571891,
  3584528711,
  113926993,
  338241895,
  666307205,
  773529912,
  1294757372,
  1396182291,
  1695183700,
  1986661051,
  2177026350,
  2456956037,
  2730485921,
  2820302411,
  3259730800,
  3345764771,
  3516065817,
  3600352804,
  4094571909,
  275423344,
  430227734,
  506948616,
  659060556,
  883997877,
  958139571,
  1322822218,
  1537002063,
  1747873779,
  1955562222,
  2024104815,
  2227730452,
  2361852424,
  2428436474,
  2756734187,
  3204031479,
  3329325298
]);
var SHA256_W = /* @__PURE__ */ new Uint32Array(64);
var SHA256 = class extends HashMD {
  constructor(outputLen = 32) {
    super(64, outputLen, 8, false);
    this.A = SHA256_IV[0] | 0;
    this.B = SHA256_IV[1] | 0;
    this.C = SHA256_IV[2] | 0;
    this.D = SHA256_IV[3] | 0;
    this.E = SHA256_IV[4] | 0;
    this.F = SHA256_IV[5] | 0;
    this.G = SHA256_IV[6] | 0;
    this.H = SHA256_IV[7] | 0;
  }
  get() {
    const { A, B, C, D, E, F, G, H } = this;
    return [A, B, C, D, E, F, G, H];
  }
  // prettier-ignore
  set(A, B, C, D, E, F, G, H) {
    this.A = A | 0;
    this.B = B | 0;
    this.C = C | 0;
    this.D = D | 0;
    this.E = E | 0;
    this.F = F | 0;
    this.G = G | 0;
    this.H = H | 0;
  }
  process(view, offset) {
    for (let i = 0; i < 16; i++, offset += 4)
      SHA256_W[i] = view.getUint32(offset, false);
    for (let i = 16; i < 64; i++) {
      const W15 = SHA256_W[i - 15];
      const W2 = SHA256_W[i - 2];
      const s0 = rotr(W15, 7) ^ rotr(W15, 18) ^ W15 >>> 3;
      const s1 = rotr(W2, 17) ^ rotr(W2, 19) ^ W2 >>> 10;
      SHA256_W[i] = s1 + SHA256_W[i - 7] + s0 + SHA256_W[i - 16] | 0;
    }
    let { A, B, C, D, E, F, G, H } = this;
    for (let i = 0; i < 64; i++) {
      const sigma1 = rotr(E, 6) ^ rotr(E, 11) ^ rotr(E, 25);
      const T1 = H + sigma1 + Chi(E, F, G) + SHA256_K[i] + SHA256_W[i] | 0;
      const sigma0 = rotr(A, 2) ^ rotr(A, 13) ^ rotr(A, 22);
      const T2 = sigma0 + Maj(A, B, C) | 0;
      H = G;
      G = F;
      F = E;
      E = D + T1 | 0;
      D = C;
      C = B;
      B = A;
      A = T1 + T2 | 0;
    }
    A = A + this.A | 0;
    B = B + this.B | 0;
    C = C + this.C | 0;
    D = D + this.D | 0;
    E = E + this.E | 0;
    F = F + this.F | 0;
    G = G + this.G | 0;
    H = H + this.H | 0;
    this.set(A, B, C, D, E, F, G, H);
  }
  roundClean() {
    clean(SHA256_W);
  }
  destroy() {
    this.set(0, 0, 0, 0, 0, 0, 0, 0);
    clean(this.buffer);
  }
};
var K512 = /* @__PURE__ */ (() => split([
  "0x428a2f98d728ae22",
  "0x7137449123ef65cd",
  "0xb5c0fbcfec4d3b2f",
  "0xe9b5dba58189dbbc",
  "0x3956c25bf348b538",
  "0x59f111f1b605d019",
  "0x923f82a4af194f9b",
  "0xab1c5ed5da6d8118",
  "0xd807aa98a3030242",
  "0x12835b0145706fbe",
  "0x243185be4ee4b28c",
  "0x550c7dc3d5ffb4e2",
  "0x72be5d74f27b896f",
  "0x80deb1fe3b1696b1",
  "0x9bdc06a725c71235",
  "0xc19bf174cf692694",
  "0xe49b69c19ef14ad2",
  "0xefbe4786384f25e3",
  "0x0fc19dc68b8cd5b5",
  "0x240ca1cc77ac9c65",
  "0x2de92c6f592b0275",
  "0x4a7484aa6ea6e483",
  "0x5cb0a9dcbd41fbd4",
  "0x76f988da831153b5",
  "0x983e5152ee66dfab",
  "0xa831c66d2db43210",
  "0xb00327c898fb213f",
  "0xbf597fc7beef0ee4",
  "0xc6e00bf33da88fc2",
  "0xd5a79147930aa725",
  "0x06ca6351e003826f",
  "0x142929670a0e6e70",
  "0x27b70a8546d22ffc",
  "0x2e1b21385c26c926",
  "0x4d2c6dfc5ac42aed",
  "0x53380d139d95b3df",
  "0x650a73548baf63de",
  "0x766a0abb3c77b2a8",
  "0x81c2c92e47edaee6",
  "0x92722c851482353b",
  "0xa2bfe8a14cf10364",
  "0xa81a664bbc423001",
  "0xc24b8b70d0f89791",
  "0xc76c51a30654be30",
  "0xd192e819d6ef5218",
  "0xd69906245565a910",
  "0xf40e35855771202a",
  "0x106aa07032bbd1b8",
  "0x19a4c116b8d2d0c8",
  "0x1e376c085141ab53",
  "0x2748774cdf8eeb99",
  "0x34b0bcb5e19b48a8",
  "0x391c0cb3c5c95a63",
  "0x4ed8aa4ae3418acb",
  "0x5b9cca4f7763e373",
  "0x682e6ff3d6b2b8a3",
  "0x748f82ee5defb2fc",
  "0x78a5636f43172f60",
  "0x84c87814a1f0ab72",
  "0x8cc702081a6439ec",
  "0x90befffa23631e28",
  "0xa4506cebde82bde9",
  "0xbef9a3f7b2c67915",
  "0xc67178f2e372532b",
  "0xca273eceea26619c",
  "0xd186b8c721c0c207",
  "0xeada7dd6cde0eb1e",
  "0xf57d4f7fee6ed178",
  "0x06f067aa72176fba",
  "0x0a637dc5a2c898a6",
  "0x113f9804bef90dae",
  "0x1b710b35131c471b",
  "0x28db77f523047d84",
  "0x32caab7b40c72493",
  "0x3c9ebe0a15c9bebc",
  "0x431d67c49c100d4c",
  "0x4cc5d4becb3e42b6",
  "0x597f299cfc657e2a",
  "0x5fcb6fab3ad6faec",
  "0x6c44198c4a475817"
].map((n) => BigInt(n))))();
var SHA512_Kh = /* @__PURE__ */ (() => K512[0])();
var SHA512_Kl = /* @__PURE__ */ (() => K512[1])();
var SHA512_W_H = /* @__PURE__ */ new Uint32Array(80);
var SHA512_W_L = /* @__PURE__ */ new Uint32Array(80);
var SHA512 = class extends HashMD {
  constructor(outputLen = 64) {
    super(128, outputLen, 16, false);
    this.Ah = SHA512_IV[0] | 0;
    this.Al = SHA512_IV[1] | 0;
    this.Bh = SHA512_IV[2] | 0;
    this.Bl = SHA512_IV[3] | 0;
    this.Ch = SHA512_IV[4] | 0;
    this.Cl = SHA512_IV[5] | 0;
    this.Dh = SHA512_IV[6] | 0;
    this.Dl = SHA512_IV[7] | 0;
    this.Eh = SHA512_IV[8] | 0;
    this.El = SHA512_IV[9] | 0;
    this.Fh = SHA512_IV[10] | 0;
    this.Fl = SHA512_IV[11] | 0;
    this.Gh = SHA512_IV[12] | 0;
    this.Gl = SHA512_IV[13] | 0;
    this.Hh = SHA512_IV[14] | 0;
    this.Hl = SHA512_IV[15] | 0;
  }
  // prettier-ignore
  get() {
    const { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
    return [Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl];
  }
  // prettier-ignore
  set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl) {
    this.Ah = Ah | 0;
    this.Al = Al | 0;
    this.Bh = Bh | 0;
    this.Bl = Bl | 0;
    this.Ch = Ch | 0;
    this.Cl = Cl | 0;
    this.Dh = Dh | 0;
    this.Dl = Dl | 0;
    this.Eh = Eh | 0;
    this.El = El | 0;
    this.Fh = Fh | 0;
    this.Fl = Fl | 0;
    this.Gh = Gh | 0;
    this.Gl = Gl | 0;
    this.Hh = Hh | 0;
    this.Hl = Hl | 0;
  }
  process(view, offset) {
    for (let i = 0; i < 16; i++, offset += 4) {
      SHA512_W_H[i] = view.getUint32(offset);
      SHA512_W_L[i] = view.getUint32(offset += 4);
    }
    for (let i = 16; i < 80; i++) {
      const W15h = SHA512_W_H[i - 15] | 0;
      const W15l = SHA512_W_L[i - 15] | 0;
      const s0h = rotrSH(W15h, W15l, 1) ^ rotrSH(W15h, W15l, 8) ^ shrSH(W15h, W15l, 7);
      const s0l = rotrSL(W15h, W15l, 1) ^ rotrSL(W15h, W15l, 8) ^ shrSL(W15h, W15l, 7);
      const W2h = SHA512_W_H[i - 2] | 0;
      const W2l = SHA512_W_L[i - 2] | 0;
      const s1h = rotrSH(W2h, W2l, 19) ^ rotrBH(W2h, W2l, 61) ^ shrSH(W2h, W2l, 6);
      const s1l = rotrSL(W2h, W2l, 19) ^ rotrBL(W2h, W2l, 61) ^ shrSL(W2h, W2l, 6);
      const SUMl = add4L(s0l, s1l, SHA512_W_L[i - 7], SHA512_W_L[i - 16]);
      const SUMh = add4H(SUMl, s0h, s1h, SHA512_W_H[i - 7], SHA512_W_H[i - 16]);
      SHA512_W_H[i] = SUMh | 0;
      SHA512_W_L[i] = SUMl | 0;
    }
    let { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
    for (let i = 0; i < 80; i++) {
      const sigma1h = rotrSH(Eh, El, 14) ^ rotrSH(Eh, El, 18) ^ rotrBH(Eh, El, 41);
      const sigma1l = rotrSL(Eh, El, 14) ^ rotrSL(Eh, El, 18) ^ rotrBL(Eh, El, 41);
      const CHIh = Eh & Fh ^ ~Eh & Gh;
      const CHIl = El & Fl ^ ~El & Gl;
      const T1ll = add5L(Hl, sigma1l, CHIl, SHA512_Kl[i], SHA512_W_L[i]);
      const T1h = add5H(T1ll, Hh, sigma1h, CHIh, SHA512_Kh[i], SHA512_W_H[i]);
      const T1l = T1ll | 0;
      const sigma0h = rotrSH(Ah, Al, 28) ^ rotrBH(Ah, Al, 34) ^ rotrBH(Ah, Al, 39);
      const sigma0l = rotrSL(Ah, Al, 28) ^ rotrBL(Ah, Al, 34) ^ rotrBL(Ah, Al, 39);
      const MAJh = Ah & Bh ^ Ah & Ch ^ Bh & Ch;
      const MAJl = Al & Bl ^ Al & Cl ^ Bl & Cl;
      Hh = Gh | 0;
      Hl = Gl | 0;
      Gh = Fh | 0;
      Gl = Fl | 0;
      Fh = Eh | 0;
      Fl = El | 0;
      ({ h: Eh, l: El } = add(Dh | 0, Dl | 0, T1h | 0, T1l | 0));
      Dh = Ch | 0;
      Dl = Cl | 0;
      Ch = Bh | 0;
      Cl = Bl | 0;
      Bh = Ah | 0;
      Bl = Al | 0;
      const All = add3L(T1l, sigma0l, MAJl);
      Ah = add3H(All, T1h, sigma0h, MAJh);
      Al = All | 0;
    }
    ({ h: Ah, l: Al } = add(this.Ah | 0, this.Al | 0, Ah | 0, Al | 0));
    ({ h: Bh, l: Bl } = add(this.Bh | 0, this.Bl | 0, Bh | 0, Bl | 0));
    ({ h: Ch, l: Cl } = add(this.Ch | 0, this.Cl | 0, Ch | 0, Cl | 0));
    ({ h: Dh, l: Dl } = add(this.Dh | 0, this.Dl | 0, Dh | 0, Dl | 0));
    ({ h: Eh, l: El } = add(this.Eh | 0, this.El | 0, Eh | 0, El | 0));
    ({ h: Fh, l: Fl } = add(this.Fh | 0, this.Fl | 0, Fh | 0, Fl | 0));
    ({ h: Gh, l: Gl } = add(this.Gh | 0, this.Gl | 0, Gh | 0, Gl | 0));
    ({ h: Hh, l: Hl } = add(this.Hh | 0, this.Hl | 0, Hh | 0, Hl | 0));
    this.set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl);
  }
  roundClean() {
    clean(SHA512_W_H, SHA512_W_L);
  }
  destroy() {
    clean(this.buffer);
    this.set(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
  }
};
var sha256 = /* @__PURE__ */ createHasher(() => new SHA256());
var sha512 = /* @__PURE__ */ createHasher(() => new SHA512());

// node_modules/@noble/hashes/esm/sha256.js
var sha2562 = sha256;

// src/prf.ts
async function evaluatePrf(credentialIdBase64, salt, options) {
  let prfOutput = null;
  try {
    const encoder = new TextEncoder();
    const saltBytes = encoder.encode(salt);
    const saltHash = sha2562(saltBytes);
    const credentialId = base64ToArrayBuffer(credentialIdBase64);
    const transports = options.authenticatorAttachment === "platform" ? ["internal"] : ["internal", "usb", "nfc", "ble"];
    const publicKeyCredentialRequestOptions = {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      allowCredentials: [
        {
          id: credentialId,
          type: "public-key",
          transports
        }
      ],
      timeout: options.timeoutMs,
      userVerification: "required",
      extensions: {
        prf: {
          eval: {
            first: saltHash.buffer
          }
        }
      }
    };
    const assertion = await navigator.credentials.get({
      publicKey: publicKeyCredentialRequestOptions
    });
    if (assertion === null) {
      return {
        success: false,
        cancelled: true
      };
    }
    const extensionResults = assertion.getClientExtensionResults();
    const prfResults = extensionResults.prf?.results;
    if (!prfResults?.first) {
      return {
        success: false,
        errorCode: "PrfNotSupported" /* PrfNotSupported */
      };
    }
    prfOutput = new Uint8Array(prfResults.first);
    if (prfOutput.length !== 32) {
      return {
        success: false,
        errorCode: "KeyDerivationFailed" /* KeyDerivationFailed */
      };
    }
    const resultBase64 = toBase64(prfOutput);
    return {
      success: true,
      value: resultBase64
    };
  } catch (error) {
    if (error instanceof DOMException && error.name === "NotAllowedError") {
      return {
        success: false,
        cancelled: true
      };
    }
    return {
      success: false,
      errorCode: "KeyDerivationFailed" /* KeyDerivationFailed */
    };
  } finally {
    if (prfOutput) {
      zeroFill(prfOutput);
    }
  }
}
async function evaluatePrfDiscoverable(salt, options) {
  let prfOutput = null;
  try {
    const encoder = new TextEncoder();
    const saltBytes = encoder.encode(salt);
    const saltHash = sha2562(saltBytes);
    const publicKeyCredentialRequestOptions = {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rpId: options.rpId ?? window.location.hostname,
      timeout: options.timeoutMs,
      userVerification: "required",
      extensions: {
        prf: {
          eval: {
            first: saltHash.buffer
          }
        }
      }
    };
    const assertion = await navigator.credentials.get({
      publicKey: publicKeyCredentialRequestOptions
    });
    if (assertion === null) {
      return {
        success: false,
        cancelled: true
      };
    }
    const extensionResults = assertion.getClientExtensionResults();
    const prfResults = extensionResults.prf?.results;
    if (!prfResults?.first) {
      return {
        success: false,
        errorCode: "PrfNotSupported" /* PrfNotSupported */
      };
    }
    prfOutput = new Uint8Array(prfResults.first);
    if (prfOutput.length !== 32) {
      return {
        success: false,
        errorCode: "KeyDerivationFailed" /* KeyDerivationFailed */
      };
    }
    const resultBase64 = toBase64(prfOutput);
    const credentialIdBase64 = toBase64(new Uint8Array(assertion.rawId));
    return {
      success: true,
      value: {
        credentialId: credentialIdBase64,
        prfOutput: resultBase64
      }
    };
  } catch (error) {
    if (error instanceof DOMException && error.name === "NotAllowedError") {
      return {
        success: false,
        cancelled: true
      };
    }
    return {
      success: false,
      errorCode: "KeyDerivationFailed" /* KeyDerivationFailed */
    };
  } finally {
    if (prfOutput) {
      zeroFill(prfOutput);
    }
  }
}

// node_modules/@noble/curves/esm/utils.js
var _0n = /* @__PURE__ */ BigInt(0);
var _1n = /* @__PURE__ */ BigInt(1);
function _abool2(value, title = "") {
  if (typeof value !== "boolean") {
    const prefix = title && `"${title}"`;
    throw new Error(prefix + "expected boolean, got type=" + typeof value);
  }
  return value;
}
function _abytes2(value, length, title = "") {
  const bytes = isBytes(value);
  const len = value?.length;
  const needsLen = length !== void 0;
  if (!bytes || needsLen && len !== length) {
    const prefix = title && `"${title}" `;
    const ofLen = needsLen ? ` of length ${length}` : "";
    const got = bytes ? `length=${len}` : `type=${typeof value}`;
    throw new Error(prefix + "expected Uint8Array" + ofLen + ", got " + got);
  }
  return value;
}
function hexToNumber(hex) {
  if (typeof hex !== "string")
    throw new Error("hex string expected, got " + typeof hex);
  return hex === "" ? _0n : BigInt("0x" + hex);
}
function bytesToNumberBE(bytes) {
  return hexToNumber(bytesToHex(bytes));
}
function bytesToNumberLE(bytes) {
  abytes(bytes);
  return hexToNumber(bytesToHex(Uint8Array.from(bytes).reverse()));
}
function numberToBytesBE(n, len) {
  return hexToBytes(n.toString(16).padStart(len * 2, "0"));
}
function numberToBytesLE(n, len) {
  return numberToBytesBE(n, len).reverse();
}
function ensureBytes(title, hex, expectedLength) {
  let res;
  if (typeof hex === "string") {
    try {
      res = hexToBytes(hex);
    } catch (e) {
      throw new Error(title + " must be hex string or Uint8Array, cause: " + e);
    }
  } else if (isBytes(hex)) {
    res = Uint8Array.from(hex);
  } else {
    throw new Error(title + " must be hex string or Uint8Array");
  }
  const len = res.length;
  if (typeof expectedLength === "number" && len !== expectedLength)
    throw new Error(title + " of length " + expectedLength + " expected, got " + len);
  return res;
}
function equalBytes(a, b) {
  if (a.length !== b.length)
    return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++)
    diff |= a[i] ^ b[i];
  return diff === 0;
}
function copyBytes(bytes) {
  return Uint8Array.from(bytes);
}
var isPosBig = (n) => typeof n === "bigint" && _0n <= n;
function inRange(n, min, max) {
  return isPosBig(n) && isPosBig(min) && isPosBig(max) && min <= n && n < max;
}
function aInRange(title, n, min, max) {
  if (!inRange(n, min, max))
    throw new Error("expected valid " + title + ": " + min + " <= n < " + max + ", got " + n);
}
function bitLen(n) {
  let len;
  for (len = 0; n > _0n; n >>= _1n, len += 1)
    ;
  return len;
}
var bitMask = (n) => (_1n << BigInt(n)) - _1n;
function _validateObject(object, fields, optFields = {}) {
  if (!object || typeof object !== "object")
    throw new Error("expected valid options object");
  function checkField(fieldName, expectedType, isOpt) {
    const val = object[fieldName];
    if (isOpt && val === void 0)
      return;
    const current = typeof val;
    if (current !== expectedType || val === null)
      throw new Error(`param "${fieldName}" is invalid: expected ${expectedType}, got ${current}`);
  }
  Object.entries(fields).forEach(([k, v]) => checkField(k, v, false));
  Object.entries(optFields).forEach(([k, v]) => checkField(k, v, true));
}
var notImplemented = () => {
  throw new Error("not implemented");
};
function memoized(fn) {
  const map = /* @__PURE__ */ new WeakMap();
  return (arg, ...args) => {
    const val = map.get(arg);
    if (val !== void 0)
      return val;
    const computed = fn(arg, ...args);
    map.set(arg, computed);
    return computed;
  };
}

// node_modules/@noble/curves/esm/abstract/modular.js
var _0n2 = BigInt(0);
var _1n2 = BigInt(1);
var _2n = /* @__PURE__ */ BigInt(2);
var _3n = /* @__PURE__ */ BigInt(3);
var _4n = /* @__PURE__ */ BigInt(4);
var _5n = /* @__PURE__ */ BigInt(5);
var _7n = /* @__PURE__ */ BigInt(7);
var _8n = /* @__PURE__ */ BigInt(8);
var _9n = /* @__PURE__ */ BigInt(9);
var _16n = /* @__PURE__ */ BigInt(16);
function mod(a, b) {
  const result = a % b;
  return result >= _0n2 ? result : b + result;
}
function pow2(x, power, modulo) {
  let res = x;
  while (power-- > _0n2) {
    res *= res;
    res %= modulo;
  }
  return res;
}
function invert(number, modulo) {
  if (number === _0n2)
    throw new Error("invert: expected non-zero number");
  if (modulo <= _0n2)
    throw new Error("invert: expected positive modulus, got " + modulo);
  let a = mod(number, modulo);
  let b = modulo;
  let x = _0n2, y = _1n2, u = _1n2, v = _0n2;
  while (a !== _0n2) {
    const q = b / a;
    const r = b % a;
    const m = x - u * q;
    const n = y - v * q;
    b = a, a = r, x = u, y = v, u = m, v = n;
  }
  const gcd = b;
  if (gcd !== _1n2)
    throw new Error("invert: does not exist");
  return mod(x, modulo);
}
function assertIsSquare(Fp2, root, n) {
  if (!Fp2.eql(Fp2.sqr(root), n))
    throw new Error("Cannot find square root");
}
function sqrt3mod4(Fp2, n) {
  const p1div4 = (Fp2.ORDER + _1n2) / _4n;
  const root = Fp2.pow(n, p1div4);
  assertIsSquare(Fp2, root, n);
  return root;
}
function sqrt5mod8(Fp2, n) {
  const p5div8 = (Fp2.ORDER - _5n) / _8n;
  const n2 = Fp2.mul(n, _2n);
  const v = Fp2.pow(n2, p5div8);
  const nv = Fp2.mul(n, v);
  const i = Fp2.mul(Fp2.mul(nv, _2n), v);
  const root = Fp2.mul(nv, Fp2.sub(i, Fp2.ONE));
  assertIsSquare(Fp2, root, n);
  return root;
}
function sqrt9mod16(P) {
  const Fp_ = Field(P);
  const tn = tonelliShanks(P);
  const c1 = tn(Fp_, Fp_.neg(Fp_.ONE));
  const c2 = tn(Fp_, c1);
  const c3 = tn(Fp_, Fp_.neg(c1));
  const c4 = (P + _7n) / _16n;
  return (Fp2, n) => {
    let tv1 = Fp2.pow(n, c4);
    let tv2 = Fp2.mul(tv1, c1);
    const tv3 = Fp2.mul(tv1, c2);
    const tv4 = Fp2.mul(tv1, c3);
    const e1 = Fp2.eql(Fp2.sqr(tv2), n);
    const e2 = Fp2.eql(Fp2.sqr(tv3), n);
    tv1 = Fp2.cmov(tv1, tv2, e1);
    tv2 = Fp2.cmov(tv4, tv3, e2);
    const e3 = Fp2.eql(Fp2.sqr(tv2), n);
    const root = Fp2.cmov(tv1, tv2, e3);
    assertIsSquare(Fp2, root, n);
    return root;
  };
}
function tonelliShanks(P) {
  if (P < _3n)
    throw new Error("sqrt is not defined for small field");
  let Q = P - _1n2;
  let S = 0;
  while (Q % _2n === _0n2) {
    Q /= _2n;
    S++;
  }
  let Z = _2n;
  const _Fp = Field(P);
  while (FpLegendre(_Fp, Z) === 1) {
    if (Z++ > 1e3)
      throw new Error("Cannot find square root: probably non-prime P");
  }
  if (S === 1)
    return sqrt3mod4;
  let cc = _Fp.pow(Z, Q);
  const Q1div2 = (Q + _1n2) / _2n;
  return function tonelliSlow(Fp2, n) {
    if (Fp2.is0(n))
      return n;
    if (FpLegendre(Fp2, n) !== 1)
      throw new Error("Cannot find square root");
    let M = S;
    let c = Fp2.mul(Fp2.ONE, cc);
    let t = Fp2.pow(n, Q);
    let R = Fp2.pow(n, Q1div2);
    while (!Fp2.eql(t, Fp2.ONE)) {
      if (Fp2.is0(t))
        return Fp2.ZERO;
      let i = 1;
      let t_tmp = Fp2.sqr(t);
      while (!Fp2.eql(t_tmp, Fp2.ONE)) {
        i++;
        t_tmp = Fp2.sqr(t_tmp);
        if (i === M)
          throw new Error("Cannot find square root");
      }
      const exponent = _1n2 << BigInt(M - i - 1);
      const b = Fp2.pow(c, exponent);
      M = i;
      c = Fp2.sqr(b);
      t = Fp2.mul(t, c);
      R = Fp2.mul(R, b);
    }
    return R;
  };
}
function FpSqrt(P) {
  if (P % _4n === _3n)
    return sqrt3mod4;
  if (P % _8n === _5n)
    return sqrt5mod8;
  if (P % _16n === _9n)
    return sqrt9mod16(P);
  return tonelliShanks(P);
}
var isNegativeLE = (num, modulo) => (mod(num, modulo) & _1n2) === _1n2;
var FIELD_FIELDS = [
  "create",
  "isValid",
  "is0",
  "neg",
  "inv",
  "sqrt",
  "sqr",
  "eql",
  "add",
  "sub",
  "mul",
  "pow",
  "div",
  "addN",
  "subN",
  "mulN",
  "sqrN"
];
function validateField(field) {
  const initial = {
    ORDER: "bigint",
    MASK: "bigint",
    BYTES: "number",
    BITS: "number"
  };
  const opts = FIELD_FIELDS.reduce((map, val) => {
    map[val] = "function";
    return map;
  }, initial);
  _validateObject(field, opts);
  return field;
}
function FpPow(Fp2, num, power) {
  if (power < _0n2)
    throw new Error("invalid exponent, negatives unsupported");
  if (power === _0n2)
    return Fp2.ONE;
  if (power === _1n2)
    return num;
  let p = Fp2.ONE;
  let d = num;
  while (power > _0n2) {
    if (power & _1n2)
      p = Fp2.mul(p, d);
    d = Fp2.sqr(d);
    power >>= _1n2;
  }
  return p;
}
function FpInvertBatch(Fp2, nums, passZero = false) {
  const inverted = new Array(nums.length).fill(passZero ? Fp2.ZERO : void 0);
  const multipliedAcc = nums.reduce((acc, num, i) => {
    if (Fp2.is0(num))
      return acc;
    inverted[i] = acc;
    return Fp2.mul(acc, num);
  }, Fp2.ONE);
  const invertedAcc = Fp2.inv(multipliedAcc);
  nums.reduceRight((acc, num, i) => {
    if (Fp2.is0(num))
      return acc;
    inverted[i] = Fp2.mul(acc, inverted[i]);
    return Fp2.mul(acc, num);
  }, invertedAcc);
  return inverted;
}
function FpLegendre(Fp2, n) {
  const p1mod2 = (Fp2.ORDER - _1n2) / _2n;
  const powered = Fp2.pow(n, p1mod2);
  const yes = Fp2.eql(powered, Fp2.ONE);
  const zero = Fp2.eql(powered, Fp2.ZERO);
  const no = Fp2.eql(powered, Fp2.neg(Fp2.ONE));
  if (!yes && !zero && !no)
    throw new Error("invalid Legendre symbol result");
  return yes ? 1 : zero ? 0 : -1;
}
function nLength(n, nBitLength) {
  if (nBitLength !== void 0)
    anumber(nBitLength);
  const _nBitLength = nBitLength !== void 0 ? nBitLength : n.toString(2).length;
  const nByteLength = Math.ceil(_nBitLength / 8);
  return { nBitLength: _nBitLength, nByteLength };
}
function Field(ORDER, bitLenOrOpts, isLE2 = false, opts = {}) {
  if (ORDER <= _0n2)
    throw new Error("invalid field: expected ORDER > 0, got " + ORDER);
  let _nbitLength = void 0;
  let _sqrt = void 0;
  let modFromBytes = false;
  let allowedLengths = void 0;
  if (typeof bitLenOrOpts === "object" && bitLenOrOpts != null) {
    if (opts.sqrt || isLE2)
      throw new Error("cannot specify opts in two arguments");
    const _opts = bitLenOrOpts;
    if (_opts.BITS)
      _nbitLength = _opts.BITS;
    if (_opts.sqrt)
      _sqrt = _opts.sqrt;
    if (typeof _opts.isLE === "boolean")
      isLE2 = _opts.isLE;
    if (typeof _opts.modFromBytes === "boolean")
      modFromBytes = _opts.modFromBytes;
    allowedLengths = _opts.allowedLengths;
  } else {
    if (typeof bitLenOrOpts === "number")
      _nbitLength = bitLenOrOpts;
    if (opts.sqrt)
      _sqrt = opts.sqrt;
  }
  const { nBitLength: BITS, nByteLength: BYTES } = nLength(ORDER, _nbitLength);
  if (BYTES > 2048)
    throw new Error("invalid field: expected ORDER of <= 2048 bytes");
  let sqrtP;
  const f = Object.freeze({
    ORDER,
    isLE: isLE2,
    BITS,
    BYTES,
    MASK: bitMask(BITS),
    ZERO: _0n2,
    ONE: _1n2,
    allowedLengths,
    create: (num) => mod(num, ORDER),
    isValid: (num) => {
      if (typeof num !== "bigint")
        throw new Error("invalid field element: expected bigint, got " + typeof num);
      return _0n2 <= num && num < ORDER;
    },
    is0: (num) => num === _0n2,
    // is valid and invertible
    isValidNot0: (num) => !f.is0(num) && f.isValid(num),
    isOdd: (num) => (num & _1n2) === _1n2,
    neg: (num) => mod(-num, ORDER),
    eql: (lhs, rhs) => lhs === rhs,
    sqr: (num) => mod(num * num, ORDER),
    add: (lhs, rhs) => mod(lhs + rhs, ORDER),
    sub: (lhs, rhs) => mod(lhs - rhs, ORDER),
    mul: (lhs, rhs) => mod(lhs * rhs, ORDER),
    pow: (num, power) => FpPow(f, num, power),
    div: (lhs, rhs) => mod(lhs * invert(rhs, ORDER), ORDER),
    // Same as above, but doesn't normalize
    sqrN: (num) => num * num,
    addN: (lhs, rhs) => lhs + rhs,
    subN: (lhs, rhs) => lhs - rhs,
    mulN: (lhs, rhs) => lhs * rhs,
    inv: (num) => invert(num, ORDER),
    sqrt: _sqrt || ((n) => {
      if (!sqrtP)
        sqrtP = FpSqrt(ORDER);
      return sqrtP(f, n);
    }),
    toBytes: (num) => isLE2 ? numberToBytesLE(num, BYTES) : numberToBytesBE(num, BYTES),
    fromBytes: (bytes, skipValidation = true) => {
      if (allowedLengths) {
        if (!allowedLengths.includes(bytes.length) || bytes.length > BYTES) {
          throw new Error("Field.fromBytes: expected " + allowedLengths + " bytes, got " + bytes.length);
        }
        const padded = new Uint8Array(BYTES);
        padded.set(bytes, isLE2 ? 0 : padded.length - bytes.length);
        bytes = padded;
      }
      if (bytes.length !== BYTES)
        throw new Error("Field.fromBytes: expected " + BYTES + " bytes, got " + bytes.length);
      let scalar = isLE2 ? bytesToNumberLE(bytes) : bytesToNumberBE(bytes);
      if (modFromBytes)
        scalar = mod(scalar, ORDER);
      if (!skipValidation) {
        if (!f.isValid(scalar))
          throw new Error("invalid field element: outside of range 0..ORDER");
      }
      return scalar;
    },
    // TODO: we don't need it here, move out to separate fn
    invertBatch: (lst) => FpInvertBatch(f, lst),
    // We can't move this out because Fp6, Fp12 implement it
    // and it's unclear what to return in there.
    cmov: (a, b, c) => c ? b : a
  });
  return Object.freeze(f);
}

// node_modules/@noble/curves/esm/abstract/curve.js
var _0n3 = BigInt(0);
var _1n3 = BigInt(1);
function negateCt(condition, item) {
  const neg = item.negate();
  return condition ? neg : item;
}
function normalizeZ(c, points) {
  const invertedZs = FpInvertBatch(c.Fp, points.map((p) => p.Z));
  return points.map((p, i) => c.fromAffine(p.toAffine(invertedZs[i])));
}
function validateW(W, bits) {
  if (!Number.isSafeInteger(W) || W <= 0 || W > bits)
    throw new Error("invalid window size, expected [1.." + bits + "], got W=" + W);
}
function calcWOpts(W, scalarBits) {
  validateW(W, scalarBits);
  const windows = Math.ceil(scalarBits / W) + 1;
  const windowSize = 2 ** (W - 1);
  const maxNumber = 2 ** W;
  const mask = bitMask(W);
  const shiftBy = BigInt(W);
  return { windows, windowSize, mask, maxNumber, shiftBy };
}
function calcOffsets(n, window2, wOpts) {
  const { windowSize, mask, maxNumber, shiftBy } = wOpts;
  let wbits = Number(n & mask);
  let nextN = n >> shiftBy;
  if (wbits > windowSize) {
    wbits -= maxNumber;
    nextN += _1n3;
  }
  const offsetStart = window2 * windowSize;
  const offset = offsetStart + Math.abs(wbits) - 1;
  const isZero = wbits === 0;
  const isNeg = wbits < 0;
  const isNegF = window2 % 2 !== 0;
  const offsetF = offsetStart;
  return { nextN, offset, isZero, isNeg, isNegF, offsetF };
}
function validateMSMPoints(points, c) {
  if (!Array.isArray(points))
    throw new Error("array expected");
  points.forEach((p, i) => {
    if (!(p instanceof c))
      throw new Error("invalid point at index " + i);
  });
}
function validateMSMScalars(scalars, field) {
  if (!Array.isArray(scalars))
    throw new Error("array of scalars expected");
  scalars.forEach((s, i) => {
    if (!field.isValid(s))
      throw new Error("invalid scalar at index " + i);
  });
}
var pointPrecomputes = /* @__PURE__ */ new WeakMap();
var pointWindowSizes = /* @__PURE__ */ new WeakMap();
function getW(P) {
  return pointWindowSizes.get(P) || 1;
}
function assert0(n) {
  if (n !== _0n3)
    throw new Error("invalid wNAF");
}
var wNAF = class {
  // Parametrized with a given Point class (not individual point)
  constructor(Point, bits) {
    this.BASE = Point.BASE;
    this.ZERO = Point.ZERO;
    this.Fn = Point.Fn;
    this.bits = bits;
  }
  // non-const time multiplication ladder
  _unsafeLadder(elm, n, p = this.ZERO) {
    let d = elm;
    while (n > _0n3) {
      if (n & _1n3)
        p = p.add(d);
      d = d.double();
      n >>= _1n3;
    }
    return p;
  }
  /**
   * Creates a wNAF precomputation window. Used for caching.
   * Default window size is set by `utils.precompute()` and is equal to 8.
   * Number of precomputed points depends on the curve size:
   * 2^(𝑊−1) * (Math.ceil(𝑛 / 𝑊) + 1), where:
   * - 𝑊 is the window size
   * - 𝑛 is the bitlength of the curve order.
   * For a 256-bit curve and window size 8, the number of precomputed points is 128 * 33 = 4224.
   * @param point Point instance
   * @param W window size
   * @returns precomputed point tables flattened to a single array
   */
  precomputeWindow(point, W) {
    const { windows, windowSize } = calcWOpts(W, this.bits);
    const points = [];
    let p = point;
    let base = p;
    for (let window2 = 0; window2 < windows; window2++) {
      base = p;
      points.push(base);
      for (let i = 1; i < windowSize; i++) {
        base = base.add(p);
        points.push(base);
      }
      p = base.double();
    }
    return points;
  }
  /**
   * Implements ec multiplication using precomputed tables and w-ary non-adjacent form.
   * More compact implementation:
   * https://github.com/paulmillr/noble-secp256k1/blob/47cb1669b6e506ad66b35fe7d76132ae97465da2/index.ts#L502-L541
   * @returns real and fake (for const-time) points
   */
  wNAF(W, precomputes, n) {
    if (!this.Fn.isValid(n))
      throw new Error("invalid scalar");
    let p = this.ZERO;
    let f = this.BASE;
    const wo = calcWOpts(W, this.bits);
    for (let window2 = 0; window2 < wo.windows; window2++) {
      const { nextN, offset, isZero, isNeg, isNegF, offsetF } = calcOffsets(n, window2, wo);
      n = nextN;
      if (isZero) {
        f = f.add(negateCt(isNegF, precomputes[offsetF]));
      } else {
        p = p.add(negateCt(isNeg, precomputes[offset]));
      }
    }
    assert0(n);
    return { p, f };
  }
  /**
   * Implements ec unsafe (non const-time) multiplication using precomputed tables and w-ary non-adjacent form.
   * @param acc accumulator point to add result of multiplication
   * @returns point
   */
  wNAFUnsafe(W, precomputes, n, acc = this.ZERO) {
    const wo = calcWOpts(W, this.bits);
    for (let window2 = 0; window2 < wo.windows; window2++) {
      if (n === _0n3)
        break;
      const { nextN, offset, isZero, isNeg } = calcOffsets(n, window2, wo);
      n = nextN;
      if (isZero) {
        continue;
      } else {
        const item = precomputes[offset];
        acc = acc.add(isNeg ? item.negate() : item);
      }
    }
    assert0(n);
    return acc;
  }
  getPrecomputes(W, point, transform) {
    let comp = pointPrecomputes.get(point);
    if (!comp) {
      comp = this.precomputeWindow(point, W);
      if (W !== 1) {
        if (typeof transform === "function")
          comp = transform(comp);
        pointPrecomputes.set(point, comp);
      }
    }
    return comp;
  }
  cached(point, scalar, transform) {
    const W = getW(point);
    return this.wNAF(W, this.getPrecomputes(W, point, transform), scalar);
  }
  unsafe(point, scalar, transform, prev) {
    const W = getW(point);
    if (W === 1)
      return this._unsafeLadder(point, scalar, prev);
    return this.wNAFUnsafe(W, this.getPrecomputes(W, point, transform), scalar, prev);
  }
  // We calculate precomputes for elliptic curve point multiplication
  // using windowed method. This specifies window size and
  // stores precomputed values. Usually only base point would be precomputed.
  createCache(P, W) {
    validateW(W, this.bits);
    pointWindowSizes.set(P, W);
    pointPrecomputes.delete(P);
  }
  hasCache(elm) {
    return getW(elm) !== 1;
  }
};
function pippenger(c, fieldN, points, scalars) {
  validateMSMPoints(points, c);
  validateMSMScalars(scalars, fieldN);
  const plength = points.length;
  const slength = scalars.length;
  if (plength !== slength)
    throw new Error("arrays of points and scalars must have equal length");
  const zero = c.ZERO;
  const wbits = bitLen(BigInt(plength));
  let windowSize = 1;
  if (wbits > 12)
    windowSize = wbits - 3;
  else if (wbits > 4)
    windowSize = wbits - 2;
  else if (wbits > 0)
    windowSize = 2;
  const MASK = bitMask(windowSize);
  const buckets = new Array(Number(MASK) + 1).fill(zero);
  const lastBits = Math.floor((fieldN.BITS - 1) / windowSize) * windowSize;
  let sum = zero;
  for (let i = lastBits; i >= 0; i -= windowSize) {
    buckets.fill(zero);
    for (let j = 0; j < slength; j++) {
      const scalar = scalars[j];
      const wbits2 = Number(scalar >> BigInt(i) & MASK);
      buckets[wbits2] = buckets[wbits2].add(points[j]);
    }
    let resI = zero;
    for (let j = buckets.length - 1, sumI = zero; j > 0; j--) {
      sumI = sumI.add(buckets[j]);
      resI = resI.add(sumI);
    }
    sum = sum.add(resI);
    if (i !== 0)
      for (let j = 0; j < windowSize; j++)
        sum = sum.double();
  }
  return sum;
}
function createField(order, field, isLE2) {
  if (field) {
    if (field.ORDER !== order)
      throw new Error("Field.ORDER must match order: Fp == p, Fn == n");
    validateField(field);
    return field;
  } else {
    return Field(order, { isLE: isLE2 });
  }
}
function _createCurveFields(type, CURVE, curveOpts = {}, FpFnLE) {
  if (FpFnLE === void 0)
    FpFnLE = type === "edwards";
  if (!CURVE || typeof CURVE !== "object")
    throw new Error(`expected valid ${type} CURVE object`);
  for (const p of ["p", "n", "h"]) {
    const val = CURVE[p];
    if (!(typeof val === "bigint" && val > _0n3))
      throw new Error(`CURVE.${p} must be positive bigint`);
  }
  const Fp2 = createField(CURVE.p, curveOpts.Fp, FpFnLE);
  const Fn2 = createField(CURVE.n, curveOpts.Fn, FpFnLE);
  const _b = type === "weierstrass" ? "b" : "d";
  const params = ["Gx", "Gy", "a", _b];
  for (const p of params) {
    if (!Fp2.isValid(CURVE[p]))
      throw new Error(`CURVE.${p} must be valid field element of CURVE.Fp`);
  }
  CURVE = Object.freeze(Object.assign({}, CURVE));
  return { CURVE, Fp: Fp2, Fn: Fn2 };
}

// node_modules/@noble/curves/esm/abstract/edwards.js
var _0n4 = BigInt(0);
var _1n4 = BigInt(1);
var _2n2 = BigInt(2);
var _8n2 = BigInt(8);
function isEdValidXY(Fp2, CURVE, x, y) {
  const x2 = Fp2.sqr(x);
  const y2 = Fp2.sqr(y);
  const left = Fp2.add(Fp2.mul(CURVE.a, x2), y2);
  const right = Fp2.add(Fp2.ONE, Fp2.mul(CURVE.d, Fp2.mul(x2, y2)));
  return Fp2.eql(left, right);
}
function edwards(params, extraOpts = {}) {
  const validated = _createCurveFields("edwards", params, extraOpts, extraOpts.FpFnLE);
  const { Fp: Fp2, Fn: Fn2 } = validated;
  let CURVE = validated.CURVE;
  const { h: cofactor } = CURVE;
  _validateObject(extraOpts, {}, { uvRatio: "function" });
  const MASK = _2n2 << BigInt(Fn2.BYTES * 8) - _1n4;
  const modP = (n) => Fp2.create(n);
  const uvRatio2 = extraOpts.uvRatio || ((u, v) => {
    try {
      return { isValid: true, value: Fp2.sqrt(Fp2.div(u, v)) };
    } catch (e) {
      return { isValid: false, value: _0n4 };
    }
  });
  if (!isEdValidXY(Fp2, CURVE, CURVE.Gx, CURVE.Gy))
    throw new Error("bad curve params: generator point");
  function acoord(title, n, banZero = false) {
    const min = banZero ? _1n4 : _0n4;
    aInRange("coordinate " + title, n, min, MASK);
    return n;
  }
  function aextpoint(other) {
    if (!(other instanceof Point))
      throw new Error("ExtendedPoint expected");
  }
  const toAffineMemo = memoized((p, iz) => {
    const { X, Y, Z } = p;
    const is0 = p.is0();
    if (iz == null)
      iz = is0 ? _8n2 : Fp2.inv(Z);
    const x = modP(X * iz);
    const y = modP(Y * iz);
    const zz = Fp2.mul(Z, iz);
    if (is0)
      return { x: _0n4, y: _1n4 };
    if (zz !== _1n4)
      throw new Error("invZ was invalid");
    return { x, y };
  });
  const assertValidMemo = memoized((p) => {
    const { a, d } = CURVE;
    if (p.is0())
      throw new Error("bad point: ZERO");
    const { X, Y, Z, T } = p;
    const X2 = modP(X * X);
    const Y2 = modP(Y * Y);
    const Z2 = modP(Z * Z);
    const Z4 = modP(Z2 * Z2);
    const aX2 = modP(X2 * a);
    const left = modP(Z2 * modP(aX2 + Y2));
    const right = modP(Z4 + modP(d * modP(X2 * Y2)));
    if (left !== right)
      throw new Error("bad point: equation left != right (1)");
    const XY = modP(X * Y);
    const ZT = modP(Z * T);
    if (XY !== ZT)
      throw new Error("bad point: equation left != right (2)");
    return true;
  });
  class Point {
    constructor(X, Y, Z, T) {
      this.X = acoord("x", X);
      this.Y = acoord("y", Y);
      this.Z = acoord("z", Z, true);
      this.T = acoord("t", T);
      Object.freeze(this);
    }
    static CURVE() {
      return CURVE;
    }
    static fromAffine(p) {
      if (p instanceof Point)
        throw new Error("extended point not allowed");
      const { x, y } = p || {};
      acoord("x", x);
      acoord("y", y);
      return new Point(x, y, _1n4, modP(x * y));
    }
    // Uses algo from RFC8032 5.1.3.
    static fromBytes(bytes, zip215 = false) {
      const len = Fp2.BYTES;
      const { a, d } = CURVE;
      bytes = copyBytes(_abytes2(bytes, len, "point"));
      _abool2(zip215, "zip215");
      const normed = copyBytes(bytes);
      const lastByte = bytes[len - 1];
      normed[len - 1] = lastByte & ~128;
      const y = bytesToNumberLE(normed);
      const max = zip215 ? MASK : Fp2.ORDER;
      aInRange("point.y", y, _0n4, max);
      const y2 = modP(y * y);
      const u = modP(y2 - _1n4);
      const v = modP(d * y2 - a);
      let { isValid, value: x } = uvRatio2(u, v);
      if (!isValid)
        throw new Error("bad point: invalid y coordinate");
      const isXOdd = (x & _1n4) === _1n4;
      const isLastByteOdd = (lastByte & 128) !== 0;
      if (!zip215 && x === _0n4 && isLastByteOdd)
        throw new Error("bad point: x=0 and x_0=1");
      if (isLastByteOdd !== isXOdd)
        x = modP(-x);
      return Point.fromAffine({ x, y });
    }
    static fromHex(bytes, zip215 = false) {
      return Point.fromBytes(ensureBytes("point", bytes), zip215);
    }
    get x() {
      return this.toAffine().x;
    }
    get y() {
      return this.toAffine().y;
    }
    precompute(windowSize = 8, isLazy = true) {
      wnaf.createCache(this, windowSize);
      if (!isLazy)
        this.multiply(_2n2);
      return this;
    }
    // Useful in fromAffine() - not for fromBytes(), which always created valid points.
    assertValidity() {
      assertValidMemo(this);
    }
    // Compare one point to another.
    equals(other) {
      aextpoint(other);
      const { X: X1, Y: Y1, Z: Z1 } = this;
      const { X: X2, Y: Y2, Z: Z2 } = other;
      const X1Z2 = modP(X1 * Z2);
      const X2Z1 = modP(X2 * Z1);
      const Y1Z2 = modP(Y1 * Z2);
      const Y2Z1 = modP(Y2 * Z1);
      return X1Z2 === X2Z1 && Y1Z2 === Y2Z1;
    }
    is0() {
      return this.equals(Point.ZERO);
    }
    negate() {
      return new Point(modP(-this.X), this.Y, this.Z, modP(-this.T));
    }
    // Fast algo for doubling Extended Point.
    // https://hyperelliptic.org/EFD/g1p/auto-twisted-extended.html#doubling-dbl-2008-hwcd
    // Cost: 4M + 4S + 1*a + 6add + 1*2.
    double() {
      const { a } = CURVE;
      const { X: X1, Y: Y1, Z: Z1 } = this;
      const A = modP(X1 * X1);
      const B = modP(Y1 * Y1);
      const C = modP(_2n2 * modP(Z1 * Z1));
      const D = modP(a * A);
      const x1y1 = X1 + Y1;
      const E = modP(modP(x1y1 * x1y1) - A - B);
      const G = D + B;
      const F = G - C;
      const H = D - B;
      const X3 = modP(E * F);
      const Y3 = modP(G * H);
      const T3 = modP(E * H);
      const Z3 = modP(F * G);
      return new Point(X3, Y3, Z3, T3);
    }
    // Fast algo for adding 2 Extended Points.
    // https://hyperelliptic.org/EFD/g1p/auto-twisted-extended.html#addition-add-2008-hwcd
    // Cost: 9M + 1*a + 1*d + 7add.
    add(other) {
      aextpoint(other);
      const { a, d } = CURVE;
      const { X: X1, Y: Y1, Z: Z1, T: T1 } = this;
      const { X: X2, Y: Y2, Z: Z2, T: T2 } = other;
      const A = modP(X1 * X2);
      const B = modP(Y1 * Y2);
      const C = modP(T1 * d * T2);
      const D = modP(Z1 * Z2);
      const E = modP((X1 + Y1) * (X2 + Y2) - A - B);
      const F = D - C;
      const G = D + C;
      const H = modP(B - a * A);
      const X3 = modP(E * F);
      const Y3 = modP(G * H);
      const T3 = modP(E * H);
      const Z3 = modP(F * G);
      return new Point(X3, Y3, Z3, T3);
    }
    subtract(other) {
      return this.add(other.negate());
    }
    // Constant-time multiplication.
    multiply(scalar) {
      if (!Fn2.isValidNot0(scalar))
        throw new Error("invalid scalar: expected 1 <= sc < curve.n");
      const { p, f } = wnaf.cached(this, scalar, (p2) => normalizeZ(Point, p2));
      return normalizeZ(Point, [p, f])[0];
    }
    // Non-constant-time multiplication. Uses double-and-add algorithm.
    // It's faster, but should only be used when you don't care about
    // an exposed private key e.g. sig verification.
    // Does NOT allow scalars higher than CURVE.n.
    // Accepts optional accumulator to merge with multiply (important for sparse scalars)
    multiplyUnsafe(scalar, acc = Point.ZERO) {
      if (!Fn2.isValid(scalar))
        throw new Error("invalid scalar: expected 0 <= sc < curve.n");
      if (scalar === _0n4)
        return Point.ZERO;
      if (this.is0() || scalar === _1n4)
        return this;
      return wnaf.unsafe(this, scalar, (p) => normalizeZ(Point, p), acc);
    }
    // Checks if point is of small order.
    // If you add something to small order point, you will have "dirty"
    // point with torsion component.
    // Multiplies point by cofactor and checks if the result is 0.
    isSmallOrder() {
      return this.multiplyUnsafe(cofactor).is0();
    }
    // Multiplies point by curve order and checks if the result is 0.
    // Returns `false` is the point is dirty.
    isTorsionFree() {
      return wnaf.unsafe(this, CURVE.n).is0();
    }
    // Converts Extended point to default (x, y) coordinates.
    // Can accept precomputed Z^-1 - for example, from invertBatch.
    toAffine(invertedZ) {
      return toAffineMemo(this, invertedZ);
    }
    clearCofactor() {
      if (cofactor === _1n4)
        return this;
      return this.multiplyUnsafe(cofactor);
    }
    toBytes() {
      const { x, y } = this.toAffine();
      const bytes = Fp2.toBytes(y);
      bytes[bytes.length - 1] |= x & _1n4 ? 128 : 0;
      return bytes;
    }
    toHex() {
      return bytesToHex(this.toBytes());
    }
    toString() {
      return `<Point ${this.is0() ? "ZERO" : this.toHex()}>`;
    }
    // TODO: remove
    get ex() {
      return this.X;
    }
    get ey() {
      return this.Y;
    }
    get ez() {
      return this.Z;
    }
    get et() {
      return this.T;
    }
    static normalizeZ(points) {
      return normalizeZ(Point, points);
    }
    static msm(points, scalars) {
      return pippenger(Point, Fn2, points, scalars);
    }
    _setWindowSize(windowSize) {
      this.precompute(windowSize);
    }
    toRawBytes() {
      return this.toBytes();
    }
  }
  Point.BASE = new Point(CURVE.Gx, CURVE.Gy, _1n4, modP(CURVE.Gx * CURVE.Gy));
  Point.ZERO = new Point(_0n4, _1n4, _1n4, _0n4);
  Point.Fp = Fp2;
  Point.Fn = Fn2;
  const wnaf = new wNAF(Point, Fn2.BITS);
  Point.BASE.precompute(8);
  return Point;
}
var PrimeEdwardsPoint = class {
  constructor(ep) {
    this.ep = ep;
  }
  // Static methods that must be implemented by subclasses
  static fromBytes(_bytes) {
    notImplemented();
  }
  static fromHex(_hex) {
    notImplemented();
  }
  get x() {
    return this.toAffine().x;
  }
  get y() {
    return this.toAffine().y;
  }
  // Common implementations
  clearCofactor() {
    return this;
  }
  assertValidity() {
    this.ep.assertValidity();
  }
  toAffine(invertedZ) {
    return this.ep.toAffine(invertedZ);
  }
  toHex() {
    return bytesToHex(this.toBytes());
  }
  toString() {
    return this.toHex();
  }
  isTorsionFree() {
    return true;
  }
  isSmallOrder() {
    return false;
  }
  add(other) {
    this.assertSame(other);
    return this.init(this.ep.add(other.ep));
  }
  subtract(other) {
    this.assertSame(other);
    return this.init(this.ep.subtract(other.ep));
  }
  multiply(scalar) {
    return this.init(this.ep.multiply(scalar));
  }
  multiplyUnsafe(scalar) {
    return this.init(this.ep.multiplyUnsafe(scalar));
  }
  double() {
    return this.init(this.ep.double());
  }
  negate() {
    return this.init(this.ep.negate());
  }
  precompute(windowSize, isLazy) {
    return this.init(this.ep.precompute(windowSize, isLazy));
  }
  /** @deprecated use `toBytes` */
  toRawBytes() {
    return this.toBytes();
  }
};
function eddsa(Point, cHash, eddsaOpts = {}) {
  if (typeof cHash !== "function")
    throw new Error('"hash" function param is required');
  _validateObject(eddsaOpts, {}, {
    adjustScalarBytes: "function",
    randomBytes: "function",
    domain: "function",
    prehash: "function",
    mapToCurve: "function"
  });
  const { prehash } = eddsaOpts;
  const { BASE, Fp: Fp2, Fn: Fn2 } = Point;
  const randomBytes3 = eddsaOpts.randomBytes || randomBytes;
  const adjustScalarBytes2 = eddsaOpts.adjustScalarBytes || ((bytes) => bytes);
  const domain = eddsaOpts.domain || ((data, ctx, phflag) => {
    _abool2(phflag, "phflag");
    if (ctx.length || phflag)
      throw new Error("Contexts/pre-hash are not supported");
    return data;
  });
  function modN_LE(hash) {
    return Fn2.create(bytesToNumberLE(hash));
  }
  function getPrivateScalar(key) {
    const len = lengths.secretKey;
    key = ensureBytes("private key", key, len);
    const hashed = ensureBytes("hashed private key", cHash(key), 2 * len);
    const head = adjustScalarBytes2(hashed.slice(0, len));
    const prefix = hashed.slice(len, 2 * len);
    const scalar = modN_LE(head);
    return { head, prefix, scalar };
  }
  function getExtendedPublicKey(secretKey) {
    const { head, prefix, scalar } = getPrivateScalar(secretKey);
    const point = BASE.multiply(scalar);
    const pointBytes = point.toBytes();
    return { head, prefix, scalar, point, pointBytes };
  }
  function getPublicKey(secretKey) {
    return getExtendedPublicKey(secretKey).pointBytes;
  }
  function hashDomainToScalar(context = Uint8Array.of(), ...msgs) {
    const msg = concatBytes(...msgs);
    return modN_LE(cHash(domain(msg, ensureBytes("context", context), !!prehash)));
  }
  function sign(msg, secretKey, options = {}) {
    msg = ensureBytes("message", msg);
    if (prehash)
      msg = prehash(msg);
    const { prefix, scalar, pointBytes } = getExtendedPublicKey(secretKey);
    const r = hashDomainToScalar(options.context, prefix, msg);
    const R = BASE.multiply(r).toBytes();
    const k = hashDomainToScalar(options.context, R, pointBytes, msg);
    const s = Fn2.create(r + k * scalar);
    if (!Fn2.isValid(s))
      throw new Error("sign failed: invalid s");
    const rs = concatBytes(R, Fn2.toBytes(s));
    return _abytes2(rs, lengths.signature, "result");
  }
  const verifyOpts = { zip215: true };
  function verify(sig, msg, publicKey, options = verifyOpts) {
    const { context, zip215 } = options;
    const len = lengths.signature;
    sig = ensureBytes("signature", sig, len);
    msg = ensureBytes("message", msg);
    publicKey = ensureBytes("publicKey", publicKey, lengths.publicKey);
    if (zip215 !== void 0)
      _abool2(zip215, "zip215");
    if (prehash)
      msg = prehash(msg);
    const mid = len / 2;
    const r = sig.subarray(0, mid);
    const s = bytesToNumberLE(sig.subarray(mid, len));
    let A, R, SB;
    try {
      A = Point.fromBytes(publicKey, zip215);
      R = Point.fromBytes(r, zip215);
      SB = BASE.multiplyUnsafe(s);
    } catch (error) {
      return false;
    }
    if (!zip215 && A.isSmallOrder())
      return false;
    const k = hashDomainToScalar(context, R.toBytes(), A.toBytes(), msg);
    const RkA = R.add(A.multiplyUnsafe(k));
    return RkA.subtract(SB).clearCofactor().is0();
  }
  const _size = Fp2.BYTES;
  const lengths = {
    secretKey: _size,
    publicKey: _size,
    signature: 2 * _size,
    seed: _size
  };
  function randomSecretKey(seed = randomBytes3(lengths.seed)) {
    return _abytes2(seed, lengths.seed, "seed");
  }
  function keygen(seed) {
    const secretKey = utils.randomSecretKey(seed);
    return { secretKey, publicKey: getPublicKey(secretKey) };
  }
  function isValidSecretKey(key) {
    return isBytes(key) && key.length === Fn2.BYTES;
  }
  function isValidPublicKey(key, zip215) {
    try {
      return !!Point.fromBytes(key, zip215);
    } catch (error) {
      return false;
    }
  }
  const utils = {
    getExtendedPublicKey,
    randomSecretKey,
    isValidSecretKey,
    isValidPublicKey,
    /**
     * Converts ed public key to x public key. Uses formula:
     * - ed25519:
     *   - `(u, v) = ((1+y)/(1-y), sqrt(-486664)*u/x)`
     *   - `(x, y) = (sqrt(-486664)*u/v, (u-1)/(u+1))`
     * - ed448:
     *   - `(u, v) = ((y-1)/(y+1), sqrt(156324)*u/x)`
     *   - `(x, y) = (sqrt(156324)*u/v, (1+u)/(1-u))`
     */
    toMontgomery(publicKey) {
      const { y } = Point.fromBytes(publicKey);
      const size = lengths.publicKey;
      const is25519 = size === 32;
      if (!is25519 && size !== 57)
        throw new Error("only defined for 25519 and 448");
      const u = is25519 ? Fp2.div(_1n4 + y, _1n4 - y) : Fp2.div(y - _1n4, y + _1n4);
      return Fp2.toBytes(u);
    },
    toMontgomerySecret(secretKey) {
      const size = lengths.secretKey;
      _abytes2(secretKey, size);
      const hashed = cHash(secretKey.subarray(0, size));
      return adjustScalarBytes2(hashed).subarray(0, size);
    },
    /** @deprecated */
    randomPrivateKey: randomSecretKey,
    /** @deprecated */
    precompute(windowSize = 8, point = Point.BASE) {
      return point.precompute(windowSize, false);
    }
  };
  return Object.freeze({
    keygen,
    getPublicKey,
    sign,
    verify,
    utils,
    Point,
    lengths
  });
}
function _eddsa_legacy_opts_to_new(c) {
  const CURVE = {
    a: c.a,
    d: c.d,
    p: c.Fp.ORDER,
    n: c.n,
    h: c.h,
    Gx: c.Gx,
    Gy: c.Gy
  };
  const Fp2 = c.Fp;
  const Fn2 = Field(CURVE.n, c.nBitLength, true);
  const curveOpts = { Fp: Fp2, Fn: Fn2, uvRatio: c.uvRatio };
  const eddsaOpts = {
    randomBytes: c.randomBytes,
    adjustScalarBytes: c.adjustScalarBytes,
    domain: c.domain,
    prehash: c.prehash,
    mapToCurve: c.mapToCurve
  };
  return { CURVE, curveOpts, hash: c.hash, eddsaOpts };
}
function _eddsa_new_output_to_legacy(c, eddsa2) {
  const Point = eddsa2.Point;
  const legacy = Object.assign({}, eddsa2, {
    ExtendedPoint: Point,
    CURVE: c,
    nBitLength: Point.Fn.BITS,
    nByteLength: Point.Fn.BYTES
  });
  return legacy;
}
function twistedEdwards(c) {
  const { CURVE, curveOpts, hash, eddsaOpts } = _eddsa_legacy_opts_to_new(c);
  const Point = edwards(CURVE, curveOpts);
  const EDDSA = eddsa(Point, hash, eddsaOpts);
  return _eddsa_new_output_to_legacy(c, EDDSA);
}

// node_modules/@noble/curves/esm/abstract/montgomery.js
var _0n5 = BigInt(0);
var _1n5 = BigInt(1);
var _2n3 = BigInt(2);
function validateOpts(curve) {
  _validateObject(curve, {
    adjustScalarBytes: "function",
    powPminus2: "function"
  });
  return Object.freeze({ ...curve });
}
function montgomery(curveDef) {
  const CURVE = validateOpts(curveDef);
  const { P, type, adjustScalarBytes: adjustScalarBytes2, powPminus2, randomBytes: rand } = CURVE;
  const is25519 = type === "x25519";
  if (!is25519 && type !== "x448")
    throw new Error("invalid type");
  const randomBytes_ = rand || randomBytes;
  const montgomeryBits = is25519 ? 255 : 448;
  const fieldLen = is25519 ? 32 : 56;
  const Gu = is25519 ? BigInt(9) : BigInt(5);
  const a24 = is25519 ? BigInt(121665) : BigInt(39081);
  const minScalar = is25519 ? _2n3 ** BigInt(254) : _2n3 ** BigInt(447);
  const maxAdded = is25519 ? BigInt(8) * _2n3 ** BigInt(251) - _1n5 : BigInt(4) * _2n3 ** BigInt(445) - _1n5;
  const maxScalar = minScalar + maxAdded + _1n5;
  const modP = (n) => mod(n, P);
  const GuBytes = encodeU(Gu);
  function encodeU(u) {
    return numberToBytesLE(modP(u), fieldLen);
  }
  function decodeU(u) {
    const _u = ensureBytes("u coordinate", u, fieldLen);
    if (is25519)
      _u[31] &= 127;
    return modP(bytesToNumberLE(_u));
  }
  function decodeScalar(scalar) {
    return bytesToNumberLE(adjustScalarBytes2(ensureBytes("scalar", scalar, fieldLen)));
  }
  function scalarMult(scalar, u) {
    const pu = montgomeryLadder(decodeU(u), decodeScalar(scalar));
    if (pu === _0n5)
      throw new Error("invalid private or public key received");
    return encodeU(pu);
  }
  function scalarMultBase(scalar) {
    return scalarMult(scalar, GuBytes);
  }
  function cswap(swap, x_2, x_3) {
    const dummy = modP(swap * (x_2 - x_3));
    x_2 = modP(x_2 - dummy);
    x_3 = modP(x_3 + dummy);
    return { x_2, x_3 };
  }
  function montgomeryLadder(u, scalar) {
    aInRange("u", u, _0n5, P);
    aInRange("scalar", scalar, minScalar, maxScalar);
    const k = scalar;
    const x_1 = u;
    let x_2 = _1n5;
    let z_2 = _0n5;
    let x_3 = u;
    let z_3 = _1n5;
    let swap = _0n5;
    for (let t = BigInt(montgomeryBits - 1); t >= _0n5; t--) {
      const k_t = k >> t & _1n5;
      swap ^= k_t;
      ({ x_2, x_3 } = cswap(swap, x_2, x_3));
      ({ x_2: z_2, x_3: z_3 } = cswap(swap, z_2, z_3));
      swap = k_t;
      const A = x_2 + z_2;
      const AA = modP(A * A);
      const B = x_2 - z_2;
      const BB = modP(B * B);
      const E = AA - BB;
      const C = x_3 + z_3;
      const D = x_3 - z_3;
      const DA = modP(D * A);
      const CB = modP(C * B);
      const dacb = DA + CB;
      const da_cb = DA - CB;
      x_3 = modP(dacb * dacb);
      z_3 = modP(x_1 * modP(da_cb * da_cb));
      x_2 = modP(AA * BB);
      z_2 = modP(E * (AA + modP(a24 * E)));
    }
    ({ x_2, x_3 } = cswap(swap, x_2, x_3));
    ({ x_2: z_2, x_3: z_3 } = cswap(swap, z_2, z_3));
    const z2 = powPminus2(z_2);
    return modP(x_2 * z2);
  }
  const lengths = {
    secretKey: fieldLen,
    publicKey: fieldLen,
    seed: fieldLen
  };
  const randomSecretKey = (seed = randomBytes_(fieldLen)) => {
    abytes(seed, lengths.seed);
    return seed;
  };
  function keygen(seed) {
    const secretKey = randomSecretKey(seed);
    return { secretKey, publicKey: scalarMultBase(secretKey) };
  }
  const utils = {
    randomSecretKey,
    randomPrivateKey: randomSecretKey
  };
  return {
    keygen,
    getSharedSecret: (secretKey, publicKey) => scalarMult(secretKey, publicKey),
    getPublicKey: (secretKey) => scalarMultBase(secretKey),
    scalarMult,
    scalarMultBase,
    utils,
    GuBytes: GuBytes.slice(),
    lengths
  };
}

// node_modules/@noble/curves/esm/ed25519.js
var _0n6 = /* @__PURE__ */ BigInt(0);
var _1n6 = BigInt(1);
var _2n4 = BigInt(2);
var _3n2 = BigInt(3);
var _5n2 = BigInt(5);
var _8n3 = BigInt(8);
var ed25519_CURVE_p = BigInt("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed");
var ed25519_CURVE = /* @__PURE__ */ (() => ({
  p: ed25519_CURVE_p,
  n: BigInt("0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed"),
  h: _8n3,
  a: BigInt("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec"),
  d: BigInt("0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3"),
  Gx: BigInt("0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a"),
  Gy: BigInt("0x6666666666666666666666666666666666666666666666666666666666666658")
}))();
function ed25519_pow_2_252_3(x) {
  const _10n = BigInt(10), _20n = BigInt(20), _40n = BigInt(40), _80n = BigInt(80);
  const P = ed25519_CURVE_p;
  const x2 = x * x % P;
  const b2 = x2 * x % P;
  const b4 = pow2(b2, _2n4, P) * b2 % P;
  const b5 = pow2(b4, _1n6, P) * x % P;
  const b10 = pow2(b5, _5n2, P) * b5 % P;
  const b20 = pow2(b10, _10n, P) * b10 % P;
  const b40 = pow2(b20, _20n, P) * b20 % P;
  const b80 = pow2(b40, _40n, P) * b40 % P;
  const b160 = pow2(b80, _80n, P) * b80 % P;
  const b240 = pow2(b160, _80n, P) * b80 % P;
  const b250 = pow2(b240, _10n, P) * b10 % P;
  const pow_p_5_8 = pow2(b250, _2n4, P) * x % P;
  return { pow_p_5_8, b2 };
}
function adjustScalarBytes(bytes) {
  bytes[0] &= 248;
  bytes[31] &= 127;
  bytes[31] |= 64;
  return bytes;
}
var ED25519_SQRT_M1 = /* @__PURE__ */ BigInt("19681161376707505956807079304988542015446066515923890162744021073123829784752");
function uvRatio(u, v) {
  const P = ed25519_CURVE_p;
  const v3 = mod(v * v * v, P);
  const v7 = mod(v3 * v3 * v, P);
  const pow = ed25519_pow_2_252_3(u * v7).pow_p_5_8;
  let x = mod(u * v3 * pow, P);
  const vx2 = mod(v * x * x, P);
  const root1 = x;
  const root2 = mod(x * ED25519_SQRT_M1, P);
  const useRoot1 = vx2 === u;
  const useRoot2 = vx2 === mod(-u, P);
  const noRoot = vx2 === mod(-u * ED25519_SQRT_M1, P);
  if (useRoot1)
    x = root1;
  if (useRoot2 || noRoot)
    x = root2;
  if (isNegativeLE(x, P))
    x = mod(-x, P);
  return { isValid: useRoot1 || useRoot2, value: x };
}
var Fp = /* @__PURE__ */ (() => Field(ed25519_CURVE.p, { isLE: true }))();
var Fn = /* @__PURE__ */ (() => Field(ed25519_CURVE.n, { isLE: true }))();
var ed25519Defaults = /* @__PURE__ */ (() => ({
  ...ed25519_CURVE,
  Fp,
  hash: sha512,
  adjustScalarBytes,
  // dom2
  // Ratio of u to v. Allows us to combine inversion and square root. Uses algo from RFC8032 5.1.3.
  // Constant-time, u/√v
  uvRatio
}))();
var ed25519 = /* @__PURE__ */ (() => twistedEdwards(ed25519Defaults))();
var x25519 = /* @__PURE__ */ (() => {
  const P = Fp.ORDER;
  return montgomery({
    P,
    type: "x25519",
    powPminus2: (x) => {
      const { pow_p_5_8, b2 } = ed25519_pow_2_252_3(x);
      return mod(pow2(pow_p_5_8, _3n2, P) * b2, P);
    },
    adjustScalarBytes
  });
})();
var SQRT_M1 = ED25519_SQRT_M1;
var SQRT_AD_MINUS_ONE = /* @__PURE__ */ BigInt("25063068953384623474111414158702152701244531502492656460079210482610430750235");
var INVSQRT_A_MINUS_D = /* @__PURE__ */ BigInt("54469307008909316920995813868745141605393597292927456921205312896311721017578");
var ONE_MINUS_D_SQ = /* @__PURE__ */ BigInt("1159843021668779879193775521855586647937357759715417654439879720876111806838");
var D_MINUS_ONE_SQ = /* @__PURE__ */ BigInt("40440834346308536858101042469323190826248399146238708352240133220865137265952");
var invertSqrt = (number) => uvRatio(_1n6, number);
var MAX_255B = /* @__PURE__ */ BigInt("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
var bytes255ToNumberLE = (bytes) => ed25519.Point.Fp.create(bytesToNumberLE(bytes) & MAX_255B);
function calcElligatorRistrettoMap(r0) {
  const { d } = ed25519_CURVE;
  const P = ed25519_CURVE_p;
  const mod2 = (n) => Fp.create(n);
  const r = mod2(SQRT_M1 * r0 * r0);
  const Ns = mod2((r + _1n6) * ONE_MINUS_D_SQ);
  let c = BigInt(-1);
  const D = mod2((c - d * r) * mod2(r + d));
  let { isValid: Ns_D_is_sq, value: s } = uvRatio(Ns, D);
  let s_ = mod2(s * r0);
  if (!isNegativeLE(s_, P))
    s_ = mod2(-s_);
  if (!Ns_D_is_sq)
    s = s_;
  if (!Ns_D_is_sq)
    c = r;
  const Nt = mod2(c * (r - _1n6) * D_MINUS_ONE_SQ - D);
  const s2 = s * s;
  const W0 = mod2((s + s) * D);
  const W1 = mod2(Nt * SQRT_AD_MINUS_ONE);
  const W2 = mod2(_1n6 - s2);
  const W3 = mod2(_1n6 + s2);
  return new ed25519.Point(mod2(W0 * W3), mod2(W2 * W1), mod2(W1 * W3), mod2(W0 * W2));
}
function ristretto255_map(bytes) {
  abytes(bytes, 64);
  const r1 = bytes255ToNumberLE(bytes.subarray(0, 32));
  const R1 = calcElligatorRistrettoMap(r1);
  const r2 = bytes255ToNumberLE(bytes.subarray(32, 64));
  const R2 = calcElligatorRistrettoMap(r2);
  return new _RistrettoPoint(R1.add(R2));
}
var _RistrettoPoint = class __RistrettoPoint extends PrimeEdwardsPoint {
  constructor(ep) {
    super(ep);
  }
  static fromAffine(ap) {
    return new __RistrettoPoint(ed25519.Point.fromAffine(ap));
  }
  assertSame(other) {
    if (!(other instanceof __RistrettoPoint))
      throw new Error("RistrettoPoint expected");
  }
  init(ep) {
    return new __RistrettoPoint(ep);
  }
  /** @deprecated use `import { ristretto255_hasher } from '@noble/curves/ed25519.js';` */
  static hashToCurve(hex) {
    return ristretto255_map(ensureBytes("ristrettoHash", hex, 64));
  }
  static fromBytes(bytes) {
    abytes(bytes, 32);
    const { a, d } = ed25519_CURVE;
    const P = ed25519_CURVE_p;
    const mod2 = (n) => Fp.create(n);
    const s = bytes255ToNumberLE(bytes);
    if (!equalBytes(Fp.toBytes(s), bytes) || isNegativeLE(s, P))
      throw new Error("invalid ristretto255 encoding 1");
    const s2 = mod2(s * s);
    const u1 = mod2(_1n6 + a * s2);
    const u2 = mod2(_1n6 - a * s2);
    const u1_2 = mod2(u1 * u1);
    const u2_2 = mod2(u2 * u2);
    const v = mod2(a * d * u1_2 - u2_2);
    const { isValid, value: I } = invertSqrt(mod2(v * u2_2));
    const Dx = mod2(I * u2);
    const Dy = mod2(I * Dx * v);
    let x = mod2((s + s) * Dx);
    if (isNegativeLE(x, P))
      x = mod2(-x);
    const y = mod2(u1 * Dy);
    const t = mod2(x * y);
    if (!isValid || isNegativeLE(t, P) || y === _0n6)
      throw new Error("invalid ristretto255 encoding 2");
    return new __RistrettoPoint(new ed25519.Point(x, y, _1n6, t));
  }
  /**
   * Converts ristretto-encoded string to ristretto point.
   * Described in [RFC9496](https://www.rfc-editor.org/rfc/rfc9496#name-decode).
   * @param hex Ristretto-encoded 32 bytes. Not every 32-byte string is valid ristretto encoding
   */
  static fromHex(hex) {
    return __RistrettoPoint.fromBytes(ensureBytes("ristrettoHex", hex, 32));
  }
  static msm(points, scalars) {
    return pippenger(__RistrettoPoint, ed25519.Point.Fn, points, scalars);
  }
  /**
   * Encodes ristretto point to Uint8Array.
   * Described in [RFC9496](https://www.rfc-editor.org/rfc/rfc9496#name-encode).
   */
  toBytes() {
    let { X, Y, Z, T } = this.ep;
    const P = ed25519_CURVE_p;
    const mod2 = (n) => Fp.create(n);
    const u1 = mod2(mod2(Z + Y) * mod2(Z - Y));
    const u2 = mod2(X * Y);
    const u2sq = mod2(u2 * u2);
    const { value: invsqrt } = invertSqrt(mod2(u1 * u2sq));
    const D1 = mod2(invsqrt * u1);
    const D2 = mod2(invsqrt * u2);
    const zInv = mod2(D1 * D2 * T);
    let D;
    if (isNegativeLE(T * zInv, P)) {
      let _x = mod2(Y * SQRT_M1);
      let _y = mod2(X * SQRT_M1);
      X = _x;
      Y = _y;
      D = mod2(D1 * INVSQRT_A_MINUS_D);
    } else {
      D = D2;
    }
    if (isNegativeLE(X * zInv, P))
      Y = mod2(-Y);
    let s = mod2((Z - Y) * D);
    if (isNegativeLE(s, P))
      s = mod2(-s);
    return Fp.toBytes(s);
  }
  /**
   * Compares two Ristretto points.
   * Described in [RFC9496](https://www.rfc-editor.org/rfc/rfc9496#name-equals).
   */
  equals(other) {
    this.assertSame(other);
    const { X: X1, Y: Y1 } = this.ep;
    const { X: X2, Y: Y2 } = other.ep;
    const mod2 = (n) => Fp.create(n);
    const one = mod2(X1 * Y2) === mod2(Y1 * X2);
    const two = mod2(Y1 * Y2) === mod2(X1 * X2);
    return one || two;
  }
  is0() {
    return this.equals(__RistrettoPoint.ZERO);
  }
};
_RistrettoPoint.BASE = /* @__PURE__ */ (() => new _RistrettoPoint(ed25519.Point.BASE))();
_RistrettoPoint.ZERO = /* @__PURE__ */ (() => new _RistrettoPoint(ed25519.Point.ZERO))();
_RistrettoPoint.Fp = /* @__PURE__ */ (() => Fp)();
_RistrettoPoint.Fn = /* @__PURE__ */ (() => Fn)();

// src/keypair.ts
function deriveKeypairFromPrf(prfOutput) {
  if (prfOutput.length !== 32) {
    throw new Error(`PRF output must be 32 bytes, got ${prfOutput.length}`);
  }
  const privateKey = new Uint8Array(prfOutput);
  const publicKey = x25519.getPublicKey(privateKey);
  return {
    privateKey,
    publicKey
  };
}
function computeSharedSecret(privateKey, publicKey) {
  if (privateKey.length !== 32) {
    throw new Error(`Private key must be 32 bytes, got ${privateKey.length}`);
  }
  if (publicKey.length !== 32) {
    throw new Error(`Public key must be 32 bytes, got ${publicKey.length}`);
  }
  return x25519.getSharedSecret(privateKey, publicKey);
}
function generateEphemeralKeypair() {
  const privateKey = x25519.utils.randomPrivateKey();
  const publicKey = x25519.getPublicKey(privateKey);
  return {
    privateKey,
    publicKey
  };
}

// node_modules/@noble/ciphers/esm/utils.js
function isBytes2(a) {
  return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array";
}
function abool(b) {
  if (typeof b !== "boolean")
    throw new Error(`boolean expected, not ${b}`);
}
function anumber2(n) {
  if (!Number.isSafeInteger(n) || n < 0)
    throw new Error("positive integer expected, got " + n);
}
function abytes2(b, ...lengths) {
  if (!isBytes2(b))
    throw new Error("Uint8Array expected");
  if (lengths.length > 0 && !lengths.includes(b.length))
    throw new Error("Uint8Array expected of length " + lengths + ", got length=" + b.length);
}
function aexists2(instance, checkFinished = true) {
  if (instance.destroyed)
    throw new Error("Hash instance has been destroyed");
  if (checkFinished && instance.finished)
    throw new Error("Hash#digest() has already been called");
}
function aoutput2(out, instance) {
  abytes2(out);
  const min = instance.outputLen;
  if (out.length < min) {
    throw new Error("digestInto() expects output buffer of length at least " + min);
  }
}
function u32(arr) {
  return new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
}
function clean2(...arrays) {
  for (let i = 0; i < arrays.length; i++) {
    arrays[i].fill(0);
  }
}
function createView2(arr) {
  return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
}
var isLE = /* @__PURE__ */ (() => new Uint8Array(new Uint32Array([287454020]).buffer)[0] === 68)();
function utf8ToBytes2(str) {
  if (typeof str !== "string")
    throw new Error("string expected");
  return new Uint8Array(new TextEncoder().encode(str));
}
function toBytes2(data) {
  if (typeof data === "string")
    data = utf8ToBytes2(data);
  else if (isBytes2(data))
    data = copyBytes2(data);
  else
    throw new Error("Uint8Array expected, got " + typeof data);
  return data;
}
function checkOpts(defaults, opts) {
  if (opts == null || typeof opts !== "object")
    throw new Error("options must be defined");
  const merged = Object.assign(defaults, opts);
  return merged;
}
function equalBytes2(a, b) {
  if (a.length !== b.length)
    return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++)
    diff |= a[i] ^ b[i];
  return diff === 0;
}
var wrapCipher = /* @__NO_SIDE_EFFECTS__ */ (params, constructor) => {
  function wrappedCipher(key, ...args) {
    abytes2(key);
    if (!isLE)
      throw new Error("Non little-endian hardware is not yet supported");
    if (params.nonceLength !== void 0) {
      const nonce = args[0];
      if (!nonce)
        throw new Error("nonce / iv required");
      if (params.varSizeNonce)
        abytes2(nonce);
      else
        abytes2(nonce, params.nonceLength);
    }
    const tagl = params.tagLength;
    if (tagl && args[1] !== void 0) {
      abytes2(args[1]);
    }
    const cipher = constructor(key, ...args);
    const checkOutput = (fnLength, output) => {
      if (output !== void 0) {
        if (fnLength !== 2)
          throw new Error("cipher output not supported");
        abytes2(output);
      }
    };
    let called = false;
    const wrCipher = {
      encrypt(data, output) {
        if (called)
          throw new Error("cannot encrypt() twice with same key + nonce");
        called = true;
        abytes2(data);
        checkOutput(cipher.encrypt.length, output);
        return cipher.encrypt(data, output);
      },
      decrypt(data, output) {
        abytes2(data);
        if (tagl && data.length < tagl)
          throw new Error("invalid ciphertext length: smaller than tagLength=" + tagl);
        checkOutput(cipher.decrypt.length, output);
        return cipher.decrypt(data, output);
      }
    };
    return wrCipher;
  }
  Object.assign(wrappedCipher, params);
  return wrappedCipher;
};
function getOutput(expectedLength, out, onlyAligned = true) {
  if (out === void 0)
    return new Uint8Array(expectedLength);
  if (out.length !== expectedLength)
    throw new Error("invalid output length, expected " + expectedLength + ", got: " + out.length);
  if (onlyAligned && !isAligned32(out))
    throw new Error("invalid output, must be aligned");
  return out;
}
function setBigUint642(view, byteOffset, value, isLE2) {
  if (typeof view.setBigUint64 === "function")
    return view.setBigUint64(byteOffset, value, isLE2);
  const _32n2 = BigInt(32);
  const _u32_max = BigInt(4294967295);
  const wh = Number(value >> _32n2 & _u32_max);
  const wl = Number(value & _u32_max);
  const h = isLE2 ? 4 : 0;
  const l = isLE2 ? 0 : 4;
  view.setUint32(byteOffset + h, wh, isLE2);
  view.setUint32(byteOffset + l, wl, isLE2);
}
function u64Lengths(dataLength, aadLength, isLE2) {
  abool(isLE2);
  const num = new Uint8Array(16);
  const view = createView2(num);
  setBigUint642(view, 0, BigInt(aadLength), isLE2);
  setBigUint642(view, 8, BigInt(dataLength), isLE2);
  return num;
}
function isAligned32(bytes) {
  return bytes.byteOffset % 4 === 0;
}
function copyBytes2(bytes) {
  return Uint8Array.from(bytes);
}

// node_modules/@noble/ciphers/esm/_arx.js
var _utf8ToBytes = (str) => Uint8Array.from(str.split("").map((c) => c.charCodeAt(0)));
var sigma16 = _utf8ToBytes("expand 16-byte k");
var sigma32 = _utf8ToBytes("expand 32-byte k");
var sigma16_32 = u32(sigma16);
var sigma32_32 = u32(sigma32);
function rotl(a, b) {
  return a << b | a >>> 32 - b;
}
function isAligned322(b) {
  return b.byteOffset % 4 === 0;
}
var BLOCK_LEN = 64;
var BLOCK_LEN32 = 16;
var MAX_COUNTER = 2 ** 32 - 1;
var U32_EMPTY = new Uint32Array();
function runCipher(core, sigma, key, nonce, data, output, counter, rounds) {
  const len = data.length;
  const block = new Uint8Array(BLOCK_LEN);
  const b32 = u32(block);
  const isAligned = isAligned322(data) && isAligned322(output);
  const d32 = isAligned ? u32(data) : U32_EMPTY;
  const o32 = isAligned ? u32(output) : U32_EMPTY;
  for (let pos = 0; pos < len; counter++) {
    core(sigma, key, nonce, b32, counter, rounds);
    if (counter >= MAX_COUNTER)
      throw new Error("arx: counter overflow");
    const take = Math.min(BLOCK_LEN, len - pos);
    if (isAligned && take === BLOCK_LEN) {
      const pos32 = pos / 4;
      if (pos % 4 !== 0)
        throw new Error("arx: invalid block position");
      for (let j = 0, posj; j < BLOCK_LEN32; j++) {
        posj = pos32 + j;
        o32[posj] = d32[posj] ^ b32[j];
      }
      pos += BLOCK_LEN;
      continue;
    }
    for (let j = 0, posj; j < take; j++) {
      posj = pos + j;
      output[posj] = data[posj] ^ block[j];
    }
    pos += take;
  }
}
function createCipher(core, opts) {
  const { allowShortKeys, extendNonceFn, counterLength, counterRight, rounds } = checkOpts({ allowShortKeys: false, counterLength: 8, counterRight: false, rounds: 20 }, opts);
  if (typeof core !== "function")
    throw new Error("core must be a function");
  anumber2(counterLength);
  anumber2(rounds);
  abool(counterRight);
  abool(allowShortKeys);
  return (key, nonce, data, output, counter = 0) => {
    abytes2(key);
    abytes2(nonce);
    abytes2(data);
    const len = data.length;
    if (output === void 0)
      output = new Uint8Array(len);
    abytes2(output);
    anumber2(counter);
    if (counter < 0 || counter >= MAX_COUNTER)
      throw new Error("arx: counter overflow");
    if (output.length < len)
      throw new Error(`arx: output (${output.length}) is shorter than data (${len})`);
    const toClean = [];
    let l = key.length;
    let k;
    let sigma;
    if (l === 32) {
      toClean.push(k = copyBytes2(key));
      sigma = sigma32_32;
    } else if (l === 16 && allowShortKeys) {
      k = new Uint8Array(32);
      k.set(key);
      k.set(key, 16);
      sigma = sigma16_32;
      toClean.push(k);
    } else {
      throw new Error(`arx: invalid 32-byte key, got length=${l}`);
    }
    if (!isAligned322(nonce))
      toClean.push(nonce = copyBytes2(nonce));
    const k32 = u32(k);
    if (extendNonceFn) {
      if (nonce.length !== 24)
        throw new Error(`arx: extended nonce must be 24 bytes`);
      extendNonceFn(sigma, k32, u32(nonce.subarray(0, 16)), k32);
      nonce = nonce.subarray(16);
    }
    const nonceNcLen = 16 - counterLength;
    if (nonceNcLen !== nonce.length)
      throw new Error(`arx: nonce must be ${nonceNcLen} or 16 bytes`);
    if (nonceNcLen !== 12) {
      const nc = new Uint8Array(12);
      nc.set(nonce, counterRight ? 0 : 12 - nonce.length);
      nonce = nc;
      toClean.push(nonce);
    }
    const n32 = u32(nonce);
    runCipher(core, sigma, k32, n32, data, output, counter, rounds);
    clean2(...toClean);
    return output;
  };
}

// node_modules/@noble/ciphers/esm/_poly1305.js
var u8to16 = (a, i) => a[i++] & 255 | (a[i++] & 255) << 8;
var Poly1305 = class {
  constructor(key) {
    this.blockLen = 16;
    this.outputLen = 16;
    this.buffer = new Uint8Array(16);
    this.r = new Uint16Array(10);
    this.h = new Uint16Array(10);
    this.pad = new Uint16Array(8);
    this.pos = 0;
    this.finished = false;
    key = toBytes2(key);
    abytes2(key, 32);
    const t0 = u8to16(key, 0);
    const t1 = u8to16(key, 2);
    const t2 = u8to16(key, 4);
    const t3 = u8to16(key, 6);
    const t4 = u8to16(key, 8);
    const t5 = u8to16(key, 10);
    const t6 = u8to16(key, 12);
    const t7 = u8to16(key, 14);
    this.r[0] = t0 & 8191;
    this.r[1] = (t0 >>> 13 | t1 << 3) & 8191;
    this.r[2] = (t1 >>> 10 | t2 << 6) & 7939;
    this.r[3] = (t2 >>> 7 | t3 << 9) & 8191;
    this.r[4] = (t3 >>> 4 | t4 << 12) & 255;
    this.r[5] = t4 >>> 1 & 8190;
    this.r[6] = (t4 >>> 14 | t5 << 2) & 8191;
    this.r[7] = (t5 >>> 11 | t6 << 5) & 8065;
    this.r[8] = (t6 >>> 8 | t7 << 8) & 8191;
    this.r[9] = t7 >>> 5 & 127;
    for (let i = 0; i < 8; i++)
      this.pad[i] = u8to16(key, 16 + 2 * i);
  }
  process(data, offset, isLast = false) {
    const hibit = isLast ? 0 : 1 << 11;
    const { h, r } = this;
    const r0 = r[0];
    const r1 = r[1];
    const r2 = r[2];
    const r3 = r[3];
    const r4 = r[4];
    const r5 = r[5];
    const r6 = r[6];
    const r7 = r[7];
    const r8 = r[8];
    const r9 = r[9];
    const t0 = u8to16(data, offset + 0);
    const t1 = u8to16(data, offset + 2);
    const t2 = u8to16(data, offset + 4);
    const t3 = u8to16(data, offset + 6);
    const t4 = u8to16(data, offset + 8);
    const t5 = u8to16(data, offset + 10);
    const t6 = u8to16(data, offset + 12);
    const t7 = u8to16(data, offset + 14);
    let h0 = h[0] + (t0 & 8191);
    let h1 = h[1] + ((t0 >>> 13 | t1 << 3) & 8191);
    let h2 = h[2] + ((t1 >>> 10 | t2 << 6) & 8191);
    let h3 = h[3] + ((t2 >>> 7 | t3 << 9) & 8191);
    let h4 = h[4] + ((t3 >>> 4 | t4 << 12) & 8191);
    let h5 = h[5] + (t4 >>> 1 & 8191);
    let h6 = h[6] + ((t4 >>> 14 | t5 << 2) & 8191);
    let h7 = h[7] + ((t5 >>> 11 | t6 << 5) & 8191);
    let h8 = h[8] + ((t6 >>> 8 | t7 << 8) & 8191);
    let h9 = h[9] + (t7 >>> 5 | hibit);
    let c = 0;
    let d0 = c + h0 * r0 + h1 * (5 * r9) + h2 * (5 * r8) + h3 * (5 * r7) + h4 * (5 * r6);
    c = d0 >>> 13;
    d0 &= 8191;
    d0 += h5 * (5 * r5) + h6 * (5 * r4) + h7 * (5 * r3) + h8 * (5 * r2) + h9 * (5 * r1);
    c += d0 >>> 13;
    d0 &= 8191;
    let d1 = c + h0 * r1 + h1 * r0 + h2 * (5 * r9) + h3 * (5 * r8) + h4 * (5 * r7);
    c = d1 >>> 13;
    d1 &= 8191;
    d1 += h5 * (5 * r6) + h6 * (5 * r5) + h7 * (5 * r4) + h8 * (5 * r3) + h9 * (5 * r2);
    c += d1 >>> 13;
    d1 &= 8191;
    let d2 = c + h0 * r2 + h1 * r1 + h2 * r0 + h3 * (5 * r9) + h4 * (5 * r8);
    c = d2 >>> 13;
    d2 &= 8191;
    d2 += h5 * (5 * r7) + h6 * (5 * r6) + h7 * (5 * r5) + h8 * (5 * r4) + h9 * (5 * r3);
    c += d2 >>> 13;
    d2 &= 8191;
    let d3 = c + h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * (5 * r9);
    c = d3 >>> 13;
    d3 &= 8191;
    d3 += h5 * (5 * r8) + h6 * (5 * r7) + h7 * (5 * r6) + h8 * (5 * r5) + h9 * (5 * r4);
    c += d3 >>> 13;
    d3 &= 8191;
    let d4 = c + h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;
    c = d4 >>> 13;
    d4 &= 8191;
    d4 += h5 * (5 * r9) + h6 * (5 * r8) + h7 * (5 * r7) + h8 * (5 * r6) + h9 * (5 * r5);
    c += d4 >>> 13;
    d4 &= 8191;
    let d5 = c + h0 * r5 + h1 * r4 + h2 * r3 + h3 * r2 + h4 * r1;
    c = d5 >>> 13;
    d5 &= 8191;
    d5 += h5 * r0 + h6 * (5 * r9) + h7 * (5 * r8) + h8 * (5 * r7) + h9 * (5 * r6);
    c += d5 >>> 13;
    d5 &= 8191;
    let d6 = c + h0 * r6 + h1 * r5 + h2 * r4 + h3 * r3 + h4 * r2;
    c = d6 >>> 13;
    d6 &= 8191;
    d6 += h5 * r1 + h6 * r0 + h7 * (5 * r9) + h8 * (5 * r8) + h9 * (5 * r7);
    c += d6 >>> 13;
    d6 &= 8191;
    let d7 = c + h0 * r7 + h1 * r6 + h2 * r5 + h3 * r4 + h4 * r3;
    c = d7 >>> 13;
    d7 &= 8191;
    d7 += h5 * r2 + h6 * r1 + h7 * r0 + h8 * (5 * r9) + h9 * (5 * r8);
    c += d7 >>> 13;
    d7 &= 8191;
    let d8 = c + h0 * r8 + h1 * r7 + h2 * r6 + h3 * r5 + h4 * r4;
    c = d8 >>> 13;
    d8 &= 8191;
    d8 += h5 * r3 + h6 * r2 + h7 * r1 + h8 * r0 + h9 * (5 * r9);
    c += d8 >>> 13;
    d8 &= 8191;
    let d9 = c + h0 * r9 + h1 * r8 + h2 * r7 + h3 * r6 + h4 * r5;
    c = d9 >>> 13;
    d9 &= 8191;
    d9 += h5 * r4 + h6 * r3 + h7 * r2 + h8 * r1 + h9 * r0;
    c += d9 >>> 13;
    d9 &= 8191;
    c = (c << 2) + c | 0;
    c = c + d0 | 0;
    d0 = c & 8191;
    c = c >>> 13;
    d1 += c;
    h[0] = d0;
    h[1] = d1;
    h[2] = d2;
    h[3] = d3;
    h[4] = d4;
    h[5] = d5;
    h[6] = d6;
    h[7] = d7;
    h[8] = d8;
    h[9] = d9;
  }
  finalize() {
    const { h, pad } = this;
    const g = new Uint16Array(10);
    let c = h[1] >>> 13;
    h[1] &= 8191;
    for (let i = 2; i < 10; i++) {
      h[i] += c;
      c = h[i] >>> 13;
      h[i] &= 8191;
    }
    h[0] += c * 5;
    c = h[0] >>> 13;
    h[0] &= 8191;
    h[1] += c;
    c = h[1] >>> 13;
    h[1] &= 8191;
    h[2] += c;
    g[0] = h[0] + 5;
    c = g[0] >>> 13;
    g[0] &= 8191;
    for (let i = 1; i < 10; i++) {
      g[i] = h[i] + c;
      c = g[i] >>> 13;
      g[i] &= 8191;
    }
    g[9] -= 1 << 13;
    let mask = (c ^ 1) - 1;
    for (let i = 0; i < 10; i++)
      g[i] &= mask;
    mask = ~mask;
    for (let i = 0; i < 10; i++)
      h[i] = h[i] & mask | g[i];
    h[0] = (h[0] | h[1] << 13) & 65535;
    h[1] = (h[1] >>> 3 | h[2] << 10) & 65535;
    h[2] = (h[2] >>> 6 | h[3] << 7) & 65535;
    h[3] = (h[3] >>> 9 | h[4] << 4) & 65535;
    h[4] = (h[4] >>> 12 | h[5] << 1 | h[6] << 14) & 65535;
    h[5] = (h[6] >>> 2 | h[7] << 11) & 65535;
    h[6] = (h[7] >>> 5 | h[8] << 8) & 65535;
    h[7] = (h[8] >>> 8 | h[9] << 5) & 65535;
    let f = h[0] + pad[0];
    h[0] = f & 65535;
    for (let i = 1; i < 8; i++) {
      f = (h[i] + pad[i] | 0) + (f >>> 16) | 0;
      h[i] = f & 65535;
    }
    clean2(g);
  }
  update(data) {
    aexists2(this);
    data = toBytes2(data);
    abytes2(data);
    const { buffer, blockLen } = this;
    const len = data.length;
    for (let pos = 0; pos < len; ) {
      const take = Math.min(blockLen - this.pos, len - pos);
      if (take === blockLen) {
        for (; blockLen <= len - pos; pos += blockLen)
          this.process(data, pos);
        continue;
      }
      buffer.set(data.subarray(pos, pos + take), this.pos);
      this.pos += take;
      pos += take;
      if (this.pos === blockLen) {
        this.process(buffer, 0, false);
        this.pos = 0;
      }
    }
    return this;
  }
  destroy() {
    clean2(this.h, this.r, this.buffer, this.pad);
  }
  digestInto(out) {
    aexists2(this);
    aoutput2(out, this);
    this.finished = true;
    const { buffer, h } = this;
    let { pos } = this;
    if (pos) {
      buffer[pos++] = 1;
      for (; pos < 16; pos++)
        buffer[pos] = 0;
      this.process(buffer, 0, true);
    }
    this.finalize();
    let opos = 0;
    for (let i = 0; i < 8; i++) {
      out[opos++] = h[i] >>> 0;
      out[opos++] = h[i] >>> 8;
    }
    return out;
  }
  digest() {
    const { buffer, outputLen } = this;
    this.digestInto(buffer);
    const res = buffer.slice(0, outputLen);
    this.destroy();
    return res;
  }
};
function wrapConstructorWithKey(hashCons) {
  const hashC = (msg, key) => hashCons(key).update(toBytes2(msg)).digest();
  const tmp = hashCons(new Uint8Array(32));
  hashC.outputLen = tmp.outputLen;
  hashC.blockLen = tmp.blockLen;
  hashC.create = (key) => hashCons(key);
  return hashC;
}
var poly1305 = wrapConstructorWithKey((key) => new Poly1305(key));

// node_modules/@noble/ciphers/esm/chacha.js
function chachaCore(s, k, n, out, cnt, rounds = 20) {
  let y00 = s[0], y01 = s[1], y02 = s[2], y03 = s[3], y04 = k[0], y05 = k[1], y06 = k[2], y07 = k[3], y08 = k[4], y09 = k[5], y10 = k[6], y11 = k[7], y12 = cnt, y13 = n[0], y14 = n[1], y15 = n[2];
  let x00 = y00, x01 = y01, x02 = y02, x03 = y03, x04 = y04, x05 = y05, x06 = y06, x07 = y07, x08 = y08, x09 = y09, x10 = y10, x11 = y11, x12 = y12, x13 = y13, x14 = y14, x15 = y15;
  for (let r = 0; r < rounds; r += 2) {
    x00 = x00 + x04 | 0;
    x12 = rotl(x12 ^ x00, 16);
    x08 = x08 + x12 | 0;
    x04 = rotl(x04 ^ x08, 12);
    x00 = x00 + x04 | 0;
    x12 = rotl(x12 ^ x00, 8);
    x08 = x08 + x12 | 0;
    x04 = rotl(x04 ^ x08, 7);
    x01 = x01 + x05 | 0;
    x13 = rotl(x13 ^ x01, 16);
    x09 = x09 + x13 | 0;
    x05 = rotl(x05 ^ x09, 12);
    x01 = x01 + x05 | 0;
    x13 = rotl(x13 ^ x01, 8);
    x09 = x09 + x13 | 0;
    x05 = rotl(x05 ^ x09, 7);
    x02 = x02 + x06 | 0;
    x14 = rotl(x14 ^ x02, 16);
    x10 = x10 + x14 | 0;
    x06 = rotl(x06 ^ x10, 12);
    x02 = x02 + x06 | 0;
    x14 = rotl(x14 ^ x02, 8);
    x10 = x10 + x14 | 0;
    x06 = rotl(x06 ^ x10, 7);
    x03 = x03 + x07 | 0;
    x15 = rotl(x15 ^ x03, 16);
    x11 = x11 + x15 | 0;
    x07 = rotl(x07 ^ x11, 12);
    x03 = x03 + x07 | 0;
    x15 = rotl(x15 ^ x03, 8);
    x11 = x11 + x15 | 0;
    x07 = rotl(x07 ^ x11, 7);
    x00 = x00 + x05 | 0;
    x15 = rotl(x15 ^ x00, 16);
    x10 = x10 + x15 | 0;
    x05 = rotl(x05 ^ x10, 12);
    x00 = x00 + x05 | 0;
    x15 = rotl(x15 ^ x00, 8);
    x10 = x10 + x15 | 0;
    x05 = rotl(x05 ^ x10, 7);
    x01 = x01 + x06 | 0;
    x12 = rotl(x12 ^ x01, 16);
    x11 = x11 + x12 | 0;
    x06 = rotl(x06 ^ x11, 12);
    x01 = x01 + x06 | 0;
    x12 = rotl(x12 ^ x01, 8);
    x11 = x11 + x12 | 0;
    x06 = rotl(x06 ^ x11, 7);
    x02 = x02 + x07 | 0;
    x13 = rotl(x13 ^ x02, 16);
    x08 = x08 + x13 | 0;
    x07 = rotl(x07 ^ x08, 12);
    x02 = x02 + x07 | 0;
    x13 = rotl(x13 ^ x02, 8);
    x08 = x08 + x13 | 0;
    x07 = rotl(x07 ^ x08, 7);
    x03 = x03 + x04 | 0;
    x14 = rotl(x14 ^ x03, 16);
    x09 = x09 + x14 | 0;
    x04 = rotl(x04 ^ x09, 12);
    x03 = x03 + x04 | 0;
    x14 = rotl(x14 ^ x03, 8);
    x09 = x09 + x14 | 0;
    x04 = rotl(x04 ^ x09, 7);
  }
  let oi = 0;
  out[oi++] = y00 + x00 | 0;
  out[oi++] = y01 + x01 | 0;
  out[oi++] = y02 + x02 | 0;
  out[oi++] = y03 + x03 | 0;
  out[oi++] = y04 + x04 | 0;
  out[oi++] = y05 + x05 | 0;
  out[oi++] = y06 + x06 | 0;
  out[oi++] = y07 + x07 | 0;
  out[oi++] = y08 + x08 | 0;
  out[oi++] = y09 + x09 | 0;
  out[oi++] = y10 + x10 | 0;
  out[oi++] = y11 + x11 | 0;
  out[oi++] = y12 + x12 | 0;
  out[oi++] = y13 + x13 | 0;
  out[oi++] = y14 + x14 | 0;
  out[oi++] = y15 + x15 | 0;
}
function hchacha(s, k, i, o32) {
  let x00 = s[0], x01 = s[1], x02 = s[2], x03 = s[3], x04 = k[0], x05 = k[1], x06 = k[2], x07 = k[3], x08 = k[4], x09 = k[5], x10 = k[6], x11 = k[7], x12 = i[0], x13 = i[1], x14 = i[2], x15 = i[3];
  for (let r = 0; r < 20; r += 2) {
    x00 = x00 + x04 | 0;
    x12 = rotl(x12 ^ x00, 16);
    x08 = x08 + x12 | 0;
    x04 = rotl(x04 ^ x08, 12);
    x00 = x00 + x04 | 0;
    x12 = rotl(x12 ^ x00, 8);
    x08 = x08 + x12 | 0;
    x04 = rotl(x04 ^ x08, 7);
    x01 = x01 + x05 | 0;
    x13 = rotl(x13 ^ x01, 16);
    x09 = x09 + x13 | 0;
    x05 = rotl(x05 ^ x09, 12);
    x01 = x01 + x05 | 0;
    x13 = rotl(x13 ^ x01, 8);
    x09 = x09 + x13 | 0;
    x05 = rotl(x05 ^ x09, 7);
    x02 = x02 + x06 | 0;
    x14 = rotl(x14 ^ x02, 16);
    x10 = x10 + x14 | 0;
    x06 = rotl(x06 ^ x10, 12);
    x02 = x02 + x06 | 0;
    x14 = rotl(x14 ^ x02, 8);
    x10 = x10 + x14 | 0;
    x06 = rotl(x06 ^ x10, 7);
    x03 = x03 + x07 | 0;
    x15 = rotl(x15 ^ x03, 16);
    x11 = x11 + x15 | 0;
    x07 = rotl(x07 ^ x11, 12);
    x03 = x03 + x07 | 0;
    x15 = rotl(x15 ^ x03, 8);
    x11 = x11 + x15 | 0;
    x07 = rotl(x07 ^ x11, 7);
    x00 = x00 + x05 | 0;
    x15 = rotl(x15 ^ x00, 16);
    x10 = x10 + x15 | 0;
    x05 = rotl(x05 ^ x10, 12);
    x00 = x00 + x05 | 0;
    x15 = rotl(x15 ^ x00, 8);
    x10 = x10 + x15 | 0;
    x05 = rotl(x05 ^ x10, 7);
    x01 = x01 + x06 | 0;
    x12 = rotl(x12 ^ x01, 16);
    x11 = x11 + x12 | 0;
    x06 = rotl(x06 ^ x11, 12);
    x01 = x01 + x06 | 0;
    x12 = rotl(x12 ^ x01, 8);
    x11 = x11 + x12 | 0;
    x06 = rotl(x06 ^ x11, 7);
    x02 = x02 + x07 | 0;
    x13 = rotl(x13 ^ x02, 16);
    x08 = x08 + x13 | 0;
    x07 = rotl(x07 ^ x08, 12);
    x02 = x02 + x07 | 0;
    x13 = rotl(x13 ^ x02, 8);
    x08 = x08 + x13 | 0;
    x07 = rotl(x07 ^ x08, 7);
    x03 = x03 + x04 | 0;
    x14 = rotl(x14 ^ x03, 16);
    x09 = x09 + x14 | 0;
    x04 = rotl(x04 ^ x09, 12);
    x03 = x03 + x04 | 0;
    x14 = rotl(x14 ^ x03, 8);
    x09 = x09 + x14 | 0;
    x04 = rotl(x04 ^ x09, 7);
  }
  let oi = 0;
  o32[oi++] = x00;
  o32[oi++] = x01;
  o32[oi++] = x02;
  o32[oi++] = x03;
  o32[oi++] = x12;
  o32[oi++] = x13;
  o32[oi++] = x14;
  o32[oi++] = x15;
}
var chacha20 = /* @__PURE__ */ createCipher(chachaCore, {
  counterRight: false,
  counterLength: 4,
  allowShortKeys: false
});
var xchacha20 = /* @__PURE__ */ createCipher(chachaCore, {
  counterRight: false,
  counterLength: 8,
  extendNonceFn: hchacha,
  allowShortKeys: false
});
var ZEROS16 = /* @__PURE__ */ new Uint8Array(16);
var updatePadded = (h, msg) => {
  h.update(msg);
  const left = msg.length % 16;
  if (left)
    h.update(ZEROS16.subarray(left));
};
var ZEROS32 = /* @__PURE__ */ new Uint8Array(32);
function computeTag(fn, key, nonce, data, AAD) {
  const authKey = fn(key, nonce, ZEROS32);
  const h = poly1305.create(authKey);
  if (AAD)
    updatePadded(h, AAD);
  updatePadded(h, data);
  const num = u64Lengths(data.length, AAD ? AAD.length : 0, true);
  h.update(num);
  const res = h.digest();
  clean2(authKey, num);
  return res;
}
var _poly1305_aead = (xorStream) => (key, nonce, AAD) => {
  const tagLength = 16;
  return {
    encrypt(plaintext, output) {
      const plength = plaintext.length;
      output = getOutput(plength + tagLength, output, false);
      output.set(plaintext);
      const oPlain = output.subarray(0, -tagLength);
      xorStream(key, nonce, oPlain, oPlain, 1);
      const tag = computeTag(xorStream, key, nonce, oPlain, AAD);
      output.set(tag, plength);
      clean2(tag);
      return output;
    },
    decrypt(ciphertext, output) {
      output = getOutput(ciphertext.length - tagLength, output, false);
      const data = ciphertext.subarray(0, -tagLength);
      const passedTag = ciphertext.subarray(-tagLength);
      const tag = computeTag(xorStream, key, nonce, data, AAD);
      if (!equalBytes2(passedTag, tag))
        throw new Error("invalid tag");
      output.set(ciphertext.subarray(0, -tagLength));
      xorStream(key, nonce, output, output, 1);
      clean2(tag);
      return output;
    }
  };
};
var chacha20poly1305 = /* @__PURE__ */ wrapCipher({ blockSize: 64, nonceLength: 12, tagLength: 16 }, _poly1305_aead(chacha20));
var xchacha20poly1305 = /* @__PURE__ */ wrapCipher({ blockSize: 64, nonceLength: 24, tagLength: 16 }, _poly1305_aead(xchacha20));

// node_modules/@noble/ciphers/esm/crypto.js
var crypto3 = typeof globalThis === "object" && "crypto" in globalThis ? globalThis.crypto : void 0;

// node_modules/@noble/ciphers/esm/webcrypto.js
function randomBytes2(bytesLength = 32) {
  if (crypto3 && typeof crypto3.getRandomValues === "function") {
    return crypto3.getRandomValues(new Uint8Array(bytesLength));
  }
  if (crypto3 && typeof crypto3.randomBytes === "function") {
    return Uint8Array.from(crypto3.randomBytes(bytesLength));
  }
  throw new Error("crypto.getRandomValues must be defined");
}

// src/symmetric.ts
var NONCE_LENGTH = 12;
function symmetricEncrypt(message, keyBase64) {
  const key = fromBase64(keyBase64);
  try {
    if (key.length !== 32) {
      throw new Error(`Symmetric key must be 32 bytes, got ${key.length}`);
    }
    const nonce = randomBytes2(NONCE_LENGTH);
    const encoder = new TextEncoder();
    const plaintext = encoder.encode(message);
    const cipher = chacha20poly1305(key, nonce);
    const ciphertext = cipher.encrypt(plaintext);
    return {
      ciphertext: toBase64(ciphertext),
      nonce: toBase64(nonce)
    };
  } finally {
    zeroFill(key);
  }
}
function symmetricDecrypt(encrypted, keyBase64) {
  const key = fromBase64(keyBase64);
  try {
    if (key.length !== 32) {
      throw new Error(`Symmetric key must be 32 bytes, got ${key.length}`);
    }
    const ciphertext = fromBase64(encrypted.ciphertext);
    const nonce = fromBase64(encrypted.nonce);
    if (nonce.length !== NONCE_LENGTH) {
      throw new Error(`Nonce must be ${NONCE_LENGTH} bytes, got ${nonce.length}`);
    }
    const cipher = chacha20poly1305(key, nonce);
    const plaintext = cipher.decrypt(ciphertext);
    const decoder = new TextDecoder();
    return decoder.decode(plaintext);
  } finally {
    zeroFill(key);
  }
}

// node_modules/@noble/hashes/esm/hmac.js
var HMAC = class extends Hash {
  constructor(hash, _key) {
    super();
    this.finished = false;
    this.destroyed = false;
    ahash(hash);
    const key = toBytes(_key);
    this.iHash = hash.create();
    if (typeof this.iHash.update !== "function")
      throw new Error("Expected instance of class which extends utils.Hash");
    this.blockLen = this.iHash.blockLen;
    this.outputLen = this.iHash.outputLen;
    const blockLen = this.blockLen;
    const pad = new Uint8Array(blockLen);
    pad.set(key.length > blockLen ? hash.create().update(key).digest() : key);
    for (let i = 0; i < pad.length; i++)
      pad[i] ^= 54;
    this.iHash.update(pad);
    this.oHash = hash.create();
    for (let i = 0; i < pad.length; i++)
      pad[i] ^= 54 ^ 92;
    this.oHash.update(pad);
    clean(pad);
  }
  update(buf) {
    aexists(this);
    this.iHash.update(buf);
    return this;
  }
  digestInto(out) {
    aexists(this);
    abytes(out, this.outputLen);
    this.finished = true;
    this.iHash.digestInto(out);
    this.oHash.update(out);
    this.oHash.digestInto(out);
    this.destroy();
  }
  digest() {
    const out = new Uint8Array(this.oHash.outputLen);
    this.digestInto(out);
    return out;
  }
  _cloneInto(to) {
    to || (to = Object.create(Object.getPrototypeOf(this), {}));
    const { oHash, iHash, finished, destroyed, blockLen, outputLen } = this;
    to = to;
    to.finished = finished;
    to.destroyed = destroyed;
    to.blockLen = blockLen;
    to.outputLen = outputLen;
    to.oHash = oHash._cloneInto(to.oHash);
    to.iHash = iHash._cloneInto(to.iHash);
    return to;
  }
  clone() {
    return this._cloneInto();
  }
  destroy() {
    this.destroyed = true;
    this.oHash.destroy();
    this.iHash.destroy();
  }
};
var hmac = (hash, key, message) => new HMAC(hash, key).update(message).digest();
hmac.create = (hash, key) => new HMAC(hash, key);

// node_modules/@noble/hashes/esm/hkdf.js
function extract(hash, ikm, salt) {
  ahash(hash);
  if (salt === void 0)
    salt = new Uint8Array(hash.outputLen);
  return hmac(hash, toBytes(salt), toBytes(ikm));
}
var HKDF_COUNTER = /* @__PURE__ */ Uint8Array.from([0]);
var EMPTY_BUFFER = /* @__PURE__ */ Uint8Array.of();
function expand(hash, prk, info, length = 32) {
  ahash(hash);
  anumber(length);
  const olen = hash.outputLen;
  if (length > 255 * olen)
    throw new Error("Length should be <= 255*HashLen");
  const blocks = Math.ceil(length / olen);
  if (info === void 0)
    info = EMPTY_BUFFER;
  const okm = new Uint8Array(blocks * olen);
  const HMAC2 = hmac.create(hash, prk);
  const HMACTmp = HMAC2._cloneInto();
  const T = new Uint8Array(HMAC2.outputLen);
  for (let counter = 0; counter < blocks; counter++) {
    HKDF_COUNTER[0] = counter + 1;
    HMACTmp.update(counter === 0 ? EMPTY_BUFFER : T).update(info).update(HKDF_COUNTER).digestInto(T);
    okm.set(T, olen * counter);
    HMAC2._cloneInto(HMACTmp);
  }
  HMAC2.destroy();
  HMACTmp.destroy();
  clean(T, HKDF_COUNTER);
  return okm.slice(0, length);
}
var hkdf = (hash, ikm, salt, info, length) => expand(hash, extract(hash, ikm, salt), info, length);

// src/asymmetric.ts
var NONCE_LENGTH2 = 12;
var HKDF_INFO = new TextEncoder().encode("BlazorPRF-ECIES-v1");
function deriveEncryptionKey(sharedSecret, ephemeralPublicKey) {
  return hkdf(
    sha2562,
    sharedSecret,
    ephemeralPublicKey,
    // Use ephemeral public key as salt
    HKDF_INFO,
    32
  );
}
function asymmetricEncrypt(message, recipientPublicKeyBase64) {
  const recipientPublicKey = fromBase64(recipientPublicKeyBase64);
  if (recipientPublicKey.length !== 32) {
    throw new Error(`Recipient public key must be 32 bytes, got ${recipientPublicKey.length}`);
  }
  const ephemeral = generateEphemeralKeypair();
  let sharedSecret = null;
  let encryptionKey = null;
  try {
    sharedSecret = computeSharedSecret(ephemeral.privateKey, recipientPublicKey);
    encryptionKey = deriveEncryptionKey(sharedSecret, ephemeral.publicKey);
    const nonce = randomBytes2(NONCE_LENGTH2);
    const encoder = new TextEncoder();
    const plaintext = encoder.encode(message);
    const cipher = chacha20poly1305(encryptionKey, nonce);
    const ciphertext = cipher.encrypt(plaintext);
    return {
      ephemeralPublicKey: toBase64(ephemeral.publicKey),
      ciphertext: toBase64(ciphertext),
      nonce: toBase64(nonce)
    };
  } finally {
    zeroFill(ephemeral.privateKey);
    if (sharedSecret) {
      zeroFill(sharedSecret);
    }
    if (encryptionKey) {
      zeroFill(encryptionKey);
    }
  }
}
function asymmetricDecrypt(encrypted, privateKeyBase64) {
  const privateKey = fromBase64(privateKeyBase64);
  if (privateKey.length !== 32) {
    throw new Error(`Private key must be 32 bytes, got ${privateKey.length}`);
  }
  const ephemeralPublicKey = fromBase64(encrypted.ephemeralPublicKey);
  const ciphertext = fromBase64(encrypted.ciphertext);
  const nonce = fromBase64(encrypted.nonce);
  if (ephemeralPublicKey.length !== 32) {
    throw new Error(`Ephemeral public key must be 32 bytes, got ${ephemeralPublicKey.length}`);
  }
  if (nonce.length !== NONCE_LENGTH2) {
    throw new Error(`Nonce must be ${NONCE_LENGTH2} bytes, got ${nonce.length}`);
  }
  let sharedSecret = null;
  let encryptionKey = null;
  try {
    sharedSecret = computeSharedSecret(privateKey, ephemeralPublicKey);
    encryptionKey = deriveEncryptionKey(sharedSecret, ephemeralPublicKey);
    const cipher = chacha20poly1305(encryptionKey, nonce);
    const plaintext = cipher.decrypt(ciphertext);
    const decoder = new TextDecoder();
    return decoder.decode(plaintext);
  } finally {
    zeroFill(privateKey);
    if (sharedSecret) {
      zeroFill(sharedSecret);
    }
    if (encryptionKey) {
      zeroFill(encryptionKey);
    }
  }
}

// src/index.ts
async function isPrfSupported() {
  return checkPrfSupport();
}
async function register(displayName, optionsJson) {
  const options = JSON.parse(optionsJson);
  const result = await registerCredentialWithPrf(displayName, options);
  return JSON.stringify(result);
}
async function deriveKeys(credentialIdBase64, salt, optionsJson) {
  const options = JSON.parse(optionsJson);
  const prfResult = await evaluatePrf(credentialIdBase64, salt, options);
  if (!prfResult.success || !prfResult.value) {
    return JSON.stringify({
      success: false,
      errorCode: prfResult.errorCode,
      cancelled: prfResult.cancelled
    });
  }
  const prfOutput = fromBase64(prfResult.value);
  const keypair = deriveKeypairFromPrf(prfOutput);
  const privateKeyBase64 = toBase64(keypair.privateKey);
  const publicKeyBase64 = toBase64(keypair.publicKey);
  zeroFill(prfOutput);
  zeroFill(keypair.privateKey);
  return JSON.stringify({
    success: true,
    value: {
      privateKeyBase64,
      publicKeyBase64
    }
  });
}
async function deriveKeysDiscoverable(salt, optionsJson) {
  const options = JSON.parse(optionsJson);
  const prfResult = await evaluatePrfDiscoverable(salt, options);
  if (!prfResult.success || !prfResult.value) {
    return JSON.stringify({
      success: false,
      errorCode: prfResult.errorCode,
      cancelled: prfResult.cancelled
    });
  }
  const prfOutput = fromBase64(prfResult.value.prfOutput);
  const keypair = deriveKeypairFromPrf(prfOutput);
  const privateKeyBase64 = toBase64(keypair.privateKey);
  const publicKeyBase64 = toBase64(keypair.publicKey);
  zeroFill(prfOutput);
  zeroFill(keypair.privateKey);
  return JSON.stringify({
    success: true,
    value: {
      credentialId: prfResult.value.credentialId,
      privateKeyBase64,
      publicKeyBase64
    }
  });
}
function encryptSymmetric(message, keyBase64) {
  const encrypted = symmetricEncrypt(message, keyBase64);
  return JSON.stringify(encrypted);
}
function decryptSymmetric(encryptedJson, keyBase64) {
  const encrypted = JSON.parse(encryptedJson);
  try {
    const plaintext = symmetricDecrypt(encrypted, keyBase64);
    return JSON.stringify({
      success: true,
      value: plaintext
    });
  } catch (error) {
    const rawMessage = error instanceof Error ? error.message : "";
    const errorCode = rawMessage.toLowerCase().includes("tag") ? "AuthenticationTagMismatch" /* AuthenticationTagMismatch */ : "DecryptionFailed" /* DecryptionFailed */;
    return JSON.stringify({
      success: false,
      errorCode
    });
  }
}
function encryptAsymmetric(plaintext, recipientPublicKeyBase64) {
  try {
    const encrypted = asymmetricEncrypt(plaintext, recipientPublicKeyBase64);
    return JSON.stringify({
      success: true,
      value: encrypted
    });
  } catch {
    return JSON.stringify({
      success: false,
      errorCode: "EncryptionFailed" /* EncryptionFailed */
    });
  }
}
function decryptAsymmetric(encryptedJson, privateKeyBase64) {
  const encrypted = JSON.parse(encryptedJson);
  try {
    const plaintext = asymmetricDecrypt(encrypted, privateKeyBase64);
    return JSON.stringify({
      success: true,
      value: plaintext
    });
  } catch (error) {
    const rawMessage = error instanceof Error ? error.message : "";
    const errorCode = rawMessage.toLowerCase().includes("tag") ? "AuthenticationTagMismatch" /* AuthenticationTagMismatch */ : "DecryptionFailed" /* DecryptionFailed */;
    return JSON.stringify({
      success: false,
      errorCode
    });
  }
}
var blazorPrf = {
  isPrfSupported,
  register,
  deriveKeys,
  deriveKeysDiscoverable,
  encryptSymmetric,
  decryptSymmetric,
  encryptAsymmetric,
  decryptAsymmetric
};
globalThis.blazorPrf = blazorPrf;
var index_default = blazorPrf;
export {
  decryptAsymmetric,
  decryptSymmetric,
  index_default as default,
  deriveKeys,
  deriveKeysDiscoverable,
  encryptAsymmetric,
  encryptSymmetric,
  isPrfSupported,
  register
};
/*! Bundled license information:

@noble/hashes/esm/utils.js:
  (*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) *)

@noble/curves/esm/utils.js:
  (*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) *)

@noble/curves/esm/abstract/modular.js:
  (*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) *)

@noble/curves/esm/abstract/curve.js:
  (*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) *)

@noble/curves/esm/abstract/edwards.js:
  (*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) *)

@noble/curves/esm/abstract/montgomery.js:
  (*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) *)

@noble/curves/esm/ed25519.js:
  (*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) *)

@noble/ciphers/esm/utils.js:
  (*! noble-ciphers - MIT License (c) 2023 Paul Miller (paulmillr.com) *)
*/
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsiLi4vVHlwZVNjcmlwdC9zcmMvdXRpbHMudHMiLCAiLi4vVHlwZVNjcmlwdC9zcmMvd2ViYXV0aG4udHMiLCAiLi4vVHlwZVNjcmlwdC9ub2RlX21vZHVsZXMvQG5vYmxlL2hhc2hlcy9zcmMvY3J5cHRvLnRzIiwgIi4uL1R5cGVTY3JpcHQvbm9kZV9tb2R1bGVzL0Bub2JsZS9oYXNoZXMvc3JjL3V0aWxzLnRzIiwgIi4uL1R5cGVTY3JpcHQvbm9kZV9tb2R1bGVzL0Bub2JsZS9oYXNoZXMvc3JjL19tZC50cyIsICIuLi9UeXBlU2NyaXB0L25vZGVfbW9kdWxlcy9Abm9ibGUvaGFzaGVzL3NyYy9fdTY0LnRzIiwgIi4uL1R5cGVTY3JpcHQvbm9kZV9tb2R1bGVzL0Bub2JsZS9oYXNoZXMvc3JjL3NoYTIudHMiLCAiLi4vVHlwZVNjcmlwdC9ub2RlX21vZHVsZXMvQG5vYmxlL2hhc2hlcy9zcmMvc2hhMjU2LnRzIiwgIi4uL1R5cGVTY3JpcHQvc3JjL3ByZi50cyIsICIuLi9UeXBlU2NyaXB0L25vZGVfbW9kdWxlcy9Abm9ibGUvY3VydmVzL3NyYy91dGlscy50cyIsICIuLi9UeXBlU2NyaXB0L25vZGVfbW9kdWxlcy9Abm9ibGUvY3VydmVzL3NyYy9hYnN0cmFjdC9tb2R1bGFyLnRzIiwgIi4uL1R5cGVTY3JpcHQvbm9kZV9tb2R1bGVzL0Bub2JsZS9jdXJ2ZXMvc3JjL2Fic3RyYWN0L2N1cnZlLnRzIiwgIi4uL1R5cGVTY3JpcHQvbm9kZV9tb2R1bGVzL0Bub2JsZS9jdXJ2ZXMvc3JjL2Fic3RyYWN0L2Vkd2FyZHMudHMiLCAiLi4vVHlwZVNjcmlwdC9ub2RlX21vZHVsZXMvQG5vYmxlL2N1cnZlcy9zcmMvYWJzdHJhY3QvbW9udGdvbWVyeS50cyIsICIuLi9UeXBlU2NyaXB0L25vZGVfbW9kdWxlcy9Abm9ibGUvY3VydmVzL3NyYy9lZDI1NTE5LnRzIiwgIi4uL1R5cGVTY3JpcHQvc3JjL2tleXBhaXIudHMiLCAiLi4vVHlwZVNjcmlwdC9ub2RlX21vZHVsZXMvQG5vYmxlL2NpcGhlcnMvc3JjL3V0aWxzLnRzIiwgIi4uL1R5cGVTY3JpcHQvbm9kZV9tb2R1bGVzL0Bub2JsZS9jaXBoZXJzL3NyYy9fYXJ4LnRzIiwgIi4uL1R5cGVTY3JpcHQvbm9kZV9tb2R1bGVzL0Bub2JsZS9jaXBoZXJzL3NyYy9fcG9seTEzMDUudHMiLCAiLi4vVHlwZVNjcmlwdC9ub2RlX21vZHVsZXMvQG5vYmxlL2NpcGhlcnMvc3JjL2NoYWNoYS50cyIsICIuLi9UeXBlU2NyaXB0L25vZGVfbW9kdWxlcy9Abm9ibGUvY2lwaGVycy9zcmMvY3J5cHRvLnRzIiwgIi4uL1R5cGVTY3JpcHQvbm9kZV9tb2R1bGVzL0Bub2JsZS9jaXBoZXJzL3NyYy93ZWJjcnlwdG8udHMiLCAiLi4vVHlwZVNjcmlwdC9zcmMvc3ltbWV0cmljLnRzIiwgIi4uL1R5cGVTY3JpcHQvbm9kZV9tb2R1bGVzL0Bub2JsZS9oYXNoZXMvc3JjL2htYWMudHMiLCAiLi4vVHlwZVNjcmlwdC9ub2RlX21vZHVsZXMvQG5vYmxlL2hhc2hlcy9zcmMvaGtkZi50cyIsICIuLi9UeXBlU2NyaXB0L3NyYy9hc3ltbWV0cmljLnRzIiwgIi4uL1R5cGVTY3JpcHQvc3JjL2luZGV4LnRzIl0sCiAgInNvdXJjZXNDb250ZW50IjogWyIvLyBVdGlsaXR5IGZ1bmN0aW9ucyBmb3Igc2VjdXJlIG1lbW9yeSBoYW5kbGluZyBhbmQgZW5jb2RpbmdcblxuLyoqXG4gKiBaZXJvLWZpbGwgYSBVaW50OEFycmF5IHRvIHNlY3VyZWx5IHdpcGUgc2Vuc2l0aXZlIGRhdGEgZnJvbSBtZW1vcnkuXG4gKiBDYWxsIHRoaXMgaW1tZWRpYXRlbHkgYWZ0ZXIgc2Vuc2l0aXZlIGRhdGEgaXMgbm8gbG9uZ2VyIG5lZWRlZC5cbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIHplcm9GaWxsKGJ1ZmZlcjogVWludDhBcnJheSk6IHZvaWQge1xuICAgIGJ1ZmZlci5maWxsKDApO1xufVxuXG4vKipcbiAqIEV4ZWN1dGUgYSBmdW5jdGlvbiB3aXRoIGEgYnVmZmVyLCBlbnN1cmluZyBpdCdzIHplcm9lZCBhZnRlciB1c2UuXG4gKiBAcGFyYW0gYnVmZmVyIFRoZSBzZW5zaXRpdmUgYnVmZmVyIHRvIHVzZVxuICogQHBhcmFtIGZuIFRoZSBmdW5jdGlvbiB0byBleGVjdXRlIHdpdGggdGhlIGJ1ZmZlclxuICogQHJldHVybnMgVGhlIHJlc3VsdCBvZiB0aGUgZnVuY3Rpb25cbiAqL1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIHdpdGhTZWN1cmVCdWZmZXI8VD4oXG4gICAgYnVmZmVyOiBVaW50OEFycmF5LFxuICAgIGZuOiAoYnVmOiBVaW50OEFycmF5KSA9PiBUIHwgUHJvbWlzZTxUPlxuKTogUHJvbWlzZTxUPiB7XG4gICAgdHJ5IHtcbiAgICAgICAgcmV0dXJuIGF3YWl0IGZuKGJ1ZmZlcik7XG4gICAgfSBmaW5hbGx5IHtcbiAgICAgICAgemVyb0ZpbGwoYnVmZmVyKTtcbiAgICB9XG59XG5cbi8qKlxuICogQ29udmVydCBVaW50OEFycmF5IHRvIEJhc2U2NCBzdHJpbmdcbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIHRvQmFzZTY0KGRhdGE6IFVpbnQ4QXJyYXkpOiBzdHJpbmcge1xuICAgIHJldHVybiBidG9hKFN0cmluZy5mcm9tQ2hhckNvZGUoLi4uZGF0YSkpO1xufVxuXG4vKipcbiAqIENvbnZlcnQgQmFzZTY0IHN0cmluZyB0byBVaW50OEFycmF5XG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBmcm9tQmFzZTY0KGJhc2U2NDogc3RyaW5nKTogVWludDhBcnJheSB7XG4gICAgY29uc3QgYmluYXJ5ID0gYXRvYihiYXNlNjQpO1xuICAgIGNvbnN0IGJ5dGVzID0gbmV3IFVpbnQ4QXJyYXkoYmluYXJ5Lmxlbmd0aCk7XG4gICAgZm9yIChsZXQgaSA9IDA7IGkgPCBiaW5hcnkubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgYnl0ZXNbaV0gPSBiaW5hcnkuY2hhckNvZGVBdChpKTtcbiAgICB9XG4gICAgcmV0dXJuIGJ5dGVzO1xufVxuXG4vKipcbiAqIENvbnZlcnQgQXJyYXlCdWZmZXIgdG8gQmFzZTY0IHN0cmluZ1xuICovXG5leHBvcnQgZnVuY3Rpb24gYXJyYXlCdWZmZXJUb0Jhc2U2NChidWZmZXI6IEFycmF5QnVmZmVyKTogc3RyaW5nIHtcbiAgICByZXR1cm4gdG9CYXNlNjQobmV3IFVpbnQ4QXJyYXkoYnVmZmVyKSk7XG59XG5cbi8qKlxuICogQ29udmVydCBCYXNlNjQgc3RyaW5nIHRvIEFycmF5QnVmZmVyXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBiYXNlNjRUb0FycmF5QnVmZmVyKGJhc2U2NDogc3RyaW5nKTogQXJyYXlCdWZmZXIge1xuICAgIHJldHVybiBmcm9tQmFzZTY0KGJhc2U2NCkuYnVmZmVyO1xufVxuXG4vKipcbiAqIENvbmNhdGVuYXRlIG11bHRpcGxlIFVpbnQ4QXJyYXlzXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBjb25jYXRCeXRlcyguLi5hcnJheXM6IFVpbnQ4QXJyYXlbXSk6IFVpbnQ4QXJyYXkge1xuICAgIGNvbnN0IHRvdGFsTGVuZ3RoID0gYXJyYXlzLnJlZHVjZSgoYWNjLCBhcnIpID0+IGFjYyArIGFyci5sZW5ndGgsIDApO1xuICAgIGNvbnN0IHJlc3VsdCA9IG5ldyBVaW50OEFycmF5KHRvdGFsTGVuZ3RoKTtcbiAgICBsZXQgb2Zmc2V0ID0gMDtcbiAgICBmb3IgKGNvbnN0IGFyciBvZiBhcnJheXMpIHtcbiAgICAgICAgcmVzdWx0LnNldChhcnIsIG9mZnNldCk7XG4gICAgICAgIG9mZnNldCArPSBhcnIubGVuZ3RoO1xuICAgIH1cbiAgICByZXR1cm4gcmVzdWx0O1xufVxuIiwgIi8vIFdlYkF1dGhuIHJlZ2lzdHJhdGlvbiB3aXRoIFBSRiBleHRlbnNpb24gc3VwcG9ydFxuXG5pbXBvcnQgeyBQcmZFcnJvckNvZGUsIHR5cGUgUHJmQ3JlZGVudGlhbCwgdHlwZSBQcmZPcHRpb25zLCB0eXBlIFByZlJlc3VsdCB9IGZyb20gJy4vdHlwZXMuanMnO1xuaW1wb3J0IHsgYXJyYXlCdWZmZXJUb0Jhc2U2NCB9IGZyb20gJy4vdXRpbHMuanMnO1xuXG4vKipcbiAqIENoZWNrIGlmIHRoZSBjdXJyZW50IGJyb3dzZXIgYW5kIHBsYXRmb3JtIHN1cHBvcnQgV2ViQXV0aG4gUFJGIGV4dGVuc2lvbi5cbiAqXG4gKiBAcmV0dXJucyB0cnVlIGlmIFBSRiBpcyBsaWtlbHkgc3VwcG9ydGVkXG4gKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBjaGVja1ByZlN1cHBvcnQoKTogUHJvbWlzZTxib29sZWFuPiB7XG4gICAgLy8gQ2hlY2sgYmFzaWMgV2ViQXV0aG4gc3VwcG9ydFxuICAgIGlmICghd2luZG93LlB1YmxpY0tleUNyZWRlbnRpYWwpIHtcbiAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgIH1cblxuICAgIC8vIENoZWNrIGlmIHBsYXRmb3JtIGF1dGhlbnRpY2F0b3IgaXMgYXZhaWxhYmxlXG4gICAgaWYgKHR5cGVvZiBQdWJsaWNLZXlDcmVkZW50aWFsLmlzVXNlclZlcmlmeWluZ1BsYXRmb3JtQXV0aGVudGljYXRvckF2YWlsYWJsZSA9PT0gJ2Z1bmN0aW9uJykge1xuICAgICAgICBjb25zdCBhdmFpbGFibGUgPSBhd2FpdCBQdWJsaWNLZXlDcmVkZW50aWFsLmlzVXNlclZlcmlmeWluZ1BsYXRmb3JtQXV0aGVudGljYXRvckF2YWlsYWJsZSgpO1xuICAgICAgICBpZiAoIWF2YWlsYWJsZSkge1xuICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICB9XG4gICAgfVxuXG4gICAgLy8gUFJGIGV4dGVuc2lvbiBzdXBwb3J0IGNhbiBvbmx5IGJlIHRydWx5IHZlcmlmaWVkIGR1cmluZyByZWdpc3RyYXRpb25cbiAgICAvLyBNb3N0IG1vZGVybiBwbGF0Zm9ybSBhdXRoZW50aWNhdG9ycyAoaU9TIDE3KywgbWFjT1MgMTQrLCBXaW5kb3dzIDEwKywgQW5kcm9pZCAxNCspIHN1cHBvcnQgaXRcbiAgICByZXR1cm4gdHJ1ZTtcbn1cblxuLyoqXG4gKiBSZWdpc3RlciBhIG5ldyBXZWJBdXRobiBjcmVkZW50aWFsIHdpdGggUFJGIGV4dGVuc2lvbiBlbmFibGVkLlxuICpcbiAqIEBwYXJhbSBkaXNwbGF5TmFtZSBPcHRpb25hbCBodW1hbi1yZWFkYWJsZSBkaXNwbGF5IG5hbWUuIElmIG51bGwsIHBsYXRmb3JtIGdlbmVyYXRlcyBvbmUuXG4gKiBAcGFyYW0gb3B0aW9ucyBQUkYgY29uZmlndXJhdGlvbiBvcHRpb25zXG4gKiBAcmV0dXJucyBQcmZSZXN1bHQgY29udGFpbmluZyB0aGUgY3JlZGVudGlhbCBvciBlcnJvclxuICovXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gcmVnaXN0ZXJDcmVkZW50aWFsV2l0aFByZihcbiAgICBkaXNwbGF5TmFtZTogc3RyaW5nIHwgbnVsbCxcbiAgICBvcHRpb25zOiBQcmZPcHRpb25zXG4pOiBQcm9taXNlPFByZlJlc3VsdDxQcmZDcmVkZW50aWFsPj4ge1xuICAgIHRyeSB7XG4gICAgICAgIC8vIEdlbmVyYXRlIHJhbmRvbSB1c2VyIElEIChyZXF1aXJlZCBieSBXZWJBdXRobiBzcGVjLCBub3QgbWVhbmluZ2Z1bCBmb3IgUFJGLW9ubHkgdXNlKVxuICAgICAgICBjb25zdCB1c2VySWQgPSBjcnlwdG8uZ2V0UmFuZG9tVmFsdWVzKG5ldyBVaW50OEFycmF5KDE2KSk7XG5cbiAgICAgICAgLy8gRGlzcGxheSBuYW1lIHNob3duIGluIHBsYXRmb3JtIHBhc3NrZXkgbWFuYWdlclxuICAgICAgICBjb25zdCBlZmZlY3RpdmVEaXNwbGF5TmFtZSA9IGRpc3BsYXlOYW1lID8/IG9wdGlvbnMucnBOYW1lO1xuXG4gICAgICAgIC8vIERldGVybWluZSBhdXRoZW50aWNhdG9yIGF0dGFjaG1lbnRcbiAgICAgICAgY29uc3QgYXV0aGVudGljYXRvckF0dGFjaG1lbnQ6IEF1dGhlbnRpY2F0b3JBdHRhY2htZW50IHwgdW5kZWZpbmVkID1cbiAgICAgICAgICAgIG9wdGlvbnMuYXV0aGVudGljYXRvckF0dGFjaG1lbnQgPT09ICdwbGF0Zm9ybScgPyAncGxhdGZvcm0nIDogJ2Nyb3NzLXBsYXRmb3JtJztcblxuICAgICAgICAvLyBCdWlsZCByZWdpc3RyYXRpb24gb3B0aW9uc1xuICAgICAgICBjb25zdCBwdWJsaWNLZXlDcmVkZW50aWFsQ3JlYXRpb25PcHRpb25zOiBQdWJsaWNLZXlDcmVkZW50aWFsQ3JlYXRpb25PcHRpb25zID0ge1xuICAgICAgICAgICAgY2hhbGxlbmdlOiBjcnlwdG8uZ2V0UmFuZG9tVmFsdWVzKG5ldyBVaW50OEFycmF5KDMyKSksXG4gICAgICAgICAgICBycDoge1xuICAgICAgICAgICAgICAgIG5hbWU6IG9wdGlvbnMucnBOYW1lLFxuICAgICAgICAgICAgICAgIGlkOiBvcHRpb25zLnJwSWQgPz8gd2luZG93LmxvY2F0aW9uLmhvc3RuYW1lXG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgdXNlcjoge1xuICAgICAgICAgICAgICAgIGlkOiB1c2VySWQsXG4gICAgICAgICAgICAgICAgbmFtZTogZWZmZWN0aXZlRGlzcGxheU5hbWUsIC8vIFJlcXVpcmVkIGJ5IHNwZWNcbiAgICAgICAgICAgICAgICBkaXNwbGF5TmFtZTogZWZmZWN0aXZlRGlzcGxheU5hbWVcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBwdWJLZXlDcmVkUGFyYW1zOiBbXG4gICAgICAgICAgICAgICAgeyBhbGc6IC03LCB0eXBlOiAncHVibGljLWtleScgfSwgICAvLyBFUzI1NiAoUC0yNTYpXG4gICAgICAgICAgICAgICAgeyBhbGc6IC0yNTcsIHR5cGU6ICdwdWJsaWMta2V5JyB9ICAvLyBSUzI1NlxuICAgICAgICAgICAgXSxcbiAgICAgICAgICAgIGF1dGhlbnRpY2F0b3JTZWxlY3Rpb246IHtcbiAgICAgICAgICAgICAgICBhdXRoZW50aWNhdG9yQXR0YWNobWVudCxcbiAgICAgICAgICAgICAgICByZXNpZGVudEtleTogJ3JlcXVpcmVkJyxcbiAgICAgICAgICAgICAgICB1c2VyVmVyaWZpY2F0aW9uOiAnZGlzY291cmFnZWQnXG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgdGltZW91dDogb3B0aW9ucy50aW1lb3V0TXMsXG4gICAgICAgICAgICBhdHRlc3RhdGlvbjogJ25vbmUnLFxuICAgICAgICAgICAgZXh0ZW5zaW9uczoge1xuICAgICAgICAgICAgICAgIHByZjoge31cbiAgICAgICAgICAgIH0gYXMgQXV0aGVudGljYXRpb25FeHRlbnNpb25zQ2xpZW50SW5wdXRzXG4gICAgICAgIH07XG5cbiAgICAgICAgLy8gQ3JlYXRlIGNyZWRlbnRpYWwgdXNpbmcgbmF2aWdhdG9yLmNyZWRlbnRpYWxzIEFQSVxuICAgICAgICBjb25zdCBjcmVkZW50aWFsID0gYXdhaXQgbmF2aWdhdG9yLmNyZWRlbnRpYWxzLmNyZWF0ZSh7XG4gICAgICAgICAgICBwdWJsaWNLZXk6IHB1YmxpY0tleUNyZWRlbnRpYWxDcmVhdGlvbk9wdGlvbnNcbiAgICAgICAgfSkgYXMgUHVibGljS2V5Q3JlZGVudGlhbCB8IG51bGw7XG5cbiAgICAgICAgaWYgKGNyZWRlbnRpYWwgPT09IG51bGwpIHtcbiAgICAgICAgICAgIHJldHVybiB7XG4gICAgICAgICAgICAgICAgc3VjY2VzczogZmFsc2UsXG4gICAgICAgICAgICAgICAgY2FuY2VsbGVkOiB0cnVlXG4gICAgICAgICAgICB9O1xuICAgICAgICB9XG5cbiAgICAgICAgLy8gQ2hlY2sgaWYgUFJGIGV4dGVuc2lvbiBpcyBlbmFibGVkXG4gICAgICAgIGNvbnN0IGV4dGVuc2lvblJlc3VsdHMgPSBjcmVkZW50aWFsLmdldENsaWVudEV4dGVuc2lvblJlc3VsdHMoKSBhcyB7XG4gICAgICAgICAgICBwcmY/OiB7IGVuYWJsZWQ/OiBib29sZWFuIH07XG4gICAgICAgIH07XG5cbiAgICAgICAgaWYgKCFleHRlbnNpb25SZXN1bHRzLnByZj8uZW5hYmxlZCkge1xuICAgICAgICAgICAgcmV0dXJuIHtcbiAgICAgICAgICAgICAgICBzdWNjZXNzOiBmYWxzZSxcbiAgICAgICAgICAgICAgICBlcnJvckNvZGU6IFByZkVycm9yQ29kZS5QcmZOb3RTdXBwb3J0ZWRcbiAgICAgICAgICAgIH07XG4gICAgICAgIH1cblxuICAgICAgICByZXR1cm4ge1xuICAgICAgICAgICAgc3VjY2VzczogdHJ1ZSxcbiAgICAgICAgICAgIHZhbHVlOiB7XG4gICAgICAgICAgICAgICAgaWQ6IGNyZWRlbnRpYWwuaWQsXG4gICAgICAgICAgICAgICAgcmF3SWQ6IGFycmF5QnVmZmVyVG9CYXNlNjQoY3JlZGVudGlhbC5yYXdJZClcbiAgICAgICAgICAgIH1cbiAgICAgICAgfTtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgICAvLyBVc2VyIGNhbmNlbGxlZCB0aGUgcmVnaXN0cmF0aW9uIC0gbm90IGFuIGVycm9yXG4gICAgICAgIGlmIChlcnJvciBpbnN0YW5jZW9mIERPTUV4Y2VwdGlvbiAmJiBlcnJvci5uYW1lID09PSAnTm90QWxsb3dlZEVycm9yJykge1xuICAgICAgICAgICAgcmV0dXJuIHtcbiAgICAgICAgICAgICAgICBzdWNjZXNzOiBmYWxzZSxcbiAgICAgICAgICAgICAgICBjYW5jZWxsZWQ6IHRydWVcbiAgICAgICAgICAgIH07XG4gICAgICAgIH1cblxuICAgICAgICByZXR1cm4ge1xuICAgICAgICAgICAgc3VjY2VzczogZmFsc2UsXG4gICAgICAgICAgICBlcnJvckNvZGU6IFByZkVycm9yQ29kZS5SZWdpc3RyYXRpb25GYWlsZWRcbiAgICAgICAgfTtcbiAgICB9XG59XG4iLCAiLyoqXG4gKiBJbnRlcm5hbCB3ZWJjcnlwdG8gYWxpYXMuXG4gKiBXZSB1c2UgV2ViQ3J5cHRvIGFrYSBnbG9iYWxUaGlzLmNyeXB0bywgd2hpY2ggZXhpc3RzIGluIGJyb3dzZXJzIGFuZCBub2RlLmpzIDE2Ky5cbiAqIFNlZSB1dGlscy50cyBmb3IgZGV0YWlscy5cbiAqIEBtb2R1bGVcbiAqL1xuZGVjbGFyZSBjb25zdCBnbG9iYWxUaGlzOiBSZWNvcmQ8c3RyaW5nLCBhbnk+IHwgdW5kZWZpbmVkO1xuZXhwb3J0IGNvbnN0IGNyeXB0bzogYW55ID1cbiAgdHlwZW9mIGdsb2JhbFRoaXMgPT09ICdvYmplY3QnICYmICdjcnlwdG8nIGluIGdsb2JhbFRoaXMgPyBnbG9iYWxUaGlzLmNyeXB0byA6IHVuZGVmaW5lZDtcbiIsICIvKipcbiAqIFV0aWxpdGllcyBmb3IgaGV4LCBieXRlcywgQ1NQUk5HLlxuICogQG1vZHVsZVxuICovXG4vKiEgbm9ibGUtaGFzaGVzIC0gTUlUIExpY2Vuc2UgKGMpIDIwMjIgUGF1bCBNaWxsZXIgKHBhdWxtaWxsci5jb20pICovXG5cbi8vIFdlIHVzZSBXZWJDcnlwdG8gYWthIGdsb2JhbFRoaXMuY3J5cHRvLCB3aGljaCBleGlzdHMgaW4gYnJvd3NlcnMgYW5kIG5vZGUuanMgMTYrLlxuLy8gbm9kZS5qcyB2ZXJzaW9ucyBlYXJsaWVyIHRoYW4gdjE5IGRvbid0IGRlY2xhcmUgaXQgaW4gZ2xvYmFsIHNjb3BlLlxuLy8gRm9yIG5vZGUuanMsIHBhY2thZ2UuanNvbiNleHBvcnRzIGZpZWxkIG1hcHBpbmcgcmV3cml0ZXMgaW1wb3J0XG4vLyBmcm9tIGBjcnlwdG9gIHRvIGBjcnlwdG9Ob2RlYCwgd2hpY2ggaW1wb3J0cyBuYXRpdmUgbW9kdWxlLlxuLy8gTWFrZXMgdGhlIHV0aWxzIHVuLWltcG9ydGFibGUgaW4gYnJvd3NlcnMgd2l0aG91dCBhIGJ1bmRsZXIuXG4vLyBPbmNlIG5vZGUuanMgMTggaXMgZGVwcmVjYXRlZCAoMjAyNS0wNC0zMCksIHdlIGNhbiBqdXN0IGRyb3AgdGhlIGltcG9ydC5cbmltcG9ydCB7IGNyeXB0byB9IGZyb20gJ0Bub2JsZS9oYXNoZXMvY3J5cHRvJztcblxuLyoqIENoZWNrcyBpZiBzb21ldGhpbmcgaXMgVWludDhBcnJheS4gQmUgY2FyZWZ1bDogbm9kZWpzIEJ1ZmZlciB3aWxsIHJldHVybiB0cnVlLiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGlzQnl0ZXMoYTogdW5rbm93bik6IGEgaXMgVWludDhBcnJheSB7XG4gIHJldHVybiBhIGluc3RhbmNlb2YgVWludDhBcnJheSB8fCAoQXJyYXlCdWZmZXIuaXNWaWV3KGEpICYmIGEuY29uc3RydWN0b3IubmFtZSA9PT0gJ1VpbnQ4QXJyYXknKTtcbn1cblxuLyoqIEFzc2VydHMgc29tZXRoaW5nIGlzIHBvc2l0aXZlIGludGVnZXIuICovXG5leHBvcnQgZnVuY3Rpb24gYW51bWJlcihuOiBudW1iZXIpOiB2b2lkIHtcbiAgaWYgKCFOdW1iZXIuaXNTYWZlSW50ZWdlcihuKSB8fCBuIDwgMCkgdGhyb3cgbmV3IEVycm9yKCdwb3NpdGl2ZSBpbnRlZ2VyIGV4cGVjdGVkLCBnb3QgJyArIG4pO1xufVxuXG4vKiogQXNzZXJ0cyBzb21ldGhpbmcgaXMgVWludDhBcnJheS4gKi9cbmV4cG9ydCBmdW5jdGlvbiBhYnl0ZXMoYjogVWludDhBcnJheSB8IHVuZGVmaW5lZCwgLi4ubGVuZ3RoczogbnVtYmVyW10pOiB2b2lkIHtcbiAgaWYgKCFpc0J5dGVzKGIpKSB0aHJvdyBuZXcgRXJyb3IoJ1VpbnQ4QXJyYXkgZXhwZWN0ZWQnKTtcbiAgaWYgKGxlbmd0aHMubGVuZ3RoID4gMCAmJiAhbGVuZ3Rocy5pbmNsdWRlcyhiLmxlbmd0aCkpXG4gICAgdGhyb3cgbmV3IEVycm9yKCdVaW50OEFycmF5IGV4cGVjdGVkIG9mIGxlbmd0aCAnICsgbGVuZ3RocyArICcsIGdvdCBsZW5ndGg9JyArIGIubGVuZ3RoKTtcbn1cblxuLyoqIEFzc2VydHMgc29tZXRoaW5nIGlzIGhhc2ggKi9cbmV4cG9ydCBmdW5jdGlvbiBhaGFzaChoOiBJSGFzaCk6IHZvaWQge1xuICBpZiAodHlwZW9mIGggIT09ICdmdW5jdGlvbicgfHwgdHlwZW9mIGguY3JlYXRlICE9PSAnZnVuY3Rpb24nKVxuICAgIHRocm93IG5ldyBFcnJvcignSGFzaCBzaG91bGQgYmUgd3JhcHBlZCBieSB1dGlscy5jcmVhdGVIYXNoZXInKTtcbiAgYW51bWJlcihoLm91dHB1dExlbik7XG4gIGFudW1iZXIoaC5ibG9ja0xlbik7XG59XG5cbi8qKiBBc3NlcnRzIGEgaGFzaCBpbnN0YW5jZSBoYXMgbm90IGJlZW4gZGVzdHJveWVkIC8gZmluaXNoZWQgKi9cbmV4cG9ydCBmdW5jdGlvbiBhZXhpc3RzKGluc3RhbmNlOiBhbnksIGNoZWNrRmluaXNoZWQgPSB0cnVlKTogdm9pZCB7XG4gIGlmIChpbnN0YW5jZS5kZXN0cm95ZWQpIHRocm93IG5ldyBFcnJvcignSGFzaCBpbnN0YW5jZSBoYXMgYmVlbiBkZXN0cm95ZWQnKTtcbiAgaWYgKGNoZWNrRmluaXNoZWQgJiYgaW5zdGFuY2UuZmluaXNoZWQpIHRocm93IG5ldyBFcnJvcignSGFzaCNkaWdlc3QoKSBoYXMgYWxyZWFkeSBiZWVuIGNhbGxlZCcpO1xufVxuXG4vKiogQXNzZXJ0cyBvdXRwdXQgaXMgcHJvcGVybHktc2l6ZWQgYnl0ZSBhcnJheSAqL1xuZXhwb3J0IGZ1bmN0aW9uIGFvdXRwdXQob3V0OiBhbnksIGluc3RhbmNlOiBhbnkpOiB2b2lkIHtcbiAgYWJ5dGVzKG91dCk7XG4gIGNvbnN0IG1pbiA9IGluc3RhbmNlLm91dHB1dExlbjtcbiAgaWYgKG91dC5sZW5ndGggPCBtaW4pIHtcbiAgICB0aHJvdyBuZXcgRXJyb3IoJ2RpZ2VzdEludG8oKSBleHBlY3RzIG91dHB1dCBidWZmZXIgb2YgbGVuZ3RoIGF0IGxlYXN0ICcgKyBtaW4pO1xuICB9XG59XG5cbi8qKiBHZW5lcmljIHR5cGUgZW5jb21wYXNzaW5nIDgvMTYvMzItYnl0ZSBhcnJheXMgLSBidXQgbm90IDY0LWJ5dGUuICovXG4vLyBwcmV0dGllci1pZ25vcmVcbmV4cG9ydCB0eXBlIFR5cGVkQXJyYXkgPSBJbnQ4QXJyYXkgfCBVaW50OENsYW1wZWRBcnJheSB8IFVpbnQ4QXJyYXkgfFxuICBVaW50MTZBcnJheSB8IEludDE2QXJyYXkgfCBVaW50MzJBcnJheSB8IEludDMyQXJyYXk7XG5cbi8qKiBDYXN0IHU4IC8gdTE2IC8gdTMyIHRvIHU4LiAqL1xuZXhwb3J0IGZ1bmN0aW9uIHU4KGFycjogVHlwZWRBcnJheSk6IFVpbnQ4QXJyYXkge1xuICByZXR1cm4gbmV3IFVpbnQ4QXJyYXkoYXJyLmJ1ZmZlciwgYXJyLmJ5dGVPZmZzZXQsIGFyci5ieXRlTGVuZ3RoKTtcbn1cblxuLyoqIENhc3QgdTggLyB1MTYgLyB1MzIgdG8gdTMyLiAqL1xuZXhwb3J0IGZ1bmN0aW9uIHUzMihhcnI6IFR5cGVkQXJyYXkpOiBVaW50MzJBcnJheSB7XG4gIHJldHVybiBuZXcgVWludDMyQXJyYXkoYXJyLmJ1ZmZlciwgYXJyLmJ5dGVPZmZzZXQsIE1hdGguZmxvb3IoYXJyLmJ5dGVMZW5ndGggLyA0KSk7XG59XG5cbi8qKiBaZXJvaXplIGEgYnl0ZSBhcnJheS4gV2FybmluZzogSlMgcHJvdmlkZXMgbm8gZ3VhcmFudGVlcy4gKi9cbmV4cG9ydCBmdW5jdGlvbiBjbGVhbiguLi5hcnJheXM6IFR5cGVkQXJyYXlbXSk6IHZvaWQge1xuICBmb3IgKGxldCBpID0gMDsgaSA8IGFycmF5cy5sZW5ndGg7IGkrKykge1xuICAgIGFycmF5c1tpXS5maWxsKDApO1xuICB9XG59XG5cbi8qKiBDcmVhdGUgRGF0YVZpZXcgb2YgYW4gYXJyYXkgZm9yIGVhc3kgYnl0ZS1sZXZlbCBtYW5pcHVsYXRpb24uICovXG5leHBvcnQgZnVuY3Rpb24gY3JlYXRlVmlldyhhcnI6IFR5cGVkQXJyYXkpOiBEYXRhVmlldyB7XG4gIHJldHVybiBuZXcgRGF0YVZpZXcoYXJyLmJ1ZmZlciwgYXJyLmJ5dGVPZmZzZXQsIGFyci5ieXRlTGVuZ3RoKTtcbn1cblxuLyoqIFRoZSByb3RhdGUgcmlnaHQgKGNpcmN1bGFyIHJpZ2h0IHNoaWZ0KSBvcGVyYXRpb24gZm9yIHVpbnQzMiAqL1xuZXhwb3J0IGZ1bmN0aW9uIHJvdHIod29yZDogbnVtYmVyLCBzaGlmdDogbnVtYmVyKTogbnVtYmVyIHtcbiAgcmV0dXJuICh3b3JkIDw8ICgzMiAtIHNoaWZ0KSkgfCAod29yZCA+Pj4gc2hpZnQpO1xufVxuXG4vKiogVGhlIHJvdGF0ZSBsZWZ0IChjaXJjdWxhciBsZWZ0IHNoaWZ0KSBvcGVyYXRpb24gZm9yIHVpbnQzMiAqL1xuZXhwb3J0IGZ1bmN0aW9uIHJvdGwod29yZDogbnVtYmVyLCBzaGlmdDogbnVtYmVyKTogbnVtYmVyIHtcbiAgcmV0dXJuICh3b3JkIDw8IHNoaWZ0KSB8ICgod29yZCA+Pj4gKDMyIC0gc2hpZnQpKSA+Pj4gMCk7XG59XG5cbi8qKiBJcyBjdXJyZW50IHBsYXRmb3JtIGxpdHRsZS1lbmRpYW4/IE1vc3QgYXJlLiBCaWctRW5kaWFuIHBsYXRmb3JtOiBJQk0gKi9cbmV4cG9ydCBjb25zdCBpc0xFOiBib29sZWFuID0gLyogQF9fUFVSRV9fICovICgoKSA9PlxuICBuZXcgVWludDhBcnJheShuZXcgVWludDMyQXJyYXkoWzB4MTEyMjMzNDRdKS5idWZmZXIpWzBdID09PSAweDQ0KSgpO1xuXG4vKiogVGhlIGJ5dGUgc3dhcCBvcGVyYXRpb24gZm9yIHVpbnQzMiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGJ5dGVTd2FwKHdvcmQ6IG51bWJlcik6IG51bWJlciB7XG4gIHJldHVybiAoXG4gICAgKCh3b3JkIDw8IDI0KSAmIDB4ZmYwMDAwMDApIHxcbiAgICAoKHdvcmQgPDwgOCkgJiAweGZmMDAwMCkgfFxuICAgICgod29yZCA+Pj4gOCkgJiAweGZmMDApIHxcbiAgICAoKHdvcmQgPj4+IDI0KSAmIDB4ZmYpXG4gICk7XG59XG4vKiogQ29uZGl0aW9uYWxseSBieXRlIHN3YXAgaWYgb24gYSBiaWctZW5kaWFuIHBsYXRmb3JtICovXG5leHBvcnQgY29uc3Qgc3dhcDhJZkJFOiAobjogbnVtYmVyKSA9PiBudW1iZXIgPSBpc0xFXG4gID8gKG46IG51bWJlcikgPT4gblxuICA6IChuOiBudW1iZXIpID0+IGJ5dGVTd2FwKG4pO1xuXG4vKiogQGRlcHJlY2F0ZWQgKi9cbmV4cG9ydCBjb25zdCBieXRlU3dhcElmQkU6IHR5cGVvZiBzd2FwOElmQkUgPSBzd2FwOElmQkU7XG4vKiogSW4gcGxhY2UgYnl0ZSBzd2FwIGZvciBVaW50MzJBcnJheSAqL1xuZXhwb3J0IGZ1bmN0aW9uIGJ5dGVTd2FwMzIoYXJyOiBVaW50MzJBcnJheSk6IFVpbnQzMkFycmF5IHtcbiAgZm9yIChsZXQgaSA9IDA7IGkgPCBhcnIubGVuZ3RoOyBpKyspIHtcbiAgICBhcnJbaV0gPSBieXRlU3dhcChhcnJbaV0pO1xuICB9XG4gIHJldHVybiBhcnI7XG59XG5cbmV4cG9ydCBjb25zdCBzd2FwMzJJZkJFOiAodTogVWludDMyQXJyYXkpID0+IFVpbnQzMkFycmF5ID0gaXNMRVxuICA/ICh1OiBVaW50MzJBcnJheSkgPT4gdVxuICA6IGJ5dGVTd2FwMzI7XG5cbi8vIEJ1aWx0LWluIGhleCBjb252ZXJzaW9uIGh0dHBzOi8vY2FuaXVzZS5jb20vbWRuLWphdmFzY3JpcHRfYnVpbHRpbnNfdWludDhhcnJheV9mcm9taGV4XG5jb25zdCBoYXNIZXhCdWlsdGluOiBib29sZWFuID0gLyogQF9fUFVSRV9fICovICgoKSA9PlxuICAvLyBAdHMtaWdub3JlXG4gIHR5cGVvZiBVaW50OEFycmF5LmZyb20oW10pLnRvSGV4ID09PSAnZnVuY3Rpb24nICYmIHR5cGVvZiBVaW50OEFycmF5LmZyb21IZXggPT09ICdmdW5jdGlvbicpKCk7XG5cbi8vIEFycmF5IHdoZXJlIGluZGV4IDB4ZjAgKDI0MCkgaXMgbWFwcGVkIHRvIHN0cmluZyAnZjAnXG5jb25zdCBoZXhlcyA9IC8qIEBfX1BVUkVfXyAqLyBBcnJheS5mcm9tKHsgbGVuZ3RoOiAyNTYgfSwgKF8sIGkpID0+XG4gIGkudG9TdHJpbmcoMTYpLnBhZFN0YXJ0KDIsICcwJylcbik7XG5cbi8qKlxuICogQ29udmVydCBieXRlIGFycmF5IHRvIGhleCBzdHJpbmcuIFVzZXMgYnVpbHQtaW4gZnVuY3Rpb24sIHdoZW4gYXZhaWxhYmxlLlxuICogQGV4YW1wbGUgYnl0ZXNUb0hleChVaW50OEFycmF5LmZyb20oWzB4Y2EsIDB4ZmUsIDB4MDEsIDB4MjNdKSkgLy8gJ2NhZmUwMTIzJ1xuICovXG5leHBvcnQgZnVuY3Rpb24gYnl0ZXNUb0hleChieXRlczogVWludDhBcnJheSk6IHN0cmluZyB7XG4gIGFieXRlcyhieXRlcyk7XG4gIC8vIEB0cy1pZ25vcmVcbiAgaWYgKGhhc0hleEJ1aWx0aW4pIHJldHVybiBieXRlcy50b0hleCgpO1xuICAvLyBwcmUtY2FjaGluZyBpbXByb3ZlcyB0aGUgc3BlZWQgNnhcbiAgbGV0IGhleCA9ICcnO1xuICBmb3IgKGxldCBpID0gMDsgaSA8IGJ5dGVzLmxlbmd0aDsgaSsrKSB7XG4gICAgaGV4ICs9IGhleGVzW2J5dGVzW2ldXTtcbiAgfVxuICByZXR1cm4gaGV4O1xufVxuXG4vLyBXZSB1c2Ugb3B0aW1pemVkIHRlY2huaXF1ZSB0byBjb252ZXJ0IGhleCBzdHJpbmcgdG8gYnl0ZSBhcnJheVxuY29uc3QgYXNjaWlzID0geyBfMDogNDgsIF85OiA1NywgQTogNjUsIEY6IDcwLCBhOiA5NywgZjogMTAyIH0gYXMgY29uc3Q7XG5mdW5jdGlvbiBhc2NpaVRvQmFzZTE2KGNoOiBudW1iZXIpOiBudW1iZXIgfCB1bmRlZmluZWQge1xuICBpZiAoY2ggPj0gYXNjaWlzLl8wICYmIGNoIDw9IGFzY2lpcy5fOSkgcmV0dXJuIGNoIC0gYXNjaWlzLl8wOyAvLyAnMicgPT4gNTAtNDhcbiAgaWYgKGNoID49IGFzY2lpcy5BICYmIGNoIDw9IGFzY2lpcy5GKSByZXR1cm4gY2ggLSAoYXNjaWlzLkEgLSAxMCk7IC8vICdCJyA9PiA2Ni0oNjUtMTApXG4gIGlmIChjaCA+PSBhc2NpaXMuYSAmJiBjaCA8PSBhc2NpaXMuZikgcmV0dXJuIGNoIC0gKGFzY2lpcy5hIC0gMTApOyAvLyAnYicgPT4gOTgtKDk3LTEwKVxuICByZXR1cm47XG59XG5cbi8qKlxuICogQ29udmVydCBoZXggc3RyaW5nIHRvIGJ5dGUgYXJyYXkuIFVzZXMgYnVpbHQtaW4gZnVuY3Rpb24sIHdoZW4gYXZhaWxhYmxlLlxuICogQGV4YW1wbGUgaGV4VG9CeXRlcygnY2FmZTAxMjMnKSAvLyBVaW50OEFycmF5LmZyb20oWzB4Y2EsIDB4ZmUsIDB4MDEsIDB4MjNdKVxuICovXG5leHBvcnQgZnVuY3Rpb24gaGV4VG9CeXRlcyhoZXg6IHN0cmluZyk6IFVpbnQ4QXJyYXkge1xuICBpZiAodHlwZW9mIGhleCAhPT0gJ3N0cmluZycpIHRocm93IG5ldyBFcnJvcignaGV4IHN0cmluZyBleHBlY3RlZCwgZ290ICcgKyB0eXBlb2YgaGV4KTtcbiAgLy8gQHRzLWlnbm9yZVxuICBpZiAoaGFzSGV4QnVpbHRpbikgcmV0dXJuIFVpbnQ4QXJyYXkuZnJvbUhleChoZXgpO1xuICBjb25zdCBobCA9IGhleC5sZW5ndGg7XG4gIGNvbnN0IGFsID0gaGwgLyAyO1xuICBpZiAoaGwgJSAyKSB0aHJvdyBuZXcgRXJyb3IoJ2hleCBzdHJpbmcgZXhwZWN0ZWQsIGdvdCB1bnBhZGRlZCBoZXggb2YgbGVuZ3RoICcgKyBobCk7XG4gIGNvbnN0IGFycmF5ID0gbmV3IFVpbnQ4QXJyYXkoYWwpO1xuICBmb3IgKGxldCBhaSA9IDAsIGhpID0gMDsgYWkgPCBhbDsgYWkrKywgaGkgKz0gMikge1xuICAgIGNvbnN0IG4xID0gYXNjaWlUb0Jhc2UxNihoZXguY2hhckNvZGVBdChoaSkpO1xuICAgIGNvbnN0IG4yID0gYXNjaWlUb0Jhc2UxNihoZXguY2hhckNvZGVBdChoaSArIDEpKTtcbiAgICBpZiAobjEgPT09IHVuZGVmaW5lZCB8fCBuMiA9PT0gdW5kZWZpbmVkKSB7XG4gICAgICBjb25zdCBjaGFyID0gaGV4W2hpXSArIGhleFtoaSArIDFdO1xuICAgICAgdGhyb3cgbmV3IEVycm9yKCdoZXggc3RyaW5nIGV4cGVjdGVkLCBnb3Qgbm9uLWhleCBjaGFyYWN0ZXIgXCInICsgY2hhciArICdcIiBhdCBpbmRleCAnICsgaGkpO1xuICAgIH1cbiAgICBhcnJheVthaV0gPSBuMSAqIDE2ICsgbjI7IC8vIG11bHRpcGx5IGZpcnN0IG9jdGV0LCBlLmcuICdhMycgPT4gMTAqMTYrMyA9PiAxNjAgKyAzID0+IDE2M1xuICB9XG4gIHJldHVybiBhcnJheTtcbn1cblxuLyoqXG4gKiBUaGVyZSBpcyBubyBzZXRJbW1lZGlhdGUgaW4gYnJvd3NlciBhbmQgc2V0VGltZW91dCBpcyBzbG93LlxuICogQ2FsbCBvZiBhc3luYyBmbiB3aWxsIHJldHVybiBQcm9taXNlLCB3aGljaCB3aWxsIGJlIGZ1bGxmaWxlZCBvbmx5IG9uXG4gKiBuZXh0IHNjaGVkdWxlciBxdWV1ZSBwcm9jZXNzaW5nIHN0ZXAgYW5kIHRoaXMgaXMgZXhhY3RseSB3aGF0IHdlIG5lZWQuXG4gKi9cbmV4cG9ydCBjb25zdCBuZXh0VGljayA9IGFzeW5jICgpOiBQcm9taXNlPHZvaWQ+ID0+IHt9O1xuXG4vKiogUmV0dXJucyBjb250cm9sIHRvIHRocmVhZCBlYWNoICd0aWNrJyBtcyB0byBhdm9pZCBibG9ja2luZy4gKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBhc3luY0xvb3AoXG4gIGl0ZXJzOiBudW1iZXIsXG4gIHRpY2s6IG51bWJlcixcbiAgY2I6IChpOiBudW1iZXIpID0+IHZvaWRcbik6IFByb21pc2U8dm9pZD4ge1xuICBsZXQgdHMgPSBEYXRlLm5vdygpO1xuICBmb3IgKGxldCBpID0gMDsgaSA8IGl0ZXJzOyBpKyspIHtcbiAgICBjYihpKTtcbiAgICAvLyBEYXRlLm5vdygpIGlzIG5vdCBtb25vdG9uaWMsIHNvIGluIGNhc2UgaWYgY2xvY2sgZ29lcyBiYWNrd2FyZHMgd2UgcmV0dXJuIHJldHVybiBjb250cm9sIHRvb1xuICAgIGNvbnN0IGRpZmYgPSBEYXRlLm5vdygpIC0gdHM7XG4gICAgaWYgKGRpZmYgPj0gMCAmJiBkaWZmIDwgdGljaykgY29udGludWU7XG4gICAgYXdhaXQgbmV4dFRpY2soKTtcbiAgICB0cyArPSBkaWZmO1xuICB9XG59XG5cbi8vIEdsb2JhbCBzeW1ib2xzLCBidXQgdHMgZG9lc24ndCBzZWUgdGhlbTogaHR0cHM6Ly9naXRodWIuY29tL21pY3Jvc29mdC9UeXBlU2NyaXB0L2lzc3Vlcy8zMTUzNVxuZGVjbGFyZSBjb25zdCBUZXh0RW5jb2RlcjogYW55O1xuZGVjbGFyZSBjb25zdCBUZXh0RGVjb2RlcjogYW55O1xuXG4vKipcbiAqIENvbnZlcnRzIHN0cmluZyB0byBieXRlcyB1c2luZyBVVEY4IGVuY29kaW5nLlxuICogQGV4YW1wbGUgdXRmOFRvQnl0ZXMoJ2FiYycpIC8vIFVpbnQ4QXJyYXkuZnJvbShbOTcsIDk4LCA5OV0pXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiB1dGY4VG9CeXRlcyhzdHI6IHN0cmluZyk6IFVpbnQ4QXJyYXkge1xuICBpZiAodHlwZW9mIHN0ciAhPT0gJ3N0cmluZycpIHRocm93IG5ldyBFcnJvcignc3RyaW5nIGV4cGVjdGVkJyk7XG4gIHJldHVybiBuZXcgVWludDhBcnJheShuZXcgVGV4dEVuY29kZXIoKS5lbmNvZGUoc3RyKSk7IC8vIGh0dHBzOi8vYnVnemlsLmxhLzE2ODE4MDlcbn1cblxuLyoqXG4gKiBDb252ZXJ0cyBieXRlcyB0byBzdHJpbmcgdXNpbmcgVVRGOCBlbmNvZGluZy5cbiAqIEBleGFtcGxlIGJ5dGVzVG9VdGY4KFVpbnQ4QXJyYXkuZnJvbShbOTcsIDk4LCA5OV0pKSAvLyAnYWJjJ1xuICovXG5leHBvcnQgZnVuY3Rpb24gYnl0ZXNUb1V0ZjgoYnl0ZXM6IFVpbnQ4QXJyYXkpOiBzdHJpbmcge1xuICByZXR1cm4gbmV3IFRleHREZWNvZGVyKCkuZGVjb2RlKGJ5dGVzKTtcbn1cblxuLyoqIEFjY2VwdGVkIGlucHV0IG9mIGhhc2ggZnVuY3Rpb25zLiBTdHJpbmdzIGFyZSBjb252ZXJ0ZWQgdG8gYnl0ZSBhcnJheXMuICovXG5leHBvcnQgdHlwZSBJbnB1dCA9IHN0cmluZyB8IFVpbnQ4QXJyYXk7XG4vKipcbiAqIE5vcm1hbGl6ZXMgKG5vbi1oZXgpIHN0cmluZyBvciBVaW50OEFycmF5IHRvIFVpbnQ4QXJyYXkuXG4gKiBXYXJuaW5nOiB3aGVuIFVpbnQ4QXJyYXkgaXMgcGFzc2VkLCBpdCB3b3VsZCBOT1QgZ2V0IGNvcGllZC5cbiAqIEtlZXAgaW4gbWluZCBmb3IgZnV0dXJlIG11dGFibGUgb3BlcmF0aW9ucy5cbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIHRvQnl0ZXMoZGF0YTogSW5wdXQpOiBVaW50OEFycmF5IHtcbiAgaWYgKHR5cGVvZiBkYXRhID09PSAnc3RyaW5nJykgZGF0YSA9IHV0ZjhUb0J5dGVzKGRhdGEpO1xuICBhYnl0ZXMoZGF0YSk7XG4gIHJldHVybiBkYXRhO1xufVxuXG4vKiogS0RGcyBjYW4gYWNjZXB0IHN0cmluZyBvciBVaW50OEFycmF5IGZvciB1c2VyIGNvbnZlbmllbmNlLiAqL1xuZXhwb3J0IHR5cGUgS0RGSW5wdXQgPSBzdHJpbmcgfCBVaW50OEFycmF5O1xuLyoqXG4gKiBIZWxwZXIgZm9yIEtERnM6IGNvbnN1bWVzIHVpbnQ4YXJyYXkgb3Igc3RyaW5nLlxuICogV2hlbiBzdHJpbmcgaXMgcGFzc2VkLCBkb2VzIHV0ZjggZGVjb2RpbmcsIHVzaW5nIFRleHREZWNvZGVyLlxuICovXG5leHBvcnQgZnVuY3Rpb24ga2RmSW5wdXRUb0J5dGVzKGRhdGE6IEtERklucHV0KTogVWludDhBcnJheSB7XG4gIGlmICh0eXBlb2YgZGF0YSA9PT0gJ3N0cmluZycpIGRhdGEgPSB1dGY4VG9CeXRlcyhkYXRhKTtcbiAgYWJ5dGVzKGRhdGEpO1xuICByZXR1cm4gZGF0YTtcbn1cblxuLyoqIENvcGllcyBzZXZlcmFsIFVpbnQ4QXJyYXlzIGludG8gb25lLiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGNvbmNhdEJ5dGVzKC4uLmFycmF5czogVWludDhBcnJheVtdKTogVWludDhBcnJheSB7XG4gIGxldCBzdW0gPSAwO1xuICBmb3IgKGxldCBpID0gMDsgaSA8IGFycmF5cy5sZW5ndGg7IGkrKykge1xuICAgIGNvbnN0IGEgPSBhcnJheXNbaV07XG4gICAgYWJ5dGVzKGEpO1xuICAgIHN1bSArPSBhLmxlbmd0aDtcbiAgfVxuICBjb25zdCByZXMgPSBuZXcgVWludDhBcnJheShzdW0pO1xuICBmb3IgKGxldCBpID0gMCwgcGFkID0gMDsgaSA8IGFycmF5cy5sZW5ndGg7IGkrKykge1xuICAgIGNvbnN0IGEgPSBhcnJheXNbaV07XG4gICAgcmVzLnNldChhLCBwYWQpO1xuICAgIHBhZCArPSBhLmxlbmd0aDtcbiAgfVxuICByZXR1cm4gcmVzO1xufVxuXG50eXBlIEVtcHR5T2JqID0ge307XG5leHBvcnQgZnVuY3Rpb24gY2hlY2tPcHRzPFQxIGV4dGVuZHMgRW1wdHlPYmosIFQyIGV4dGVuZHMgRW1wdHlPYmo+KFxuICBkZWZhdWx0czogVDEsXG4gIG9wdHM/OiBUMlxuKTogVDEgJiBUMiB7XG4gIGlmIChvcHRzICE9PSB1bmRlZmluZWQgJiYge30udG9TdHJpbmcuY2FsbChvcHRzKSAhPT0gJ1tvYmplY3QgT2JqZWN0XScpXG4gICAgdGhyb3cgbmV3IEVycm9yKCdvcHRpb25zIHNob3VsZCBiZSBvYmplY3Qgb3IgdW5kZWZpbmVkJyk7XG4gIGNvbnN0IG1lcmdlZCA9IE9iamVjdC5hc3NpZ24oZGVmYXVsdHMsIG9wdHMpO1xuICByZXR1cm4gbWVyZ2VkIGFzIFQxICYgVDI7XG59XG5cbi8qKiBIYXNoIGludGVyZmFjZS4gKi9cbmV4cG9ydCB0eXBlIElIYXNoID0ge1xuICAoZGF0YTogVWludDhBcnJheSk6IFVpbnQ4QXJyYXk7XG4gIGJsb2NrTGVuOiBudW1iZXI7XG4gIG91dHB1dExlbjogbnVtYmVyO1xuICBjcmVhdGU6IGFueTtcbn07XG5cbi8qKiBGb3IgcnVudGltZSBjaGVjayBpZiBjbGFzcyBpbXBsZW1lbnRzIGludGVyZmFjZSAqL1xuZXhwb3J0IGFic3RyYWN0IGNsYXNzIEhhc2g8VCBleHRlbmRzIEhhc2g8VD4+IHtcbiAgYWJzdHJhY3QgYmxvY2tMZW46IG51bWJlcjsgLy8gQnl0ZXMgcGVyIGJsb2NrXG4gIGFic3RyYWN0IG91dHB1dExlbjogbnVtYmVyOyAvLyBCeXRlcyBpbiBvdXRwdXRcbiAgYWJzdHJhY3QgdXBkYXRlKGJ1ZjogSW5wdXQpOiB0aGlzO1xuICAvLyBXcml0ZXMgZGlnZXN0IGludG8gYnVmXG4gIGFic3RyYWN0IGRpZ2VzdEludG8oYnVmOiBVaW50OEFycmF5KTogdm9pZDtcbiAgYWJzdHJhY3QgZGlnZXN0KCk6IFVpbnQ4QXJyYXk7XG4gIC8qKlxuICAgKiBSZXNldHMgaW50ZXJuYWwgc3RhdGUuIE1ha2VzIEhhc2ggaW5zdGFuY2UgdW51c2FibGUuXG4gICAqIFJlc2V0IGlzIGltcG9zc2libGUgZm9yIGtleWVkIGhhc2hlcyBpZiBrZXkgaXMgY29uc3VtZWQgaW50byBzdGF0ZS4gSWYgZGlnZXN0IGlzIG5vdCBjb25zdW1lZFxuICAgKiBieSB1c2VyLCB0aGV5IHdpbGwgbmVlZCB0byBtYW51YWxseSBjYWxsIGBkZXN0cm95KClgIHdoZW4gemVyb2luZyBpcyBuZWNlc3NhcnkuXG4gICAqL1xuICBhYnN0cmFjdCBkZXN0cm95KCk6IHZvaWQ7XG4gIC8qKlxuICAgKiBDbG9uZXMgaGFzaCBpbnN0YW5jZS4gVW5zYWZlOiBkb2Vzbid0IGNoZWNrIHdoZXRoZXIgYHRvYCBpcyB2YWxpZC4gQ2FuIGJlIHVzZWQgYXMgYGNsb25lKClgXG4gICAqIHdoZW4gbm8gb3B0aW9ucyBhcmUgcGFzc2VkLlxuICAgKiBSZWFzb25zIHRvIHVzZSBgX2Nsb25lSW50b2AgaW5zdGVhZCBvZiBjbG9uZTogMSkgcGVyZm9ybWFuY2UgMikgcmV1c2UgaW5zdGFuY2UgPT4gYWxsIGludGVybmFsXG4gICAqIGJ1ZmZlcnMgYXJlIG92ZXJ3cml0dGVuID0+IGNhdXNlcyBidWZmZXIgb3ZlcndyaXRlIHdoaWNoIGlzIHVzZWQgZm9yIGRpZ2VzdCBpbiBzb21lIGNhc2VzLlxuICAgKiBUaGVyZSBhcmUgbm8gZ3VhcmFudGVlcyBmb3IgY2xlYW4tdXAgYmVjYXVzZSBpdCdzIGltcG9zc2libGUgaW4gSlMuXG4gICAqL1xuICBhYnN0cmFjdCBfY2xvbmVJbnRvKHRvPzogVCk6IFQ7XG4gIC8vIFNhZmUgdmVyc2lvbiB0aGF0IGNsb25lcyBpbnRlcm5hbCBzdGF0ZVxuICBhYnN0cmFjdCBjbG9uZSgpOiBUO1xufVxuXG4vKipcbiAqIFhPRjogc3RyZWFtaW5nIEFQSSB0byByZWFkIGRpZ2VzdCBpbiBjaHVua3MuXG4gKiBTYW1lIGFzICdzcXVlZXplJyBpbiBrZWNjYWsvazEyIGFuZCAnc2VlaycgaW4gYmxha2UzLCBidXQgbW9yZSBnZW5lcmljIG5hbWUuXG4gKiBXaGVuIGhhc2ggdXNlZCBpbiBYT0YgbW9kZSBpdCBpcyB1cCB0byB1c2VyIHRvIGNhbGwgJy5kZXN0cm95JyBhZnRlcndhcmRzLCBzaW5jZSB3ZSBjYW5ub3RcbiAqIGRlc3Ryb3kgc3RhdGUsIG5leHQgY2FsbCBjYW4gcmVxdWlyZSBtb3JlIGJ5dGVzLlxuICovXG5leHBvcnQgdHlwZSBIYXNoWE9GPFQgZXh0ZW5kcyBIYXNoPFQ+PiA9IEhhc2g8VD4gJiB7XG4gIHhvZihieXRlczogbnVtYmVyKTogVWludDhBcnJheTsgLy8gUmVhZCAnYnl0ZXMnIGJ5dGVzIGZyb20gZGlnZXN0IHN0cmVhbVxuICB4b2ZJbnRvKGJ1ZjogVWludDhBcnJheSk6IFVpbnQ4QXJyYXk7IC8vIHJlYWQgYnVmLmxlbmd0aCBieXRlcyBmcm9tIGRpZ2VzdCBzdHJlYW0gaW50byBidWZcbn07XG5cbi8qKiBIYXNoIGZ1bmN0aW9uICovXG5leHBvcnQgdHlwZSBDSGFzaCA9IFJldHVyblR5cGU8dHlwZW9mIGNyZWF0ZUhhc2hlcj47XG4vKiogSGFzaCBmdW5jdGlvbiB3aXRoIG91dHB1dCAqL1xuZXhwb3J0IHR5cGUgQ0hhc2hPID0gUmV0dXJuVHlwZTx0eXBlb2YgY3JlYXRlT3B0SGFzaGVyPjtcbi8qKiBYT0Ygd2l0aCBvdXRwdXQgKi9cbmV4cG9ydCB0eXBlIENIYXNoWE8gPSBSZXR1cm5UeXBlPHR5cGVvZiBjcmVhdGVYT0Zlcj47XG5cbi8qKiBXcmFwcyBoYXNoIGZ1bmN0aW9uLCBjcmVhdGluZyBhbiBpbnRlcmZhY2Ugb24gdG9wIG9mIGl0ICovXG5leHBvcnQgZnVuY3Rpb24gY3JlYXRlSGFzaGVyPFQgZXh0ZW5kcyBIYXNoPFQ+PihcbiAgaGFzaENvbnM6ICgpID0+IEhhc2g8VD5cbik6IHtcbiAgKG1zZzogSW5wdXQpOiBVaW50OEFycmF5O1xuICBvdXRwdXRMZW46IG51bWJlcjtcbiAgYmxvY2tMZW46IG51bWJlcjtcbiAgY3JlYXRlKCk6IEhhc2g8VD47XG59IHtcbiAgY29uc3QgaGFzaEMgPSAobXNnOiBJbnB1dCk6IFVpbnQ4QXJyYXkgPT4gaGFzaENvbnMoKS51cGRhdGUodG9CeXRlcyhtc2cpKS5kaWdlc3QoKTtcbiAgY29uc3QgdG1wID0gaGFzaENvbnMoKTtcbiAgaGFzaEMub3V0cHV0TGVuID0gdG1wLm91dHB1dExlbjtcbiAgaGFzaEMuYmxvY2tMZW4gPSB0bXAuYmxvY2tMZW47XG4gIGhhc2hDLmNyZWF0ZSA9ICgpID0+IGhhc2hDb25zKCk7XG4gIHJldHVybiBoYXNoQztcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIGNyZWF0ZU9wdEhhc2hlcjxIIGV4dGVuZHMgSGFzaDxIPiwgVCBleHRlbmRzIE9iamVjdD4oXG4gIGhhc2hDb25zOiAob3B0cz86IFQpID0+IEhhc2g8SD5cbik6IHtcbiAgKG1zZzogSW5wdXQsIG9wdHM/OiBUKTogVWludDhBcnJheTtcbiAgb3V0cHV0TGVuOiBudW1iZXI7XG4gIGJsb2NrTGVuOiBudW1iZXI7XG4gIGNyZWF0ZShvcHRzPzogVCk6IEhhc2g8SD47XG59IHtcbiAgY29uc3QgaGFzaEMgPSAobXNnOiBJbnB1dCwgb3B0cz86IFQpOiBVaW50OEFycmF5ID0+IGhhc2hDb25zKG9wdHMpLnVwZGF0ZSh0b0J5dGVzKG1zZykpLmRpZ2VzdCgpO1xuICBjb25zdCB0bXAgPSBoYXNoQ29ucyh7fSBhcyBUKTtcbiAgaGFzaEMub3V0cHV0TGVuID0gdG1wLm91dHB1dExlbjtcbiAgaGFzaEMuYmxvY2tMZW4gPSB0bXAuYmxvY2tMZW47XG4gIGhhc2hDLmNyZWF0ZSA9IChvcHRzPzogVCkgPT4gaGFzaENvbnMob3B0cyk7XG4gIHJldHVybiBoYXNoQztcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIGNyZWF0ZVhPRmVyPEggZXh0ZW5kcyBIYXNoWE9GPEg+LCBUIGV4dGVuZHMgT2JqZWN0PihcbiAgaGFzaENvbnM6IChvcHRzPzogVCkgPT4gSGFzaFhPRjxIPlxuKToge1xuICAobXNnOiBJbnB1dCwgb3B0cz86IFQpOiBVaW50OEFycmF5O1xuICBvdXRwdXRMZW46IG51bWJlcjtcbiAgYmxvY2tMZW46IG51bWJlcjtcbiAgY3JlYXRlKG9wdHM/OiBUKTogSGFzaFhPRjxIPjtcbn0ge1xuICBjb25zdCBoYXNoQyA9IChtc2c6IElucHV0LCBvcHRzPzogVCk6IFVpbnQ4QXJyYXkgPT4gaGFzaENvbnMob3B0cykudXBkYXRlKHRvQnl0ZXMobXNnKSkuZGlnZXN0KCk7XG4gIGNvbnN0IHRtcCA9IGhhc2hDb25zKHt9IGFzIFQpO1xuICBoYXNoQy5vdXRwdXRMZW4gPSB0bXAub3V0cHV0TGVuO1xuICBoYXNoQy5ibG9ja0xlbiA9IHRtcC5ibG9ja0xlbjtcbiAgaGFzaEMuY3JlYXRlID0gKG9wdHM/OiBUKSA9PiBoYXNoQ29ucyhvcHRzKTtcbiAgcmV0dXJuIGhhc2hDO1xufVxuZXhwb3J0IGNvbnN0IHdyYXBDb25zdHJ1Y3RvcjogdHlwZW9mIGNyZWF0ZUhhc2hlciA9IGNyZWF0ZUhhc2hlcjtcbmV4cG9ydCBjb25zdCB3cmFwQ29uc3RydWN0b3JXaXRoT3B0czogdHlwZW9mIGNyZWF0ZU9wdEhhc2hlciA9IGNyZWF0ZU9wdEhhc2hlcjtcbmV4cG9ydCBjb25zdCB3cmFwWE9GQ29uc3RydWN0b3JXaXRoT3B0czogdHlwZW9mIGNyZWF0ZVhPRmVyID0gY3JlYXRlWE9GZXI7XG5cbi8qKiBDcnlwdG9ncmFwaGljYWxseSBzZWN1cmUgUFJORy4gVXNlcyBpbnRlcm5hbCBPUy1sZXZlbCBgY3J5cHRvLmdldFJhbmRvbVZhbHVlc2AuICovXG5leHBvcnQgZnVuY3Rpb24gcmFuZG9tQnl0ZXMoYnl0ZXNMZW5ndGggPSAzMik6IFVpbnQ4QXJyYXkge1xuICBpZiAoY3J5cHRvICYmIHR5cGVvZiBjcnlwdG8uZ2V0UmFuZG9tVmFsdWVzID09PSAnZnVuY3Rpb24nKSB7XG4gICAgcmV0dXJuIGNyeXB0by5nZXRSYW5kb21WYWx1ZXMobmV3IFVpbnQ4QXJyYXkoYnl0ZXNMZW5ndGgpKTtcbiAgfVxuICAvLyBMZWdhY3kgTm9kZS5qcyBjb21wYXRpYmlsaXR5XG4gIGlmIChjcnlwdG8gJiYgdHlwZW9mIGNyeXB0by5yYW5kb21CeXRlcyA9PT0gJ2Z1bmN0aW9uJykge1xuICAgIHJldHVybiBVaW50OEFycmF5LmZyb20oY3J5cHRvLnJhbmRvbUJ5dGVzKGJ5dGVzTGVuZ3RoKSk7XG4gIH1cbiAgdGhyb3cgbmV3IEVycm9yKCdjcnlwdG8uZ2V0UmFuZG9tVmFsdWVzIG11c3QgYmUgZGVmaW5lZCcpO1xufVxuIiwgIi8qKlxuICogSW50ZXJuYWwgTWVya2xlLURhbWdhcmQgaGFzaCB1dGlscy5cbiAqIEBtb2R1bGVcbiAqL1xuaW1wb3J0IHsgdHlwZSBJbnB1dCwgSGFzaCwgYWJ5dGVzLCBhZXhpc3RzLCBhb3V0cHV0LCBjbGVhbiwgY3JlYXRlVmlldywgdG9CeXRlcyB9IGZyb20gJy4vdXRpbHMudHMnO1xuXG4vKiogUG9seWZpbGwgZm9yIFNhZmFyaSAxNC4gaHR0cHM6Ly9jYW5pdXNlLmNvbS9tZG4tamF2YXNjcmlwdF9idWlsdGluc19kYXRhdmlld19zZXRiaWd1aW50NjQgKi9cbmV4cG9ydCBmdW5jdGlvbiBzZXRCaWdVaW50NjQoXG4gIHZpZXc6IERhdGFWaWV3LFxuICBieXRlT2Zmc2V0OiBudW1iZXIsXG4gIHZhbHVlOiBiaWdpbnQsXG4gIGlzTEU6IGJvb2xlYW5cbik6IHZvaWQge1xuICBpZiAodHlwZW9mIHZpZXcuc2V0QmlnVWludDY0ID09PSAnZnVuY3Rpb24nKSByZXR1cm4gdmlldy5zZXRCaWdVaW50NjQoYnl0ZU9mZnNldCwgdmFsdWUsIGlzTEUpO1xuICBjb25zdCBfMzJuID0gQmlnSW50KDMyKTtcbiAgY29uc3QgX3UzMl9tYXggPSBCaWdJbnQoMHhmZmZmZmZmZik7XG4gIGNvbnN0IHdoID0gTnVtYmVyKCh2YWx1ZSA+PiBfMzJuKSAmIF91MzJfbWF4KTtcbiAgY29uc3Qgd2wgPSBOdW1iZXIodmFsdWUgJiBfdTMyX21heCk7XG4gIGNvbnN0IGggPSBpc0xFID8gNCA6IDA7XG4gIGNvbnN0IGwgPSBpc0xFID8gMCA6IDQ7XG4gIHZpZXcuc2V0VWludDMyKGJ5dGVPZmZzZXQgKyBoLCB3aCwgaXNMRSk7XG4gIHZpZXcuc2V0VWludDMyKGJ5dGVPZmZzZXQgKyBsLCB3bCwgaXNMRSk7XG59XG5cbi8qKiBDaG9pY2U6IGEgPyBiIDogYyAqL1xuZXhwb3J0IGZ1bmN0aW9uIENoaShhOiBudW1iZXIsIGI6IG51bWJlciwgYzogbnVtYmVyKTogbnVtYmVyIHtcbiAgcmV0dXJuIChhICYgYikgXiAofmEgJiBjKTtcbn1cblxuLyoqIE1ham9yaXR5IGZ1bmN0aW9uLCB0cnVlIGlmIGFueSB0d28gaW5wdXRzIGlzIHRydWUuICovXG5leHBvcnQgZnVuY3Rpb24gTWFqKGE6IG51bWJlciwgYjogbnVtYmVyLCBjOiBudW1iZXIpOiBudW1iZXIge1xuICByZXR1cm4gKGEgJiBiKSBeIChhICYgYykgXiAoYiAmIGMpO1xufVxuXG4vKipcbiAqIE1lcmtsZS1EYW1nYXJkIGhhc2ggY29uc3RydWN0aW9uIGJhc2UgY2xhc3MuXG4gKiBDb3VsZCBiZSB1c2VkIHRvIGNyZWF0ZSBNRDUsIFJJUEVNRCwgU0hBMSwgU0hBMi5cbiAqL1xuZXhwb3J0IGFic3RyYWN0IGNsYXNzIEhhc2hNRDxUIGV4dGVuZHMgSGFzaE1EPFQ+PiBleHRlbmRzIEhhc2g8VD4ge1xuICBwcm90ZWN0ZWQgYWJzdHJhY3QgcHJvY2VzcyhidWY6IERhdGFWaWV3LCBvZmZzZXQ6IG51bWJlcik6IHZvaWQ7XG4gIHByb3RlY3RlZCBhYnN0cmFjdCBnZXQoKTogbnVtYmVyW107XG4gIHByb3RlY3RlZCBhYnN0cmFjdCBzZXQoLi4uYXJnczogbnVtYmVyW10pOiB2b2lkO1xuICBhYnN0cmFjdCBkZXN0cm95KCk6IHZvaWQ7XG4gIHByb3RlY3RlZCBhYnN0cmFjdCByb3VuZENsZWFuKCk6IHZvaWQ7XG5cbiAgcmVhZG9ubHkgYmxvY2tMZW46IG51bWJlcjtcbiAgcmVhZG9ubHkgb3V0cHV0TGVuOiBudW1iZXI7XG4gIHJlYWRvbmx5IHBhZE9mZnNldDogbnVtYmVyO1xuICByZWFkb25seSBpc0xFOiBib29sZWFuO1xuXG4gIC8vIEZvciBwYXJ0aWFsIHVwZGF0ZXMgbGVzcyB0aGFuIGJsb2NrIHNpemVcbiAgcHJvdGVjdGVkIGJ1ZmZlcjogVWludDhBcnJheTtcbiAgcHJvdGVjdGVkIHZpZXc6IERhdGFWaWV3O1xuICBwcm90ZWN0ZWQgZmluaXNoZWQgPSBmYWxzZTtcbiAgcHJvdGVjdGVkIGxlbmd0aCA9IDA7XG4gIHByb3RlY3RlZCBwb3MgPSAwO1xuICBwcm90ZWN0ZWQgZGVzdHJveWVkID0gZmFsc2U7XG5cbiAgY29uc3RydWN0b3IoYmxvY2tMZW46IG51bWJlciwgb3V0cHV0TGVuOiBudW1iZXIsIHBhZE9mZnNldDogbnVtYmVyLCBpc0xFOiBib29sZWFuKSB7XG4gICAgc3VwZXIoKTtcbiAgICB0aGlzLmJsb2NrTGVuID0gYmxvY2tMZW47XG4gICAgdGhpcy5vdXRwdXRMZW4gPSBvdXRwdXRMZW47XG4gICAgdGhpcy5wYWRPZmZzZXQgPSBwYWRPZmZzZXQ7XG4gICAgdGhpcy5pc0xFID0gaXNMRTtcbiAgICB0aGlzLmJ1ZmZlciA9IG5ldyBVaW50OEFycmF5KGJsb2NrTGVuKTtcbiAgICB0aGlzLnZpZXcgPSBjcmVhdGVWaWV3KHRoaXMuYnVmZmVyKTtcbiAgfVxuICB1cGRhdGUoZGF0YTogSW5wdXQpOiB0aGlzIHtcbiAgICBhZXhpc3RzKHRoaXMpO1xuICAgIGRhdGEgPSB0b0J5dGVzKGRhdGEpO1xuICAgIGFieXRlcyhkYXRhKTtcbiAgICBjb25zdCB7IHZpZXcsIGJ1ZmZlciwgYmxvY2tMZW4gfSA9IHRoaXM7XG4gICAgY29uc3QgbGVuID0gZGF0YS5sZW5ndGg7XG4gICAgZm9yIChsZXQgcG9zID0gMDsgcG9zIDwgbGVuOyApIHtcbiAgICAgIGNvbnN0IHRha2UgPSBNYXRoLm1pbihibG9ja0xlbiAtIHRoaXMucG9zLCBsZW4gLSBwb3MpO1xuICAgICAgLy8gRmFzdCBwYXRoOiB3ZSBoYXZlIGF0IGxlYXN0IG9uZSBibG9jayBpbiBpbnB1dCwgY2FzdCBpdCB0byB2aWV3IGFuZCBwcm9jZXNzXG4gICAgICBpZiAodGFrZSA9PT0gYmxvY2tMZW4pIHtcbiAgICAgICAgY29uc3QgZGF0YVZpZXcgPSBjcmVhdGVWaWV3KGRhdGEpO1xuICAgICAgICBmb3IgKDsgYmxvY2tMZW4gPD0gbGVuIC0gcG9zOyBwb3MgKz0gYmxvY2tMZW4pIHRoaXMucHJvY2VzcyhkYXRhVmlldywgcG9zKTtcbiAgICAgICAgY29udGludWU7XG4gICAgICB9XG4gICAgICBidWZmZXIuc2V0KGRhdGEuc3ViYXJyYXkocG9zLCBwb3MgKyB0YWtlKSwgdGhpcy5wb3MpO1xuICAgICAgdGhpcy5wb3MgKz0gdGFrZTtcbiAgICAgIHBvcyArPSB0YWtlO1xuICAgICAgaWYgKHRoaXMucG9zID09PSBibG9ja0xlbikge1xuICAgICAgICB0aGlzLnByb2Nlc3ModmlldywgMCk7XG4gICAgICAgIHRoaXMucG9zID0gMDtcbiAgICAgIH1cbiAgICB9XG4gICAgdGhpcy5sZW5ndGggKz0gZGF0YS5sZW5ndGg7XG4gICAgdGhpcy5yb3VuZENsZWFuKCk7XG4gICAgcmV0dXJuIHRoaXM7XG4gIH1cbiAgZGlnZXN0SW50byhvdXQ6IFVpbnQ4QXJyYXkpOiB2b2lkIHtcbiAgICBhZXhpc3RzKHRoaXMpO1xuICAgIGFvdXRwdXQob3V0LCB0aGlzKTtcbiAgICB0aGlzLmZpbmlzaGVkID0gdHJ1ZTtcbiAgICAvLyBQYWRkaW5nXG4gICAgLy8gV2UgY2FuIGF2b2lkIGFsbG9jYXRpb24gb2YgYnVmZmVyIGZvciBwYWRkaW5nIGNvbXBsZXRlbHkgaWYgaXRcbiAgICAvLyB3YXMgcHJldmlvdXNseSBub3QgYWxsb2NhdGVkIGhlcmUuIEJ1dCBpdCB3b24ndCBjaGFuZ2UgcGVyZm9ybWFuY2UuXG4gICAgY29uc3QgeyBidWZmZXIsIHZpZXcsIGJsb2NrTGVuLCBpc0xFIH0gPSB0aGlzO1xuICAgIGxldCB7IHBvcyB9ID0gdGhpcztcbiAgICAvLyBhcHBlbmQgdGhlIGJpdCAnMScgdG8gdGhlIG1lc3NhZ2VcbiAgICBidWZmZXJbcG9zKytdID0gMGIxMDAwMDAwMDtcbiAgICBjbGVhbih0aGlzLmJ1ZmZlci5zdWJhcnJheShwb3MpKTtcbiAgICAvLyB3ZSBoYXZlIGxlc3MgdGhhbiBwYWRPZmZzZXQgbGVmdCBpbiBidWZmZXIsIHNvIHdlIGNhbm5vdCBwdXQgbGVuZ3RoIGluXG4gICAgLy8gY3VycmVudCBibG9jaywgbmVlZCBwcm9jZXNzIGl0IGFuZCBwYWQgYWdhaW5cbiAgICBpZiAodGhpcy5wYWRPZmZzZXQgPiBibG9ja0xlbiAtIHBvcykge1xuICAgICAgdGhpcy5wcm9jZXNzKHZpZXcsIDApO1xuICAgICAgcG9zID0gMDtcbiAgICB9XG4gICAgLy8gUGFkIHVudGlsIGZ1bGwgYmxvY2sgYnl0ZSB3aXRoIHplcm9zXG4gICAgZm9yIChsZXQgaSA9IHBvczsgaSA8IGJsb2NrTGVuOyBpKyspIGJ1ZmZlcltpXSA9IDA7XG4gICAgLy8gTm90ZTogc2hhNTEyIHJlcXVpcmVzIGxlbmd0aCB0byBiZSAxMjhiaXQgaW50ZWdlciwgYnV0IGxlbmd0aCBpbiBKUyB3aWxsIG92ZXJmbG93IGJlZm9yZSB0aGF0XG4gICAgLy8gWW91IG5lZWQgdG8gd3JpdGUgYXJvdW5kIDIgZXhhYnl0ZXMgKHU2NF9tYXggLyA4IC8gKDEwMjQqKjYpKSBmb3IgdGhpcyB0byBoYXBwZW4uXG4gICAgLy8gU28gd2UganVzdCB3cml0ZSBsb3dlc3QgNjQgYml0cyBvZiB0aGF0IHZhbHVlLlxuICAgIHNldEJpZ1VpbnQ2NCh2aWV3LCBibG9ja0xlbiAtIDgsIEJpZ0ludCh0aGlzLmxlbmd0aCAqIDgpLCBpc0xFKTtcbiAgICB0aGlzLnByb2Nlc3ModmlldywgMCk7XG4gICAgY29uc3Qgb3ZpZXcgPSBjcmVhdGVWaWV3KG91dCk7XG4gICAgY29uc3QgbGVuID0gdGhpcy5vdXRwdXRMZW47XG4gICAgLy8gTk9URTogd2UgZG8gZGl2aXNpb24gYnkgNCBsYXRlciwgd2hpY2ggc2hvdWxkIGJlIGZ1c2VkIGluIHNpbmdsZSBvcCB3aXRoIG1vZHVsbyBieSBKSVRcbiAgICBpZiAobGVuICUgNCkgdGhyb3cgbmV3IEVycm9yKCdfc2hhMjogb3V0cHV0TGVuIHNob3VsZCBiZSBhbGlnbmVkIHRvIDMyYml0Jyk7XG4gICAgY29uc3Qgb3V0TGVuID0gbGVuIC8gNDtcbiAgICBjb25zdCBzdGF0ZSA9IHRoaXMuZ2V0KCk7XG4gICAgaWYgKG91dExlbiA+IHN0YXRlLmxlbmd0aCkgdGhyb3cgbmV3IEVycm9yKCdfc2hhMjogb3V0cHV0TGVuIGJpZ2dlciB0aGFuIHN0YXRlJyk7XG4gICAgZm9yIChsZXQgaSA9IDA7IGkgPCBvdXRMZW47IGkrKykgb3ZpZXcuc2V0VWludDMyKDQgKiBpLCBzdGF0ZVtpXSwgaXNMRSk7XG4gIH1cbiAgZGlnZXN0KCk6IFVpbnQ4QXJyYXkge1xuICAgIGNvbnN0IHsgYnVmZmVyLCBvdXRwdXRMZW4gfSA9IHRoaXM7XG4gICAgdGhpcy5kaWdlc3RJbnRvKGJ1ZmZlcik7XG4gICAgY29uc3QgcmVzID0gYnVmZmVyLnNsaWNlKDAsIG91dHB1dExlbik7XG4gICAgdGhpcy5kZXN0cm95KCk7XG4gICAgcmV0dXJuIHJlcztcbiAgfVxuICBfY2xvbmVJbnRvKHRvPzogVCk6IFQge1xuICAgIHRvIHx8PSBuZXcgKHRoaXMuY29uc3RydWN0b3IgYXMgYW55KSgpIGFzIFQ7XG4gICAgdG8uc2V0KC4uLnRoaXMuZ2V0KCkpO1xuICAgIGNvbnN0IHsgYmxvY2tMZW4sIGJ1ZmZlciwgbGVuZ3RoLCBmaW5pc2hlZCwgZGVzdHJveWVkLCBwb3MgfSA9IHRoaXM7XG4gICAgdG8uZGVzdHJveWVkID0gZGVzdHJveWVkO1xuICAgIHRvLmZpbmlzaGVkID0gZmluaXNoZWQ7XG4gICAgdG8ubGVuZ3RoID0gbGVuZ3RoO1xuICAgIHRvLnBvcyA9IHBvcztcbiAgICBpZiAobGVuZ3RoICUgYmxvY2tMZW4pIHRvLmJ1ZmZlci5zZXQoYnVmZmVyKTtcbiAgICByZXR1cm4gdG87XG4gIH1cbiAgY2xvbmUoKTogVCB7XG4gICAgcmV0dXJuIHRoaXMuX2Nsb25lSW50bygpO1xuICB9XG59XG5cbi8qKlxuICogSW5pdGlhbCBTSEEtMiBzdGF0ZTogZnJhY3Rpb25hbCBwYXJ0cyBvZiBzcXVhcmUgcm9vdHMgb2YgZmlyc3QgMTYgcHJpbWVzIDIuLjUzLlxuICogQ2hlY2sgb3V0IGB0ZXN0L21pc2Mvc2hhMi1nZW4taXYuanNgIGZvciByZWNvbXB1dGF0aW9uIGd1aWRlLlxuICovXG5cbi8qKiBJbml0aWFsIFNIQTI1NiBzdGF0ZS4gQml0cyAwLi4zMiBvZiBmcmFjIHBhcnQgb2Ygc3FydCBvZiBwcmltZXMgMi4uMTkgKi9cbmV4cG9ydCBjb25zdCBTSEEyNTZfSVY6IFVpbnQzMkFycmF5ID0gLyogQF9fUFVSRV9fICovIFVpbnQzMkFycmF5LmZyb20oW1xuICAweDZhMDllNjY3LCAweGJiNjdhZTg1LCAweDNjNmVmMzcyLCAweGE1NGZmNTNhLCAweDUxMGU1MjdmLCAweDliMDU2ODhjLCAweDFmODNkOWFiLCAweDViZTBjZDE5LFxuXSk7XG5cbi8qKiBJbml0aWFsIFNIQTIyNCBzdGF0ZS4gQml0cyAzMi4uNjQgb2YgZnJhYyBwYXJ0IG9mIHNxcnQgb2YgcHJpbWVzIDIzLi41MyAqL1xuZXhwb3J0IGNvbnN0IFNIQTIyNF9JVjogVWludDMyQXJyYXkgPSAvKiBAX19QVVJFX18gKi8gVWludDMyQXJyYXkuZnJvbShbXG4gIDB4YzEwNTllZDgsIDB4MzY3Y2Q1MDcsIDB4MzA3MGRkMTcsIDB4ZjcwZTU5MzksIDB4ZmZjMDBiMzEsIDB4Njg1ODE1MTEsIDB4NjRmOThmYTcsIDB4YmVmYTRmYTQsXG5dKTtcblxuLyoqIEluaXRpYWwgU0hBMzg0IHN0YXRlLiBCaXRzIDAuLjY0IG9mIGZyYWMgcGFydCBvZiBzcXJ0IG9mIHByaW1lcyAyMy4uNTMgKi9cbmV4cG9ydCBjb25zdCBTSEEzODRfSVY6IFVpbnQzMkFycmF5ID0gLyogQF9fUFVSRV9fICovIFVpbnQzMkFycmF5LmZyb20oW1xuICAweGNiYmI5ZDVkLCAweGMxMDU5ZWQ4LCAweDYyOWEyOTJhLCAweDM2N2NkNTA3LCAweDkxNTkwMTVhLCAweDMwNzBkZDE3LCAweDE1MmZlY2Q4LCAweGY3MGU1OTM5LFxuICAweDY3MzMyNjY3LCAweGZmYzAwYjMxLCAweDhlYjQ0YTg3LCAweDY4NTgxNTExLCAweGRiMGMyZTBkLCAweDY0Zjk4ZmE3LCAweDQ3YjU0ODFkLCAweGJlZmE0ZmE0LFxuXSk7XG5cbi8qKiBJbml0aWFsIFNIQTUxMiBzdGF0ZS4gQml0cyAwLi42NCBvZiBmcmFjIHBhcnQgb2Ygc3FydCBvZiBwcmltZXMgMi4uMTkgKi9cbmV4cG9ydCBjb25zdCBTSEE1MTJfSVY6IFVpbnQzMkFycmF5ID0gLyogQF9fUFVSRV9fICovIFVpbnQzMkFycmF5LmZyb20oW1xuICAweDZhMDllNjY3LCAweGYzYmNjOTA4LCAweGJiNjdhZTg1LCAweDg0Y2FhNzNiLCAweDNjNmVmMzcyLCAweGZlOTRmODJiLCAweGE1NGZmNTNhLCAweDVmMWQzNmYxLFxuICAweDUxMGU1MjdmLCAweGFkZTY4MmQxLCAweDliMDU2ODhjLCAweDJiM2U2YzFmLCAweDFmODNkOWFiLCAweGZiNDFiZDZiLCAweDViZTBjZDE5LCAweDEzN2UyMTc5LFxuXSk7XG4iLCAiLyoqXG4gKiBJbnRlcm5hbCBoZWxwZXJzIGZvciB1NjQuIEJpZ1VpbnQ2NEFycmF5IGlzIHRvbyBzbG93IGFzIHBlciAyMDI1LCBzbyB3ZSBpbXBsZW1lbnQgaXQgdXNpbmcgVWludDMyQXJyYXkuXG4gKiBAdG9kbyByZS1jaGVjayBodHRwczovL2lzc3Vlcy5jaHJvbWl1bS5vcmcvaXNzdWVzLzQyMjEyNTg4XG4gKiBAbW9kdWxlXG4gKi9cbmNvbnN0IFUzMl9NQVNLNjQgPSAvKiBAX19QVVJFX18gKi8gQmlnSW50KDIgKiogMzIgLSAxKTtcbmNvbnN0IF8zMm4gPSAvKiBAX19QVVJFX18gKi8gQmlnSW50KDMyKTtcblxuZnVuY3Rpb24gZnJvbUJpZyhcbiAgbjogYmlnaW50LFxuICBsZSA9IGZhbHNlXG4pOiB7XG4gIGg6IG51bWJlcjtcbiAgbDogbnVtYmVyO1xufSB7XG4gIGlmIChsZSkgcmV0dXJuIHsgaDogTnVtYmVyKG4gJiBVMzJfTUFTSzY0KSwgbDogTnVtYmVyKChuID4+IF8zMm4pICYgVTMyX01BU0s2NCkgfTtcbiAgcmV0dXJuIHsgaDogTnVtYmVyKChuID4+IF8zMm4pICYgVTMyX01BU0s2NCkgfCAwLCBsOiBOdW1iZXIobiAmIFUzMl9NQVNLNjQpIHwgMCB9O1xufVxuXG5mdW5jdGlvbiBzcGxpdChsc3Q6IGJpZ2ludFtdLCBsZSA9IGZhbHNlKTogVWludDMyQXJyYXlbXSB7XG4gIGNvbnN0IGxlbiA9IGxzdC5sZW5ndGg7XG4gIGxldCBBaCA9IG5ldyBVaW50MzJBcnJheShsZW4pO1xuICBsZXQgQWwgPSBuZXcgVWludDMyQXJyYXkobGVuKTtcbiAgZm9yIChsZXQgaSA9IDA7IGkgPCBsZW47IGkrKykge1xuICAgIGNvbnN0IHsgaCwgbCB9ID0gZnJvbUJpZyhsc3RbaV0sIGxlKTtcbiAgICBbQWhbaV0sIEFsW2ldXSA9IFtoLCBsXTtcbiAgfVxuICByZXR1cm4gW0FoLCBBbF07XG59XG5cbmNvbnN0IHRvQmlnID0gKGg6IG51bWJlciwgbDogbnVtYmVyKTogYmlnaW50ID0+IChCaWdJbnQoaCA+Pj4gMCkgPDwgXzMybikgfCBCaWdJbnQobCA+Pj4gMCk7XG4vLyBmb3IgU2hpZnQgaW4gWzAsIDMyKVxuY29uc3Qgc2hyU0ggPSAoaDogbnVtYmVyLCBfbDogbnVtYmVyLCBzOiBudW1iZXIpOiBudW1iZXIgPT4gaCA+Pj4gcztcbmNvbnN0IHNoclNMID0gKGg6IG51bWJlciwgbDogbnVtYmVyLCBzOiBudW1iZXIpOiBudW1iZXIgPT4gKGggPDwgKDMyIC0gcykpIHwgKGwgPj4+IHMpO1xuLy8gUmlnaHQgcm90YXRlIGZvciBTaGlmdCBpbiBbMSwgMzIpXG5jb25zdCByb3RyU0ggPSAoaDogbnVtYmVyLCBsOiBudW1iZXIsIHM6IG51bWJlcik6IG51bWJlciA9PiAoaCA+Pj4gcykgfCAobCA8PCAoMzIgLSBzKSk7XG5jb25zdCByb3RyU0wgPSAoaDogbnVtYmVyLCBsOiBudW1iZXIsIHM6IG51bWJlcik6IG51bWJlciA9PiAoaCA8PCAoMzIgLSBzKSkgfCAobCA+Pj4gcyk7XG4vLyBSaWdodCByb3RhdGUgZm9yIFNoaWZ0IGluICgzMiwgNjQpLCBOT1RFOiAzMiBpcyBzcGVjaWFsIGNhc2UuXG5jb25zdCByb3RyQkggPSAoaDogbnVtYmVyLCBsOiBudW1iZXIsIHM6IG51bWJlcik6IG51bWJlciA9PiAoaCA8PCAoNjQgLSBzKSkgfCAobCA+Pj4gKHMgLSAzMikpO1xuY29uc3Qgcm90ckJMID0gKGg6IG51bWJlciwgbDogbnVtYmVyLCBzOiBudW1iZXIpOiBudW1iZXIgPT4gKGggPj4+IChzIC0gMzIpKSB8IChsIDw8ICg2NCAtIHMpKTtcbi8vIFJpZ2h0IHJvdGF0ZSBmb3Igc2hpZnQ9PT0zMiAoanVzdCBzd2FwcyBsJmgpXG5jb25zdCByb3RyMzJIID0gKF9oOiBudW1iZXIsIGw6IG51bWJlcik6IG51bWJlciA9PiBsO1xuY29uc3Qgcm90cjMyTCA9IChoOiBudW1iZXIsIF9sOiBudW1iZXIpOiBudW1iZXIgPT4gaDtcbi8vIExlZnQgcm90YXRlIGZvciBTaGlmdCBpbiBbMSwgMzIpXG5jb25zdCByb3RsU0ggPSAoaDogbnVtYmVyLCBsOiBudW1iZXIsIHM6IG51bWJlcik6IG51bWJlciA9PiAoaCA8PCBzKSB8IChsID4+PiAoMzIgLSBzKSk7XG5jb25zdCByb3RsU0wgPSAoaDogbnVtYmVyLCBsOiBudW1iZXIsIHM6IG51bWJlcik6IG51bWJlciA9PiAobCA8PCBzKSB8IChoID4+PiAoMzIgLSBzKSk7XG4vLyBMZWZ0IHJvdGF0ZSBmb3IgU2hpZnQgaW4gKDMyLCA2NCksIE5PVEU6IDMyIGlzIHNwZWNpYWwgY2FzZS5cbmNvbnN0IHJvdGxCSCA9IChoOiBudW1iZXIsIGw6IG51bWJlciwgczogbnVtYmVyKTogbnVtYmVyID0+IChsIDw8IChzIC0gMzIpKSB8IChoID4+PiAoNjQgLSBzKSk7XG5jb25zdCByb3RsQkwgPSAoaDogbnVtYmVyLCBsOiBudW1iZXIsIHM6IG51bWJlcik6IG51bWJlciA9PiAoaCA8PCAocyAtIDMyKSkgfCAobCA+Pj4gKDY0IC0gcykpO1xuXG4vLyBKUyB1c2VzIDMyLWJpdCBzaWduZWQgaW50ZWdlcnMgZm9yIGJpdHdpc2Ugb3BlcmF0aW9ucyB3aGljaCBtZWFucyB3ZSBjYW5ub3Rcbi8vIHNpbXBsZSB0YWtlIGNhcnJ5IG91dCBvZiBsb3cgYml0IHN1bSBieSBzaGlmdCwgd2UgbmVlZCB0byB1c2UgZGl2aXNpb24uXG5mdW5jdGlvbiBhZGQoXG4gIEFoOiBudW1iZXIsXG4gIEFsOiBudW1iZXIsXG4gIEJoOiBudW1iZXIsXG4gIEJsOiBudW1iZXJcbik6IHtcbiAgaDogbnVtYmVyO1xuICBsOiBudW1iZXI7XG59IHtcbiAgY29uc3QgbCA9IChBbCA+Pj4gMCkgKyAoQmwgPj4+IDApO1xuICByZXR1cm4geyBoOiAoQWggKyBCaCArICgobCAvIDIgKiogMzIpIHwgMCkpIHwgMCwgbDogbCB8IDAgfTtcbn1cbi8vIEFkZGl0aW9uIHdpdGggbW9yZSB0aGFuIDIgZWxlbWVudHNcbmNvbnN0IGFkZDNMID0gKEFsOiBudW1iZXIsIEJsOiBudW1iZXIsIENsOiBudW1iZXIpOiBudW1iZXIgPT4gKEFsID4+PiAwKSArIChCbCA+Pj4gMCkgKyAoQ2wgPj4+IDApO1xuY29uc3QgYWRkM0ggPSAobG93OiBudW1iZXIsIEFoOiBudW1iZXIsIEJoOiBudW1iZXIsIENoOiBudW1iZXIpOiBudW1iZXIgPT5cbiAgKEFoICsgQmggKyBDaCArICgobG93IC8gMiAqKiAzMikgfCAwKSkgfCAwO1xuY29uc3QgYWRkNEwgPSAoQWw6IG51bWJlciwgQmw6IG51bWJlciwgQ2w6IG51bWJlciwgRGw6IG51bWJlcik6IG51bWJlciA9PlxuICAoQWwgPj4+IDApICsgKEJsID4+PiAwKSArIChDbCA+Pj4gMCkgKyAoRGwgPj4+IDApO1xuY29uc3QgYWRkNEggPSAobG93OiBudW1iZXIsIEFoOiBudW1iZXIsIEJoOiBudW1iZXIsIENoOiBudW1iZXIsIERoOiBudW1iZXIpOiBudW1iZXIgPT5cbiAgKEFoICsgQmggKyBDaCArIERoICsgKChsb3cgLyAyICoqIDMyKSB8IDApKSB8IDA7XG5jb25zdCBhZGQ1TCA9IChBbDogbnVtYmVyLCBCbDogbnVtYmVyLCBDbDogbnVtYmVyLCBEbDogbnVtYmVyLCBFbDogbnVtYmVyKTogbnVtYmVyID0+XG4gIChBbCA+Pj4gMCkgKyAoQmwgPj4+IDApICsgKENsID4+PiAwKSArIChEbCA+Pj4gMCkgKyAoRWwgPj4+IDApO1xuY29uc3QgYWRkNUggPSAobG93OiBudW1iZXIsIEFoOiBudW1iZXIsIEJoOiBudW1iZXIsIENoOiBudW1iZXIsIERoOiBudW1iZXIsIEVoOiBudW1iZXIpOiBudW1iZXIgPT5cbiAgKEFoICsgQmggKyBDaCArIERoICsgRWggKyAoKGxvdyAvIDIgKiogMzIpIHwgMCkpIHwgMDtcblxuLy8gcHJldHRpZXItaWdub3JlXG5leHBvcnQge1xuICBhZGQsIGFkZDNILCBhZGQzTCwgYWRkNEgsIGFkZDRMLCBhZGQ1SCwgYWRkNUwsIGZyb21CaWcsIHJvdGxCSCwgcm90bEJMLCByb3RsU0gsIHJvdGxTTCwgcm90cjMySCwgcm90cjMyTCwgcm90ckJILCByb3RyQkwsIHJvdHJTSCwgcm90clNMLCBzaHJTSCwgc2hyU0wsIHNwbGl0LCB0b0JpZ1xufTtcbi8vIHByZXR0aWVyLWlnbm9yZVxuY29uc3QgdTY0OiB7IGZyb21CaWc6IHR5cGVvZiBmcm9tQmlnOyBzcGxpdDogdHlwZW9mIHNwbGl0OyB0b0JpZzogKGg6IG51bWJlciwgbDogbnVtYmVyKSA9PiBiaWdpbnQ7IHNoclNIOiAoaDogbnVtYmVyLCBfbDogbnVtYmVyLCBzOiBudW1iZXIpID0+IG51bWJlcjsgc2hyU0w6IChoOiBudW1iZXIsIGw6IG51bWJlciwgczogbnVtYmVyKSA9PiBudW1iZXI7IHJvdHJTSDogKGg6IG51bWJlciwgbDogbnVtYmVyLCBzOiBudW1iZXIpID0+IG51bWJlcjsgcm90clNMOiAoaDogbnVtYmVyLCBsOiBudW1iZXIsIHM6IG51bWJlcikgPT4gbnVtYmVyOyByb3RyQkg6IChoOiBudW1iZXIsIGw6IG51bWJlciwgczogbnVtYmVyKSA9PiBudW1iZXI7IHJvdHJCTDogKGg6IG51bWJlciwgbDogbnVtYmVyLCBzOiBudW1iZXIpID0+IG51bWJlcjsgcm90cjMySDogKF9oOiBudW1iZXIsIGw6IG51bWJlcikgPT4gbnVtYmVyOyByb3RyMzJMOiAoaDogbnVtYmVyLCBfbDogbnVtYmVyKSA9PiBudW1iZXI7IHJvdGxTSDogKGg6IG51bWJlciwgbDogbnVtYmVyLCBzOiBudW1iZXIpID0+IG51bWJlcjsgcm90bFNMOiAoaDogbnVtYmVyLCBsOiBudW1iZXIsIHM6IG51bWJlcikgPT4gbnVtYmVyOyByb3RsQkg6IChoOiBudW1iZXIsIGw6IG51bWJlciwgczogbnVtYmVyKSA9PiBudW1iZXI7IHJvdGxCTDogKGg6IG51bWJlciwgbDogbnVtYmVyLCBzOiBudW1iZXIpID0+IG51bWJlcjsgYWRkOiB0eXBlb2YgYWRkOyBhZGQzTDogKEFsOiBudW1iZXIsIEJsOiBudW1iZXIsIENsOiBudW1iZXIpID0+IG51bWJlcjsgYWRkM0g6IChsb3c6IG51bWJlciwgQWg6IG51bWJlciwgQmg6IG51bWJlciwgQ2g6IG51bWJlcikgPT4gbnVtYmVyOyBhZGQ0TDogKEFsOiBudW1iZXIsIEJsOiBudW1iZXIsIENsOiBudW1iZXIsIERsOiBudW1iZXIpID0+IG51bWJlcjsgYWRkNEg6IChsb3c6IG51bWJlciwgQWg6IG51bWJlciwgQmg6IG51bWJlciwgQ2g6IG51bWJlciwgRGg6IG51bWJlcikgPT4gbnVtYmVyOyBhZGQ1SDogKGxvdzogbnVtYmVyLCBBaDogbnVtYmVyLCBCaDogbnVtYmVyLCBDaDogbnVtYmVyLCBEaDogbnVtYmVyLCBFaDogbnVtYmVyKSA9PiBudW1iZXI7IGFkZDVMOiAoQWw6IG51bWJlciwgQmw6IG51bWJlciwgQ2w6IG51bWJlciwgRGw6IG51bWJlciwgRWw6IG51bWJlcikgPT4gbnVtYmVyOyB9ID0ge1xuICBmcm9tQmlnLCBzcGxpdCwgdG9CaWcsXG4gIHNoclNILCBzaHJTTCxcbiAgcm90clNILCByb3RyU0wsIHJvdHJCSCwgcm90ckJMLFxuICByb3RyMzJILCByb3RyMzJMLFxuICByb3RsU0gsIHJvdGxTTCwgcm90bEJILCByb3RsQkwsXG4gIGFkZCwgYWRkM0wsIGFkZDNILCBhZGQ0TCwgYWRkNEgsIGFkZDVILCBhZGQ1TCxcbn07XG5leHBvcnQgZGVmYXVsdCB1NjQ7XG4iLCAiLyoqXG4gKiBTSEEyIGhhc2ggZnVuY3Rpb24uIEEuay5hLiBzaGEyNTYsIHNoYTM4NCwgc2hhNTEyLCBzaGE1MTJfMjI0LCBzaGE1MTJfMjU2LlxuICogU0hBMjU2IGlzIHRoZSBmYXN0ZXN0IGhhc2ggaW1wbGVtZW50YWJsZSBpbiBKUywgZXZlbiBmYXN0ZXIgdGhhbiBCbGFrZTMuXG4gKiBDaGVjayBvdXQgW1JGQyA0NjM0XShodHRwczovL2RhdGF0cmFja2VyLmlldGYub3JnL2RvYy9odG1sL3JmYzQ2MzQpIGFuZFxuICogW0ZJUFMgMTgwLTRdKGh0dHBzOi8vbnZscHVicy5uaXN0Lmdvdi9uaXN0cHVicy9GSVBTL05JU1QuRklQUy4xODAtNC5wZGYpLlxuICogQG1vZHVsZVxuICovXG5pbXBvcnQgeyBDaGksIEhhc2hNRCwgTWFqLCBTSEEyMjRfSVYsIFNIQTI1Nl9JViwgU0hBMzg0X0lWLCBTSEE1MTJfSVYgfSBmcm9tICcuL19tZC50cyc7XG5pbXBvcnQgKiBhcyB1NjQgZnJvbSAnLi9fdTY0LnRzJztcbmltcG9ydCB7IHR5cGUgQ0hhc2gsIGNsZWFuLCBjcmVhdGVIYXNoZXIsIHJvdHIgfSBmcm9tICcuL3V0aWxzLnRzJztcblxuLyoqXG4gKiBSb3VuZCBjb25zdGFudHM6XG4gKiBGaXJzdCAzMiBiaXRzIG9mIGZyYWN0aW9uYWwgcGFydHMgb2YgdGhlIGN1YmUgcm9vdHMgb2YgdGhlIGZpcnN0IDY0IHByaW1lcyAyLi4zMTEpXG4gKi9cbi8vIHByZXR0aWVyLWlnbm9yZVxuY29uc3QgU0hBMjU2X0sgPSAvKiBAX19QVVJFX18gKi8gVWludDMyQXJyYXkuZnJvbShbXG4gIDB4NDI4YTJmOTgsIDB4NzEzNzQ0OTEsIDB4YjVjMGZiY2YsIDB4ZTliNWRiYTUsIDB4Mzk1NmMyNWIsIDB4NTlmMTExZjEsIDB4OTIzZjgyYTQsIDB4YWIxYzVlZDUsXG4gIDB4ZDgwN2FhOTgsIDB4MTI4MzViMDEsIDB4MjQzMTg1YmUsIDB4NTUwYzdkYzMsIDB4NzJiZTVkNzQsIDB4ODBkZWIxZmUsIDB4OWJkYzA2YTcsIDB4YzE5YmYxNzQsXG4gIDB4ZTQ5YjY5YzEsIDB4ZWZiZTQ3ODYsIDB4MGZjMTlkYzYsIDB4MjQwY2ExY2MsIDB4MmRlOTJjNmYsIDB4NGE3NDg0YWEsIDB4NWNiMGE5ZGMsIDB4NzZmOTg4ZGEsXG4gIDB4OTgzZTUxNTIsIDB4YTgzMWM2NmQsIDB4YjAwMzI3YzgsIDB4YmY1OTdmYzcsIDB4YzZlMDBiZjMsIDB4ZDVhNzkxNDcsIDB4MDZjYTYzNTEsIDB4MTQyOTI5NjcsXG4gIDB4MjdiNzBhODUsIDB4MmUxYjIxMzgsIDB4NGQyYzZkZmMsIDB4NTMzODBkMTMsIDB4NjUwYTczNTQsIDB4NzY2YTBhYmIsIDB4ODFjMmM5MmUsIDB4OTI3MjJjODUsXG4gIDB4YTJiZmU4YTEsIDB4YTgxYTY2NGIsIDB4YzI0YjhiNzAsIDB4Yzc2YzUxYTMsIDB4ZDE5MmU4MTksIDB4ZDY5OTA2MjQsIDB4ZjQwZTM1ODUsIDB4MTA2YWEwNzAsXG4gIDB4MTlhNGMxMTYsIDB4MWUzNzZjMDgsIDB4Mjc0ODc3NGMsIDB4MzRiMGJjYjUsIDB4MzkxYzBjYjMsIDB4NGVkOGFhNGEsIDB4NWI5Y2NhNGYsIDB4NjgyZTZmZjMsXG4gIDB4NzQ4ZjgyZWUsIDB4NzhhNTYzNmYsIDB4ODRjODc4MTQsIDB4OGNjNzAyMDgsIDB4OTBiZWZmZmEsIDB4YTQ1MDZjZWIsIDB4YmVmOWEzZjcsIDB4YzY3MTc4ZjJcbl0pO1xuXG4vKiogUmV1c2FibGUgdGVtcG9yYXJ5IGJ1ZmZlci4gXCJXXCIgY29tZXMgc3RyYWlnaHQgZnJvbSBzcGVjLiAqL1xuY29uc3QgU0hBMjU2X1cgPSAvKiBAX19QVVJFX18gKi8gbmV3IFVpbnQzMkFycmF5KDY0KTtcbmV4cG9ydCBjbGFzcyBTSEEyNTYgZXh0ZW5kcyBIYXNoTUQ8U0hBMjU2PiB7XG4gIC8vIFdlIGNhbm5vdCB1c2UgYXJyYXkgaGVyZSBzaW5jZSBhcnJheSBhbGxvd3MgaW5kZXhpbmcgYnkgdmFyaWFibGVcbiAgLy8gd2hpY2ggbWVhbnMgb3B0aW1pemVyL2NvbXBpbGVyIGNhbm5vdCB1c2UgcmVnaXN0ZXJzLlxuICBwcm90ZWN0ZWQgQTogbnVtYmVyID0gU0hBMjU2X0lWWzBdIHwgMDtcbiAgcHJvdGVjdGVkIEI6IG51bWJlciA9IFNIQTI1Nl9JVlsxXSB8IDA7XG4gIHByb3RlY3RlZCBDOiBudW1iZXIgPSBTSEEyNTZfSVZbMl0gfCAwO1xuICBwcm90ZWN0ZWQgRDogbnVtYmVyID0gU0hBMjU2X0lWWzNdIHwgMDtcbiAgcHJvdGVjdGVkIEU6IG51bWJlciA9IFNIQTI1Nl9JVls0XSB8IDA7XG4gIHByb3RlY3RlZCBGOiBudW1iZXIgPSBTSEEyNTZfSVZbNV0gfCAwO1xuICBwcm90ZWN0ZWQgRzogbnVtYmVyID0gU0hBMjU2X0lWWzZdIHwgMDtcbiAgcHJvdGVjdGVkIEg6IG51bWJlciA9IFNIQTI1Nl9JVls3XSB8IDA7XG5cbiAgY29uc3RydWN0b3Iob3V0cHV0TGVuOiBudW1iZXIgPSAzMikge1xuICAgIHN1cGVyKDY0LCBvdXRwdXRMZW4sIDgsIGZhbHNlKTtcbiAgfVxuICBwcm90ZWN0ZWQgZ2V0KCk6IFtudW1iZXIsIG51bWJlciwgbnVtYmVyLCBudW1iZXIsIG51bWJlciwgbnVtYmVyLCBudW1iZXIsIG51bWJlcl0ge1xuICAgIGNvbnN0IHsgQSwgQiwgQywgRCwgRSwgRiwgRywgSCB9ID0gdGhpcztcbiAgICByZXR1cm4gW0EsIEIsIEMsIEQsIEUsIEYsIEcsIEhdO1xuICB9XG4gIC8vIHByZXR0aWVyLWlnbm9yZVxuICBwcm90ZWN0ZWQgc2V0KFxuICAgIEE6IG51bWJlciwgQjogbnVtYmVyLCBDOiBudW1iZXIsIEQ6IG51bWJlciwgRTogbnVtYmVyLCBGOiBudW1iZXIsIEc6IG51bWJlciwgSDogbnVtYmVyXG4gICk6IHZvaWQge1xuICAgIHRoaXMuQSA9IEEgfCAwO1xuICAgIHRoaXMuQiA9IEIgfCAwO1xuICAgIHRoaXMuQyA9IEMgfCAwO1xuICAgIHRoaXMuRCA9IEQgfCAwO1xuICAgIHRoaXMuRSA9IEUgfCAwO1xuICAgIHRoaXMuRiA9IEYgfCAwO1xuICAgIHRoaXMuRyA9IEcgfCAwO1xuICAgIHRoaXMuSCA9IEggfCAwO1xuICB9XG4gIHByb3RlY3RlZCBwcm9jZXNzKHZpZXc6IERhdGFWaWV3LCBvZmZzZXQ6IG51bWJlcik6IHZvaWQge1xuICAgIC8vIEV4dGVuZCB0aGUgZmlyc3QgMTYgd29yZHMgaW50byB0aGUgcmVtYWluaW5nIDQ4IHdvcmRzIHdbMTYuLjYzXSBvZiB0aGUgbWVzc2FnZSBzY2hlZHVsZSBhcnJheVxuICAgIGZvciAobGV0IGkgPSAwOyBpIDwgMTY7IGkrKywgb2Zmc2V0ICs9IDQpIFNIQTI1Nl9XW2ldID0gdmlldy5nZXRVaW50MzIob2Zmc2V0LCBmYWxzZSk7XG4gICAgZm9yIChsZXQgaSA9IDE2OyBpIDwgNjQ7IGkrKykge1xuICAgICAgY29uc3QgVzE1ID0gU0hBMjU2X1dbaSAtIDE1XTtcbiAgICAgIGNvbnN0IFcyID0gU0hBMjU2X1dbaSAtIDJdO1xuICAgICAgY29uc3QgczAgPSByb3RyKFcxNSwgNykgXiByb3RyKFcxNSwgMTgpIF4gKFcxNSA+Pj4gMyk7XG4gICAgICBjb25zdCBzMSA9IHJvdHIoVzIsIDE3KSBeIHJvdHIoVzIsIDE5KSBeIChXMiA+Pj4gMTApO1xuICAgICAgU0hBMjU2X1dbaV0gPSAoczEgKyBTSEEyNTZfV1tpIC0gN10gKyBzMCArIFNIQTI1Nl9XW2kgLSAxNl0pIHwgMDtcbiAgICB9XG4gICAgLy8gQ29tcHJlc3Npb24gZnVuY3Rpb24gbWFpbiBsb29wLCA2NCByb3VuZHNcbiAgICBsZXQgeyBBLCBCLCBDLCBELCBFLCBGLCBHLCBIIH0gPSB0aGlzO1xuICAgIGZvciAobGV0IGkgPSAwOyBpIDwgNjQ7IGkrKykge1xuICAgICAgY29uc3Qgc2lnbWExID0gcm90cihFLCA2KSBeIHJvdHIoRSwgMTEpIF4gcm90cihFLCAyNSk7XG4gICAgICBjb25zdCBUMSA9IChIICsgc2lnbWExICsgQ2hpKEUsIEYsIEcpICsgU0hBMjU2X0tbaV0gKyBTSEEyNTZfV1tpXSkgfCAwO1xuICAgICAgY29uc3Qgc2lnbWEwID0gcm90cihBLCAyKSBeIHJvdHIoQSwgMTMpIF4gcm90cihBLCAyMik7XG4gICAgICBjb25zdCBUMiA9IChzaWdtYTAgKyBNYWooQSwgQiwgQykpIHwgMDtcbiAgICAgIEggPSBHO1xuICAgICAgRyA9IEY7XG4gICAgICBGID0gRTtcbiAgICAgIEUgPSAoRCArIFQxKSB8IDA7XG4gICAgICBEID0gQztcbiAgICAgIEMgPSBCO1xuICAgICAgQiA9IEE7XG4gICAgICBBID0gKFQxICsgVDIpIHwgMDtcbiAgICB9XG4gICAgLy8gQWRkIHRoZSBjb21wcmVzc2VkIGNodW5rIHRvIHRoZSBjdXJyZW50IGhhc2ggdmFsdWVcbiAgICBBID0gKEEgKyB0aGlzLkEpIHwgMDtcbiAgICBCID0gKEIgKyB0aGlzLkIpIHwgMDtcbiAgICBDID0gKEMgKyB0aGlzLkMpIHwgMDtcbiAgICBEID0gKEQgKyB0aGlzLkQpIHwgMDtcbiAgICBFID0gKEUgKyB0aGlzLkUpIHwgMDtcbiAgICBGID0gKEYgKyB0aGlzLkYpIHwgMDtcbiAgICBHID0gKEcgKyB0aGlzLkcpIHwgMDtcbiAgICBIID0gKEggKyB0aGlzLkgpIHwgMDtcbiAgICB0aGlzLnNldChBLCBCLCBDLCBELCBFLCBGLCBHLCBIKTtcbiAgfVxuICBwcm90ZWN0ZWQgcm91bmRDbGVhbigpOiB2b2lkIHtcbiAgICBjbGVhbihTSEEyNTZfVyk7XG4gIH1cbiAgZGVzdHJveSgpOiB2b2lkIHtcbiAgICB0aGlzLnNldCgwLCAwLCAwLCAwLCAwLCAwLCAwLCAwKTtcbiAgICBjbGVhbih0aGlzLmJ1ZmZlcik7XG4gIH1cbn1cblxuZXhwb3J0IGNsYXNzIFNIQTIyNCBleHRlbmRzIFNIQTI1NiB7XG4gIHByb3RlY3RlZCBBOiBudW1iZXIgPSBTSEEyMjRfSVZbMF0gfCAwO1xuICBwcm90ZWN0ZWQgQjogbnVtYmVyID0gU0hBMjI0X0lWWzFdIHwgMDtcbiAgcHJvdGVjdGVkIEM6IG51bWJlciA9IFNIQTIyNF9JVlsyXSB8IDA7XG4gIHByb3RlY3RlZCBEOiBudW1iZXIgPSBTSEEyMjRfSVZbM10gfCAwO1xuICBwcm90ZWN0ZWQgRTogbnVtYmVyID0gU0hBMjI0X0lWWzRdIHwgMDtcbiAgcHJvdGVjdGVkIEY6IG51bWJlciA9IFNIQTIyNF9JVls1XSB8IDA7XG4gIHByb3RlY3RlZCBHOiBudW1iZXIgPSBTSEEyMjRfSVZbNl0gfCAwO1xuICBwcm90ZWN0ZWQgSDogbnVtYmVyID0gU0hBMjI0X0lWWzddIHwgMDtcbiAgY29uc3RydWN0b3IoKSB7XG4gICAgc3VwZXIoMjgpO1xuICB9XG59XG5cbi8vIFNIQTItNTEyIGlzIHNsb3dlciB0aGFuIHNoYTI1NiBpbiBqcyBiZWNhdXNlIHU2NCBvcGVyYXRpb25zIGFyZSBzbG93LlxuXG4vLyBSb3VuZCBjb250YW50c1xuLy8gRmlyc3QgMzIgYml0cyBvZiB0aGUgZnJhY3Rpb25hbCBwYXJ0cyBvZiB0aGUgY3ViZSByb290cyBvZiB0aGUgZmlyc3QgODAgcHJpbWVzIDIuLjQwOVxuLy8gcHJldHRpZXItaWdub3JlXG5jb25zdCBLNTEyID0gLyogQF9fUFVSRV9fICovICgoKSA9PiB1NjQuc3BsaXQoW1xuICAnMHg0MjhhMmY5OGQ3MjhhZTIyJywgJzB4NzEzNzQ0OTEyM2VmNjVjZCcsICcweGI1YzBmYmNmZWM0ZDNiMmYnLCAnMHhlOWI1ZGJhNTgxODlkYmJjJyxcbiAgJzB4Mzk1NmMyNWJmMzQ4YjUzOCcsICcweDU5ZjExMWYxYjYwNWQwMTknLCAnMHg5MjNmODJhNGFmMTk0ZjliJywgJzB4YWIxYzVlZDVkYTZkODExOCcsXG4gICcweGQ4MDdhYTk4YTMwMzAyNDInLCAnMHgxMjgzNWIwMTQ1NzA2ZmJlJywgJzB4MjQzMTg1YmU0ZWU0YjI4YycsICcweDU1MGM3ZGMzZDVmZmI0ZTInLFxuICAnMHg3MmJlNWQ3NGYyN2I4OTZmJywgJzB4ODBkZWIxZmUzYjE2OTZiMScsICcweDliZGMwNmE3MjVjNzEyMzUnLCAnMHhjMTliZjE3NGNmNjkyNjk0JyxcbiAgJzB4ZTQ5YjY5YzE5ZWYxNGFkMicsICcweGVmYmU0Nzg2Mzg0ZjI1ZTMnLCAnMHgwZmMxOWRjNjhiOGNkNWI1JywgJzB4MjQwY2ExY2M3N2FjOWM2NScsXG4gICcweDJkZTkyYzZmNTkyYjAyNzUnLCAnMHg0YTc0ODRhYTZlYTZlNDgzJywgJzB4NWNiMGE5ZGNiZDQxZmJkNCcsICcweDc2Zjk4OGRhODMxMTUzYjUnLFxuICAnMHg5ODNlNTE1MmVlNjZkZmFiJywgJzB4YTgzMWM2NmQyZGI0MzIxMCcsICcweGIwMDMyN2M4OThmYjIxM2YnLCAnMHhiZjU5N2ZjN2JlZWYwZWU0JyxcbiAgJzB4YzZlMDBiZjMzZGE4OGZjMicsICcweGQ1YTc5MTQ3OTMwYWE3MjUnLCAnMHgwNmNhNjM1MWUwMDM4MjZmJywgJzB4MTQyOTI5NjcwYTBlNmU3MCcsXG4gICcweDI3YjcwYTg1NDZkMjJmZmMnLCAnMHgyZTFiMjEzODVjMjZjOTI2JywgJzB4NGQyYzZkZmM1YWM0MmFlZCcsICcweDUzMzgwZDEzOWQ5NWIzZGYnLFxuICAnMHg2NTBhNzM1NDhiYWY2M2RlJywgJzB4NzY2YTBhYmIzYzc3YjJhOCcsICcweDgxYzJjOTJlNDdlZGFlZTYnLCAnMHg5MjcyMmM4NTE0ODIzNTNiJyxcbiAgJzB4YTJiZmU4YTE0Y2YxMDM2NCcsICcweGE4MWE2NjRiYmM0MjMwMDEnLCAnMHhjMjRiOGI3MGQwZjg5NzkxJywgJzB4Yzc2YzUxYTMwNjU0YmUzMCcsXG4gICcweGQxOTJlODE5ZDZlZjUyMTgnLCAnMHhkNjk5MDYyNDU1NjVhOTEwJywgJzB4ZjQwZTM1ODU1NzcxMjAyYScsICcweDEwNmFhMDcwMzJiYmQxYjgnLFxuICAnMHgxOWE0YzExNmI4ZDJkMGM4JywgJzB4MWUzNzZjMDg1MTQxYWI1MycsICcweDI3NDg3NzRjZGY4ZWViOTknLCAnMHgzNGIwYmNiNWUxOWI0OGE4JyxcbiAgJzB4MzkxYzBjYjNjNWM5NWE2MycsICcweDRlZDhhYTRhZTM0MThhY2InLCAnMHg1YjljY2E0Zjc3NjNlMzczJywgJzB4NjgyZTZmZjNkNmIyYjhhMycsXG4gICcweDc0OGY4MmVlNWRlZmIyZmMnLCAnMHg3OGE1NjM2ZjQzMTcyZjYwJywgJzB4ODRjODc4MTRhMWYwYWI3MicsICcweDhjYzcwMjA4MWE2NDM5ZWMnLFxuICAnMHg5MGJlZmZmYTIzNjMxZTI4JywgJzB4YTQ1MDZjZWJkZTgyYmRlOScsICcweGJlZjlhM2Y3YjJjNjc5MTUnLCAnMHhjNjcxNzhmMmUzNzI1MzJiJyxcbiAgJzB4Y2EyNzNlY2VlYTI2NjE5YycsICcweGQxODZiOGM3MjFjMGMyMDcnLCAnMHhlYWRhN2RkNmNkZTBlYjFlJywgJzB4ZjU3ZDRmN2ZlZTZlZDE3OCcsXG4gICcweDA2ZjA2N2FhNzIxNzZmYmEnLCAnMHgwYTYzN2RjNWEyYzg5OGE2JywgJzB4MTEzZjk4MDRiZWY5MGRhZScsICcweDFiNzEwYjM1MTMxYzQ3MWInLFxuICAnMHgyOGRiNzdmNTIzMDQ3ZDg0JywgJzB4MzJjYWFiN2I0MGM3MjQ5MycsICcweDNjOWViZTBhMTVjOWJlYmMnLCAnMHg0MzFkNjdjNDljMTAwZDRjJyxcbiAgJzB4NGNjNWQ0YmVjYjNlNDJiNicsICcweDU5N2YyOTljZmM2NTdlMmEnLCAnMHg1ZmNiNmZhYjNhZDZmYWVjJywgJzB4NmM0NDE5OGM0YTQ3NTgxNydcbl0ubWFwKG4gPT4gQmlnSW50KG4pKSkpKCk7XG5jb25zdCBTSEE1MTJfS2ggPSAvKiBAX19QVVJFX18gKi8gKCgpID0+IEs1MTJbMF0pKCk7XG5jb25zdCBTSEE1MTJfS2wgPSAvKiBAX19QVVJFX18gKi8gKCgpID0+IEs1MTJbMV0pKCk7XG5cbi8vIFJldXNhYmxlIHRlbXBvcmFyeSBidWZmZXJzXG5jb25zdCBTSEE1MTJfV19IID0gLyogQF9fUFVSRV9fICovIG5ldyBVaW50MzJBcnJheSg4MCk7XG5jb25zdCBTSEE1MTJfV19MID0gLyogQF9fUFVSRV9fICovIG5ldyBVaW50MzJBcnJheSg4MCk7XG5cbmV4cG9ydCBjbGFzcyBTSEE1MTIgZXh0ZW5kcyBIYXNoTUQ8U0hBNTEyPiB7XG4gIC8vIFdlIGNhbm5vdCB1c2UgYXJyYXkgaGVyZSBzaW5jZSBhcnJheSBhbGxvd3MgaW5kZXhpbmcgYnkgdmFyaWFibGVcbiAgLy8gd2hpY2ggbWVhbnMgb3B0aW1pemVyL2NvbXBpbGVyIGNhbm5vdCB1c2UgcmVnaXN0ZXJzLlxuICAvLyBoIC0tIGhpZ2ggMzIgYml0cywgbCAtLSBsb3cgMzIgYml0c1xuICBwcm90ZWN0ZWQgQWg6IG51bWJlciA9IFNIQTUxMl9JVlswXSB8IDA7XG4gIHByb3RlY3RlZCBBbDogbnVtYmVyID0gU0hBNTEyX0lWWzFdIHwgMDtcbiAgcHJvdGVjdGVkIEJoOiBudW1iZXIgPSBTSEE1MTJfSVZbMl0gfCAwO1xuICBwcm90ZWN0ZWQgQmw6IG51bWJlciA9IFNIQTUxMl9JVlszXSB8IDA7XG4gIHByb3RlY3RlZCBDaDogbnVtYmVyID0gU0hBNTEyX0lWWzRdIHwgMDtcbiAgcHJvdGVjdGVkIENsOiBudW1iZXIgPSBTSEE1MTJfSVZbNV0gfCAwO1xuICBwcm90ZWN0ZWQgRGg6IG51bWJlciA9IFNIQTUxMl9JVls2XSB8IDA7XG4gIHByb3RlY3RlZCBEbDogbnVtYmVyID0gU0hBNTEyX0lWWzddIHwgMDtcbiAgcHJvdGVjdGVkIEVoOiBudW1iZXIgPSBTSEE1MTJfSVZbOF0gfCAwO1xuICBwcm90ZWN0ZWQgRWw6IG51bWJlciA9IFNIQTUxMl9JVls5XSB8IDA7XG4gIHByb3RlY3RlZCBGaDogbnVtYmVyID0gU0hBNTEyX0lWWzEwXSB8IDA7XG4gIHByb3RlY3RlZCBGbDogbnVtYmVyID0gU0hBNTEyX0lWWzExXSB8IDA7XG4gIHByb3RlY3RlZCBHaDogbnVtYmVyID0gU0hBNTEyX0lWWzEyXSB8IDA7XG4gIHByb3RlY3RlZCBHbDogbnVtYmVyID0gU0hBNTEyX0lWWzEzXSB8IDA7XG4gIHByb3RlY3RlZCBIaDogbnVtYmVyID0gU0hBNTEyX0lWWzE0XSB8IDA7XG4gIHByb3RlY3RlZCBIbDogbnVtYmVyID0gU0hBNTEyX0lWWzE1XSB8IDA7XG5cbiAgY29uc3RydWN0b3Iob3V0cHV0TGVuOiBudW1iZXIgPSA2NCkge1xuICAgIHN1cGVyKDEyOCwgb3V0cHV0TGVuLCAxNiwgZmFsc2UpO1xuICB9XG4gIC8vIHByZXR0aWVyLWlnbm9yZVxuICBwcm90ZWN0ZWQgZ2V0KCk6IFtcbiAgICBudW1iZXIsIG51bWJlciwgbnVtYmVyLCBudW1iZXIsIG51bWJlciwgbnVtYmVyLCBudW1iZXIsIG51bWJlcixcbiAgICBudW1iZXIsIG51bWJlciwgbnVtYmVyLCBudW1iZXIsIG51bWJlciwgbnVtYmVyLCBudW1iZXIsIG51bWJlclxuICBdIHtcbiAgICBjb25zdCB7IEFoLCBBbCwgQmgsIEJsLCBDaCwgQ2wsIERoLCBEbCwgRWgsIEVsLCBGaCwgRmwsIEdoLCBHbCwgSGgsIEhsIH0gPSB0aGlzO1xuICAgIHJldHVybiBbQWgsIEFsLCBCaCwgQmwsIENoLCBDbCwgRGgsIERsLCBFaCwgRWwsIEZoLCBGbCwgR2gsIEdsLCBIaCwgSGxdO1xuICB9XG4gIC8vIHByZXR0aWVyLWlnbm9yZVxuICBwcm90ZWN0ZWQgc2V0KFxuICAgIEFoOiBudW1iZXIsIEFsOiBudW1iZXIsIEJoOiBudW1iZXIsIEJsOiBudW1iZXIsIENoOiBudW1iZXIsIENsOiBudW1iZXIsIERoOiBudW1iZXIsIERsOiBudW1iZXIsXG4gICAgRWg6IG51bWJlciwgRWw6IG51bWJlciwgRmg6IG51bWJlciwgRmw6IG51bWJlciwgR2g6IG51bWJlciwgR2w6IG51bWJlciwgSGg6IG51bWJlciwgSGw6IG51bWJlclxuICApOiB2b2lkIHtcbiAgICB0aGlzLkFoID0gQWggfCAwO1xuICAgIHRoaXMuQWwgPSBBbCB8IDA7XG4gICAgdGhpcy5CaCA9IEJoIHwgMDtcbiAgICB0aGlzLkJsID0gQmwgfCAwO1xuICAgIHRoaXMuQ2ggPSBDaCB8IDA7XG4gICAgdGhpcy5DbCA9IENsIHwgMDtcbiAgICB0aGlzLkRoID0gRGggfCAwO1xuICAgIHRoaXMuRGwgPSBEbCB8IDA7XG4gICAgdGhpcy5FaCA9IEVoIHwgMDtcbiAgICB0aGlzLkVsID0gRWwgfCAwO1xuICAgIHRoaXMuRmggPSBGaCB8IDA7XG4gICAgdGhpcy5GbCA9IEZsIHwgMDtcbiAgICB0aGlzLkdoID0gR2ggfCAwO1xuICAgIHRoaXMuR2wgPSBHbCB8IDA7XG4gICAgdGhpcy5IaCA9IEhoIHwgMDtcbiAgICB0aGlzLkhsID0gSGwgfCAwO1xuICB9XG4gIHByb3RlY3RlZCBwcm9jZXNzKHZpZXc6IERhdGFWaWV3LCBvZmZzZXQ6IG51bWJlcik6IHZvaWQge1xuICAgIC8vIEV4dGVuZCB0aGUgZmlyc3QgMTYgd29yZHMgaW50byB0aGUgcmVtYWluaW5nIDY0IHdvcmRzIHdbMTYuLjc5XSBvZiB0aGUgbWVzc2FnZSBzY2hlZHVsZSBhcnJheVxuICAgIGZvciAobGV0IGkgPSAwOyBpIDwgMTY7IGkrKywgb2Zmc2V0ICs9IDQpIHtcbiAgICAgIFNIQTUxMl9XX0hbaV0gPSB2aWV3LmdldFVpbnQzMihvZmZzZXQpO1xuICAgICAgU0hBNTEyX1dfTFtpXSA9IHZpZXcuZ2V0VWludDMyKChvZmZzZXQgKz0gNCkpO1xuICAgIH1cbiAgICBmb3IgKGxldCBpID0gMTY7IGkgPCA4MDsgaSsrKSB7XG4gICAgICAvLyBzMCA6PSAod1tpLTE1XSByaWdodHJvdGF0ZSAxKSB4b3IgKHdbaS0xNV0gcmlnaHRyb3RhdGUgOCkgeG9yICh3W2ktMTVdIHJpZ2h0c2hpZnQgNylcbiAgICAgIGNvbnN0IFcxNWggPSBTSEE1MTJfV19IW2kgLSAxNV0gfCAwO1xuICAgICAgY29uc3QgVzE1bCA9IFNIQTUxMl9XX0xbaSAtIDE1XSB8IDA7XG4gICAgICBjb25zdCBzMGggPSB1NjQucm90clNIKFcxNWgsIFcxNWwsIDEpIF4gdTY0LnJvdHJTSChXMTVoLCBXMTVsLCA4KSBeIHU2NC5zaHJTSChXMTVoLCBXMTVsLCA3KTtcbiAgICAgIGNvbnN0IHMwbCA9IHU2NC5yb3RyU0woVzE1aCwgVzE1bCwgMSkgXiB1NjQucm90clNMKFcxNWgsIFcxNWwsIDgpIF4gdTY0LnNoclNMKFcxNWgsIFcxNWwsIDcpO1xuICAgICAgLy8gczEgOj0gKHdbaS0yXSByaWdodHJvdGF0ZSAxOSkgeG9yICh3W2ktMl0gcmlnaHRyb3RhdGUgNjEpIHhvciAod1tpLTJdIHJpZ2h0c2hpZnQgNilcbiAgICAgIGNvbnN0IFcyaCA9IFNIQTUxMl9XX0hbaSAtIDJdIHwgMDtcbiAgICAgIGNvbnN0IFcybCA9IFNIQTUxMl9XX0xbaSAtIDJdIHwgMDtcbiAgICAgIGNvbnN0IHMxaCA9IHU2NC5yb3RyU0goVzJoLCBXMmwsIDE5KSBeIHU2NC5yb3RyQkgoVzJoLCBXMmwsIDYxKSBeIHU2NC5zaHJTSChXMmgsIFcybCwgNik7XG4gICAgICBjb25zdCBzMWwgPSB1NjQucm90clNMKFcyaCwgVzJsLCAxOSkgXiB1NjQucm90ckJMKFcyaCwgVzJsLCA2MSkgXiB1NjQuc2hyU0woVzJoLCBXMmwsIDYpO1xuICAgICAgLy8gU0hBMjU2X1dbaV0gPSBzMCArIHMxICsgU0hBMjU2X1dbaSAtIDddICsgU0hBMjU2X1dbaSAtIDE2XTtcbiAgICAgIGNvbnN0IFNVTWwgPSB1NjQuYWRkNEwoczBsLCBzMWwsIFNIQTUxMl9XX0xbaSAtIDddLCBTSEE1MTJfV19MW2kgLSAxNl0pO1xuICAgICAgY29uc3QgU1VNaCA9IHU2NC5hZGQ0SChTVU1sLCBzMGgsIHMxaCwgU0hBNTEyX1dfSFtpIC0gN10sIFNIQTUxMl9XX0hbaSAtIDE2XSk7XG4gICAgICBTSEE1MTJfV19IW2ldID0gU1VNaCB8IDA7XG4gICAgICBTSEE1MTJfV19MW2ldID0gU1VNbCB8IDA7XG4gICAgfVxuICAgIGxldCB7IEFoLCBBbCwgQmgsIEJsLCBDaCwgQ2wsIERoLCBEbCwgRWgsIEVsLCBGaCwgRmwsIEdoLCBHbCwgSGgsIEhsIH0gPSB0aGlzO1xuICAgIC8vIENvbXByZXNzaW9uIGZ1bmN0aW9uIG1haW4gbG9vcCwgODAgcm91bmRzXG4gICAgZm9yIChsZXQgaSA9IDA7IGkgPCA4MDsgaSsrKSB7XG4gICAgICAvLyBTMSA6PSAoZSByaWdodHJvdGF0ZSAxNCkgeG9yIChlIHJpZ2h0cm90YXRlIDE4KSB4b3IgKGUgcmlnaHRyb3RhdGUgNDEpXG4gICAgICBjb25zdCBzaWdtYTFoID0gdTY0LnJvdHJTSChFaCwgRWwsIDE0KSBeIHU2NC5yb3RyU0goRWgsIEVsLCAxOCkgXiB1NjQucm90ckJIKEVoLCBFbCwgNDEpO1xuICAgICAgY29uc3Qgc2lnbWExbCA9IHU2NC5yb3RyU0woRWgsIEVsLCAxNCkgXiB1NjQucm90clNMKEVoLCBFbCwgMTgpIF4gdTY0LnJvdHJCTChFaCwgRWwsIDQxKTtcbiAgICAgIC8vY29uc3QgVDEgPSAoSCArIHNpZ21hMSArIENoaShFLCBGLCBHKSArIFNIQTI1Nl9LW2ldICsgU0hBMjU2X1dbaV0pIHwgMDtcbiAgICAgIGNvbnN0IENISWggPSAoRWggJiBGaCkgXiAofkVoICYgR2gpO1xuICAgICAgY29uc3QgQ0hJbCA9IChFbCAmIEZsKSBeICh+RWwgJiBHbCk7XG4gICAgICAvLyBUMSA9IEggKyBzaWdtYTEgKyBDaGkoRSwgRiwgRykgKyBTSEE1MTJfS1tpXSArIFNIQTUxMl9XW2ldXG4gICAgICAvLyBwcmV0dGllci1pZ25vcmVcbiAgICAgIGNvbnN0IFQxbGwgPSB1NjQuYWRkNUwoSGwsIHNpZ21hMWwsIENISWwsIFNIQTUxMl9LbFtpXSwgU0hBNTEyX1dfTFtpXSk7XG4gICAgICBjb25zdCBUMWggPSB1NjQuYWRkNUgoVDFsbCwgSGgsIHNpZ21hMWgsIENISWgsIFNIQTUxMl9LaFtpXSwgU0hBNTEyX1dfSFtpXSk7XG4gICAgICBjb25zdCBUMWwgPSBUMWxsIHwgMDtcbiAgICAgIC8vIFMwIDo9IChhIHJpZ2h0cm90YXRlIDI4KSB4b3IgKGEgcmlnaHRyb3RhdGUgMzQpIHhvciAoYSByaWdodHJvdGF0ZSAzOSlcbiAgICAgIGNvbnN0IHNpZ21hMGggPSB1NjQucm90clNIKEFoLCBBbCwgMjgpIF4gdTY0LnJvdHJCSChBaCwgQWwsIDM0KSBeIHU2NC5yb3RyQkgoQWgsIEFsLCAzOSk7XG4gICAgICBjb25zdCBzaWdtYTBsID0gdTY0LnJvdHJTTChBaCwgQWwsIDI4KSBeIHU2NC5yb3RyQkwoQWgsIEFsLCAzNCkgXiB1NjQucm90ckJMKEFoLCBBbCwgMzkpO1xuICAgICAgY29uc3QgTUFKaCA9IChBaCAmIEJoKSBeIChBaCAmIENoKSBeIChCaCAmIENoKTtcbiAgICAgIGNvbnN0IE1BSmwgPSAoQWwgJiBCbCkgXiAoQWwgJiBDbCkgXiAoQmwgJiBDbCk7XG4gICAgICBIaCA9IEdoIHwgMDtcbiAgICAgIEhsID0gR2wgfCAwO1xuICAgICAgR2ggPSBGaCB8IDA7XG4gICAgICBHbCA9IEZsIHwgMDtcbiAgICAgIEZoID0gRWggfCAwO1xuICAgICAgRmwgPSBFbCB8IDA7XG4gICAgICAoeyBoOiBFaCwgbDogRWwgfSA9IHU2NC5hZGQoRGggfCAwLCBEbCB8IDAsIFQxaCB8IDAsIFQxbCB8IDApKTtcbiAgICAgIERoID0gQ2ggfCAwO1xuICAgICAgRGwgPSBDbCB8IDA7XG4gICAgICBDaCA9IEJoIHwgMDtcbiAgICAgIENsID0gQmwgfCAwO1xuICAgICAgQmggPSBBaCB8IDA7XG4gICAgICBCbCA9IEFsIHwgMDtcbiAgICAgIGNvbnN0IEFsbCA9IHU2NC5hZGQzTChUMWwsIHNpZ21hMGwsIE1BSmwpO1xuICAgICAgQWggPSB1NjQuYWRkM0goQWxsLCBUMWgsIHNpZ21hMGgsIE1BSmgpO1xuICAgICAgQWwgPSBBbGwgfCAwO1xuICAgIH1cbiAgICAvLyBBZGQgdGhlIGNvbXByZXNzZWQgY2h1bmsgdG8gdGhlIGN1cnJlbnQgaGFzaCB2YWx1ZVxuICAgICh7IGg6IEFoLCBsOiBBbCB9ID0gdTY0LmFkZCh0aGlzLkFoIHwgMCwgdGhpcy5BbCB8IDAsIEFoIHwgMCwgQWwgfCAwKSk7XG4gICAgKHsgaDogQmgsIGw6IEJsIH0gPSB1NjQuYWRkKHRoaXMuQmggfCAwLCB0aGlzLkJsIHwgMCwgQmggfCAwLCBCbCB8IDApKTtcbiAgICAoeyBoOiBDaCwgbDogQ2wgfSA9IHU2NC5hZGQodGhpcy5DaCB8IDAsIHRoaXMuQ2wgfCAwLCBDaCB8IDAsIENsIHwgMCkpO1xuICAgICh7IGg6IERoLCBsOiBEbCB9ID0gdTY0LmFkZCh0aGlzLkRoIHwgMCwgdGhpcy5EbCB8IDAsIERoIHwgMCwgRGwgfCAwKSk7XG4gICAgKHsgaDogRWgsIGw6IEVsIH0gPSB1NjQuYWRkKHRoaXMuRWggfCAwLCB0aGlzLkVsIHwgMCwgRWggfCAwLCBFbCB8IDApKTtcbiAgICAoeyBoOiBGaCwgbDogRmwgfSA9IHU2NC5hZGQodGhpcy5GaCB8IDAsIHRoaXMuRmwgfCAwLCBGaCB8IDAsIEZsIHwgMCkpO1xuICAgICh7IGg6IEdoLCBsOiBHbCB9ID0gdTY0LmFkZCh0aGlzLkdoIHwgMCwgdGhpcy5HbCB8IDAsIEdoIHwgMCwgR2wgfCAwKSk7XG4gICAgKHsgaDogSGgsIGw6IEhsIH0gPSB1NjQuYWRkKHRoaXMuSGggfCAwLCB0aGlzLkhsIHwgMCwgSGggfCAwLCBIbCB8IDApKTtcbiAgICB0aGlzLnNldChBaCwgQWwsIEJoLCBCbCwgQ2gsIENsLCBEaCwgRGwsIEVoLCBFbCwgRmgsIEZsLCBHaCwgR2wsIEhoLCBIbCk7XG4gIH1cbiAgcHJvdGVjdGVkIHJvdW5kQ2xlYW4oKTogdm9pZCB7XG4gICAgY2xlYW4oU0hBNTEyX1dfSCwgU0hBNTEyX1dfTCk7XG4gIH1cbiAgZGVzdHJveSgpOiB2b2lkIHtcbiAgICBjbGVhbih0aGlzLmJ1ZmZlcik7XG4gICAgdGhpcy5zZXQoMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCk7XG4gIH1cbn1cblxuZXhwb3J0IGNsYXNzIFNIQTM4NCBleHRlbmRzIFNIQTUxMiB7XG4gIHByb3RlY3RlZCBBaDogbnVtYmVyID0gU0hBMzg0X0lWWzBdIHwgMDtcbiAgcHJvdGVjdGVkIEFsOiBudW1iZXIgPSBTSEEzODRfSVZbMV0gfCAwO1xuICBwcm90ZWN0ZWQgQmg6IG51bWJlciA9IFNIQTM4NF9JVlsyXSB8IDA7XG4gIHByb3RlY3RlZCBCbDogbnVtYmVyID0gU0hBMzg0X0lWWzNdIHwgMDtcbiAgcHJvdGVjdGVkIENoOiBudW1iZXIgPSBTSEEzODRfSVZbNF0gfCAwO1xuICBwcm90ZWN0ZWQgQ2w6IG51bWJlciA9IFNIQTM4NF9JVls1XSB8IDA7XG4gIHByb3RlY3RlZCBEaDogbnVtYmVyID0gU0hBMzg0X0lWWzZdIHwgMDtcbiAgcHJvdGVjdGVkIERsOiBudW1iZXIgPSBTSEEzODRfSVZbN10gfCAwO1xuICBwcm90ZWN0ZWQgRWg6IG51bWJlciA9IFNIQTM4NF9JVls4XSB8IDA7XG4gIHByb3RlY3RlZCBFbDogbnVtYmVyID0gU0hBMzg0X0lWWzldIHwgMDtcbiAgcHJvdGVjdGVkIEZoOiBudW1iZXIgPSBTSEEzODRfSVZbMTBdIHwgMDtcbiAgcHJvdGVjdGVkIEZsOiBudW1iZXIgPSBTSEEzODRfSVZbMTFdIHwgMDtcbiAgcHJvdGVjdGVkIEdoOiBudW1iZXIgPSBTSEEzODRfSVZbMTJdIHwgMDtcbiAgcHJvdGVjdGVkIEdsOiBudW1iZXIgPSBTSEEzODRfSVZbMTNdIHwgMDtcbiAgcHJvdGVjdGVkIEhoOiBudW1iZXIgPSBTSEEzODRfSVZbMTRdIHwgMDtcbiAgcHJvdGVjdGVkIEhsOiBudW1iZXIgPSBTSEEzODRfSVZbMTVdIHwgMDtcblxuICBjb25zdHJ1Y3RvcigpIHtcbiAgICBzdXBlcig0OCk7XG4gIH1cbn1cblxuLyoqXG4gKiBUcnVuY2F0ZWQgU0hBNTEyLzI1NiBhbmQgU0hBNTEyLzIyNC5cbiAqIFNIQTUxMl9JViBpcyBYT1JlZCB3aXRoIDB4YTVhNWE1YTVhNWE1YTVhNSwgdGhlbiB1c2VkIGFzIFwiaW50ZXJtZWRpYXJ5XCIgSVYgb2YgU0hBNTEyL3QuXG4gKiBUaGVuIHQgaGFzaGVzIHN0cmluZyB0byBwcm9kdWNlIHJlc3VsdCBJVi5cbiAqIFNlZSBgdGVzdC9taXNjL3NoYTItZ2VuLWl2LmpzYC5cbiAqL1xuXG4vKiogU0hBNTEyLzIyNCBJViAqL1xuY29uc3QgVDIyNF9JViA9IC8qIEBfX1BVUkVfXyAqLyBVaW50MzJBcnJheS5mcm9tKFtcbiAgMHg4YzNkMzdjOCwgMHgxOTU0NGRhMiwgMHg3M2UxOTk2NiwgMHg4OWRjZDRkNiwgMHgxZGZhYjdhZSwgMHgzMmZmOWM4MiwgMHg2NzlkZDUxNCwgMHg1ODJmOWZjZixcbiAgMHgwZjZkMmI2OSwgMHg3YmQ0NGRhOCwgMHg3N2UzNmY3MywgMHgwNGM0ODk0MiwgMHgzZjlkODVhOCwgMHg2YTFkMzZjOCwgMHgxMTEyZTZhZCwgMHg5MWQ2OTJhMSxcbl0pO1xuXG4vKiogU0hBNTEyLzI1NiBJViAqL1xuY29uc3QgVDI1Nl9JViA9IC8qIEBfX1BVUkVfXyAqLyBVaW50MzJBcnJheS5mcm9tKFtcbiAgMHgyMjMxMjE5NCwgMHhmYzJiZjcyYywgMHg5ZjU1NWZhMywgMHhjODRjNjRjMiwgMHgyMzkzYjg2YiwgMHg2ZjUzYjE1MSwgMHg5NjM4NzcxOSwgMHg1OTQwZWFiZCxcbiAgMHg5NjI4M2VlMiwgMHhhODhlZmZlMywgMHhiZTVlMWUyNSwgMHg1Mzg2Mzk5MiwgMHgyYjAxOTlmYywgMHgyYzg1YjhhYSwgMHgwZWI3MmRkYywgMHg4MWM1MmNhMixcbl0pO1xuXG5leHBvcnQgY2xhc3MgU0hBNTEyXzIyNCBleHRlbmRzIFNIQTUxMiB7XG4gIHByb3RlY3RlZCBBaDogbnVtYmVyID0gVDIyNF9JVlswXSB8IDA7XG4gIHByb3RlY3RlZCBBbDogbnVtYmVyID0gVDIyNF9JVlsxXSB8IDA7XG4gIHByb3RlY3RlZCBCaDogbnVtYmVyID0gVDIyNF9JVlsyXSB8IDA7XG4gIHByb3RlY3RlZCBCbDogbnVtYmVyID0gVDIyNF9JVlszXSB8IDA7XG4gIHByb3RlY3RlZCBDaDogbnVtYmVyID0gVDIyNF9JVls0XSB8IDA7XG4gIHByb3RlY3RlZCBDbDogbnVtYmVyID0gVDIyNF9JVls1XSB8IDA7XG4gIHByb3RlY3RlZCBEaDogbnVtYmVyID0gVDIyNF9JVls2XSB8IDA7XG4gIHByb3RlY3RlZCBEbDogbnVtYmVyID0gVDIyNF9JVls3XSB8IDA7XG4gIHByb3RlY3RlZCBFaDogbnVtYmVyID0gVDIyNF9JVls4XSB8IDA7XG4gIHByb3RlY3RlZCBFbDogbnVtYmVyID0gVDIyNF9JVls5XSB8IDA7XG4gIHByb3RlY3RlZCBGaDogbnVtYmVyID0gVDIyNF9JVlsxMF0gfCAwO1xuICBwcm90ZWN0ZWQgRmw6IG51bWJlciA9IFQyMjRfSVZbMTFdIHwgMDtcbiAgcHJvdGVjdGVkIEdoOiBudW1iZXIgPSBUMjI0X0lWWzEyXSB8IDA7XG4gIHByb3RlY3RlZCBHbDogbnVtYmVyID0gVDIyNF9JVlsxM10gfCAwO1xuICBwcm90ZWN0ZWQgSGg6IG51bWJlciA9IFQyMjRfSVZbMTRdIHwgMDtcbiAgcHJvdGVjdGVkIEhsOiBudW1iZXIgPSBUMjI0X0lWWzE1XSB8IDA7XG5cbiAgY29uc3RydWN0b3IoKSB7XG4gICAgc3VwZXIoMjgpO1xuICB9XG59XG5cbmV4cG9ydCBjbGFzcyBTSEE1MTJfMjU2IGV4dGVuZHMgU0hBNTEyIHtcbiAgcHJvdGVjdGVkIEFoOiBudW1iZXIgPSBUMjU2X0lWWzBdIHwgMDtcbiAgcHJvdGVjdGVkIEFsOiBudW1iZXIgPSBUMjU2X0lWWzFdIHwgMDtcbiAgcHJvdGVjdGVkIEJoOiBudW1iZXIgPSBUMjU2X0lWWzJdIHwgMDtcbiAgcHJvdGVjdGVkIEJsOiBudW1iZXIgPSBUMjU2X0lWWzNdIHwgMDtcbiAgcHJvdGVjdGVkIENoOiBudW1iZXIgPSBUMjU2X0lWWzRdIHwgMDtcbiAgcHJvdGVjdGVkIENsOiBudW1iZXIgPSBUMjU2X0lWWzVdIHwgMDtcbiAgcHJvdGVjdGVkIERoOiBudW1iZXIgPSBUMjU2X0lWWzZdIHwgMDtcbiAgcHJvdGVjdGVkIERsOiBudW1iZXIgPSBUMjU2X0lWWzddIHwgMDtcbiAgcHJvdGVjdGVkIEVoOiBudW1iZXIgPSBUMjU2X0lWWzhdIHwgMDtcbiAgcHJvdGVjdGVkIEVsOiBudW1iZXIgPSBUMjU2X0lWWzldIHwgMDtcbiAgcHJvdGVjdGVkIEZoOiBudW1iZXIgPSBUMjU2X0lWWzEwXSB8IDA7XG4gIHByb3RlY3RlZCBGbDogbnVtYmVyID0gVDI1Nl9JVlsxMV0gfCAwO1xuICBwcm90ZWN0ZWQgR2g6IG51bWJlciA9IFQyNTZfSVZbMTJdIHwgMDtcbiAgcHJvdGVjdGVkIEdsOiBudW1iZXIgPSBUMjU2X0lWWzEzXSB8IDA7XG4gIHByb3RlY3RlZCBIaDogbnVtYmVyID0gVDI1Nl9JVlsxNF0gfCAwO1xuICBwcm90ZWN0ZWQgSGw6IG51bWJlciA9IFQyNTZfSVZbMTVdIHwgMDtcblxuICBjb25zdHJ1Y3RvcigpIHtcbiAgICBzdXBlcigzMik7XG4gIH1cbn1cblxuLyoqXG4gKiBTSEEyLTI1NiBoYXNoIGZ1bmN0aW9uIGZyb20gUkZDIDQ2MzQuXG4gKlxuICogSXQgaXMgdGhlIGZhc3Rlc3QgSlMgaGFzaCwgZXZlbiBmYXN0ZXIgdGhhbiBCbGFrZTMuXG4gKiBUbyBicmVhayBzaGEyNTYgdXNpbmcgYmlydGhkYXkgYXR0YWNrLCBhdHRhY2tlcnMgbmVlZCB0byB0cnkgMl4xMjggaGFzaGVzLlxuICogQlRDIG5ldHdvcmsgaXMgZG9pbmcgMl43MCBoYXNoZXMvc2VjICgyXjk1IGhhc2hlcy95ZWFyKSBhcyBwZXIgMjAyNS5cbiAqL1xuZXhwb3J0IGNvbnN0IHNoYTI1NjogQ0hhc2ggPSAvKiBAX19QVVJFX18gKi8gY3JlYXRlSGFzaGVyKCgpID0+IG5ldyBTSEEyNTYoKSk7XG4vKiogU0hBMi0yMjQgaGFzaCBmdW5jdGlvbiBmcm9tIFJGQyA0NjM0ICovXG5leHBvcnQgY29uc3Qgc2hhMjI0OiBDSGFzaCA9IC8qIEBfX1BVUkVfXyAqLyBjcmVhdGVIYXNoZXIoKCkgPT4gbmV3IFNIQTIyNCgpKTtcblxuLyoqIFNIQTItNTEyIGhhc2ggZnVuY3Rpb24gZnJvbSBSRkMgNDYzNC4gKi9cbmV4cG9ydCBjb25zdCBzaGE1MTI6IENIYXNoID0gLyogQF9fUFVSRV9fICovIGNyZWF0ZUhhc2hlcigoKSA9PiBuZXcgU0hBNTEyKCkpO1xuLyoqIFNIQTItMzg0IGhhc2ggZnVuY3Rpb24gZnJvbSBSRkMgNDYzNC4gKi9cbmV4cG9ydCBjb25zdCBzaGEzODQ6IENIYXNoID0gLyogQF9fUFVSRV9fICovIGNyZWF0ZUhhc2hlcigoKSA9PiBuZXcgU0hBMzg0KCkpO1xuXG4vKipcbiAqIFNIQTItNTEyLzI1NiBcInRydW5jYXRlZFwiIGhhc2ggZnVuY3Rpb24sIHdpdGggaW1wcm92ZWQgcmVzaXN0YW5jZSB0byBsZW5ndGggZXh0ZW5zaW9uIGF0dGFja3MuXG4gKiBTZWUgdGhlIHBhcGVyIG9uIFt0cnVuY2F0ZWQgU0hBNTEyXShodHRwczovL2VwcmludC5pYWNyLm9yZy8yMDEwLzU0OC5wZGYpLlxuICovXG5leHBvcnQgY29uc3Qgc2hhNTEyXzI1NjogQ0hhc2ggPSAvKiBAX19QVVJFX18gKi8gY3JlYXRlSGFzaGVyKCgpID0+IG5ldyBTSEE1MTJfMjU2KCkpO1xuLyoqXG4gKiBTSEEyLTUxMi8yMjQgXCJ0cnVuY2F0ZWRcIiBoYXNoIGZ1bmN0aW9uLCB3aXRoIGltcHJvdmVkIHJlc2lzdGFuY2UgdG8gbGVuZ3RoIGV4dGVuc2lvbiBhdHRhY2tzLlxuICogU2VlIHRoZSBwYXBlciBvbiBbdHJ1bmNhdGVkIFNIQTUxMl0oaHR0cHM6Ly9lcHJpbnQuaWFjci5vcmcvMjAxMC81NDgucGRmKS5cbiAqL1xuZXhwb3J0IGNvbnN0IHNoYTUxMl8yMjQ6IENIYXNoID0gLyogQF9fUFVSRV9fICovIGNyZWF0ZUhhc2hlcigoKSA9PiBuZXcgU0hBNTEyXzIyNCgpKTtcbiIsICIvKipcbiAqIFNIQTItMjU2IGEuay5hLiBzaGEyNTYuIEluIEpTLCBpdCBpcyB0aGUgZmFzdGVzdCBoYXNoLCBldmVuIGZhc3RlciB0aGFuIEJsYWtlMy5cbiAqXG4gKiBUbyBicmVhayBzaGEyNTYgdXNpbmcgYmlydGhkYXkgYXR0YWNrLCBhdHRhY2tlcnMgbmVlZCB0byB0cnkgMl4xMjggaGFzaGVzLlxuICogQlRDIG5ldHdvcmsgaXMgZG9pbmcgMl43MCBoYXNoZXMvc2VjICgyXjk1IGhhc2hlcy95ZWFyKSBhcyBwZXIgMjAyNS5cbiAqXG4gKiBDaGVjayBvdXQgW0ZJUFMgMTgwLTRdKGh0dHBzOi8vbnZscHVicy5uaXN0Lmdvdi9uaXN0cHVicy9GSVBTL05JU1QuRklQUy4xODAtNC5wZGYpLlxuICogQG1vZHVsZVxuICogQGRlcHJlY2F0ZWRcbiAqL1xuaW1wb3J0IHtcbiAgU0hBMjI0IGFzIFNIQTIyNG4sXG4gIHNoYTIyNCBhcyBzaGEyMjRuLFxuICBTSEEyNTYgYXMgU0hBMjU2bixcbiAgc2hhMjU2IGFzIHNoYTI1Nm4sXG59IGZyb20gJy4vc2hhMi50cyc7XG4vKiogQGRlcHJlY2F0ZWQgVXNlIGltcG9ydCBmcm9tIGBub2JsZS9oYXNoZXMvc2hhMmAgbW9kdWxlICovXG5leHBvcnQgY29uc3QgU0hBMjU2OiB0eXBlb2YgU0hBMjU2biA9IFNIQTI1Nm47XG4vKiogQGRlcHJlY2F0ZWQgVXNlIGltcG9ydCBmcm9tIGBub2JsZS9oYXNoZXMvc2hhMmAgbW9kdWxlICovXG5leHBvcnQgY29uc3Qgc2hhMjU2OiB0eXBlb2Ygc2hhMjU2biA9IHNoYTI1Nm47XG4vKiogQGRlcHJlY2F0ZWQgVXNlIGltcG9ydCBmcm9tIGBub2JsZS9oYXNoZXMvc2hhMmAgbW9kdWxlICovXG5leHBvcnQgY29uc3QgU0hBMjI0OiB0eXBlb2YgU0hBMjI0biA9IFNIQTIyNG47XG4vKiogQGRlcHJlY2F0ZWQgVXNlIGltcG9ydCBmcm9tIGBub2JsZS9oYXNoZXMvc2hhMmAgbW9kdWxlICovXG5leHBvcnQgY29uc3Qgc2hhMjI0OiB0eXBlb2Ygc2hhMjI0biA9IHNoYTIyNG47XG4iLCAiLy8gUFJGIGV2YWx1YXRpb24gZm9yIGRldGVybWluaXN0aWMga2V5IGRlcml2YXRpb25cblxuaW1wb3J0IHsgc2hhMjU2IH0gZnJvbSAnQG5vYmxlL2hhc2hlcy9zaGEyNTYnO1xuaW1wb3J0IHsgUHJmRXJyb3JDb2RlLCB0eXBlIFByZk9wdGlvbnMsIHR5cGUgUHJmUmVzdWx0IH0gZnJvbSAnLi90eXBlcy5qcyc7XG5pbXBvcnQgeyBiYXNlNjRUb0FycmF5QnVmZmVyLCB0b0Jhc2U2NCwgemVyb0ZpbGwgfSBmcm9tICcuL3V0aWxzLmpzJztcblxuLyoqXG4gKiBFdmFsdWF0ZSB0aGUgUFJGIGV4dGVuc2lvbiB3aXRoIGEgZ2l2ZW4gc2FsdCB0byBkZXJpdmUgYSBkZXRlcm1pbmlzdGljIDMyLWJ5dGUgb3V0cHV0LlxuICogVGhlIFBSRiBvdXRwdXQgaXMgcmV0dXJuZWQgdG8gQyMgZm9yIHNlY3VyZSBzdG9yYWdlIGluIFdBU00gbGluZWFyIG1lbW9yeS5cbiAqXG4gKiBJTVBPUlRBTlQ6IFRoZSBQUkYgb3V0cHV0IGlzIHNlbnNpdGl2ZSBhbmQgc2hvdWxkIGJlIGhhbmRsZWQgc2VjdXJlbHkuXG4gKiBUaGlzIGZ1bmN0aW9uIHplcm9zIHRoZSBpbnRlcm5hbCBidWZmZXJzIGFmdGVyIHJldHVybmluZyB0aGUgQmFzZTY0IHJlc3VsdC5cbiAqXG4gKiBAcGFyYW0gY3JlZGVudGlhbElkQmFzZTY0IFRoZSBjcmVkZW50aWFsIElEIChCYXNlNjQgZW5jb2RlZClcbiAqIEBwYXJhbSBzYWx0IEEgc3RyaW5nIHNhbHQgdGhhdCBkZXRlcm1pbmVzIHRoZSBkZXJpdmVkIGtleSAobXVzdCBiZSBjb25zaXN0ZW50IGFjcm9zcyBkZXZpY2VzKVxuICogQHBhcmFtIG9wdGlvbnMgUFJGIGNvbmZpZ3VyYXRpb24gb3B0aW9uc1xuICogQHJldHVybnMgUHJmUmVzdWx0IGNvbnRhaW5pbmcgdGhlIDMyLWJ5dGUgUFJGIG91dHB1dCBhcyBCYXNlNjRcbiAqL1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGV2YWx1YXRlUHJmKFxuICAgIGNyZWRlbnRpYWxJZEJhc2U2NDogc3RyaW5nLFxuICAgIHNhbHQ6IHN0cmluZyxcbiAgICBvcHRpb25zOiBQcmZPcHRpb25zXG4pOiBQcm9taXNlPFByZlJlc3VsdDxzdHJpbmc+PiB7XG4gICAgbGV0IHByZk91dHB1dDogVWludDhBcnJheSB8IG51bGwgPSBudWxsO1xuXG4gICAgdHJ5IHtcbiAgICAgICAgLy8gSGFzaCB0aGUgc2FsdCB0byBlbnN1cmUgY29uc2lzdGVudCAzMi1ieXRlIGxlbmd0aFxuICAgICAgICBjb25zdCBlbmNvZGVyID0gbmV3IFRleHRFbmNvZGVyKCk7XG4gICAgICAgIGNvbnN0IHNhbHRCeXRlcyA9IGVuY29kZXIuZW5jb2RlKHNhbHQpO1xuICAgICAgICBjb25zdCBzYWx0SGFzaCA9IHNoYTI1NihzYWx0Qnl0ZXMpO1xuXG4gICAgICAgIGNvbnN0IGNyZWRlbnRpYWxJZCA9IGJhc2U2NFRvQXJyYXlCdWZmZXIoY3JlZGVudGlhbElkQmFzZTY0KTtcblxuICAgICAgICAvLyBEZXRlcm1pbmUgdHJhbnNwb3J0cyBiYXNlZCBvbiBhdXRoZW50aWNhdG9yIGF0dGFjaG1lbnRcbiAgICAgICAgY29uc3QgdHJhbnNwb3J0czogQXV0aGVudGljYXRvclRyYW5zcG9ydFtdID1cbiAgICAgICAgICAgIG9wdGlvbnMuYXV0aGVudGljYXRvckF0dGFjaG1lbnQgPT09ICdwbGF0Zm9ybSdcbiAgICAgICAgICAgICAgICA/IFsnaW50ZXJuYWwnXVxuICAgICAgICAgICAgICAgIDogWydpbnRlcm5hbCcsICd1c2InLCAnbmZjJywgJ2JsZSddO1xuXG4gICAgICAgIC8vIEJ1aWxkIGF1dGhlbnRpY2F0aW9uIG9wdGlvbnMgd2l0aCBQUkYgZXh0ZW5zaW9uXG4gICAgICAgIGNvbnN0IHB1YmxpY0tleUNyZWRlbnRpYWxSZXF1ZXN0T3B0aW9uczogUHVibGljS2V5Q3JlZGVudGlhbFJlcXVlc3RPcHRpb25zID0ge1xuICAgICAgICAgICAgY2hhbGxlbmdlOiBjcnlwdG8uZ2V0UmFuZG9tVmFsdWVzKG5ldyBVaW50OEFycmF5KDMyKSksXG4gICAgICAgICAgICBhbGxvd0NyZWRlbnRpYWxzOiBbXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICBpZDogY3JlZGVudGlhbElkLFxuICAgICAgICAgICAgICAgICAgICB0eXBlOiAncHVibGljLWtleScsXG4gICAgICAgICAgICAgICAgICAgIHRyYW5zcG9ydHNcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICBdLFxuICAgICAgICAgICAgdGltZW91dDogb3B0aW9ucy50aW1lb3V0TXMsXG4gICAgICAgICAgICB1c2VyVmVyaWZpY2F0aW9uOiAncmVxdWlyZWQnLFxuICAgICAgICAgICAgZXh0ZW5zaW9uczoge1xuICAgICAgICAgICAgICAgIHByZjoge1xuICAgICAgICAgICAgICAgICAgICBldmFsOiB7XG4gICAgICAgICAgICAgICAgICAgICAgICBmaXJzdDogc2FsdEhhc2guYnVmZmVyIGFzIEFycmF5QnVmZmVyXG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9IGFzIEF1dGhlbnRpY2F0aW9uRXh0ZW5zaW9uc0NsaWVudElucHV0c1xuICAgICAgICB9O1xuXG4gICAgICAgIC8vIFBlcmZvcm0gYXV0aGVudGljYXRpb24gd2l0aCBQUkYgZXZhbHVhdGlvblxuICAgICAgICBjb25zdCBhc3NlcnRpb24gPSBhd2FpdCBuYXZpZ2F0b3IuY3JlZGVudGlhbHMuZ2V0KHtcbiAgICAgICAgICAgIHB1YmxpY0tleTogcHVibGljS2V5Q3JlZGVudGlhbFJlcXVlc3RPcHRpb25zXG4gICAgICAgIH0pIGFzIFB1YmxpY0tleUNyZWRlbnRpYWwgfCBudWxsO1xuXG4gICAgICAgIGlmIChhc3NlcnRpb24gPT09IG51bGwpIHtcbiAgICAgICAgICAgIHJldHVybiB7XG4gICAgICAgICAgICAgICAgc3VjY2VzczogZmFsc2UsXG4gICAgICAgICAgICAgICAgY2FuY2VsbGVkOiB0cnVlXG4gICAgICAgICAgICB9O1xuICAgICAgICB9XG5cbiAgICAgICAgLy8gRXh0cmFjdCBQUkYgcmVzdWx0c1xuICAgICAgICBjb25zdCBleHRlbnNpb25SZXN1bHRzID0gYXNzZXJ0aW9uLmdldENsaWVudEV4dGVuc2lvblJlc3VsdHMoKSBhcyB7XG4gICAgICAgICAgICBwcmY/OiB7XG4gICAgICAgICAgICAgICAgcmVzdWx0cz86IHtcbiAgICAgICAgICAgICAgICAgICAgZmlyc3Q/OiBBcnJheUJ1ZmZlcjtcbiAgICAgICAgICAgICAgICB9O1xuICAgICAgICAgICAgfTtcbiAgICAgICAgfTtcblxuICAgICAgICBjb25zdCBwcmZSZXN1bHRzID0gZXh0ZW5zaW9uUmVzdWx0cy5wcmY/LnJlc3VsdHM7XG5cbiAgICAgICAgaWYgKCFwcmZSZXN1bHRzPy5maXJzdCkge1xuICAgICAgICAgICAgcmV0dXJuIHtcbiAgICAgICAgICAgICAgICBzdWNjZXNzOiBmYWxzZSxcbiAgICAgICAgICAgICAgICBlcnJvckNvZGU6IFByZkVycm9yQ29kZS5QcmZOb3RTdXBwb3J0ZWRcbiAgICAgICAgICAgIH07XG4gICAgICAgIH1cblxuICAgICAgICAvLyBDb252ZXJ0IHRvIFVpbnQ4QXJyYXlcbiAgICAgICAgcHJmT3V0cHV0ID0gbmV3IFVpbnQ4QXJyYXkocHJmUmVzdWx0cy5maXJzdCk7XG5cbiAgICAgICAgaWYgKHByZk91dHB1dC5sZW5ndGggIT09IDMyKSB7XG4gICAgICAgICAgICByZXR1cm4ge1xuICAgICAgICAgICAgICAgIHN1Y2Nlc3M6IGZhbHNlLFxuICAgICAgICAgICAgICAgIGVycm9yQ29kZTogUHJmRXJyb3JDb2RlLktleURlcml2YXRpb25GYWlsZWRcbiAgICAgICAgICAgIH07XG4gICAgICAgIH1cblxuICAgICAgICAvLyBDb252ZXJ0IHRvIEJhc2U2NCBmb3IgdHJhbnNmZXIgdG8gQyNcbiAgICAgICAgY29uc3QgcmVzdWx0QmFzZTY0ID0gdG9CYXNlNjQocHJmT3V0cHV0KTtcblxuICAgICAgICByZXR1cm4ge1xuICAgICAgICAgICAgc3VjY2VzczogdHJ1ZSxcbiAgICAgICAgICAgIHZhbHVlOiByZXN1bHRCYXNlNjRcbiAgICAgICAgfTtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgICAvLyBVc2VyIGNhbmNlbGxlZCB0aGUgYXV0aGVudGljYXRpb24gLSBub3QgYW4gZXJyb3JcbiAgICAgICAgaWYgKGVycm9yIGluc3RhbmNlb2YgRE9NRXhjZXB0aW9uICYmIGVycm9yLm5hbWUgPT09ICdOb3RBbGxvd2VkRXJyb3InKSB7XG4gICAgICAgICAgICByZXR1cm4ge1xuICAgICAgICAgICAgICAgIHN1Y2Nlc3M6IGZhbHNlLFxuICAgICAgICAgICAgICAgIGNhbmNlbGxlZDogdHJ1ZVxuICAgICAgICAgICAgfTtcbiAgICAgICAgfVxuXG4gICAgICAgIHJldHVybiB7XG4gICAgICAgICAgICBzdWNjZXNzOiBmYWxzZSxcbiAgICAgICAgICAgIGVycm9yQ29kZTogUHJmRXJyb3JDb2RlLktleURlcml2YXRpb25GYWlsZWRcbiAgICAgICAgfTtcbiAgICB9IGZpbmFsbHkge1xuICAgICAgICAvLyBaZXJvIHRoZSBQUkYgb3V0cHV0IGluIEphdmFTY3JpcHQgbWVtb3J5XG4gICAgICAgIC8vIFRoZSBCYXNlNjQgc3RyaW5nIGhhcyBhbHJlYWR5IGJlZW4gY3JlYXRlZCBmb3IgQyMgdHJhbnNmZXJcbiAgICAgICAgaWYgKHByZk91dHB1dCkge1xuICAgICAgICAgICAgemVyb0ZpbGwocHJmT3V0cHV0KTtcbiAgICAgICAgfVxuICAgIH1cbn1cblxuLyoqXG4gKiBFdmFsdWF0ZSBQUkYgd2l0aG91dCBhIHNwZWNpZmljIGNyZWRlbnRpYWwgSUQgKGRpc2NvdmVyYWJsZSBjcmVkZW50aWFsKS5cbiAqIFRoZSBhdXRoZW50aWNhdG9yIHdpbGwgcHJvbXB0IHRoZSB1c2VyIHRvIHNlbGVjdCBhIGNyZWRlbnRpYWwuXG4gKlxuICogQHBhcmFtIHNhbHQgQSBzdHJpbmcgc2FsdCB0aGF0IGRldGVybWluZXMgdGhlIGRlcml2ZWQga2V5XG4gKiBAcGFyYW0gb3B0aW9ucyBQUkYgY29uZmlndXJhdGlvbiBvcHRpb25zXG4gKiBAcmV0dXJucyBQcmZSZXN1bHQgY29udGFpbmluZyB0aGUgY3JlZGVudGlhbCBJRCBhbmQgMzItYnl0ZSBQUkYgb3V0cHV0IGFzIEJhc2U2NFxuICovXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZXZhbHVhdGVQcmZEaXNjb3ZlcmFibGUoXG4gICAgc2FsdDogc3RyaW5nLFxuICAgIG9wdGlvbnM6IFByZk9wdGlvbnNcbik6IFByb21pc2U8UHJmUmVzdWx0PHsgY3JlZGVudGlhbElkOiBzdHJpbmc7IHByZk91dHB1dDogc3RyaW5nIH0+PiB7XG4gICAgbGV0IHByZk91dHB1dDogVWludDhBcnJheSB8IG51bGwgPSBudWxsO1xuXG4gICAgdHJ5IHtcbiAgICAgICAgLy8gSGFzaCB0aGUgc2FsdCB0byBlbnN1cmUgY29uc2lzdGVudCAzMi1ieXRlIGxlbmd0aFxuICAgICAgICBjb25zdCBlbmNvZGVyID0gbmV3IFRleHRFbmNvZGVyKCk7XG4gICAgICAgIGNvbnN0IHNhbHRCeXRlcyA9IGVuY29kZXIuZW5jb2RlKHNhbHQpO1xuICAgICAgICBjb25zdCBzYWx0SGFzaCA9IHNoYTI1NihzYWx0Qnl0ZXMpO1xuXG4gICAgICAgIC8vIEJ1aWxkIGF1dGhlbnRpY2F0aW9uIG9wdGlvbnMgd2l0aG91dCBhbGxvd0NyZWRlbnRpYWxzIChkaXNjb3ZlcmFibGUpXG4gICAgICAgIGNvbnN0IHB1YmxpY0tleUNyZWRlbnRpYWxSZXF1ZXN0T3B0aW9uczogUHVibGljS2V5Q3JlZGVudGlhbFJlcXVlc3RPcHRpb25zID0ge1xuICAgICAgICAgICAgY2hhbGxlbmdlOiBjcnlwdG8uZ2V0UmFuZG9tVmFsdWVzKG5ldyBVaW50OEFycmF5KDMyKSksXG4gICAgICAgICAgICBycElkOiBvcHRpb25zLnJwSWQgPz8gd2luZG93LmxvY2F0aW9uLmhvc3RuYW1lLFxuICAgICAgICAgICAgdGltZW91dDogb3B0aW9ucy50aW1lb3V0TXMsXG4gICAgICAgICAgICB1c2VyVmVyaWZpY2F0aW9uOiAncmVxdWlyZWQnLFxuICAgICAgICAgICAgZXh0ZW5zaW9uczoge1xuICAgICAgICAgICAgICAgIHByZjoge1xuICAgICAgICAgICAgICAgICAgICBldmFsOiB7XG4gICAgICAgICAgICAgICAgICAgICAgICBmaXJzdDogc2FsdEhhc2guYnVmZmVyIGFzIEFycmF5QnVmZmVyXG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9IGFzIEF1dGhlbnRpY2F0aW9uRXh0ZW5zaW9uc0NsaWVudElucHV0c1xuICAgICAgICB9O1xuXG4gICAgICAgIC8vIFBlcmZvcm0gYXV0aGVudGljYXRpb24gd2l0aCBQUkYgZXZhbHVhdGlvblxuICAgICAgICBjb25zdCBhc3NlcnRpb24gPSBhd2FpdCBuYXZpZ2F0b3IuY3JlZGVudGlhbHMuZ2V0KHtcbiAgICAgICAgICAgIHB1YmxpY0tleTogcHVibGljS2V5Q3JlZGVudGlhbFJlcXVlc3RPcHRpb25zXG4gICAgICAgIH0pIGFzIFB1YmxpY0tleUNyZWRlbnRpYWwgfCBudWxsO1xuXG4gICAgICAgIGlmIChhc3NlcnRpb24gPT09IG51bGwpIHtcbiAgICAgICAgICAgIHJldHVybiB7XG4gICAgICAgICAgICAgICAgc3VjY2VzczogZmFsc2UsXG4gICAgICAgICAgICAgICAgY2FuY2VsbGVkOiB0cnVlXG4gICAgICAgICAgICB9O1xuICAgICAgICB9XG5cbiAgICAgICAgLy8gRXh0cmFjdCBQUkYgcmVzdWx0c1xuICAgICAgICBjb25zdCBleHRlbnNpb25SZXN1bHRzID0gYXNzZXJ0aW9uLmdldENsaWVudEV4dGVuc2lvblJlc3VsdHMoKSBhcyB7XG4gICAgICAgICAgICBwcmY/OiB7XG4gICAgICAgICAgICAgICAgcmVzdWx0cz86IHtcbiAgICAgICAgICAgICAgICAgICAgZmlyc3Q/OiBBcnJheUJ1ZmZlcjtcbiAgICAgICAgICAgICAgICB9O1xuICAgICAgICAgICAgfTtcbiAgICAgICAgfTtcblxuICAgICAgICBjb25zdCBwcmZSZXN1bHRzID0gZXh0ZW5zaW9uUmVzdWx0cy5wcmY/LnJlc3VsdHM7XG5cbiAgICAgICAgaWYgKCFwcmZSZXN1bHRzPy5maXJzdCkge1xuICAgICAgICAgICAgcmV0dXJuIHtcbiAgICAgICAgICAgICAgICBzdWNjZXNzOiBmYWxzZSxcbiAgICAgICAgICAgICAgICBlcnJvckNvZGU6IFByZkVycm9yQ29kZS5QcmZOb3RTdXBwb3J0ZWRcbiAgICAgICAgICAgIH07XG4gICAgICAgIH1cblxuICAgICAgICAvLyBDb252ZXJ0IHRvIFVpbnQ4QXJyYXlcbiAgICAgICAgcHJmT3V0cHV0ID0gbmV3IFVpbnQ4QXJyYXkocHJmUmVzdWx0cy5maXJzdCk7XG5cbiAgICAgICAgaWYgKHByZk91dHB1dC5sZW5ndGggIT09IDMyKSB7XG4gICAgICAgICAgICByZXR1cm4ge1xuICAgICAgICAgICAgICAgIHN1Y2Nlc3M6IGZhbHNlLFxuICAgICAgICAgICAgICAgIGVycm9yQ29kZTogUHJmRXJyb3JDb2RlLktleURlcml2YXRpb25GYWlsZWRcbiAgICAgICAgICAgIH07XG4gICAgICAgIH1cblxuICAgICAgICAvLyBDb252ZXJ0IHRvIEJhc2U2NCBmb3IgdHJhbnNmZXIgdG8gQyNcbiAgICAgICAgY29uc3QgcmVzdWx0QmFzZTY0ID0gdG9CYXNlNjQocHJmT3V0cHV0KTtcbiAgICAgICAgY29uc3QgY3JlZGVudGlhbElkQmFzZTY0ID0gdG9CYXNlNjQobmV3IFVpbnQ4QXJyYXkoYXNzZXJ0aW9uLnJhd0lkKSk7XG5cbiAgICAgICAgcmV0dXJuIHtcbiAgICAgICAgICAgIHN1Y2Nlc3M6IHRydWUsXG4gICAgICAgICAgICB2YWx1ZToge1xuICAgICAgICAgICAgICAgIGNyZWRlbnRpYWxJZDogY3JlZGVudGlhbElkQmFzZTY0LFxuICAgICAgICAgICAgICAgIHByZk91dHB1dDogcmVzdWx0QmFzZTY0XG4gICAgICAgICAgICB9XG4gICAgICAgIH07XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgICAgLy8gVXNlciBjYW5jZWxsZWQgdGhlIGF1dGhlbnRpY2F0aW9uIC0gbm90IGFuIGVycm9yXG4gICAgICAgIGlmIChlcnJvciBpbnN0YW5jZW9mIERPTUV4Y2VwdGlvbiAmJiBlcnJvci5uYW1lID09PSAnTm90QWxsb3dlZEVycm9yJykge1xuICAgICAgICAgICAgcmV0dXJuIHtcbiAgICAgICAgICAgICAgICBzdWNjZXNzOiBmYWxzZSxcbiAgICAgICAgICAgICAgICBjYW5jZWxsZWQ6IHRydWVcbiAgICAgICAgICAgIH07XG4gICAgICAgIH1cblxuICAgICAgICByZXR1cm4ge1xuICAgICAgICAgICAgc3VjY2VzczogZmFsc2UsXG4gICAgICAgICAgICBlcnJvckNvZGU6IFByZkVycm9yQ29kZS5LZXlEZXJpdmF0aW9uRmFpbGVkXG4gICAgICAgIH07XG4gICAgfSBmaW5hbGx5IHtcbiAgICAgICAgLy8gWmVybyB0aGUgUFJGIG91dHB1dCBpbiBKYXZhU2NyaXB0IG1lbW9yeVxuICAgICAgICBpZiAocHJmT3V0cHV0KSB7XG4gICAgICAgICAgICB6ZXJvRmlsbChwcmZPdXRwdXQpO1xuICAgICAgICB9XG4gICAgfVxufVxuIiwgIi8qKlxuICogSGV4LCBieXRlcyBhbmQgbnVtYmVyIHV0aWxpdGllcy5cbiAqIEBtb2R1bGVcbiAqL1xuLyohIG5vYmxlLWN1cnZlcyAtIE1JVCBMaWNlbnNlIChjKSAyMDIyIFBhdWwgTWlsbGVyIChwYXVsbWlsbHIuY29tKSAqL1xuaW1wb3J0IHtcbiAgYWJ5dGVzIGFzIGFieXRlc18sXG4gIGJ5dGVzVG9IZXggYXMgYnl0ZXNUb0hleF8sXG4gIGNvbmNhdEJ5dGVzIGFzIGNvbmNhdEJ5dGVzXyxcbiAgaGV4VG9CeXRlcyBhcyBoZXhUb0J5dGVzXyxcbiAgaXNCeXRlcyBhcyBpc0J5dGVzXyxcbn0gZnJvbSAnQG5vYmxlL2hhc2hlcy91dGlscy5qcyc7XG5leHBvcnQge1xuICBhYnl0ZXMsXG4gIGFudW1iZXIsXG4gIGJ5dGVzVG9IZXgsXG4gIGJ5dGVzVG9VdGY4LFxuICBjb25jYXRCeXRlcyxcbiAgaGV4VG9CeXRlcyxcbiAgaXNCeXRlcyxcbiAgcmFuZG9tQnl0ZXMsXG4gIHV0ZjhUb0J5dGVzLFxufSBmcm9tICdAbm9ibGUvaGFzaGVzL3V0aWxzLmpzJztcbmNvbnN0IF8wbiA9IC8qIEBfX1BVUkVfXyAqLyBCaWdJbnQoMCk7XG5jb25zdCBfMW4gPSAvKiBAX19QVVJFX18gKi8gQmlnSW50KDEpO1xuZXhwb3J0IHR5cGUgSGV4ID0gVWludDhBcnJheSB8IHN0cmluZzsgLy8gaGV4IHN0cmluZ3MgYXJlIGFjY2VwdGVkIGZvciBzaW1wbGljaXR5XG5leHBvcnQgdHlwZSBQcml2S2V5ID0gSGV4IHwgYmlnaW50OyAvLyBiaWdpbnRzIGFyZSBhY2NlcHRlZCB0byBlYXNlIGxlYXJuaW5nIGN1cnZlXG5leHBvcnQgdHlwZSBDSGFzaCA9IHtcbiAgKG1lc3NhZ2U6IFVpbnQ4QXJyYXkgfCBzdHJpbmcpOiBVaW50OEFycmF5O1xuICBibG9ja0xlbjogbnVtYmVyO1xuICBvdXRwdXRMZW46IG51bWJlcjtcbiAgY3JlYXRlKG9wdHM/OiB7IGRrTGVuPzogbnVtYmVyIH0pOiBhbnk7IC8vIEZvciBzaGFrZVxufTtcbmV4cG9ydCB0eXBlIEZIYXNoID0gKG1lc3NhZ2U6IFVpbnQ4QXJyYXkgfCBzdHJpbmcpID0+IFVpbnQ4QXJyYXk7XG5cbmV4cG9ydCBmdW5jdGlvbiBhYm9vbCh0aXRsZTogc3RyaW5nLCB2YWx1ZTogYm9vbGVhbik6IHZvaWQge1xuICBpZiAodHlwZW9mIHZhbHVlICE9PSAnYm9vbGVhbicpIHRocm93IG5ldyBFcnJvcih0aXRsZSArICcgYm9vbGVhbiBleHBlY3RlZCwgZ290ICcgKyB2YWx1ZSk7XG59XG5cbi8vIHRtcCBuYW1lIHVudGlsIHYyXG5leHBvcnQgZnVuY3Rpb24gX2Fib29sMih2YWx1ZTogYm9vbGVhbiwgdGl0bGU6IHN0cmluZyA9ICcnKTogYm9vbGVhbiB7XG4gIGlmICh0eXBlb2YgdmFsdWUgIT09ICdib29sZWFuJykge1xuICAgIGNvbnN0IHByZWZpeCA9IHRpdGxlICYmIGBcIiR7dGl0bGV9XCJgO1xuICAgIHRocm93IG5ldyBFcnJvcihwcmVmaXggKyAnZXhwZWN0ZWQgYm9vbGVhbiwgZ290IHR5cGU9JyArIHR5cGVvZiB2YWx1ZSk7XG4gIH1cbiAgcmV0dXJuIHZhbHVlO1xufVxuXG4vLyB0bXAgbmFtZSB1bnRpbCB2MlxuLyoqIEFzc2VydHMgc29tZXRoaW5nIGlzIFVpbnQ4QXJyYXkuICovXG5leHBvcnQgZnVuY3Rpb24gX2FieXRlczIodmFsdWU6IFVpbnQ4QXJyYXksIGxlbmd0aD86IG51bWJlciwgdGl0bGU6IHN0cmluZyA9ICcnKTogVWludDhBcnJheSB7XG4gIGNvbnN0IGJ5dGVzID0gaXNCeXRlc18odmFsdWUpO1xuICBjb25zdCBsZW4gPSB2YWx1ZT8ubGVuZ3RoO1xuICBjb25zdCBuZWVkc0xlbiA9IGxlbmd0aCAhPT0gdW5kZWZpbmVkO1xuICBpZiAoIWJ5dGVzIHx8IChuZWVkc0xlbiAmJiBsZW4gIT09IGxlbmd0aCkpIHtcbiAgICBjb25zdCBwcmVmaXggPSB0aXRsZSAmJiBgXCIke3RpdGxlfVwiIGA7XG4gICAgY29uc3Qgb2ZMZW4gPSBuZWVkc0xlbiA/IGAgb2YgbGVuZ3RoICR7bGVuZ3RofWAgOiAnJztcbiAgICBjb25zdCBnb3QgPSBieXRlcyA/IGBsZW5ndGg9JHtsZW59YCA6IGB0eXBlPSR7dHlwZW9mIHZhbHVlfWA7XG4gICAgdGhyb3cgbmV3IEVycm9yKHByZWZpeCArICdleHBlY3RlZCBVaW50OEFycmF5JyArIG9mTGVuICsgJywgZ290ICcgKyBnb3QpO1xuICB9XG4gIHJldHVybiB2YWx1ZTtcbn1cblxuLy8gVXNlZCBpbiB3ZWllcnN0cmFzcywgZGVyXG5leHBvcnQgZnVuY3Rpb24gbnVtYmVyVG9IZXhVbnBhZGRlZChudW06IG51bWJlciB8IGJpZ2ludCk6IHN0cmluZyB7XG4gIGNvbnN0IGhleCA9IG51bS50b1N0cmluZygxNik7XG4gIHJldHVybiBoZXgubGVuZ3RoICYgMSA/ICcwJyArIGhleCA6IGhleDtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIGhleFRvTnVtYmVyKGhleDogc3RyaW5nKTogYmlnaW50IHtcbiAgaWYgKHR5cGVvZiBoZXggIT09ICdzdHJpbmcnKSB0aHJvdyBuZXcgRXJyb3IoJ2hleCBzdHJpbmcgZXhwZWN0ZWQsIGdvdCAnICsgdHlwZW9mIGhleCk7XG4gIHJldHVybiBoZXggPT09ICcnID8gXzBuIDogQmlnSW50KCcweCcgKyBoZXgpOyAvLyBCaWcgRW5kaWFuXG59XG5cbi8vIEJFOiBCaWcgRW5kaWFuLCBMRTogTGl0dGxlIEVuZGlhblxuZXhwb3J0IGZ1bmN0aW9uIGJ5dGVzVG9OdW1iZXJCRShieXRlczogVWludDhBcnJheSk6IGJpZ2ludCB7XG4gIHJldHVybiBoZXhUb051bWJlcihieXRlc1RvSGV4XyhieXRlcykpO1xufVxuZXhwb3J0IGZ1bmN0aW9uIGJ5dGVzVG9OdW1iZXJMRShieXRlczogVWludDhBcnJheSk6IGJpZ2ludCB7XG4gIGFieXRlc18oYnl0ZXMpO1xuICByZXR1cm4gaGV4VG9OdW1iZXIoYnl0ZXNUb0hleF8oVWludDhBcnJheS5mcm9tKGJ5dGVzKS5yZXZlcnNlKCkpKTtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIG51bWJlclRvQnl0ZXNCRShuOiBudW1iZXIgfCBiaWdpbnQsIGxlbjogbnVtYmVyKTogVWludDhBcnJheSB7XG4gIHJldHVybiBoZXhUb0J5dGVzXyhuLnRvU3RyaW5nKDE2KS5wYWRTdGFydChsZW4gKiAyLCAnMCcpKTtcbn1cbmV4cG9ydCBmdW5jdGlvbiBudW1iZXJUb0J5dGVzTEUobjogbnVtYmVyIHwgYmlnaW50LCBsZW46IG51bWJlcik6IFVpbnQ4QXJyYXkge1xuICByZXR1cm4gbnVtYmVyVG9CeXRlc0JFKG4sIGxlbikucmV2ZXJzZSgpO1xufVxuLy8gVW5wYWRkZWQsIHJhcmVseSB1c2VkXG5leHBvcnQgZnVuY3Rpb24gbnVtYmVyVG9WYXJCeXRlc0JFKG46IG51bWJlciB8IGJpZ2ludCk6IFVpbnQ4QXJyYXkge1xuICByZXR1cm4gaGV4VG9CeXRlc18obnVtYmVyVG9IZXhVbnBhZGRlZChuKSk7XG59XG5cbi8qKlxuICogVGFrZXMgaGV4IHN0cmluZyBvciBVaW50OEFycmF5LCBjb252ZXJ0cyB0byBVaW50OEFycmF5LlxuICogVmFsaWRhdGVzIG91dHB1dCBsZW5ndGguXG4gKiBXaWxsIHRocm93IGVycm9yIGZvciBvdGhlciB0eXBlcy5cbiAqIEBwYXJhbSB0aXRsZSBkZXNjcmlwdGl2ZSB0aXRsZSBmb3IgYW4gZXJyb3IgZS5nLiAnc2VjcmV0IGtleSdcbiAqIEBwYXJhbSBoZXggaGV4IHN0cmluZyBvciBVaW50OEFycmF5XG4gKiBAcGFyYW0gZXhwZWN0ZWRMZW5ndGggb3B0aW9uYWwsIHdpbGwgY29tcGFyZSB0byByZXN1bHQgYXJyYXkncyBsZW5ndGhcbiAqIEByZXR1cm5zXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBlbnN1cmVCeXRlcyh0aXRsZTogc3RyaW5nLCBoZXg6IEhleCwgZXhwZWN0ZWRMZW5ndGg/OiBudW1iZXIpOiBVaW50OEFycmF5IHtcbiAgbGV0IHJlczogVWludDhBcnJheTtcbiAgaWYgKHR5cGVvZiBoZXggPT09ICdzdHJpbmcnKSB7XG4gICAgdHJ5IHtcbiAgICAgIHJlcyA9IGhleFRvQnl0ZXNfKGhleCk7XG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKHRpdGxlICsgJyBtdXN0IGJlIGhleCBzdHJpbmcgb3IgVWludDhBcnJheSwgY2F1c2U6ICcgKyBlKTtcbiAgICB9XG4gIH0gZWxzZSBpZiAoaXNCeXRlc18oaGV4KSkge1xuICAgIC8vIFVpbnQ4QXJyYXkuZnJvbSgpIGluc3RlYWQgb2YgaGFzaC5zbGljZSgpIGJlY2F1c2Ugbm9kZS5qcyBCdWZmZXJcbiAgICAvLyBpcyBpbnN0YW5jZSBvZiBVaW50OEFycmF5LCBhbmQgaXRzIHNsaWNlKCkgY3JlYXRlcyAqKm11dGFibGUqKiBjb3B5XG4gICAgcmVzID0gVWludDhBcnJheS5mcm9tKGhleCk7XG4gIH0gZWxzZSB7XG4gICAgdGhyb3cgbmV3IEVycm9yKHRpdGxlICsgJyBtdXN0IGJlIGhleCBzdHJpbmcgb3IgVWludDhBcnJheScpO1xuICB9XG4gIGNvbnN0IGxlbiA9IHJlcy5sZW5ndGg7XG4gIGlmICh0eXBlb2YgZXhwZWN0ZWRMZW5ndGggPT09ICdudW1iZXInICYmIGxlbiAhPT0gZXhwZWN0ZWRMZW5ndGgpXG4gICAgdGhyb3cgbmV3IEVycm9yKHRpdGxlICsgJyBvZiBsZW5ndGggJyArIGV4cGVjdGVkTGVuZ3RoICsgJyBleHBlY3RlZCwgZ290ICcgKyBsZW4pO1xuICByZXR1cm4gcmVzO1xufVxuXG4vLyBDb21wYXJlcyAyIHU4YS1zIGluIGtpbmRhIGNvbnN0YW50IHRpbWVcbmV4cG9ydCBmdW5jdGlvbiBlcXVhbEJ5dGVzKGE6IFVpbnQ4QXJyYXksIGI6IFVpbnQ4QXJyYXkpOiBib29sZWFuIHtcbiAgaWYgKGEubGVuZ3RoICE9PSBiLmxlbmd0aCkgcmV0dXJuIGZhbHNlO1xuICBsZXQgZGlmZiA9IDA7XG4gIGZvciAobGV0IGkgPSAwOyBpIDwgYS5sZW5ndGg7IGkrKykgZGlmZiB8PSBhW2ldIF4gYltpXTtcbiAgcmV0dXJuIGRpZmYgPT09IDA7XG59XG4vKipcbiAqIENvcGllcyBVaW50OEFycmF5LiBXZSBjYW4ndCB1c2UgdThhLnNsaWNlKCksIGJlY2F1c2UgdThhIGNhbiBiZSBCdWZmZXIsXG4gKiBhbmQgQnVmZmVyI3NsaWNlIGNyZWF0ZXMgbXV0YWJsZSBjb3B5LiBOZXZlciB1c2UgQnVmZmVycyFcbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGNvcHlCeXRlcyhieXRlczogVWludDhBcnJheSk6IFVpbnQ4QXJyYXkge1xuICByZXR1cm4gVWludDhBcnJheS5mcm9tKGJ5dGVzKTtcbn1cblxuLyoqXG4gKiBEZWNvZGVzIDctYml0IEFTQ0lJIHN0cmluZyB0byBVaW50OEFycmF5LCB0aHJvd3Mgb24gbm9uLWFzY2lpIHN5bWJvbHNcbiAqIFNob3VsZCBiZSBzYWZlIHRvIHVzZSBmb3IgdGhpbmdzIGV4cGVjdGVkIHRvIGJlIEFTQ0lJLlxuICogUmV0dXJucyBleGFjdCBzYW1lIHJlc3VsdCBhcyB1dGY4VG9CeXRlcyBmb3IgQVNDSUkgb3IgdGhyb3dzLlxuICovXG5leHBvcnQgZnVuY3Rpb24gYXNjaWlUb0J5dGVzKGFzY2lpOiBzdHJpbmcpOiBVaW50OEFycmF5IHtcbiAgcmV0dXJuIFVpbnQ4QXJyYXkuZnJvbShhc2NpaSwgKGMsIGkpID0+IHtcbiAgICBjb25zdCBjaGFyQ29kZSA9IGMuY2hhckNvZGVBdCgwKTtcbiAgICBpZiAoYy5sZW5ndGggIT09IDEgfHwgY2hhckNvZGUgPiAxMjcpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcihcbiAgICAgICAgYHN0cmluZyBjb250YWlucyBub24tQVNDSUkgY2hhcmFjdGVyIFwiJHthc2NpaVtpXX1cIiB3aXRoIGNvZGUgJHtjaGFyQ29kZX0gYXQgcG9zaXRpb24gJHtpfWBcbiAgICAgICk7XG4gICAgfVxuICAgIHJldHVybiBjaGFyQ29kZTtcbiAgfSk7XG59XG5cbi8qKlxuICogQGV4YW1wbGUgdXRmOFRvQnl0ZXMoJ2FiYycpIC8vIG5ldyBVaW50OEFycmF5KFs5NywgOTgsIDk5XSlcbiAqL1xuLy8gZXhwb3J0IGNvbnN0IHV0ZjhUb0J5dGVzOiB0eXBlb2YgdXRmOFRvQnl0ZXNfID0gdXRmOFRvQnl0ZXNfO1xuLyoqXG4gKiBDb252ZXJ0cyBieXRlcyB0byBzdHJpbmcgdXNpbmcgVVRGOCBlbmNvZGluZy5cbiAqIEBleGFtcGxlIGJ5dGVzVG9VdGY4KFVpbnQ4QXJyYXkuZnJvbShbOTcsIDk4LCA5OV0pKSAvLyAnYWJjJ1xuICovXG4vLyBleHBvcnQgY29uc3QgYnl0ZXNUb1V0Zjg6IHR5cGVvZiBieXRlc1RvVXRmOF8gPSBieXRlc1RvVXRmOF87XG5cbi8vIElzIHBvc2l0aXZlIGJpZ2ludFxuY29uc3QgaXNQb3NCaWcgPSAobjogYmlnaW50KSA9PiB0eXBlb2YgbiA9PT0gJ2JpZ2ludCcgJiYgXzBuIDw9IG47XG5cbmV4cG9ydCBmdW5jdGlvbiBpblJhbmdlKG46IGJpZ2ludCwgbWluOiBiaWdpbnQsIG1heDogYmlnaW50KTogYm9vbGVhbiB7XG4gIHJldHVybiBpc1Bvc0JpZyhuKSAmJiBpc1Bvc0JpZyhtaW4pICYmIGlzUG9zQmlnKG1heCkgJiYgbWluIDw9IG4gJiYgbiA8IG1heDtcbn1cblxuLyoqXG4gKiBBc3NlcnRzIG1pbiA8PSBuIDwgbWF4LiBOT1RFOiBJdCdzIDwgbWF4IGFuZCBub3QgPD0gbWF4LlxuICogQGV4YW1wbGVcbiAqIGFJblJhbmdlKCd4JywgeCwgMW4sIDI1Nm4pOyAvLyB3b3VsZCBhc3N1bWUgeCBpcyBpbiAoMW4uLjI1NW4pXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBhSW5SYW5nZSh0aXRsZTogc3RyaW5nLCBuOiBiaWdpbnQsIG1pbjogYmlnaW50LCBtYXg6IGJpZ2ludCk6IHZvaWQge1xuICAvLyBXaHkgbWluIDw9IG4gPCBtYXggYW5kIG5vdCBhIChtaW4gPCBuIDwgbWF4KSBPUiBiIChtaW4gPD0gbiA8PSBtYXgpP1xuICAvLyBjb25zaWRlciBQPTI1Nm4sIG1pbj0wbiwgbWF4PVBcbiAgLy8gLSBhIGZvciBtaW49MCB3b3VsZCByZXF1aXJlIC0xOiAgICAgICAgICBgaW5SYW5nZSgneCcsIHgsIC0xbiwgUClgXG4gIC8vIC0gYiB3b3VsZCBjb21tb25seSByZXF1aXJlIHN1YnRyYWN0aW9uOiAgYGluUmFuZ2UoJ3gnLCB4LCAwbiwgUCAtIDFuKWBcbiAgLy8gLSBvdXIgd2F5IGlzIHRoZSBjbGVhbmVzdDogICAgICAgICAgICAgICBgaW5SYW5nZSgneCcsIHgsIDBuLCBQKVxuICBpZiAoIWluUmFuZ2UobiwgbWluLCBtYXgpKVxuICAgIHRocm93IG5ldyBFcnJvcignZXhwZWN0ZWQgdmFsaWQgJyArIHRpdGxlICsgJzogJyArIG1pbiArICcgPD0gbiA8ICcgKyBtYXggKyAnLCBnb3QgJyArIG4pO1xufVxuXG4vLyBCaXQgb3BlcmF0aW9uc1xuXG4vKipcbiAqIENhbGN1bGF0ZXMgYW1vdW50IG9mIGJpdHMgaW4gYSBiaWdpbnQuXG4gKiBTYW1lIGFzIGBuLnRvU3RyaW5nKDIpLmxlbmd0aGBcbiAqIFRPRE86IG1lcmdlIHdpdGggbkxlbmd0aCBpbiBtb2R1bGFyXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBiaXRMZW4objogYmlnaW50KTogbnVtYmVyIHtcbiAgbGV0IGxlbjtcbiAgZm9yIChsZW4gPSAwOyBuID4gXzBuOyBuID4+PSBfMW4sIGxlbiArPSAxKTtcbiAgcmV0dXJuIGxlbjtcbn1cblxuLyoqXG4gKiBHZXRzIHNpbmdsZSBiaXQgYXQgcG9zaXRpb24uXG4gKiBOT1RFOiBmaXJzdCBiaXQgcG9zaXRpb24gaXMgMCAoc2FtZSBhcyBhcnJheXMpXG4gKiBTYW1lIGFzIGAhIStBcnJheS5mcm9tKG4udG9TdHJpbmcoMikpLnJldmVyc2UoKVtwb3NdYFxuICovXG5leHBvcnQgZnVuY3Rpb24gYml0R2V0KG46IGJpZ2ludCwgcG9zOiBudW1iZXIpOiBiaWdpbnQge1xuICByZXR1cm4gKG4gPj4gQmlnSW50KHBvcykpICYgXzFuO1xufVxuXG4vKipcbiAqIFNldHMgc2luZ2xlIGJpdCBhdCBwb3NpdGlvbi5cbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGJpdFNldChuOiBiaWdpbnQsIHBvczogbnVtYmVyLCB2YWx1ZTogYm9vbGVhbik6IGJpZ2ludCB7XG4gIHJldHVybiBuIHwgKCh2YWx1ZSA/IF8xbiA6IF8wbikgPDwgQmlnSW50KHBvcykpO1xufVxuXG4vKipcbiAqIENhbGN1bGF0ZSBtYXNrIGZvciBOIGJpdHMuIE5vdCB1c2luZyAqKiBvcGVyYXRvciB3aXRoIGJpZ2ludHMgYmVjYXVzZSBvZiBvbGQgZW5naW5lcy5cbiAqIFNhbWUgYXMgQmlnSW50KGAwYiR7QXJyYXkoaSkuZmlsbCgnMScpLmpvaW4oJycpfWApXG4gKi9cbmV4cG9ydCBjb25zdCBiaXRNYXNrID0gKG46IG51bWJlcik6IGJpZ2ludCA9PiAoXzFuIDw8IEJpZ0ludChuKSkgLSBfMW47XG5cbi8vIERSQkdcblxudHlwZSBQcmVkPFQ+ID0gKHY6IFVpbnQ4QXJyYXkpID0+IFQgfCB1bmRlZmluZWQ7XG4vKipcbiAqIE1pbmltYWwgSE1BQy1EUkJHIGZyb20gTklTVCA4MDAtOTAgZm9yIFJGQzY5Nzkgc2lncy5cbiAqIEByZXR1cm5zIGZ1bmN0aW9uIHRoYXQgd2lsbCBjYWxsIERSQkcgdW50aWwgMm5kIGFyZyByZXR1cm5zIHNvbWV0aGluZyBtZWFuaW5nZnVsXG4gKiBAZXhhbXBsZVxuICogICBjb25zdCBkcmJnID0gY3JlYXRlSG1hY0RSQkc8S2V5PigzMiwgMzIsIGhtYWMpO1xuICogICBkcmJnKHNlZWQsIGJ5dGVzVG9LZXkpOyAvLyBieXRlc1RvS2V5IG11c3QgcmV0dXJuIEtleSBvciB1bmRlZmluZWRcbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGNyZWF0ZUhtYWNEcmJnPFQ+KFxuICBoYXNoTGVuOiBudW1iZXIsXG4gIHFCeXRlTGVuOiBudW1iZXIsXG4gIGhtYWNGbjogKGtleTogVWludDhBcnJheSwgLi4ubWVzc2FnZXM6IFVpbnQ4QXJyYXlbXSkgPT4gVWludDhBcnJheVxuKTogKHNlZWQ6IFVpbnQ4QXJyYXksIHByZWRpY2F0ZTogUHJlZDxUPikgPT4gVCB7XG4gIGlmICh0eXBlb2YgaGFzaExlbiAhPT0gJ251bWJlcicgfHwgaGFzaExlbiA8IDIpIHRocm93IG5ldyBFcnJvcignaGFzaExlbiBtdXN0IGJlIGEgbnVtYmVyJyk7XG4gIGlmICh0eXBlb2YgcUJ5dGVMZW4gIT09ICdudW1iZXInIHx8IHFCeXRlTGVuIDwgMikgdGhyb3cgbmV3IEVycm9yKCdxQnl0ZUxlbiBtdXN0IGJlIGEgbnVtYmVyJyk7XG4gIGlmICh0eXBlb2YgaG1hY0ZuICE9PSAnZnVuY3Rpb24nKSB0aHJvdyBuZXcgRXJyb3IoJ2htYWNGbiBtdXN0IGJlIGEgZnVuY3Rpb24nKTtcbiAgLy8gU3RlcCBCLCBTdGVwIEM6IHNldCBoYXNoTGVuIHRvIDgqY2VpbChobGVuLzgpXG4gIGNvbnN0IHU4biA9IChsZW46IG51bWJlcikgPT4gbmV3IFVpbnQ4QXJyYXkobGVuKTsgLy8gY3JlYXRlcyBVaW50OEFycmF5XG4gIGNvbnN0IHU4b2YgPSAoYnl0ZTogbnVtYmVyKSA9PiBVaW50OEFycmF5Lm9mKGJ5dGUpOyAvLyBhbm90aGVyIHNob3J0Y3V0XG4gIGxldCB2ID0gdThuKGhhc2hMZW4pOyAvLyBNaW5pbWFsIG5vbi1mdWxsLXNwZWMgSE1BQy1EUkJHIGZyb20gTklTVCA4MDAtOTAgZm9yIFJGQzY5Nzkgc2lncy5cbiAgbGV0IGsgPSB1OG4oaGFzaExlbik7IC8vIFN0ZXBzIEIgYW5kIEMgb2YgUkZDNjk3OSAzLjI6IHNldCBoYXNoTGVuLCBpbiBvdXIgY2FzZSBhbHdheXMgc2FtZVxuICBsZXQgaSA9IDA7IC8vIEl0ZXJhdGlvbnMgY291bnRlciwgd2lsbCB0aHJvdyB3aGVuIG92ZXIgMTAwMFxuICBjb25zdCByZXNldCA9ICgpID0+IHtcbiAgICB2LmZpbGwoMSk7XG4gICAgay5maWxsKDApO1xuICAgIGkgPSAwO1xuICB9O1xuICBjb25zdCBoID0gKC4uLmI6IFVpbnQ4QXJyYXlbXSkgPT4gaG1hY0ZuKGssIHYsIC4uLmIpOyAvLyBobWFjKGspKHYsIC4uLnZhbHVlcylcbiAgY29uc3QgcmVzZWVkID0gKHNlZWQgPSB1OG4oMCkpID0+IHtcbiAgICAvLyBITUFDLURSQkcgcmVzZWVkKCkgZnVuY3Rpb24uIFN0ZXBzIEQtR1xuICAgIGsgPSBoKHU4b2YoMHgwMCksIHNlZWQpOyAvLyBrID0gaG1hYyhrIHx8IHYgfHwgMHgwMCB8fCBzZWVkKVxuICAgIHYgPSBoKCk7IC8vIHYgPSBobWFjKGsgfHwgdilcbiAgICBpZiAoc2VlZC5sZW5ndGggPT09IDApIHJldHVybjtcbiAgICBrID0gaCh1OG9mKDB4MDEpLCBzZWVkKTsgLy8gayA9IGhtYWMoayB8fCB2IHx8IDB4MDEgfHwgc2VlZClcbiAgICB2ID0gaCgpOyAvLyB2ID0gaG1hYyhrIHx8IHYpXG4gIH07XG4gIGNvbnN0IGdlbiA9ICgpID0+IHtcbiAgICAvLyBITUFDLURSQkcgZ2VuZXJhdGUoKSBmdW5jdGlvblxuICAgIGlmIChpKysgPj0gMTAwMCkgdGhyb3cgbmV3IEVycm9yKCdkcmJnOiB0cmllZCAxMDAwIHZhbHVlcycpO1xuICAgIGxldCBsZW4gPSAwO1xuICAgIGNvbnN0IG91dDogVWludDhBcnJheVtdID0gW107XG4gICAgd2hpbGUgKGxlbiA8IHFCeXRlTGVuKSB7XG4gICAgICB2ID0gaCgpO1xuICAgICAgY29uc3Qgc2wgPSB2LnNsaWNlKCk7XG4gICAgICBvdXQucHVzaChzbCk7XG4gICAgICBsZW4gKz0gdi5sZW5ndGg7XG4gICAgfVxuICAgIHJldHVybiBjb25jYXRCeXRlc18oLi4ub3V0KTtcbiAgfTtcbiAgY29uc3QgZ2VuVW50aWwgPSAoc2VlZDogVWludDhBcnJheSwgcHJlZDogUHJlZDxUPik6IFQgPT4ge1xuICAgIHJlc2V0KCk7XG4gICAgcmVzZWVkKHNlZWQpOyAvLyBTdGVwcyBELUdcbiAgICBsZXQgcmVzOiBUIHwgdW5kZWZpbmVkID0gdW5kZWZpbmVkOyAvLyBTdGVwIEg6IGdyaW5kIHVudGlsIGsgaXMgaW4gWzEuLm4tMV1cbiAgICB3aGlsZSAoIShyZXMgPSBwcmVkKGdlbigpKSkpIHJlc2VlZCgpO1xuICAgIHJlc2V0KCk7XG4gICAgcmV0dXJuIHJlcztcbiAgfTtcbiAgcmV0dXJuIGdlblVudGlsO1xufVxuXG4vLyBWYWxpZGF0aW5nIGN1cnZlcyBhbmQgZmllbGRzXG5cbmNvbnN0IHZhbGlkYXRvckZucyA9IHtcbiAgYmlnaW50OiAodmFsOiBhbnkpOiBib29sZWFuID0+IHR5cGVvZiB2YWwgPT09ICdiaWdpbnQnLFxuICBmdW5jdGlvbjogKHZhbDogYW55KTogYm9vbGVhbiA9PiB0eXBlb2YgdmFsID09PSAnZnVuY3Rpb24nLFxuICBib29sZWFuOiAodmFsOiBhbnkpOiBib29sZWFuID0+IHR5cGVvZiB2YWwgPT09ICdib29sZWFuJyxcbiAgc3RyaW5nOiAodmFsOiBhbnkpOiBib29sZWFuID0+IHR5cGVvZiB2YWwgPT09ICdzdHJpbmcnLFxuICBzdHJpbmdPclVpbnQ4QXJyYXk6ICh2YWw6IGFueSk6IGJvb2xlYW4gPT4gdHlwZW9mIHZhbCA9PT0gJ3N0cmluZycgfHwgaXNCeXRlc18odmFsKSxcbiAgaXNTYWZlSW50ZWdlcjogKHZhbDogYW55KTogYm9vbGVhbiA9PiBOdW1iZXIuaXNTYWZlSW50ZWdlcih2YWwpLFxuICBhcnJheTogKHZhbDogYW55KTogYm9vbGVhbiA9PiBBcnJheS5pc0FycmF5KHZhbCksXG4gIGZpZWxkOiAodmFsOiBhbnksIG9iamVjdDogYW55KTogYW55ID0+IChvYmplY3QgYXMgYW55KS5GcC5pc1ZhbGlkKHZhbCksXG4gIGhhc2g6ICh2YWw6IGFueSk6IGJvb2xlYW4gPT4gdHlwZW9mIHZhbCA9PT0gJ2Z1bmN0aW9uJyAmJiBOdW1iZXIuaXNTYWZlSW50ZWdlcih2YWwub3V0cHV0TGVuKSxcbn0gYXMgY29uc3Q7XG50eXBlIFZhbGlkYXRvciA9IGtleW9mIHR5cGVvZiB2YWxpZGF0b3JGbnM7XG50eXBlIFZhbE1hcDxUIGV4dGVuZHMgUmVjb3JkPHN0cmluZywgYW55Pj4gPSB7IFtLIGluIGtleW9mIFRdPzogVmFsaWRhdG9yIH07XG4vLyB0eXBlIFJlY29yZDxLIGV4dGVuZHMgc3RyaW5nIHwgbnVtYmVyIHwgc3ltYm9sLCBUPiA9IHsgW1AgaW4gS106IFQ7IH1cblxuZXhwb3J0IGZ1bmN0aW9uIHZhbGlkYXRlT2JqZWN0PFQgZXh0ZW5kcyBSZWNvcmQ8c3RyaW5nLCBhbnk+PihcbiAgb2JqZWN0OiBULFxuICB2YWxpZGF0b3JzOiBWYWxNYXA8VD4sXG4gIG9wdFZhbGlkYXRvcnM6IFZhbE1hcDxUPiA9IHt9XG4pOiBUIHtcbiAgY29uc3QgY2hlY2tGaWVsZCA9IChmaWVsZE5hbWU6IGtleW9mIFQsIHR5cGU6IFZhbGlkYXRvciwgaXNPcHRpb25hbDogYm9vbGVhbikgPT4ge1xuICAgIGNvbnN0IGNoZWNrVmFsID0gdmFsaWRhdG9yRm5zW3R5cGVdO1xuICAgIGlmICh0eXBlb2YgY2hlY2tWYWwgIT09ICdmdW5jdGlvbicpIHRocm93IG5ldyBFcnJvcignaW52YWxpZCB2YWxpZGF0b3IgZnVuY3Rpb24nKTtcblxuICAgIGNvbnN0IHZhbCA9IG9iamVjdFtmaWVsZE5hbWUgYXMga2V5b2YgdHlwZW9mIG9iamVjdF07XG4gICAgaWYgKGlzT3B0aW9uYWwgJiYgdmFsID09PSB1bmRlZmluZWQpIHJldHVybjtcbiAgICBpZiAoIWNoZWNrVmFsKHZhbCwgb2JqZWN0KSkge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKFxuICAgICAgICAncGFyYW0gJyArIFN0cmluZyhmaWVsZE5hbWUpICsgJyBpcyBpbnZhbGlkLiBFeHBlY3RlZCAnICsgdHlwZSArICcsIGdvdCAnICsgdmFsXG4gICAgICApO1xuICAgIH1cbiAgfTtcbiAgZm9yIChjb25zdCBbZmllbGROYW1lLCB0eXBlXSBvZiBPYmplY3QuZW50cmllcyh2YWxpZGF0b3JzKSkgY2hlY2tGaWVsZChmaWVsZE5hbWUsIHR5cGUhLCBmYWxzZSk7XG4gIGZvciAoY29uc3QgW2ZpZWxkTmFtZSwgdHlwZV0gb2YgT2JqZWN0LmVudHJpZXMob3B0VmFsaWRhdG9ycykpIGNoZWNrRmllbGQoZmllbGROYW1lLCB0eXBlISwgdHJ1ZSk7XG4gIHJldHVybiBvYmplY3Q7XG59XG4vLyB2YWxpZGF0ZSB0eXBlIHRlc3RzXG4vLyBjb25zdCBvOiB7IGE6IG51bWJlcjsgYjogbnVtYmVyOyBjOiBudW1iZXIgfSA9IHsgYTogMSwgYjogNSwgYzogNiB9O1xuLy8gY29uc3QgejAgPSB2YWxpZGF0ZU9iamVjdChvLCB7IGE6ICdpc1NhZmVJbnRlZ2VyJyB9LCB7IGM6ICdiaWdpbnQnIH0pOyAvLyBPayFcbi8vIC8vIFNob3VsZCBmYWlsIHR5cGUtY2hlY2tcbi8vIGNvbnN0IHoxID0gdmFsaWRhdGVPYmplY3QobywgeyBhOiAndG1wJyB9LCB7IGM6ICd6eicgfSk7XG4vLyBjb25zdCB6MiA9IHZhbGlkYXRlT2JqZWN0KG8sIHsgYTogJ2lzU2FmZUludGVnZXInIH0sIHsgYzogJ3p6JyB9KTtcbi8vIGNvbnN0IHozID0gdmFsaWRhdGVPYmplY3QobywgeyB0ZXN0OiAnYm9vbGVhbicsIHo6ICdidWcnIH0pO1xuLy8gY29uc3QgejQgPSB2YWxpZGF0ZU9iamVjdChvLCB7IGE6ICdib29sZWFuJywgejogJ2J1ZycgfSk7XG5cbmV4cG9ydCBmdW5jdGlvbiBpc0hhc2godmFsOiBDSGFzaCk6IGJvb2xlYW4ge1xuICByZXR1cm4gdHlwZW9mIHZhbCA9PT0gJ2Z1bmN0aW9uJyAmJiBOdW1iZXIuaXNTYWZlSW50ZWdlcih2YWwub3V0cHV0TGVuKTtcbn1cbmV4cG9ydCBmdW5jdGlvbiBfdmFsaWRhdGVPYmplY3QoXG4gIG9iamVjdDogUmVjb3JkPHN0cmluZywgYW55PixcbiAgZmllbGRzOiBSZWNvcmQ8c3RyaW5nLCBzdHJpbmc+LFxuICBvcHRGaWVsZHM6IFJlY29yZDxzdHJpbmcsIHN0cmluZz4gPSB7fVxuKTogdm9pZCB7XG4gIGlmICghb2JqZWN0IHx8IHR5cGVvZiBvYmplY3QgIT09ICdvYmplY3QnKSB0aHJvdyBuZXcgRXJyb3IoJ2V4cGVjdGVkIHZhbGlkIG9wdGlvbnMgb2JqZWN0Jyk7XG4gIHR5cGUgSXRlbSA9IGtleW9mIHR5cGVvZiBvYmplY3Q7XG4gIGZ1bmN0aW9uIGNoZWNrRmllbGQoZmllbGROYW1lOiBJdGVtLCBleHBlY3RlZFR5cGU6IHN0cmluZywgaXNPcHQ6IGJvb2xlYW4pIHtcbiAgICBjb25zdCB2YWwgPSBvYmplY3RbZmllbGROYW1lXTtcbiAgICBpZiAoaXNPcHQgJiYgdmFsID09PSB1bmRlZmluZWQpIHJldHVybjtcbiAgICBjb25zdCBjdXJyZW50ID0gdHlwZW9mIHZhbDtcbiAgICBpZiAoY3VycmVudCAhPT0gZXhwZWN0ZWRUeXBlIHx8IHZhbCA9PT0gbnVsbClcbiAgICAgIHRocm93IG5ldyBFcnJvcihgcGFyYW0gXCIke2ZpZWxkTmFtZX1cIiBpcyBpbnZhbGlkOiBleHBlY3RlZCAke2V4cGVjdGVkVHlwZX0sIGdvdCAke2N1cnJlbnR9YCk7XG4gIH1cbiAgT2JqZWN0LmVudHJpZXMoZmllbGRzKS5mb3JFYWNoKChbaywgdl0pID0+IGNoZWNrRmllbGQoaywgdiwgZmFsc2UpKTtcbiAgT2JqZWN0LmVudHJpZXMob3B0RmllbGRzKS5mb3JFYWNoKChbaywgdl0pID0+IGNoZWNrRmllbGQoaywgdiwgdHJ1ZSkpO1xufVxuXG4vKipcbiAqIHRocm93cyBub3QgaW1wbGVtZW50ZWQgZXJyb3JcbiAqL1xuZXhwb3J0IGNvbnN0IG5vdEltcGxlbWVudGVkID0gKCk6IG5ldmVyID0+IHtcbiAgdGhyb3cgbmV3IEVycm9yKCdub3QgaW1wbGVtZW50ZWQnKTtcbn07XG5cbi8qKlxuICogTWVtb2l6ZXMgKGNhY2hlcykgY29tcHV0YXRpb24gcmVzdWx0LlxuICogVXNlcyBXZWFrTWFwOiB0aGUgdmFsdWUgaXMgZ29pbmcgYXV0by1jbGVhbmVkIGJ5IEdDIGFmdGVyIGxhc3QgcmVmZXJlbmNlIGlzIHJlbW92ZWQuXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBtZW1vaXplZDxUIGV4dGVuZHMgb2JqZWN0LCBSLCBPIGV4dGVuZHMgYW55W10+KFxuICBmbjogKGFyZzogVCwgLi4uYXJnczogTykgPT4gUlxuKTogKGFyZzogVCwgLi4uYXJnczogTykgPT4gUiB7XG4gIGNvbnN0IG1hcCA9IG5ldyBXZWFrTWFwPFQsIFI+KCk7XG4gIHJldHVybiAoYXJnOiBULCAuLi5hcmdzOiBPKTogUiA9PiB7XG4gICAgY29uc3QgdmFsID0gbWFwLmdldChhcmcpO1xuICAgIGlmICh2YWwgIT09IHVuZGVmaW5lZCkgcmV0dXJuIHZhbDtcbiAgICBjb25zdCBjb21wdXRlZCA9IGZuKGFyZywgLi4uYXJncyk7XG4gICAgbWFwLnNldChhcmcsIGNvbXB1dGVkKTtcbiAgICByZXR1cm4gY29tcHV0ZWQ7XG4gIH07XG59XG4iLCAiLyoqXG4gKiBVdGlscyBmb3IgbW9kdWxhciBkaXZpc2lvbiBhbmQgZmllbGRzLlxuICogRmllbGQgb3ZlciAxMSBpcyBhIGZpbml0ZSAoR2Fsb2lzKSBmaWVsZCBpcyBpbnRlZ2VyIG51bWJlciBvcGVyYXRpb25zIGBtb2QgMTFgLlxuICogVGhlcmUgaXMgbm8gZGl2aXNpb246IGl0IGlzIHJlcGxhY2VkIGJ5IG1vZHVsYXIgbXVsdGlwbGljYXRpdmUgaW52ZXJzZS5cbiAqIEBtb2R1bGVcbiAqL1xuLyohIG5vYmxlLWN1cnZlcyAtIE1JVCBMaWNlbnNlIChjKSAyMDIyIFBhdWwgTWlsbGVyIChwYXVsbWlsbHIuY29tKSAqL1xuaW1wb3J0IHtcbiAgX3ZhbGlkYXRlT2JqZWN0LFxuICBhbnVtYmVyLFxuICBiaXRNYXNrLFxuICBieXRlc1RvTnVtYmVyQkUsXG4gIGJ5dGVzVG9OdW1iZXJMRSxcbiAgZW5zdXJlQnl0ZXMsXG4gIG51bWJlclRvQnl0ZXNCRSxcbiAgbnVtYmVyVG9CeXRlc0xFLFxufSBmcm9tICcuLi91dGlscy50cyc7XG5cbi8vIHByZXR0aWVyLWlnbm9yZVxuY29uc3QgXzBuID0gQmlnSW50KDApLCBfMW4gPSBCaWdJbnQoMSksIF8ybiA9IC8qIEBfX1BVUkVfXyAqLyBCaWdJbnQoMiksIF8zbiA9IC8qIEBfX1BVUkVfXyAqLyBCaWdJbnQoMyk7XG4vLyBwcmV0dGllci1pZ25vcmVcbmNvbnN0IF80biA9IC8qIEBfX1BVUkVfXyAqLyBCaWdJbnQoNCksIF81biA9IC8qIEBfX1BVUkVfXyAqLyBCaWdJbnQoNSksIF83biA9IC8qIEBfX1BVUkVfXyAqLyBCaWdJbnQoNyk7XG4vLyBwcmV0dGllci1pZ25vcmVcbmNvbnN0IF84biA9IC8qIEBfX1BVUkVfXyAqLyBCaWdJbnQoOCksIF85biA9IC8qIEBfX1BVUkVfXyAqLyBCaWdJbnQoOSksIF8xNm4gPSAvKiBAX19QVVJFX18gKi8gQmlnSW50KDE2KTtcblxuLy8gQ2FsY3VsYXRlcyBhIG1vZHVsbyBiXG5leHBvcnQgZnVuY3Rpb24gbW9kKGE6IGJpZ2ludCwgYjogYmlnaW50KTogYmlnaW50IHtcbiAgY29uc3QgcmVzdWx0ID0gYSAlIGI7XG4gIHJldHVybiByZXN1bHQgPj0gXzBuID8gcmVzdWx0IDogYiArIHJlc3VsdDtcbn1cbi8qKlxuICogRWZmaWNpZW50bHkgcmFpc2UgbnVtIHRvIHBvd2VyIGFuZCBkbyBtb2R1bGFyIGRpdmlzaW9uLlxuICogVW5zYWZlIGluIHNvbWUgY29udGV4dHM6IHVzZXMgbGFkZGVyLCBzbyBjYW4gZXhwb3NlIGJpZ2ludCBiaXRzLlxuICogQGV4YW1wbGVcbiAqIHBvdygybiwgNm4sIDExbikgLy8gNjRuICUgMTFuID09IDluXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBwb3cobnVtOiBiaWdpbnQsIHBvd2VyOiBiaWdpbnQsIG1vZHVsbzogYmlnaW50KTogYmlnaW50IHtcbiAgcmV0dXJuIEZwUG93KEZpZWxkKG1vZHVsbyksIG51bSwgcG93ZXIpO1xufVxuXG4vKiogRG9lcyBgeF4oMl5wb3dlcilgIG1vZCBwLiBgcG93MigzMCwgNClgID09IGAzMF4oMl40KWAgKi9cbmV4cG9ydCBmdW5jdGlvbiBwb3cyKHg6IGJpZ2ludCwgcG93ZXI6IGJpZ2ludCwgbW9kdWxvOiBiaWdpbnQpOiBiaWdpbnQge1xuICBsZXQgcmVzID0geDtcbiAgd2hpbGUgKHBvd2VyLS0gPiBfMG4pIHtcbiAgICByZXMgKj0gcmVzO1xuICAgIHJlcyAlPSBtb2R1bG87XG4gIH1cbiAgcmV0dXJuIHJlcztcbn1cblxuLyoqXG4gKiBJbnZlcnNlcyBudW1iZXIgb3ZlciBtb2R1bG8uXG4gKiBJbXBsZW1lbnRlZCB1c2luZyBbRXVjbGlkZWFuIEdDRF0oaHR0cHM6Ly9icmlsbGlhbnQub3JnL3dpa2kvZXh0ZW5kZWQtZXVjbGlkZWFuLWFsZ29yaXRobS8pLlxuICovXG5leHBvcnQgZnVuY3Rpb24gaW52ZXJ0KG51bWJlcjogYmlnaW50LCBtb2R1bG86IGJpZ2ludCk6IGJpZ2ludCB7XG4gIGlmIChudW1iZXIgPT09IF8wbikgdGhyb3cgbmV3IEVycm9yKCdpbnZlcnQ6IGV4cGVjdGVkIG5vbi16ZXJvIG51bWJlcicpO1xuICBpZiAobW9kdWxvIDw9IF8wbikgdGhyb3cgbmV3IEVycm9yKCdpbnZlcnQ6IGV4cGVjdGVkIHBvc2l0aXZlIG1vZHVsdXMsIGdvdCAnICsgbW9kdWxvKTtcbiAgLy8gRmVybWF0J3MgbGl0dGxlIHRoZW9yZW0gXCJDVC1saWtlXCIgdmVyc2lvbiBpbnYobikgPSBuXihtLTIpIG1vZCBtIGlzIDMweCBzbG93ZXIuXG4gIGxldCBhID0gbW9kKG51bWJlciwgbW9kdWxvKTtcbiAgbGV0IGIgPSBtb2R1bG87XG4gIC8vIHByZXR0aWVyLWlnbm9yZVxuICBsZXQgeCA9IF8wbiwgeSA9IF8xbiwgdSA9IF8xbiwgdiA9IF8wbjtcbiAgd2hpbGUgKGEgIT09IF8wbikge1xuICAgIC8vIEpJVCBhcHBsaWVzIG9wdGltaXphdGlvbiBpZiB0aG9zZSB0d28gbGluZXMgZm9sbG93IGVhY2ggb3RoZXJcbiAgICBjb25zdCBxID0gYiAvIGE7XG4gICAgY29uc3QgciA9IGIgJSBhO1xuICAgIGNvbnN0IG0gPSB4IC0gdSAqIHE7XG4gICAgY29uc3QgbiA9IHkgLSB2ICogcTtcbiAgICAvLyBwcmV0dGllci1pZ25vcmVcbiAgICBiID0gYSwgYSA9IHIsIHggPSB1LCB5ID0gdiwgdSA9IG0sIHYgPSBuO1xuICB9XG4gIGNvbnN0IGdjZCA9IGI7XG4gIGlmIChnY2QgIT09IF8xbikgdGhyb3cgbmV3IEVycm9yKCdpbnZlcnQ6IGRvZXMgbm90IGV4aXN0Jyk7XG4gIHJldHVybiBtb2QoeCwgbW9kdWxvKTtcbn1cblxuZnVuY3Rpb24gYXNzZXJ0SXNTcXVhcmU8VD4oRnA6IElGaWVsZDxUPiwgcm9vdDogVCwgbjogVCk6IHZvaWQge1xuICBpZiAoIUZwLmVxbChGcC5zcXIocm9vdCksIG4pKSB0aHJvdyBuZXcgRXJyb3IoJ0Nhbm5vdCBmaW5kIHNxdWFyZSByb290Jyk7XG59XG5cbi8vIE5vdCBhbGwgcm9vdHMgYXJlIHBvc3NpYmxlISBFeGFtcGxlIHdoaWNoIHdpbGwgdGhyb3c6XG4vLyBjb25zdCBOVU0gPVxuLy8gbiA9IDcyMDU3NTk0MDM3OTI3ODE2bjtcbi8vIEZwID0gRmllbGQoQmlnSW50KCcweDFhMDExMWVhMzk3ZmU2OWE0YjFiYTdiNjQzNGJhY2Q3NjQ3NzRiODRmMzg1MTJiZjY3MzBkMmEwZjZiMGY2MjQxZWFiZmZmZWIxNTNmZmZmYjlmZWZmZmZmZmZmYWFhYicpKTtcbmZ1bmN0aW9uIHNxcnQzbW9kNDxUPihGcDogSUZpZWxkPFQ+LCBuOiBUKSB7XG4gIGNvbnN0IHAxZGl2NCA9IChGcC5PUkRFUiArIF8xbikgLyBfNG47XG4gIGNvbnN0IHJvb3QgPSBGcC5wb3cobiwgcDFkaXY0KTtcbiAgYXNzZXJ0SXNTcXVhcmUoRnAsIHJvb3QsIG4pO1xuICByZXR1cm4gcm9vdDtcbn1cblxuZnVuY3Rpb24gc3FydDVtb2Q4PFQ+KEZwOiBJRmllbGQ8VD4sIG46IFQpIHtcbiAgY29uc3QgcDVkaXY4ID0gKEZwLk9SREVSIC0gXzVuKSAvIF84bjtcbiAgY29uc3QgbjIgPSBGcC5tdWwobiwgXzJuKTtcbiAgY29uc3QgdiA9IEZwLnBvdyhuMiwgcDVkaXY4KTtcbiAgY29uc3QgbnYgPSBGcC5tdWwobiwgdik7XG4gIGNvbnN0IGkgPSBGcC5tdWwoRnAubXVsKG52LCBfMm4pLCB2KTtcbiAgY29uc3Qgcm9vdCA9IEZwLm11bChudiwgRnAuc3ViKGksIEZwLk9ORSkpO1xuICBhc3NlcnRJc1NxdWFyZShGcCwgcm9vdCwgbik7XG4gIHJldHVybiByb290O1xufVxuXG4vLyBCYXNlZCBvbiBSRkM5MzgwLCBLb25nIGFsZ29yaXRobVxuLy8gcHJldHRpZXItaWdub3JlXG5mdW5jdGlvbiBzcXJ0OW1vZDE2KFA6IGJpZ2ludCk6IDxUPihGcDogSUZpZWxkPFQ+LCBuOiBUKSA9PiBUIHtcbiAgY29uc3QgRnBfID0gRmllbGQoUCk7XG4gIGNvbnN0IHRuID0gdG9uZWxsaVNoYW5rcyhQKTtcbiAgY29uc3QgYzEgPSB0bihGcF8sIEZwXy5uZWcoRnBfLk9ORSkpOy8vICAxLiBjMSA9IHNxcnQoLTEpIGluIEYsIGkuZS4sIChjMV4yKSA9PSAtMSBpbiBGXG4gIGNvbnN0IGMyID0gdG4oRnBfLCBjMSk7ICAgICAgICAgICAgICAvLyAgMi4gYzIgPSBzcXJ0KGMxKSBpbiBGLCBpLmUuLCAoYzJeMikgPT0gYzEgaW4gRlxuICBjb25zdCBjMyA9IHRuKEZwXywgRnBfLm5lZyhjMSkpOyAgICAgLy8gIDMuIGMzID0gc3FydCgtYzEpIGluIEYsIGkuZS4sIChjM14yKSA9PSAtYzEgaW4gRlxuICBjb25zdCBjNCA9IChQICsgXzduKSAvIF8xNm47ICAgICAgICAgLy8gIDQuIGM0ID0gKHEgKyA3KSAvIDE2ICAgICAgICAjIEludGVnZXIgYXJpdGhtZXRpY1xuICByZXR1cm4gPFQ+KEZwOiBJRmllbGQ8VD4sIG46IFQpID0+IHtcbiAgICBsZXQgdHYxID0gRnAucG93KG4sIGM0KTsgICAgICAgICAgIC8vICAxLiB0djEgPSB4XmM0XG4gICAgbGV0IHR2MiA9IEZwLm11bCh0djEsIGMxKTsgICAgICAgICAvLyAgMi4gdHYyID0gYzEgKiB0djFcbiAgICBjb25zdCB0djMgPSBGcC5tdWwodHYxLCBjMik7ICAgICAgIC8vICAzLiB0djMgPSBjMiAqIHR2MVxuICAgIGNvbnN0IHR2NCA9IEZwLm11bCh0djEsIGMzKTsgICAgICAgLy8gIDQuIHR2NCA9IGMzICogdHYxXG4gICAgY29uc3QgZTEgPSBGcC5lcWwoRnAuc3FyKHR2MiksIG4pOyAvLyAgNS4gIGUxID0gKHR2Ml4yKSA9PSB4XG4gICAgY29uc3QgZTIgPSBGcC5lcWwoRnAuc3FyKHR2MyksIG4pOyAvLyAgNi4gIGUyID0gKHR2M14yKSA9PSB4XG4gICAgdHYxID0gRnAuY21vdih0djEsIHR2MiwgZTEpOyAgICAgICAvLyAgNy4gdHYxID0gQ01PVih0djEsIHR2MiwgZTEpICAjIFNlbGVjdCB0djIgaWYgKHR2Ml4yKSA9PSB4XG4gICAgdHYyID0gRnAuY21vdih0djQsIHR2MywgZTIpOyAgICAgICAvLyAgOC4gdHYyID0gQ01PVih0djQsIHR2MywgZTIpICAjIFNlbGVjdCB0djMgaWYgKHR2M14yKSA9PSB4XG4gICAgY29uc3QgZTMgPSBGcC5lcWwoRnAuc3FyKHR2MiksIG4pOyAvLyAgOS4gIGUzID0gKHR2Ml4yKSA9PSB4XG4gICAgY29uc3Qgcm9vdCA9IEZwLmNtb3YodHYxLCB0djIsIGUzKTsvLyAxMC4gIHogPSBDTU9WKHR2MSwgdHYyLCBlMykgICAjIFNlbGVjdCBzcXJ0IGZyb20gdHYxICYgdHYyXG4gICAgYXNzZXJ0SXNTcXVhcmUoRnAsIHJvb3QsIG4pO1xuICAgIHJldHVybiByb290O1xuICB9O1xufVxuXG4vKipcbiAqIFRvbmVsbGktU2hhbmtzIHNxdWFyZSByb290IHNlYXJjaCBhbGdvcml0aG0uXG4gKiAxLiBodHRwczovL2VwcmludC5pYWNyLm9yZy8yMDEyLzY4NS5wZGYgKHBhZ2UgMTIpXG4gKiAyLiBTcXVhcmUgUm9vdHMgZnJvbSAxOyAyNCwgNTEsIDEwIHRvIERhbiBTaGFua3NcbiAqIEBwYXJhbSBQIGZpZWxkIG9yZGVyXG4gKiBAcmV0dXJucyBmdW5jdGlvbiB0aGF0IHRha2VzIGZpZWxkIEZwIChjcmVhdGVkIGZyb20gUCkgYW5kIG51bWJlciBuXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiB0b25lbGxpU2hhbmtzKFA6IGJpZ2ludCk6IDxUPihGcDogSUZpZWxkPFQ+LCBuOiBUKSA9PiBUIHtcbiAgLy8gSW5pdGlhbGl6YXRpb24gKHByZWNvbXB1dGF0aW9uKS5cbiAgLy8gQ2FjaGluZyBpbml0aWFsaXphdGlvbiBjb3VsZCBib29zdCBwZXJmIGJ5IDclLlxuICBpZiAoUCA8IF8zbikgdGhyb3cgbmV3IEVycm9yKCdzcXJ0IGlzIG5vdCBkZWZpbmVkIGZvciBzbWFsbCBmaWVsZCcpO1xuICAvLyBGYWN0b3IgUCAtIDEgPSBRICogMl5TLCB3aGVyZSBRIGlzIG9kZFxuICBsZXQgUSA9IFAgLSBfMW47XG4gIGxldCBTID0gMDtcbiAgd2hpbGUgKFEgJSBfMm4gPT09IF8wbikge1xuICAgIFEgLz0gXzJuO1xuICAgIFMrKztcbiAgfVxuXG4gIC8vIEZpbmQgdGhlIGZpcnN0IHF1YWRyYXRpYyBub24tcmVzaWR1ZSBaID49IDJcbiAgbGV0IFogPSBfMm47XG4gIGNvbnN0IF9GcCA9IEZpZWxkKFApO1xuICB3aGlsZSAoRnBMZWdlbmRyZShfRnAsIFopID09PSAxKSB7XG4gICAgLy8gQmFzaWMgcHJpbWFsaXR5IHRlc3QgZm9yIFAuIEFmdGVyIHggaXRlcmF0aW9ucywgY2hhbmNlIG9mXG4gICAgLy8gbm90IGZpbmRpbmcgcXVhZHJhdGljIG5vbi1yZXNpZHVlIGlzIDJeeCwgc28gMl4xMDAwLlxuICAgIGlmIChaKysgPiAxMDAwKSB0aHJvdyBuZXcgRXJyb3IoJ0Nhbm5vdCBmaW5kIHNxdWFyZSByb290OiBwcm9iYWJseSBub24tcHJpbWUgUCcpO1xuICB9XG4gIC8vIEZhc3QtcGF0aDsgdXN1YWxseSBkb25lIGJlZm9yZSBaLCBidXQgd2UgZG8gXCJwcmltYWxpdHkgdGVzdFwiLlxuICBpZiAoUyA9PT0gMSkgcmV0dXJuIHNxcnQzbW9kNDtcblxuICAvLyBTbG93LXBhdGhcbiAgLy8gVE9ETzogdGVzdCBvbiBGcDIgYW5kIG90aGVyc1xuICBsZXQgY2MgPSBfRnAucG93KFosIFEpOyAvLyBjID0gel5RXG4gIGNvbnN0IFExZGl2MiA9IChRICsgXzFuKSAvIF8ybjtcbiAgcmV0dXJuIGZ1bmN0aW9uIHRvbmVsbGlTbG93PFQ+KEZwOiBJRmllbGQ8VD4sIG46IFQpOiBUIHtcbiAgICBpZiAoRnAuaXMwKG4pKSByZXR1cm4gbjtcbiAgICAvLyBDaGVjayBpZiBuIGlzIGEgcXVhZHJhdGljIHJlc2lkdWUgdXNpbmcgTGVnZW5kcmUgc3ltYm9sXG4gICAgaWYgKEZwTGVnZW5kcmUoRnAsIG4pICE9PSAxKSB0aHJvdyBuZXcgRXJyb3IoJ0Nhbm5vdCBmaW5kIHNxdWFyZSByb290Jyk7XG5cbiAgICAvLyBJbml0aWFsaXplIHZhcmlhYmxlcyBmb3IgdGhlIG1haW4gbG9vcFxuICAgIGxldCBNID0gUztcbiAgICBsZXQgYyA9IEZwLm11bChGcC5PTkUsIGNjKTsgLy8gYyA9IHpeUSwgbW92ZSBjYyBmcm9tIGZpZWxkIF9GcCBpbnRvIGZpZWxkIEZwXG4gICAgbGV0IHQgPSBGcC5wb3cobiwgUSk7IC8vIHQgPSBuXlEsIGZpcnN0IGd1ZXNzIGF0IHRoZSBmdWRnZSBmYWN0b3JcbiAgICBsZXQgUiA9IEZwLnBvdyhuLCBRMWRpdjIpOyAvLyBSID0gbl4oKFErMSkvMiksIGZpcnN0IGd1ZXNzIGF0IHRoZSBzcXVhcmUgcm9vdFxuXG4gICAgLy8gTWFpbiBsb29wXG4gICAgLy8gd2hpbGUgdCAhPSAxXG4gICAgd2hpbGUgKCFGcC5lcWwodCwgRnAuT05FKSkge1xuICAgICAgaWYgKEZwLmlzMCh0KSkgcmV0dXJuIEZwLlpFUk87IC8vIGlmIHQ9MCByZXR1cm4gUj0wXG4gICAgICBsZXQgaSA9IDE7XG5cbiAgICAgIC8vIEZpbmQgdGhlIHNtYWxsZXN0IGkgPj0gMSBzdWNoIHRoYXQgdF4oMl5pKSBcdTIyNjEgMSAobW9kIFApXG4gICAgICBsZXQgdF90bXAgPSBGcC5zcXIodCk7IC8vIHReKDJeMSlcbiAgICAgIHdoaWxlICghRnAuZXFsKHRfdG1wLCBGcC5PTkUpKSB7XG4gICAgICAgIGkrKztcbiAgICAgICAgdF90bXAgPSBGcC5zcXIodF90bXApOyAvLyB0XigyXjIpLi4uXG4gICAgICAgIGlmIChpID09PSBNKSB0aHJvdyBuZXcgRXJyb3IoJ0Nhbm5vdCBmaW5kIHNxdWFyZSByb290Jyk7XG4gICAgICB9XG5cbiAgICAgIC8vIENhbGN1bGF0ZSB0aGUgZXhwb25lbnQgZm9yIGI6IDJeKE0gLSBpIC0gMSlcbiAgICAgIGNvbnN0IGV4cG9uZW50ID0gXzFuIDw8IEJpZ0ludChNIC0gaSAtIDEpOyAvLyBiaWdpbnQgaXMgaW1wb3J0YW50XG4gICAgICBjb25zdCBiID0gRnAucG93KGMsIGV4cG9uZW50KTsgLy8gYiA9IDJeKE0gLSBpIC0gMSlcblxuICAgICAgLy8gVXBkYXRlIHZhcmlhYmxlc1xuICAgICAgTSA9IGk7XG4gICAgICBjID0gRnAuc3FyKGIpOyAvLyBjID0gYl4yXG4gICAgICB0ID0gRnAubXVsKHQsIGMpOyAvLyB0ID0gKHQgKiBiXjIpXG4gICAgICBSID0gRnAubXVsKFIsIGIpOyAvLyBSID0gUipiXG4gICAgfVxuICAgIHJldHVybiBSO1xuICB9O1xufVxuXG4vKipcbiAqIFNxdWFyZSByb290IGZvciBhIGZpbml0ZSBmaWVsZC4gV2lsbCB0cnkgb3B0aW1pemVkIHZlcnNpb25zIGZpcnN0OlxuICpcbiAqIDEuIFAgXHUyMjYxIDMgKG1vZCA0KVxuICogMi4gUCBcdTIyNjEgNSAobW9kIDgpXG4gKiAzLiBQIFx1MjI2MSA5IChtb2QgMTYpXG4gKiA0LiBUb25lbGxpLVNoYW5rcyBhbGdvcml0aG1cbiAqXG4gKiBEaWZmZXJlbnQgYWxnb3JpdGhtcyBjYW4gZ2l2ZSBkaWZmZXJlbnQgcm9vdHMsIGl0IGlzIHVwIHRvIHVzZXIgdG8gZGVjaWRlIHdoaWNoIG9uZSB0aGV5IHdhbnQuXG4gKiBGb3IgZXhhbXBsZSB0aGVyZSBpcyBGcFNxcnRPZGQvRnBTcXJ0RXZlbiB0byBjaG9pY2Ugcm9vdCBiYXNlZCBvbiBvZGRuZXNzICh1c2VkIGZvciBoYXNoLXRvLWN1cnZlKS5cbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIEZwU3FydChQOiBiaWdpbnQpOiA8VD4oRnA6IElGaWVsZDxUPiwgbjogVCkgPT4gVCB7XG4gIC8vIFAgXHUyMjYxIDMgKG1vZCA0KSA9PiBcdTIyMUFuID0gbl4oKFArMSkvNClcbiAgaWYgKFAgJSBfNG4gPT09IF8zbikgcmV0dXJuIHNxcnQzbW9kNDtcbiAgLy8gUCBcdTIyNjEgNSAobW9kIDgpID0+IEF0a2luIGFsZ29yaXRobSwgcGFnZSAxMCBvZiBodHRwczovL2VwcmludC5pYWNyLm9yZy8yMDEyLzY4NS5wZGZcbiAgaWYgKFAgJSBfOG4gPT09IF81bikgcmV0dXJuIHNxcnQ1bW9kODtcbiAgLy8gUCBcdTIyNjEgOSAobW9kIDE2KSA9PiBLb25nIGFsZ29yaXRobSwgcGFnZSAxMSBvZiBodHRwczovL2VwcmludC5pYWNyLm9yZy8yMDEyLzY4NS5wZGYgKGFsZ29yaXRobSA0KVxuICBpZiAoUCAlIF8xNm4gPT09IF85bikgcmV0dXJuIHNxcnQ5bW9kMTYoUCk7XG4gIC8vIFRvbmVsbGktU2hhbmtzIGFsZ29yaXRobVxuICByZXR1cm4gdG9uZWxsaVNoYW5rcyhQKTtcbn1cblxuLy8gTGl0dGxlLWVuZGlhbiBjaGVjayBmb3IgZmlyc3QgTEUgYml0IChsYXN0IEJFIGJpdCk7XG5leHBvcnQgY29uc3QgaXNOZWdhdGl2ZUxFID0gKG51bTogYmlnaW50LCBtb2R1bG86IGJpZ2ludCk6IGJvb2xlYW4gPT5cbiAgKG1vZChudW0sIG1vZHVsbykgJiBfMW4pID09PSBfMW47XG5cbi8qKiBGaWVsZCBpcyBub3QgYWx3YXlzIG92ZXIgcHJpbWU6IGZvciBleGFtcGxlLCBGcDIgaGFzIE9SREVSKHEpPXBebS4gKi9cbmV4cG9ydCBpbnRlcmZhY2UgSUZpZWxkPFQ+IHtcbiAgT1JERVI6IGJpZ2ludDtcbiAgaXNMRTogYm9vbGVhbjtcbiAgQllURVM6IG51bWJlcjtcbiAgQklUUzogbnVtYmVyO1xuICBNQVNLOiBiaWdpbnQ7XG4gIFpFUk86IFQ7XG4gIE9ORTogVDtcbiAgLy8gMS1hcmdcbiAgY3JlYXRlOiAobnVtOiBUKSA9PiBUO1xuICBpc1ZhbGlkOiAobnVtOiBUKSA9PiBib29sZWFuO1xuICBpczA6IChudW06IFQpID0+IGJvb2xlYW47XG4gIGlzVmFsaWROb3QwOiAobnVtOiBUKSA9PiBib29sZWFuO1xuICBuZWcobnVtOiBUKTogVDtcbiAgaW52KG51bTogVCk6IFQ7XG4gIHNxcnQobnVtOiBUKTogVDtcbiAgc3FyKG51bTogVCk6IFQ7XG4gIC8vIDItYXJnc1xuICBlcWwobGhzOiBULCByaHM6IFQpOiBib29sZWFuO1xuICBhZGQobGhzOiBULCByaHM6IFQpOiBUO1xuICBzdWIobGhzOiBULCByaHM6IFQpOiBUO1xuICBtdWwobGhzOiBULCByaHM6IFQgfCBiaWdpbnQpOiBUO1xuICBwb3cobGhzOiBULCBwb3dlcjogYmlnaW50KTogVDtcbiAgZGl2KGxoczogVCwgcmhzOiBUIHwgYmlnaW50KTogVDtcbiAgLy8gTiBmb3IgTm9uTm9ybWFsaXplZCAoZm9yIG5vdylcbiAgYWRkTihsaHM6IFQsIHJoczogVCk6IFQ7XG4gIHN1Yk4obGhzOiBULCByaHM6IFQpOiBUO1xuICBtdWxOKGxoczogVCwgcmhzOiBUIHwgYmlnaW50KTogVDtcbiAgc3FyTihudW06IFQpOiBUO1xuXG4gIC8vIE9wdGlvbmFsXG4gIC8vIFNob3VsZCBiZSBzYW1lIGFzIHNnbjAgZnVuY3Rpb24gaW5cbiAgLy8gW1JGQzkzODBdKGh0dHBzOi8vd3d3LnJmYy1lZGl0b3Iub3JnL3JmYy9yZmM5MzgwI3NlY3Rpb24tNC4xKS5cbiAgLy8gTk9URTogc2duMCBpcyAnbmVnYXRpdmUgaW4gTEUnLCB3aGljaCBpcyBzYW1lIGFzIG9kZC4gQW5kIG5lZ2F0aXZlIGluIExFIGlzIGtpbmRhIHN0cmFuZ2UgZGVmaW5pdGlvbiBhbnl3YXkuXG4gIGlzT2RkPyhudW06IFQpOiBib29sZWFuOyAvLyBPZGQgaW5zdGVhZCBvZiBldmVuIHNpbmNlIHdlIGhhdmUgaXQgZm9yIEZwMlxuICBhbGxvd2VkTGVuZ3Rocz86IG51bWJlcltdO1xuICAvLyBsZWdlbmRyZT8obnVtOiBUKTogVDtcbiAgaW52ZXJ0QmF0Y2g6IChsc3Q6IFRbXSkgPT4gVFtdO1xuICB0b0J5dGVzKG51bTogVCk6IFVpbnQ4QXJyYXk7XG4gIGZyb21CeXRlcyhieXRlczogVWludDhBcnJheSwgc2tpcFZhbGlkYXRpb24/OiBib29sZWFuKTogVDtcbiAgLy8gSWYgYyBpcyBGYWxzZSwgQ01PViByZXR1cm5zIGEsIG90aGVyd2lzZSBpdCByZXR1cm5zIGIuXG4gIGNtb3YoYTogVCwgYjogVCwgYzogYm9vbGVhbik6IFQ7XG59XG4vLyBwcmV0dGllci1pZ25vcmVcbmNvbnN0IEZJRUxEX0ZJRUxEUyA9IFtcbiAgJ2NyZWF0ZScsICdpc1ZhbGlkJywgJ2lzMCcsICduZWcnLCAnaW52JywgJ3NxcnQnLCAnc3FyJyxcbiAgJ2VxbCcsICdhZGQnLCAnc3ViJywgJ211bCcsICdwb3cnLCAnZGl2JyxcbiAgJ2FkZE4nLCAnc3ViTicsICdtdWxOJywgJ3Nxck4nXG5dIGFzIGNvbnN0O1xuZXhwb3J0IGZ1bmN0aW9uIHZhbGlkYXRlRmllbGQ8VD4oZmllbGQ6IElGaWVsZDxUPik6IElGaWVsZDxUPiB7XG4gIGNvbnN0IGluaXRpYWwgPSB7XG4gICAgT1JERVI6ICdiaWdpbnQnLFxuICAgIE1BU0s6ICdiaWdpbnQnLFxuICAgIEJZVEVTOiAnbnVtYmVyJyxcbiAgICBCSVRTOiAnbnVtYmVyJyxcbiAgfSBhcyBSZWNvcmQ8c3RyaW5nLCBzdHJpbmc+O1xuICBjb25zdCBvcHRzID0gRklFTERfRklFTERTLnJlZHVjZSgobWFwLCB2YWw6IHN0cmluZykgPT4ge1xuICAgIG1hcFt2YWxdID0gJ2Z1bmN0aW9uJztcbiAgICByZXR1cm4gbWFwO1xuICB9LCBpbml0aWFsKTtcbiAgX3ZhbGlkYXRlT2JqZWN0KGZpZWxkLCBvcHRzKTtcbiAgLy8gY29uc3QgbWF4ID0gMTYzODQ7XG4gIC8vIGlmIChmaWVsZC5CWVRFUyA8IDEgfHwgZmllbGQuQllURVMgPiBtYXgpIHRocm93IG5ldyBFcnJvcignaW52YWxpZCBmaWVsZCcpO1xuICAvLyBpZiAoZmllbGQuQklUUyA8IDEgfHwgZmllbGQuQklUUyA+IDggKiBtYXgpIHRocm93IG5ldyBFcnJvcignaW52YWxpZCBmaWVsZCcpO1xuICByZXR1cm4gZmllbGQ7XG59XG5cbi8vIEdlbmVyaWMgZmllbGQgZnVuY3Rpb25zXG5cbi8qKlxuICogU2FtZSBhcyBgcG93YCBidXQgZm9yIEZwOiBub24tY29uc3RhbnQtdGltZS5cbiAqIFVuc2FmZSBpbiBzb21lIGNvbnRleHRzOiB1c2VzIGxhZGRlciwgc28gY2FuIGV4cG9zZSBiaWdpbnQgYml0cy5cbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIEZwUG93PFQ+KEZwOiBJRmllbGQ8VD4sIG51bTogVCwgcG93ZXI6IGJpZ2ludCk6IFQge1xuICBpZiAocG93ZXIgPCBfMG4pIHRocm93IG5ldyBFcnJvcignaW52YWxpZCBleHBvbmVudCwgbmVnYXRpdmVzIHVuc3VwcG9ydGVkJyk7XG4gIGlmIChwb3dlciA9PT0gXzBuKSByZXR1cm4gRnAuT05FO1xuICBpZiAocG93ZXIgPT09IF8xbikgcmV0dXJuIG51bTtcbiAgbGV0IHAgPSBGcC5PTkU7XG4gIGxldCBkID0gbnVtO1xuICB3aGlsZSAocG93ZXIgPiBfMG4pIHtcbiAgICBpZiAocG93ZXIgJiBfMW4pIHAgPSBGcC5tdWwocCwgZCk7XG4gICAgZCA9IEZwLnNxcihkKTtcbiAgICBwb3dlciA+Pj0gXzFuO1xuICB9XG4gIHJldHVybiBwO1xufVxuXG4vKipcbiAqIEVmZmljaWVudGx5IGludmVydCBhbiBhcnJheSBvZiBGaWVsZCBlbGVtZW50cy5cbiAqIEV4Y2VwdGlvbi1mcmVlLiBXaWxsIHJldHVybiBgdW5kZWZpbmVkYCBmb3IgMCBlbGVtZW50cy5cbiAqIEBwYXJhbSBwYXNzWmVybyBtYXAgMCB0byAwIChpbnN0ZWFkIG9mIHVuZGVmaW5lZClcbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIEZwSW52ZXJ0QmF0Y2g8VD4oRnA6IElGaWVsZDxUPiwgbnVtczogVFtdLCBwYXNzWmVybyA9IGZhbHNlKTogVFtdIHtcbiAgY29uc3QgaW52ZXJ0ZWQgPSBuZXcgQXJyYXkobnVtcy5sZW5ndGgpLmZpbGwocGFzc1plcm8gPyBGcC5aRVJPIDogdW5kZWZpbmVkKTtcbiAgLy8gV2FsayBmcm9tIGZpcnN0IHRvIGxhc3QsIG11bHRpcGx5IHRoZW0gYnkgZWFjaCBvdGhlciBNT0QgcFxuICBjb25zdCBtdWx0aXBsaWVkQWNjID0gbnVtcy5yZWR1Y2UoKGFjYywgbnVtLCBpKSA9PiB7XG4gICAgaWYgKEZwLmlzMChudW0pKSByZXR1cm4gYWNjO1xuICAgIGludmVydGVkW2ldID0gYWNjO1xuICAgIHJldHVybiBGcC5tdWwoYWNjLCBudW0pO1xuICB9LCBGcC5PTkUpO1xuICAvLyBJbnZlcnQgbGFzdCBlbGVtZW50XG4gIGNvbnN0IGludmVydGVkQWNjID0gRnAuaW52KG11bHRpcGxpZWRBY2MpO1xuICAvLyBXYWxrIGZyb20gbGFzdCB0byBmaXJzdCwgbXVsdGlwbHkgdGhlbSBieSBpbnZlcnRlZCBlYWNoIG90aGVyIE1PRCBwXG4gIG51bXMucmVkdWNlUmlnaHQoKGFjYywgbnVtLCBpKSA9PiB7XG4gICAgaWYgKEZwLmlzMChudW0pKSByZXR1cm4gYWNjO1xuICAgIGludmVydGVkW2ldID0gRnAubXVsKGFjYywgaW52ZXJ0ZWRbaV0pO1xuICAgIHJldHVybiBGcC5tdWwoYWNjLCBudW0pO1xuICB9LCBpbnZlcnRlZEFjYyk7XG4gIHJldHVybiBpbnZlcnRlZDtcbn1cblxuLy8gVE9ETzogcmVtb3ZlXG5leHBvcnQgZnVuY3Rpb24gRnBEaXY8VD4oRnA6IElGaWVsZDxUPiwgbGhzOiBULCByaHM6IFQgfCBiaWdpbnQpOiBUIHtcbiAgcmV0dXJuIEZwLm11bChsaHMsIHR5cGVvZiByaHMgPT09ICdiaWdpbnQnID8gaW52ZXJ0KHJocywgRnAuT1JERVIpIDogRnAuaW52KHJocykpO1xufVxuXG4vKipcbiAqIExlZ2VuZHJlIHN5bWJvbC5cbiAqIExlZ2VuZHJlIGNvbnN0YW50IGlzIHVzZWQgdG8gY2FsY3VsYXRlIExlZ2VuZHJlIHN5bWJvbCAoYSB8IHApXG4gKiB3aGljaCBkZW5vdGVzIHRoZSB2YWx1ZSBvZiBhXigocC0xKS8yKSAobW9kIHApLlxuICpcbiAqICogKGEgfCBwKSBcdTIyNjEgMSAgICBpZiBhIGlzIGEgc3F1YXJlIChtb2QgcCksIHF1YWRyYXRpYyByZXNpZHVlXG4gKiAqIChhIHwgcCkgXHUyMjYxIC0xICAgaWYgYSBpcyBub3QgYSBzcXVhcmUgKG1vZCBwKSwgcXVhZHJhdGljIG5vbiByZXNpZHVlXG4gKiAqIChhIHwgcCkgXHUyMjYxIDAgICAgaWYgYSBcdTIyNjEgMCAobW9kIHApXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBGcExlZ2VuZHJlPFQ+KEZwOiBJRmllbGQ8VD4sIG46IFQpOiAtMSB8IDAgfCAxIHtcbiAgLy8gV2UgY2FuIHVzZSAzcmQgYXJndW1lbnQgYXMgb3B0aW9uYWwgY2FjaGUgb2YgdGhpcyB2YWx1ZVxuICAvLyBidXQgc2VlbXMgdW5uZWVkZWQgZm9yIG5vdy4gVGhlIG9wZXJhdGlvbiBpcyB2ZXJ5IGZhc3QuXG4gIGNvbnN0IHAxbW9kMiA9IChGcC5PUkRFUiAtIF8xbikgLyBfMm47XG4gIGNvbnN0IHBvd2VyZWQgPSBGcC5wb3cobiwgcDFtb2QyKTtcbiAgY29uc3QgeWVzID0gRnAuZXFsKHBvd2VyZWQsIEZwLk9ORSk7XG4gIGNvbnN0IHplcm8gPSBGcC5lcWwocG93ZXJlZCwgRnAuWkVSTyk7XG4gIGNvbnN0IG5vID0gRnAuZXFsKHBvd2VyZWQsIEZwLm5lZyhGcC5PTkUpKTtcbiAgaWYgKCF5ZXMgJiYgIXplcm8gJiYgIW5vKSB0aHJvdyBuZXcgRXJyb3IoJ2ludmFsaWQgTGVnZW5kcmUgc3ltYm9sIHJlc3VsdCcpO1xuICByZXR1cm4geWVzID8gMSA6IHplcm8gPyAwIDogLTE7XG59XG5cbi8vIFRoaXMgZnVuY3Rpb24gcmV0dXJucyBUcnVlIHdoZW5ldmVyIHRoZSB2YWx1ZSB4IGlzIGEgc3F1YXJlIGluIHRoZSBmaWVsZCBGLlxuZXhwb3J0IGZ1bmN0aW9uIEZwSXNTcXVhcmU8VD4oRnA6IElGaWVsZDxUPiwgbjogVCk6IGJvb2xlYW4ge1xuICBjb25zdCBsID0gRnBMZWdlbmRyZShGcCwgbik7XG4gIHJldHVybiBsID09PSAxO1xufVxuXG5leHBvcnQgdHlwZSBOTGVuZ3RoID0geyBuQnl0ZUxlbmd0aDogbnVtYmVyOyBuQml0TGVuZ3RoOiBudW1iZXIgfTtcbi8vIENVUlZFLm4gbGVuZ3Roc1xuZXhwb3J0IGZ1bmN0aW9uIG5MZW5ndGgobjogYmlnaW50LCBuQml0TGVuZ3RoPzogbnVtYmVyKTogTkxlbmd0aCB7XG4gIC8vIEJpdCBzaXplLCBieXRlIHNpemUgb2YgQ1VSVkUublxuICBpZiAobkJpdExlbmd0aCAhPT0gdW5kZWZpbmVkKSBhbnVtYmVyKG5CaXRMZW5ndGgpO1xuICBjb25zdCBfbkJpdExlbmd0aCA9IG5CaXRMZW5ndGggIT09IHVuZGVmaW5lZCA/IG5CaXRMZW5ndGggOiBuLnRvU3RyaW5nKDIpLmxlbmd0aDtcbiAgY29uc3QgbkJ5dGVMZW5ndGggPSBNYXRoLmNlaWwoX25CaXRMZW5ndGggLyA4KTtcbiAgcmV0dXJuIHsgbkJpdExlbmd0aDogX25CaXRMZW5ndGgsIG5CeXRlTGVuZ3RoIH07XG59XG5cbnR5cGUgRnBGaWVsZCA9IElGaWVsZDxiaWdpbnQ+ICYgUmVxdWlyZWQ8UGljazxJRmllbGQ8YmlnaW50PiwgJ2lzT2RkJz4+O1xudHlwZSBTcXJ0Rm4gPSAobjogYmlnaW50KSA9PiBiaWdpbnQ7XG50eXBlIEZpZWxkT3B0cyA9IFBhcnRpYWw8e1xuICBzcXJ0OiBTcXJ0Rm47XG4gIGlzTEU6IGJvb2xlYW47XG4gIEJJVFM6IG51bWJlcjtcbiAgbW9kRnJvbUJ5dGVzOiBib29sZWFuOyAvLyBibHMxMi0zODEgcmVxdWlyZXMgbW9kKG4pIGluc3RlYWQgb2YgcmVqZWN0aW5nIGtleXMgPj0gblxuICBhbGxvd2VkTGVuZ3Rocz86IHJlYWRvbmx5IG51bWJlcltdOyAvLyBmb3IgUDUyMSAoYWRkcyBwYWRkaW5nIGZvciBzbWFsbGVyIHNpemVzKVxufT47XG4vKipcbiAqIENyZWF0ZXMgYSBmaW5pdGUgZmllbGQuIE1ham9yIHBlcmZvcm1hbmNlIG9wdGltaXphdGlvbnM6XG4gKiAqIDEuIERlbm9ybWFsaXplZCBvcGVyYXRpb25zIGxpa2UgbXVsTiBpbnN0ZWFkIG9mIG11bC5cbiAqICogMi4gSWRlbnRpY2FsIG9iamVjdCBzaGFwZTogbmV2ZXIgYWRkIG9yIHJlbW92ZSBrZXlzLlxuICogKiAzLiBgT2JqZWN0LmZyZWV6ZWAuXG4gKiBGcmFnaWxlOiBhbHdheXMgcnVuIGEgYmVuY2htYXJrIG9uIGEgY2hhbmdlLlxuICogU2VjdXJpdHkgbm90ZTogb3BlcmF0aW9ucyBkb24ndCBjaGVjayAnaXNWYWxpZCcgZm9yIGFsbCBlbGVtZW50cyBmb3IgcGVyZm9ybWFuY2UgcmVhc29ucyxcbiAqIGl0IGlzIGNhbGxlciByZXNwb25zaWJpbGl0eSB0byBjaGVjayB0aGlzLlxuICogVGhpcyBpcyBsb3ctbGV2ZWwgY29kZSwgcGxlYXNlIG1ha2Ugc3VyZSB5b3Uga25vdyB3aGF0IHlvdSdyZSBkb2luZy5cbiAqXG4gKiBOb3RlIGFib3V0IGZpZWxkIHByb3BlcnRpZXM6XG4gKiAqIENIQVJBQ1RFUklTVElDIHAgPSBwcmltZSBudW1iZXIsIG51bWJlciBvZiBlbGVtZW50cyBpbiBtYWluIHN1Ymdyb3VwLlxuICogKiBPUkRFUiBxID0gc2ltaWxhciB0byBjb2ZhY3RvciBpbiBjdXJ2ZXMsIG1heSBiZSBjb21wb3NpdGUgYHEgPSBwXm1gLlxuICpcbiAqIEBwYXJhbSBPUkRFUiBmaWVsZCBvcmRlciwgcHJvYmFibHkgcHJpbWUsIG9yIGNvdWxkIGJlIGNvbXBvc2l0ZVxuICogQHBhcmFtIGJpdExlbiBob3cgbWFueSBiaXRzIHRoZSBmaWVsZCBjb25zdW1lc1xuICogQHBhcmFtIGlzTEUgKGRlZmF1bHQ6IGZhbHNlKSBpZiBlbmNvZGluZyAvIGRlY29kaW5nIHNob3VsZCBiZSBpbiBsaXR0bGUtZW5kaWFuXG4gKiBAcGFyYW0gcmVkZWYgb3B0aW9uYWwgZmFzdGVyIHJlZGVmaW5pdGlvbnMgb2Ygc3FydCBhbmQgb3RoZXIgbWV0aG9kc1xuICovXG5leHBvcnQgZnVuY3Rpb24gRmllbGQoXG4gIE9SREVSOiBiaWdpbnQsXG4gIGJpdExlbk9yT3B0cz86IG51bWJlciB8IEZpZWxkT3B0cywgLy8gVE9ETzogdXNlIG9wdHMgb25seSBpbiB2Mj9cbiAgaXNMRSA9IGZhbHNlLFxuICBvcHRzOiB7IHNxcnQ/OiBTcXJ0Rm4gfSA9IHt9XG4pOiBSZWFkb25seTxGcEZpZWxkPiB7XG4gIGlmIChPUkRFUiA8PSBfMG4pIHRocm93IG5ldyBFcnJvcignaW52YWxpZCBmaWVsZDogZXhwZWN0ZWQgT1JERVIgPiAwLCBnb3QgJyArIE9SREVSKTtcbiAgbGV0IF9uYml0TGVuZ3RoOiBudW1iZXIgfCB1bmRlZmluZWQgPSB1bmRlZmluZWQ7XG4gIGxldCBfc3FydDogU3FydEZuIHwgdW5kZWZpbmVkID0gdW5kZWZpbmVkO1xuICBsZXQgbW9kRnJvbUJ5dGVzOiBib29sZWFuID0gZmFsc2U7XG4gIGxldCBhbGxvd2VkTGVuZ3RoczogdW5kZWZpbmVkIHwgcmVhZG9ubHkgbnVtYmVyW10gPSB1bmRlZmluZWQ7XG4gIGlmICh0eXBlb2YgYml0TGVuT3JPcHRzID09PSAnb2JqZWN0JyAmJiBiaXRMZW5Pck9wdHMgIT0gbnVsbCkge1xuICAgIGlmIChvcHRzLnNxcnQgfHwgaXNMRSkgdGhyb3cgbmV3IEVycm9yKCdjYW5ub3Qgc3BlY2lmeSBvcHRzIGluIHR3byBhcmd1bWVudHMnKTtcbiAgICBjb25zdCBfb3B0cyA9IGJpdExlbk9yT3B0cztcbiAgICBpZiAoX29wdHMuQklUUykgX25iaXRMZW5ndGggPSBfb3B0cy5CSVRTO1xuICAgIGlmIChfb3B0cy5zcXJ0KSBfc3FydCA9IF9vcHRzLnNxcnQ7XG4gICAgaWYgKHR5cGVvZiBfb3B0cy5pc0xFID09PSAnYm9vbGVhbicpIGlzTEUgPSBfb3B0cy5pc0xFO1xuICAgIGlmICh0eXBlb2YgX29wdHMubW9kRnJvbUJ5dGVzID09PSAnYm9vbGVhbicpIG1vZEZyb21CeXRlcyA9IF9vcHRzLm1vZEZyb21CeXRlcztcbiAgICBhbGxvd2VkTGVuZ3RocyA9IF9vcHRzLmFsbG93ZWRMZW5ndGhzO1xuICB9IGVsc2Uge1xuICAgIGlmICh0eXBlb2YgYml0TGVuT3JPcHRzID09PSAnbnVtYmVyJykgX25iaXRMZW5ndGggPSBiaXRMZW5Pck9wdHM7XG4gICAgaWYgKG9wdHMuc3FydCkgX3NxcnQgPSBvcHRzLnNxcnQ7XG4gIH1cbiAgY29uc3QgeyBuQml0TGVuZ3RoOiBCSVRTLCBuQnl0ZUxlbmd0aDogQllURVMgfSA9IG5MZW5ndGgoT1JERVIsIF9uYml0TGVuZ3RoKTtcbiAgaWYgKEJZVEVTID4gMjA0OCkgdGhyb3cgbmV3IEVycm9yKCdpbnZhbGlkIGZpZWxkOiBleHBlY3RlZCBPUkRFUiBvZiA8PSAyMDQ4IGJ5dGVzJyk7XG4gIGxldCBzcXJ0UDogUmV0dXJuVHlwZTx0eXBlb2YgRnBTcXJ0PjsgLy8gY2FjaGVkIHNxcnRQXG4gIGNvbnN0IGY6IFJlYWRvbmx5PEZwRmllbGQ+ID0gT2JqZWN0LmZyZWV6ZSh7XG4gICAgT1JERVIsXG4gICAgaXNMRSxcbiAgICBCSVRTLFxuICAgIEJZVEVTLFxuICAgIE1BU0s6IGJpdE1hc2soQklUUyksXG4gICAgWkVSTzogXzBuLFxuICAgIE9ORTogXzFuLFxuICAgIGFsbG93ZWRMZW5ndGhzOiBhbGxvd2VkTGVuZ3RocyxcbiAgICBjcmVhdGU6IChudW0pID0+IG1vZChudW0sIE9SREVSKSxcbiAgICBpc1ZhbGlkOiAobnVtKSA9PiB7XG4gICAgICBpZiAodHlwZW9mIG51bSAhPT0gJ2JpZ2ludCcpXG4gICAgICAgIHRocm93IG5ldyBFcnJvcignaW52YWxpZCBmaWVsZCBlbGVtZW50OiBleHBlY3RlZCBiaWdpbnQsIGdvdCAnICsgdHlwZW9mIG51bSk7XG4gICAgICByZXR1cm4gXzBuIDw9IG51bSAmJiBudW0gPCBPUkRFUjsgLy8gMCBpcyB2YWxpZCBlbGVtZW50LCBidXQgaXQncyBub3QgaW52ZXJ0aWJsZVxuICAgIH0sXG4gICAgaXMwOiAobnVtKSA9PiBudW0gPT09IF8wbixcbiAgICAvLyBpcyB2YWxpZCBhbmQgaW52ZXJ0aWJsZVxuICAgIGlzVmFsaWROb3QwOiAobnVtOiBiaWdpbnQpID0+ICFmLmlzMChudW0pICYmIGYuaXNWYWxpZChudW0pLFxuICAgIGlzT2RkOiAobnVtKSA9PiAobnVtICYgXzFuKSA9PT0gXzFuLFxuICAgIG5lZzogKG51bSkgPT4gbW9kKC1udW0sIE9SREVSKSxcbiAgICBlcWw6IChsaHMsIHJocykgPT4gbGhzID09PSByaHMsXG5cbiAgICBzcXI6IChudW0pID0+IG1vZChudW0gKiBudW0sIE9SREVSKSxcbiAgICBhZGQ6IChsaHMsIHJocykgPT4gbW9kKGxocyArIHJocywgT1JERVIpLFxuICAgIHN1YjogKGxocywgcmhzKSA9PiBtb2QobGhzIC0gcmhzLCBPUkRFUiksXG4gICAgbXVsOiAobGhzLCByaHMpID0+IG1vZChsaHMgKiByaHMsIE9SREVSKSxcbiAgICBwb3c6IChudW0sIHBvd2VyKSA9PiBGcFBvdyhmLCBudW0sIHBvd2VyKSxcbiAgICBkaXY6IChsaHMsIHJocykgPT4gbW9kKGxocyAqIGludmVydChyaHMsIE9SREVSKSwgT1JERVIpLFxuXG4gICAgLy8gU2FtZSBhcyBhYm92ZSwgYnV0IGRvZXNuJ3Qgbm9ybWFsaXplXG4gICAgc3FyTjogKG51bSkgPT4gbnVtICogbnVtLFxuICAgIGFkZE46IChsaHMsIHJocykgPT4gbGhzICsgcmhzLFxuICAgIHN1Yk46IChsaHMsIHJocykgPT4gbGhzIC0gcmhzLFxuICAgIG11bE46IChsaHMsIHJocykgPT4gbGhzICogcmhzLFxuXG4gICAgaW52OiAobnVtKSA9PiBpbnZlcnQobnVtLCBPUkRFUiksXG4gICAgc3FydDpcbiAgICAgIF9zcXJ0IHx8XG4gICAgICAoKG4pID0+IHtcbiAgICAgICAgaWYgKCFzcXJ0UCkgc3FydFAgPSBGcFNxcnQoT1JERVIpO1xuICAgICAgICByZXR1cm4gc3FydFAoZiwgbik7XG4gICAgICB9KSxcbiAgICB0b0J5dGVzOiAobnVtKSA9PiAoaXNMRSA/IG51bWJlclRvQnl0ZXNMRShudW0sIEJZVEVTKSA6IG51bWJlclRvQnl0ZXNCRShudW0sIEJZVEVTKSksXG4gICAgZnJvbUJ5dGVzOiAoYnl0ZXMsIHNraXBWYWxpZGF0aW9uID0gdHJ1ZSkgPT4ge1xuICAgICAgaWYgKGFsbG93ZWRMZW5ndGhzKSB7XG4gICAgICAgIGlmICghYWxsb3dlZExlbmd0aHMuaW5jbHVkZXMoYnl0ZXMubGVuZ3RoKSB8fCBieXRlcy5sZW5ndGggPiBCWVRFUykge1xuICAgICAgICAgIHRocm93IG5ldyBFcnJvcihcbiAgICAgICAgICAgICdGaWVsZC5mcm9tQnl0ZXM6IGV4cGVjdGVkICcgKyBhbGxvd2VkTGVuZ3RocyArICcgYnl0ZXMsIGdvdCAnICsgYnl0ZXMubGVuZ3RoXG4gICAgICAgICAgKTtcbiAgICAgICAgfVxuICAgICAgICBjb25zdCBwYWRkZWQgPSBuZXcgVWludDhBcnJheShCWVRFUyk7XG4gICAgICAgIC8vIGlzTEUgYWRkIDAgdG8gcmlnaHQsICFpc0xFIHRvIHRoZSBsZWZ0LlxuICAgICAgICBwYWRkZWQuc2V0KGJ5dGVzLCBpc0xFID8gMCA6IHBhZGRlZC5sZW5ndGggLSBieXRlcy5sZW5ndGgpO1xuICAgICAgICBieXRlcyA9IHBhZGRlZDtcbiAgICAgIH1cbiAgICAgIGlmIChieXRlcy5sZW5ndGggIT09IEJZVEVTKVxuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ0ZpZWxkLmZyb21CeXRlczogZXhwZWN0ZWQgJyArIEJZVEVTICsgJyBieXRlcywgZ290ICcgKyBieXRlcy5sZW5ndGgpO1xuICAgICAgbGV0IHNjYWxhciA9IGlzTEUgPyBieXRlc1RvTnVtYmVyTEUoYnl0ZXMpIDogYnl0ZXNUb051bWJlckJFKGJ5dGVzKTtcbiAgICAgIGlmIChtb2RGcm9tQnl0ZXMpIHNjYWxhciA9IG1vZChzY2FsYXIsIE9SREVSKTtcbiAgICAgIGlmICghc2tpcFZhbGlkYXRpb24pXG4gICAgICAgIGlmICghZi5pc1ZhbGlkKHNjYWxhcikpIHRocm93IG5ldyBFcnJvcignaW52YWxpZCBmaWVsZCBlbGVtZW50OiBvdXRzaWRlIG9mIHJhbmdlIDAuLk9SREVSJyk7XG4gICAgICAvLyBOT1RFOiB3ZSBkb24ndCB2YWxpZGF0ZSBzY2FsYXIgaGVyZSwgcGxlYXNlIHVzZSBpc1ZhbGlkLiBUaGlzIGRvbmUgc3VjaCB3YXkgYmVjYXVzZSBzb21lXG4gICAgICAvLyBwcm90b2NvbCBtYXkgYWxsb3cgbm9uLXJlZHVjZWQgc2NhbGFyIHRoYXQgcmVkdWNlZCBsYXRlciBvciBjaGFuZ2VkIHNvbWUgb3RoZXIgd2F5LlxuICAgICAgcmV0dXJuIHNjYWxhcjtcbiAgICB9LFxuICAgIC8vIFRPRE86IHdlIGRvbid0IG5lZWQgaXQgaGVyZSwgbW92ZSBvdXQgdG8gc2VwYXJhdGUgZm5cbiAgICBpbnZlcnRCYXRjaDogKGxzdCkgPT4gRnBJbnZlcnRCYXRjaChmLCBsc3QpLFxuICAgIC8vIFdlIGNhbid0IG1vdmUgdGhpcyBvdXQgYmVjYXVzZSBGcDYsIEZwMTIgaW1wbGVtZW50IGl0XG4gICAgLy8gYW5kIGl0J3MgdW5jbGVhciB3aGF0IHRvIHJldHVybiBpbiB0aGVyZS5cbiAgICBjbW92OiAoYSwgYiwgYykgPT4gKGMgPyBiIDogYSksXG4gIH0gYXMgRnBGaWVsZCk7XG4gIHJldHVybiBPYmplY3QuZnJlZXplKGYpO1xufVxuXG4vLyBHZW5lcmljIHJhbmRvbSBzY2FsYXIsIHdlIGNhbiBkbyBzYW1lIGZvciBvdGhlciBmaWVsZHMgaWYgdmlhIEZwMi5tdWwoRnAyLk9ORSwgRnAyLnJhbmRvbSk/XG4vLyBUaGlzIGFsbG93cyB1bnNhZmUgbWV0aG9kcyBsaWtlIGlnbm9yZSBiaWFzIG9yIHplcm8uIFRoZXNlIHVuc2FmZSwgYnV0IG9mdGVuIHVzZWQgaW4gZGlmZmVyZW50IHByb3RvY29scyAoaWYgZGV0ZXJtaW5pc3RpYyBSTkcpLlxuLy8gd2hpY2ggbWVhbiB3ZSBjYW5ub3QgZm9yY2UgdGhpcyB2aWEgb3B0cy5cbi8vIE5vdCBzdXJlIHdoYXQgdG8gZG8gd2l0aCByYW5kb21CeXRlcywgd2UgY2FuIGFjY2VwdCBpdCBpbnNpZGUgb3B0cyBpZiB3YW50ZWQuXG4vLyBQcm9iYWJseSBuZWVkIHRvIGV4cG9ydCBnZXRNaW5IYXNoTGVuZ3RoIHNvbWV3aGVyZT9cbi8vIHJhbmRvbShieXRlcz86IFVpbnQ4QXJyYXksIHVuc2FmZUFsbG93WmVybyA9IGZhbHNlLCB1bnNhZmVBbGxvd0JpYXMgPSBmYWxzZSkge1xuLy8gICBjb25zdCBMRU4gPSAhdW5zYWZlQWxsb3dCaWFzID8gZ2V0TWluSGFzaExlbmd0aChPUkRFUikgOiBCWVRFUztcbi8vICAgaWYgKGJ5dGVzID09PSB1bmRlZmluZWQpIGJ5dGVzID0gcmFuZG9tQnl0ZXMoTEVOKTsgLy8gX29wdHMucmFuZG9tQnl0ZXM/XG4vLyAgIGNvbnN0IG51bSA9IGlzTEUgPyBieXRlc1RvTnVtYmVyTEUoYnl0ZXMpIDogYnl0ZXNUb051bWJlckJFKGJ5dGVzKTtcbi8vICAgLy8gYG1vZCh4LCAxMSlgIGNhbiBzb21ldGltZXMgcHJvZHVjZSAwLiBgbW9kKHgsIDEwKSArIDFgIGlzIHRoZSBzYW1lLCBidXQgbm8gMFxuLy8gICBjb25zdCByZWR1Y2VkID0gdW5zYWZlQWxsb3daZXJvID8gbW9kKG51bSwgT1JERVIpIDogbW9kKG51bSwgT1JERVIgLSBfMW4pICsgXzFuO1xuLy8gICByZXR1cm4gcmVkdWNlZDtcbi8vIH0sXG5cbmV4cG9ydCBmdW5jdGlvbiBGcFNxcnRPZGQ8VD4oRnA6IElGaWVsZDxUPiwgZWxtOiBUKTogVCB7XG4gIGlmICghRnAuaXNPZGQpIHRocm93IG5ldyBFcnJvcihcIkZpZWxkIGRvZXNuJ3QgaGF2ZSBpc09kZFwiKTtcbiAgY29uc3Qgcm9vdCA9IEZwLnNxcnQoZWxtKTtcbiAgcmV0dXJuIEZwLmlzT2RkKHJvb3QpID8gcm9vdCA6IEZwLm5lZyhyb290KTtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIEZwU3FydEV2ZW48VD4oRnA6IElGaWVsZDxUPiwgZWxtOiBUKTogVCB7XG4gIGlmICghRnAuaXNPZGQpIHRocm93IG5ldyBFcnJvcihcIkZpZWxkIGRvZXNuJ3QgaGF2ZSBpc09kZFwiKTtcbiAgY29uc3Qgcm9vdCA9IEZwLnNxcnQoZWxtKTtcbiAgcmV0dXJuIEZwLmlzT2RkKHJvb3QpID8gRnAubmVnKHJvb3QpIDogcm9vdDtcbn1cblxuLyoqXG4gKiBcIkNvbnN0YW50LXRpbWVcIiBwcml2YXRlIGtleSBnZW5lcmF0aW9uIHV0aWxpdHkuXG4gKiBTYW1lIGFzIG1hcEtleVRvRmllbGQsIGJ1dCBhY2NlcHRzIGxlc3MgYnl0ZXMgKDQwIGluc3RlYWQgb2YgNDggZm9yIDMyLWJ5dGUgZmllbGQpLlxuICogV2hpY2ggbWFrZXMgaXQgc2xpZ2h0bHkgbW9yZSBiaWFzZWQsIGxlc3Mgc2VjdXJlLlxuICogQGRlcHJlY2F0ZWQgdXNlIGBtYXBLZXlUb0ZpZWxkYCBpbnN0ZWFkXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBoYXNoVG9Qcml2YXRlU2NhbGFyKFxuICBoYXNoOiBzdHJpbmcgfCBVaW50OEFycmF5LFxuICBncm91cE9yZGVyOiBiaWdpbnQsXG4gIGlzTEUgPSBmYWxzZVxuKTogYmlnaW50IHtcbiAgaGFzaCA9IGVuc3VyZUJ5dGVzKCdwcml2YXRlSGFzaCcsIGhhc2gpO1xuICBjb25zdCBoYXNoTGVuID0gaGFzaC5sZW5ndGg7XG4gIGNvbnN0IG1pbkxlbiA9IG5MZW5ndGgoZ3JvdXBPcmRlcikubkJ5dGVMZW5ndGggKyA4O1xuICBpZiAobWluTGVuIDwgMjQgfHwgaGFzaExlbiA8IG1pbkxlbiB8fCBoYXNoTGVuID4gMTAyNClcbiAgICB0aHJvdyBuZXcgRXJyb3IoXG4gICAgICAnaGFzaFRvUHJpdmF0ZVNjYWxhcjogZXhwZWN0ZWQgJyArIG1pbkxlbiArICctMTAyNCBieXRlcyBvZiBpbnB1dCwgZ290ICcgKyBoYXNoTGVuXG4gICAgKTtcbiAgY29uc3QgbnVtID0gaXNMRSA/IGJ5dGVzVG9OdW1iZXJMRShoYXNoKSA6IGJ5dGVzVG9OdW1iZXJCRShoYXNoKTtcbiAgcmV0dXJuIG1vZChudW0sIGdyb3VwT3JkZXIgLSBfMW4pICsgXzFuO1xufVxuXG4vKipcbiAqIFJldHVybnMgdG90YWwgbnVtYmVyIG9mIGJ5dGVzIGNvbnN1bWVkIGJ5IHRoZSBmaWVsZCBlbGVtZW50LlxuICogRm9yIGV4YW1wbGUsIDMyIGJ5dGVzIGZvciB1c3VhbCAyNTYtYml0IHdlaWVyc3RyYXNzIGN1cnZlLlxuICogQHBhcmFtIGZpZWxkT3JkZXIgbnVtYmVyIG9mIGZpZWxkIGVsZW1lbnRzLCB1c3VhbGx5IENVUlZFLm5cbiAqIEByZXR1cm5zIGJ5dGUgbGVuZ3RoIG9mIGZpZWxkXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBnZXRGaWVsZEJ5dGVzTGVuZ3RoKGZpZWxkT3JkZXI6IGJpZ2ludCk6IG51bWJlciB7XG4gIGlmICh0eXBlb2YgZmllbGRPcmRlciAhPT0gJ2JpZ2ludCcpIHRocm93IG5ldyBFcnJvcignZmllbGQgb3JkZXIgbXVzdCBiZSBiaWdpbnQnKTtcbiAgY29uc3QgYml0TGVuZ3RoID0gZmllbGRPcmRlci50b1N0cmluZygyKS5sZW5ndGg7XG4gIHJldHVybiBNYXRoLmNlaWwoYml0TGVuZ3RoIC8gOCk7XG59XG5cbi8qKlxuICogUmV0dXJucyBtaW5pbWFsIGFtb3VudCBvZiBieXRlcyB0aGF0IGNhbiBiZSBzYWZlbHkgcmVkdWNlZFxuICogYnkgZmllbGQgb3JkZXIuXG4gKiBTaG91bGQgYmUgMl4tMTI4IGZvciAxMjgtYml0IGN1cnZlIHN1Y2ggYXMgUDI1Ni5cbiAqIEBwYXJhbSBmaWVsZE9yZGVyIG51bWJlciBvZiBmaWVsZCBlbGVtZW50cywgdXN1YWxseSBDVVJWRS5uXG4gKiBAcmV0dXJucyBieXRlIGxlbmd0aCBvZiB0YXJnZXQgaGFzaFxuICovXG5leHBvcnQgZnVuY3Rpb24gZ2V0TWluSGFzaExlbmd0aChmaWVsZE9yZGVyOiBiaWdpbnQpOiBudW1iZXIge1xuICBjb25zdCBsZW5ndGggPSBnZXRGaWVsZEJ5dGVzTGVuZ3RoKGZpZWxkT3JkZXIpO1xuICByZXR1cm4gbGVuZ3RoICsgTWF0aC5jZWlsKGxlbmd0aCAvIDIpO1xufVxuXG4vKipcbiAqIFwiQ29uc3RhbnQtdGltZVwiIHByaXZhdGUga2V5IGdlbmVyYXRpb24gdXRpbGl0eS5cbiAqIENhbiB0YWtlIChuICsgbi8yKSBvciBtb3JlIGJ5dGVzIG9mIHVuaWZvcm0gaW5wdXQgZS5nLiBmcm9tIENTUFJORyBvciBLREZcbiAqIGFuZCBjb252ZXJ0IHRoZW0gaW50byBwcml2YXRlIHNjYWxhciwgd2l0aCB0aGUgbW9kdWxvIGJpYXMgYmVpbmcgbmVnbGlnaWJsZS5cbiAqIE5lZWRzIGF0IGxlYXN0IDQ4IGJ5dGVzIG9mIGlucHV0IGZvciAzMi1ieXRlIHByaXZhdGUga2V5LlxuICogaHR0cHM6Ly9yZXNlYXJjaC5rdWRlbHNraXNlY3VyaXR5LmNvbS8yMDIwLzA3LzI4L3RoZS1kZWZpbml0aXZlLWd1aWRlLXRvLW1vZHVsby1iaWFzLWFuZC1ob3ctdG8tYXZvaWQtaXQvXG4gKiBGSVBTIDE4Ni01LCBBLjIgaHR0cHM6Ly9jc3JjLm5pc3QuZ292L3B1YmxpY2F0aW9ucy9kZXRhaWwvZmlwcy8xODYvNS9maW5hbFxuICogUkZDIDkzODAsIGh0dHBzOi8vd3d3LnJmYy1lZGl0b3Iub3JnL3JmYy9yZmM5MzgwI3NlY3Rpb24tNVxuICogQHBhcmFtIGhhc2ggaGFzaCBvdXRwdXQgZnJvbSBTSEEzIG9yIGEgc2ltaWxhciBmdW5jdGlvblxuICogQHBhcmFtIGdyb3VwT3JkZXIgc2l6ZSBvZiBzdWJncm91cCAtIChlLmcuIHNlY3AyNTZrMS5DVVJWRS5uKVxuICogQHBhcmFtIGlzTEUgaW50ZXJwcmV0IGhhc2ggYnl0ZXMgYXMgTEUgbnVtXG4gKiBAcmV0dXJucyB2YWxpZCBwcml2YXRlIHNjYWxhclxuICovXG5leHBvcnQgZnVuY3Rpb24gbWFwSGFzaFRvRmllbGQoa2V5OiBVaW50OEFycmF5LCBmaWVsZE9yZGVyOiBiaWdpbnQsIGlzTEUgPSBmYWxzZSk6IFVpbnQ4QXJyYXkge1xuICBjb25zdCBsZW4gPSBrZXkubGVuZ3RoO1xuICBjb25zdCBmaWVsZExlbiA9IGdldEZpZWxkQnl0ZXNMZW5ndGgoZmllbGRPcmRlcik7XG4gIGNvbnN0IG1pbkxlbiA9IGdldE1pbkhhc2hMZW5ndGgoZmllbGRPcmRlcik7XG4gIC8vIE5vIHNtYWxsIG51bWJlcnM6IG5lZWQgdG8gdW5kZXJzdGFuZCBiaWFzIHN0b3J5LiBObyBodWdlIG51bWJlcnM6IGVhc2llciB0byBkZXRlY3QgSlMgdGltaW5ncy5cbiAgaWYgKGxlbiA8IDE2IHx8IGxlbiA8IG1pbkxlbiB8fCBsZW4gPiAxMDI0KVxuICAgIHRocm93IG5ldyBFcnJvcignZXhwZWN0ZWQgJyArIG1pbkxlbiArICctMTAyNCBieXRlcyBvZiBpbnB1dCwgZ290ICcgKyBsZW4pO1xuICBjb25zdCBudW0gPSBpc0xFID8gYnl0ZXNUb051bWJlckxFKGtleSkgOiBieXRlc1RvTnVtYmVyQkUoa2V5KTtcbiAgLy8gYG1vZCh4LCAxMSlgIGNhbiBzb21ldGltZXMgcHJvZHVjZSAwLiBgbW9kKHgsIDEwKSArIDFgIGlzIHRoZSBzYW1lLCBidXQgbm8gMFxuICBjb25zdCByZWR1Y2VkID0gbW9kKG51bSwgZmllbGRPcmRlciAtIF8xbikgKyBfMW47XG4gIHJldHVybiBpc0xFID8gbnVtYmVyVG9CeXRlc0xFKHJlZHVjZWQsIGZpZWxkTGVuKSA6IG51bWJlclRvQnl0ZXNCRShyZWR1Y2VkLCBmaWVsZExlbik7XG59XG4iLCAiLyoqXG4gKiBNZXRob2RzIGZvciBlbGxpcHRpYyBjdXJ2ZSBtdWx0aXBsaWNhdGlvbiBieSBzY2FsYXJzLlxuICogQ29udGFpbnMgd05BRiwgcGlwcGVuZ2VyLlxuICogQG1vZHVsZVxuICovXG4vKiEgbm9ibGUtY3VydmVzIC0gTUlUIExpY2Vuc2UgKGMpIDIwMjIgUGF1bCBNaWxsZXIgKHBhdWxtaWxsci5jb20pICovXG5pbXBvcnQgeyBiaXRMZW4sIGJpdE1hc2ssIHZhbGlkYXRlT2JqZWN0IH0gZnJvbSAnLi4vdXRpbHMudHMnO1xuaW1wb3J0IHsgRmllbGQsIEZwSW52ZXJ0QmF0Y2gsIG5MZW5ndGgsIHZhbGlkYXRlRmllbGQsIHR5cGUgSUZpZWxkIH0gZnJvbSAnLi9tb2R1bGFyLnRzJztcblxuY29uc3QgXzBuID0gQmlnSW50KDApO1xuY29uc3QgXzFuID0gQmlnSW50KDEpO1xuXG5leHBvcnQgdHlwZSBBZmZpbmVQb2ludDxUPiA9IHtcbiAgeDogVDtcbiAgeTogVDtcbn0gJiB7IFo/OiBuZXZlciB9O1xuXG4vLyBUaGlzIHdhcyBpbml0aWFseSBkbyB0aGlzIHdheSB0byByZS11c2UgbW9udGdvbWVyeSBsYWRkZXIgaW4gZmllbGQgKGFkZC0+bXVsLGRvdWJsZS0+c3FyKSwgYnV0XG4vLyB0aGF0IGRpZG4ndCBoYXBwZW4gYW5kIHRoZXJlIGlzIHByb2JhYmx5IG5vdCBtdWNoIHJlYXNvbiB0byBoYXZlIHNlcGFyYXRlIEdyb3VwIGxpa2UgdGhpcz9cbmV4cG9ydCBpbnRlcmZhY2UgR3JvdXA8VCBleHRlbmRzIEdyb3VwPFQ+PiB7XG4gIGRvdWJsZSgpOiBUO1xuICBuZWdhdGUoKTogVDtcbiAgYWRkKG90aGVyOiBUKTogVDtcbiAgc3VidHJhY3Qob3RoZXI6IFQpOiBUO1xuICBlcXVhbHMob3RoZXI6IFQpOiBib29sZWFuO1xuICBtdWx0aXBseShzY2FsYXI6IGJpZ2ludCk6IFQ7XG4gIHRvQWZmaW5lPyhpbnZlcnRlZFo/OiBhbnkpOiBBZmZpbmVQb2ludDxhbnk+O1xufVxuXG4vLyBXZSBjYW4ndCBcImFic3RyYWN0IG91dFwiIGNvb3JkaW5hdGVzIChYLCBZLCBaOyBhbmQgVCBpbiBFZHdhcmRzKTogYXJndW1lbnQgbmFtZXMgb2YgY29uc3RydWN0b3Jcbi8vIGFyZSBub3QgYWNjZXNzaWJsZS4gU2VlIFR5cGVzY3JpcHQgZ2gtNTYwOTMsIGdoLTQxNTk0LlxuLy9cbi8vIFdlIGhhdmUgdG8gdXNlIHJlY3Vyc2l2ZSB0eXBlcywgc28gaXQgd2lsbCByZXR1cm4gYWN0dWFsIHBvaW50LCBub3QgY29uc3RhaW5lZCBgQ3VydmVQb2ludGAuXG4vLyBJZiwgYXQgYW55IHBvaW50LCBQIGlzIGBhbnlgLCBpdCB3aWxsIGVyYXNlIGFsbCB0eXBlcyBhbmQgcmVwbGFjZSBpdFxuLy8gd2l0aCBgYW55YCwgYmVjYXVzZSBvZiByZWN1cnNpb24sIGBhbnkgaW1wbGVtZW50cyBDdXJ2ZVBvaW50YCxcbi8vIGJ1dCB3ZSBsb3NlIGFsbCBjb25zdHJhaW5zIG9uIG1ldGhvZHMuXG5cbi8qKiBCYXNlIGludGVyZmFjZSBmb3IgYWxsIGVsbGlwdGljIGN1cnZlIFBvaW50cy4gKi9cbmV4cG9ydCBpbnRlcmZhY2UgQ3VydmVQb2ludDxGLCBQIGV4dGVuZHMgQ3VydmVQb2ludDxGLCBQPj4gZXh0ZW5kcyBHcm91cDxQPiB7XG4gIC8qKiBBZmZpbmUgeCBjb29yZGluYXRlLiBEaWZmZXJlbnQgZnJvbSBwcm9qZWN0aXZlIC8gZXh0ZW5kZWQgWCBjb29yZGluYXRlLiAqL1xuICB4OiBGO1xuICAvKiogQWZmaW5lIHkgY29vcmRpbmF0ZS4gRGlmZmVyZW50IGZyb20gcHJvamVjdGl2ZSAvIGV4dGVuZGVkIFkgY29vcmRpbmF0ZS4gKi9cbiAgeTogRjtcbiAgWj86IEY7XG4gIGRvdWJsZSgpOiBQO1xuICBuZWdhdGUoKTogUDtcbiAgYWRkKG90aGVyOiBQKTogUDtcbiAgc3VidHJhY3Qob3RoZXI6IFApOiBQO1xuICBlcXVhbHMob3RoZXI6IFApOiBib29sZWFuO1xuICBtdWx0aXBseShzY2FsYXI6IGJpZ2ludCk6IFA7XG4gIGFzc2VydFZhbGlkaXR5KCk6IHZvaWQ7XG4gIGNsZWFyQ29mYWN0b3IoKTogUDtcbiAgaXMwKCk6IGJvb2xlYW47XG4gIGlzVG9yc2lvbkZyZWUoKTogYm9vbGVhbjtcbiAgaXNTbWFsbE9yZGVyKCk6IGJvb2xlYW47XG4gIG11bHRpcGx5VW5zYWZlKHNjYWxhcjogYmlnaW50KTogUDtcbiAgLyoqXG4gICAqIE1hc3NpdmVseSBzcGVlZHMgdXAgYHAubXVsdGlwbHkobilgIGJ5IHVzaW5nIHByZWNvbXB1dGUgdGFibGVzIChjYWNoaW5nKS4gU2VlIHtAbGluayB3TkFGfS5cbiAgICogQHBhcmFtIGlzTGF6eSBjYWxjdWxhdGUgY2FjaGUgbm93LiBEZWZhdWx0ICh0cnVlKSBlbnN1cmVzIGl0J3MgZGVmZXJyZWQgdG8gZmlyc3QgYG11bHRpcGx5KClgXG4gICAqL1xuICBwcmVjb21wdXRlKHdpbmRvd1NpemU/OiBudW1iZXIsIGlzTGF6eT86IGJvb2xlYW4pOiBQO1xuICAvKiogQ29udmVydHMgcG9pbnQgdG8gMkQgeHkgYWZmaW5lIGNvb3JkaW5hdGVzICovXG4gIHRvQWZmaW5lKGludmVydGVkWj86IEYpOiBBZmZpbmVQb2ludDxGPjtcbiAgdG9CeXRlcygpOiBVaW50OEFycmF5O1xuICB0b0hleCgpOiBzdHJpbmc7XG59XG5cbi8qKiBCYXNlIGludGVyZmFjZSBmb3IgYWxsIGVsbGlwdGljIGN1cnZlIFBvaW50IGNvbnN0cnVjdG9ycy4gKi9cbmV4cG9ydCBpbnRlcmZhY2UgQ3VydmVQb2ludENvbnM8UCBleHRlbmRzIEN1cnZlUG9pbnQ8YW55LCBQPj4ge1xuICBbU3ltYm9sLmhhc0luc3RhbmNlXTogKGl0ZW06IHVua25vd24pID0+IGJvb2xlYW47XG4gIEJBU0U6IFA7XG4gIFpFUk86IFA7XG4gIC8qKiBGaWVsZCBmb3IgYmFzaWMgY3VydmUgbWF0aCAqL1xuICBGcDogSUZpZWxkPFBfRjxQPj47XG4gIC8qKiBTY2FsYXIgZmllbGQsIGZvciBzY2FsYXJzIGluIG11bHRpcGx5IGFuZCBvdGhlcnMgKi9cbiAgRm46IElGaWVsZDxiaWdpbnQ+O1xuICAvKiogQ3JlYXRlcyBwb2ludCBmcm9tIHgsIHkuIERvZXMgTk9UIHZhbGlkYXRlIGlmIHRoZSBwb2ludCBpcyB2YWxpZC4gVXNlIGAuYXNzZXJ0VmFsaWRpdHkoKWAuICovXG4gIGZyb21BZmZpbmUocDogQWZmaW5lUG9pbnQ8UF9GPFA+Pik6IFA7XG4gIGZyb21CeXRlcyhieXRlczogVWludDhBcnJheSk6IFA7XG4gIGZyb21IZXgoaGV4OiBVaW50OEFycmF5IHwgc3RyaW5nKTogUDtcbn1cblxuLy8gVHlwZSBpbmZlcmVuY2UgaGVscGVyczogUEMgLSBQb2ludENvbnN0cnVjdG9yLCBQIC0gUG9pbnQsIEZwIC0gRmllbGQgZWxlbWVudFxuLy8gU2hvcnQgbmFtZXMsIGJlY2F1c2Ugd2UgdXNlIHRoZW0gYSBsb3QgaW4gcmVzdWx0IHR5cGVzOlxuLy8gKiB3ZSBjYW4ndCBkbyAnUCA9IEdldEN1cnZlUG9pbnQ8UEM+JzogdGhpcyBpcyBkZWZhdWx0IHZhbHVlIGFuZCBkb2Vzbid0IGNvbnN0cmFpbiBhbnl0aGluZ1xuLy8gKiB3ZSBjYW4ndCBkbyAndHlwZSBYID0gR2V0Q3VydmVQb2ludDxQQz4nOiBpdCB3b24ndCBiZSBhY2Nlc2libGUgZm9yIGFyZ3VtZW50cy9yZXR1cm4gdHlwZXNcbi8vICogYEN1cnZlUG9pbnRDb25zPFAgZXh0ZW5kcyBDdXJ2ZVBvaW50PGFueSwgUD4+YCBjb25zdHJhaW50cyBmcm9tIGludGVyZmFjZSBkZWZpbml0aW9uXG4vLyAgIHdvbid0IHByb3BhZ2F0ZSwgaWYgYFBDIGV4dGVuZHMgQ3VydmVQb2ludENvbnM8YW55PmA6IHRoZSBQIHdvdWxkIGJlICdhbnknLCB3aGljaCBpcyBpbmNvcnJlY3Rcbi8vICogUEMgY291bGQgYmUgc3VwZXIgc3BlY2lmaWMgd2l0aCBzdXBlciBzcGVjaWZpYyBQLCB3aGljaCBpbXBsZW1lbnRzIEN1cnZlUG9pbnQ8YW55LCBQPi5cbi8vICAgdGhpcyBtZWFucyB3ZSBuZWVkIHRvIGRvIHN0dWZmIGxpa2Vcbi8vICAgYGZ1bmN0aW9uIHRlc3Q8UCBleHRlbmRzIEN1cnZlUG9pbnQ8YW55LCBQPiwgUEMgZXh0ZW5kcyBDdXJ2ZVBvaW50Q29uczxQPj4oYFxuLy8gICBpZiB3ZSB3YW50IHR5cGUgc2FmZXR5IGFyb3VuZCBQLCBvdGhlcndpc2UgUENfUDxQQz4gd2lsbCBiZSBhbnlcblxuLyoqIFJldHVybnMgRnAgdHlwZSBmcm9tIFBvaW50IChQX0Y8UD4gPT0gUC5GKSAqL1xuZXhwb3J0IHR5cGUgUF9GPFAgZXh0ZW5kcyBDdXJ2ZVBvaW50PGFueSwgUD4+ID0gUCBleHRlbmRzIEN1cnZlUG9pbnQ8aW5mZXIgRiwgUD4gPyBGIDogbmV2ZXI7XG4vKiogUmV0dXJucyBGcCB0eXBlIGZyb20gUG9pbnRDb25zIChQQ19GPFBDPiA9PSBQQy5QLkYpICovXG5leHBvcnQgdHlwZSBQQ19GPFBDIGV4dGVuZHMgQ3VydmVQb2ludENvbnM8Q3VydmVQb2ludDxhbnksIGFueT4+PiA9IFBDWydGcCddWydaRVJPJ107XG4vKiogUmV0dXJucyBQb2ludCB0eXBlIGZyb20gUG9pbnRDb25zIChQQ19QPFBDPiA9PSBQQy5QKSAqL1xuZXhwb3J0IHR5cGUgUENfUDxQQyBleHRlbmRzIEN1cnZlUG9pbnRDb25zPEN1cnZlUG9pbnQ8YW55LCBhbnk+Pj4gPSBQQ1snWkVSTyddO1xuXG4vLyBVZ2x5IGhhY2sgdG8gZ2V0IHByb3BlciB0eXBlIGluZmVyZW5jZSwgYmVjYXVzZSBpbiB0eXBlc2NyaXB0IGZhaWxzIHRvIGluZmVyIHJlc3Vyc2l2ZWx5LlxuLy8gVGhlIGhhY2sgYWxsb3dzIHRvIGRvIHVwIHRvIDEwIGNoYWluZWQgb3BlcmF0aW9ucyB3aXRob3V0IGFwcGx5aW5nIHR5cGUgZXJhc3VyZS5cbi8vXG4vLyBUeXBlcyB3aGljaCB3b24ndCB3b3JrOlxuLy8gKiBgQ3VydmVQb2ludENvbnM8Q3VydmVQb2ludDxhbnksIGFueT4+YCwgd2lsbCByZXR1cm4gYGFueWAgYWZ0ZXIgMSBvcGVyYXRpb25cbi8vICogYEN1cnZlUG9pbnRDb25zPGFueT46IFdlaWVyc3RyYXNzUG9pbnRDb25zPGJpZ2ludD4gZXh0ZW5kcyBDdXJ2ZVBvaW50Q29uczxhbnk+ID0gZmFsc2VgXG4vLyAqIGBQIGV4dGVuZHMgQ3VydmVQb2ludCwgUEMgZXh0ZW5kcyBDdXJ2ZVBvaW50Q29uczxQPmBcbi8vICAgICAqIEl0IGNhbid0IGluZmVyIFAgZnJvbSBQQyBhbG9uZVxuLy8gICAgICogVG9vIG1hbnkgcmVsYXRpb25zIGJldHdlZW4gRiwgUCAmIFBDXG4vLyAgICAgKiBJdCB3aWxsIGluZmVyIFAvRiBpZiBgYXJnOiBDdXJ2ZVBvaW50Q29uczxGLCBQPmAsIGJ1dCB3aWxsIGZhaWwgaWYgUEMgaXMgZ2VuZXJpY1xuLy8gICAgICogSXQgd2lsbCB3b3JrIGNvcnJlY3RseSBpZiB0aGVyZSBpcyBhbiBhZGRpdGlvbmFsIGFyZ3VtZW50IG9mIHR5cGUgUFxuLy8gICAgICogQnV0IGdlbmVyYWxseSwgd2UgZG9uJ3Qgd2FudCB0byBwYXJhbWV0cml6ZSBgQ3VydmVQb2ludENvbnNgIG92ZXIgYEZgOiBpdCB3aWxsIGNvbXBsaWNhdGVcbi8vICAgICAgIHR5cGVzLCBtYWtpbmcgdGhlbSB1bi1pbmZlcmFibGVcbi8vIHByZXR0aWVyLWlnbm9yZVxuZXhwb3J0IHR5cGUgUENfQU5ZID0gQ3VydmVQb2ludENvbnM8XG4gIEN1cnZlUG9pbnQ8YW55LFxuICBDdXJ2ZVBvaW50PGFueSxcbiAgQ3VydmVQb2ludDxhbnksXG4gIEN1cnZlUG9pbnQ8YW55LFxuICBDdXJ2ZVBvaW50PGFueSxcbiAgQ3VydmVQb2ludDxhbnksXG4gIEN1cnZlUG9pbnQ8YW55LFxuICBDdXJ2ZVBvaW50PGFueSxcbiAgQ3VydmVQb2ludDxhbnksXG4gIEN1cnZlUG9pbnQ8YW55LCBhbnk+XG4gID4+Pj4+Pj4+PlxuPjtcblxuZXhwb3J0IGludGVyZmFjZSBDdXJ2ZUxlbmd0aHMge1xuICBzZWNyZXRLZXk/OiBudW1iZXI7XG4gIHB1YmxpY0tleT86IG51bWJlcjtcbiAgcHVibGljS2V5VW5jb21wcmVzc2VkPzogbnVtYmVyO1xuICBwdWJsaWNLZXlIYXNQcmVmaXg/OiBib29sZWFuO1xuICBzaWduYXR1cmU/OiBudW1iZXI7XG4gIHNlZWQ/OiBudW1iZXI7XG59XG5leHBvcnQgdHlwZSBHcm91cENvbnN0cnVjdG9yPFQ+ID0ge1xuICBCQVNFOiBUO1xuICBaRVJPOiBUO1xufTtcbi8qKiBAZGVwcmVjYXRlZCAqL1xuZXhwb3J0IHR5cGUgRXh0ZW5kZWRHcm91cENvbnN0cnVjdG9yPFQ+ID0gR3JvdXBDb25zdHJ1Y3RvcjxUPiAmIHtcbiAgRnA6IElGaWVsZDxhbnk+O1xuICBGbjogSUZpZWxkPGJpZ2ludD47XG4gIGZyb21BZmZpbmUoYXA6IEFmZmluZVBvaW50PGFueT4pOiBUO1xufTtcbmV4cG9ydCB0eXBlIE1hcHBlcjxUPiA9IChpOiBUW10pID0+IFRbXTtcblxuZXhwb3J0IGZ1bmN0aW9uIG5lZ2F0ZUN0PFQgZXh0ZW5kcyB7IG5lZ2F0ZTogKCkgPT4gVCB9Pihjb25kaXRpb246IGJvb2xlYW4sIGl0ZW06IFQpOiBUIHtcbiAgY29uc3QgbmVnID0gaXRlbS5uZWdhdGUoKTtcbiAgcmV0dXJuIGNvbmRpdGlvbiA/IG5lZyA6IGl0ZW07XG59XG5cbi8qKlxuICogVGFrZXMgYSBidW5jaCBvZiBQcm9qZWN0aXZlIFBvaW50cyBidXQgZXhlY3V0ZXMgb25seSBvbmVcbiAqIGludmVyc2lvbiBvbiBhbGwgb2YgdGhlbS4gSW52ZXJzaW9uIGlzIHZlcnkgc2xvdyBvcGVyYXRpb24sXG4gKiBzbyB0aGlzIGltcHJvdmVzIHBlcmZvcm1hbmNlIG1hc3NpdmVseS5cbiAqIE9wdGltaXphdGlvbjogY29udmVydHMgYSBsaXN0IG9mIHByb2plY3RpdmUgcG9pbnRzIHRvIGEgbGlzdCBvZiBpZGVudGljYWwgcG9pbnRzIHdpdGggWj0xLlxuICovXG5leHBvcnQgZnVuY3Rpb24gbm9ybWFsaXplWjxQIGV4dGVuZHMgQ3VydmVQb2ludDxhbnksIFA+LCBQQyBleHRlbmRzIEN1cnZlUG9pbnRDb25zPFA+PihcbiAgYzogUEMsXG4gIHBvaW50czogUFtdXG4pOiBQW10ge1xuICBjb25zdCBpbnZlcnRlZFpzID0gRnBJbnZlcnRCYXRjaChcbiAgICBjLkZwLFxuICAgIHBvaW50cy5tYXAoKHApID0+IHAuWiEpXG4gICk7XG4gIHJldHVybiBwb2ludHMubWFwKChwLCBpKSA9PiBjLmZyb21BZmZpbmUocC50b0FmZmluZShpbnZlcnRlZFpzW2ldKSkpO1xufVxuXG5mdW5jdGlvbiB2YWxpZGF0ZVcoVzogbnVtYmVyLCBiaXRzOiBudW1iZXIpIHtcbiAgaWYgKCFOdW1iZXIuaXNTYWZlSW50ZWdlcihXKSB8fCBXIDw9IDAgfHwgVyA+IGJpdHMpXG4gICAgdGhyb3cgbmV3IEVycm9yKCdpbnZhbGlkIHdpbmRvdyBzaXplLCBleHBlY3RlZCBbMS4uJyArIGJpdHMgKyAnXSwgZ290IFc9JyArIFcpO1xufVxuXG4vKiogSW50ZXJuYWwgd05BRiBvcHRzIGZvciBzcGVjaWZpYyBXIGFuZCBzY2FsYXJCaXRzICovXG5leHBvcnQgdHlwZSBXT3B0cyA9IHtcbiAgd2luZG93czogbnVtYmVyO1xuICB3aW5kb3dTaXplOiBudW1iZXI7XG4gIG1hc2s6IGJpZ2ludDtcbiAgbWF4TnVtYmVyOiBudW1iZXI7XG4gIHNoaWZ0Qnk6IGJpZ2ludDtcbn07XG5cbmZ1bmN0aW9uIGNhbGNXT3B0cyhXOiBudW1iZXIsIHNjYWxhckJpdHM6IG51bWJlcik6IFdPcHRzIHtcbiAgdmFsaWRhdGVXKFcsIHNjYWxhckJpdHMpO1xuICBjb25zdCB3aW5kb3dzID0gTWF0aC5jZWlsKHNjYWxhckJpdHMgLyBXKSArIDE7IC8vIFc9OCAzMy4gTm90IDMyLCBiZWNhdXNlIHdlIHNraXAgemVyb1xuICBjb25zdCB3aW5kb3dTaXplID0gMiAqKiAoVyAtIDEpOyAvLyBXPTggMTI4LiBOb3QgMjU2LCBiZWNhdXNlIHdlIHNraXAgemVyb1xuICBjb25zdCBtYXhOdW1iZXIgPSAyICoqIFc7IC8vIFc9OCAyNTZcbiAgY29uc3QgbWFzayA9IGJpdE1hc2soVyk7IC8vIFc9OCAyNTUgPT0gbWFzayAwYjExMTExMTExXG4gIGNvbnN0IHNoaWZ0QnkgPSBCaWdJbnQoVyk7IC8vIFc9OCA4XG4gIHJldHVybiB7IHdpbmRvd3MsIHdpbmRvd1NpemUsIG1hc2ssIG1heE51bWJlciwgc2hpZnRCeSB9O1xufVxuXG5mdW5jdGlvbiBjYWxjT2Zmc2V0cyhuOiBiaWdpbnQsIHdpbmRvdzogbnVtYmVyLCB3T3B0czogV09wdHMpIHtcbiAgY29uc3QgeyB3aW5kb3dTaXplLCBtYXNrLCBtYXhOdW1iZXIsIHNoaWZ0QnkgfSA9IHdPcHRzO1xuICBsZXQgd2JpdHMgPSBOdW1iZXIobiAmIG1hc2spOyAvLyBleHRyYWN0IFcgYml0cy5cbiAgbGV0IG5leHROID0gbiA+PiBzaGlmdEJ5OyAvLyBzaGlmdCBudW1iZXIgYnkgVyBiaXRzLlxuXG4gIC8vIFdoYXQgYWN0dWFsbHkgaGFwcGVucyBoZXJlOlxuICAvLyBjb25zdCBoaWdoZXN0Qml0ID0gTnVtYmVyKG1hc2sgXiAobWFzayA+PiAxbikpO1xuICAvLyBsZXQgd2JpdHMyID0gd2JpdHMgLSAxOyAvLyBza2lwIHplcm9cbiAgLy8gaWYgKHdiaXRzMiAmIGhpZ2hlc3RCaXQpIHsgd2JpdHMyIF49IE51bWJlcihtYXNrKTsgLy8gKH4pO1xuXG4gIC8vIHNwbGl0IGlmIGJpdHMgPiBtYXg6ICsyMjQgPT4gMjU2LTMyXG4gIGlmICh3Yml0cyA+IHdpbmRvd1NpemUpIHtcbiAgICAvLyB3ZSBza2lwIHplcm8sIHdoaWNoIG1lYW5zIGluc3RlYWQgb2YgYD49IHNpemUtMWAsIHdlIGRvIGA+IHNpemVgXG4gICAgd2JpdHMgLT0gbWF4TnVtYmVyOyAvLyAtMzIsIGNhbiBiZSBtYXhOdW1iZXIgLSB3Yml0cywgYnV0IHRoZW4gd2UgbmVlZCB0byBzZXQgaXNOZWcgaGVyZS5cbiAgICBuZXh0TiArPSBfMW47IC8vICsyNTYgKGNhcnJ5KVxuICB9XG4gIGNvbnN0IG9mZnNldFN0YXJ0ID0gd2luZG93ICogd2luZG93U2l6ZTtcbiAgY29uc3Qgb2Zmc2V0ID0gb2Zmc2V0U3RhcnQgKyBNYXRoLmFicyh3Yml0cykgLSAxOyAvLyAtMSBiZWNhdXNlIHdlIHNraXAgemVyb1xuICBjb25zdCBpc1plcm8gPSB3Yml0cyA9PT0gMDsgLy8gaXMgY3VycmVudCB3aW5kb3cgc2xpY2UgYSAwP1xuICBjb25zdCBpc05lZyA9IHdiaXRzIDwgMDsgLy8gaXMgY3VycmVudCB3aW5kb3cgc2xpY2UgbmVnYXRpdmU/XG4gIGNvbnN0IGlzTmVnRiA9IHdpbmRvdyAlIDIgIT09IDA7IC8vIGZha2UgcmFuZG9tIHN0YXRlbWVudCBmb3Igbm9pc2VcbiAgY29uc3Qgb2Zmc2V0RiA9IG9mZnNldFN0YXJ0OyAvLyBmYWtlIG9mZnNldCBmb3Igbm9pc2VcbiAgcmV0dXJuIHsgbmV4dE4sIG9mZnNldCwgaXNaZXJvLCBpc05lZywgaXNOZWdGLCBvZmZzZXRGIH07XG59XG5cbmZ1bmN0aW9uIHZhbGlkYXRlTVNNUG9pbnRzKHBvaW50czogYW55W10sIGM6IGFueSkge1xuICBpZiAoIUFycmF5LmlzQXJyYXkocG9pbnRzKSkgdGhyb3cgbmV3IEVycm9yKCdhcnJheSBleHBlY3RlZCcpO1xuICBwb2ludHMuZm9yRWFjaCgocCwgaSkgPT4ge1xuICAgIGlmICghKHAgaW5zdGFuY2VvZiBjKSkgdGhyb3cgbmV3IEVycm9yKCdpbnZhbGlkIHBvaW50IGF0IGluZGV4ICcgKyBpKTtcbiAgfSk7XG59XG5mdW5jdGlvbiB2YWxpZGF0ZU1TTVNjYWxhcnMoc2NhbGFyczogYW55W10sIGZpZWxkOiBhbnkpIHtcbiAgaWYgKCFBcnJheS5pc0FycmF5KHNjYWxhcnMpKSB0aHJvdyBuZXcgRXJyb3IoJ2FycmF5IG9mIHNjYWxhcnMgZXhwZWN0ZWQnKTtcbiAgc2NhbGFycy5mb3JFYWNoKChzLCBpKSA9PiB7XG4gICAgaWYgKCFmaWVsZC5pc1ZhbGlkKHMpKSB0aHJvdyBuZXcgRXJyb3IoJ2ludmFsaWQgc2NhbGFyIGF0IGluZGV4ICcgKyBpKTtcbiAgfSk7XG59XG5cbi8vIFNpbmNlIHBvaW50cyBpbiBkaWZmZXJlbnQgZ3JvdXBzIGNhbm5vdCBiZSBlcXVhbCAoZGlmZmVyZW50IG9iamVjdCBjb25zdHJ1Y3RvciksXG4vLyB3ZSBjYW4gaGF2ZSBzaW5nbGUgcGxhY2UgdG8gc3RvcmUgcHJlY29tcHV0ZXMuXG4vLyBBbGxvd3MgdG8gbWFrZSBwb2ludHMgZnJvemVuIC8gaW1tdXRhYmxlLlxuY29uc3QgcG9pbnRQcmVjb21wdXRlcyA9IG5ldyBXZWFrTWFwPGFueSwgYW55W10+KCk7XG5jb25zdCBwb2ludFdpbmRvd1NpemVzID0gbmV3IFdlYWtNYXA8YW55LCBudW1iZXI+KCk7XG5cbmZ1bmN0aW9uIGdldFcoUDogYW55KTogbnVtYmVyIHtcbiAgLy8gVG8gZGlzYWJsZSBwcmVjb21wdXRlczpcbiAgLy8gcmV0dXJuIDE7XG4gIHJldHVybiBwb2ludFdpbmRvd1NpemVzLmdldChQKSB8fCAxO1xufVxuXG5mdW5jdGlvbiBhc3NlcnQwKG46IGJpZ2ludCk6IHZvaWQge1xuICBpZiAobiAhPT0gXzBuKSB0aHJvdyBuZXcgRXJyb3IoJ2ludmFsaWQgd05BRicpO1xufVxuXG4vKipcbiAqIEVsbGlwdGljIGN1cnZlIG11bHRpcGxpY2F0aW9uIG9mIFBvaW50IGJ5IHNjYWxhci4gRnJhZ2lsZS5cbiAqIFRhYmxlIGdlbmVyYXRpb24gdGFrZXMgKiozME1CIG9mIHJhbSBhbmQgMTBtcyBvbiBoaWdoLWVuZCBDUFUqKixcbiAqIGJ1dCBtYXkgdGFrZSBtdWNoIGxvbmdlciBvbiBzbG93IGRldmljZXMuIEFjdHVhbCBnZW5lcmF0aW9uIHdpbGwgaGFwcGVuIG9uXG4gKiBmaXJzdCBjYWxsIG9mIGBtdWx0aXBseSgpYC4gQnkgZGVmYXVsdCwgYEJBU0VgIHBvaW50IGlzIHByZWNvbXB1dGVkLlxuICpcbiAqIFNjYWxhcnMgc2hvdWxkIGFsd2F5cyBiZSBsZXNzIHRoYW4gY3VydmUgb3JkZXI6IHRoaXMgc2hvdWxkIGJlIGNoZWNrZWQgaW5zaWRlIG9mIGEgY3VydmUgaXRzZWxmLlxuICogQ3JlYXRlcyBwcmVjb21wdXRhdGlvbiB0YWJsZXMgZm9yIGZhc3QgbXVsdGlwbGljYXRpb246XG4gKiAtIHByaXZhdGUgc2NhbGFyIGlzIHNwbGl0IGJ5IGZpeGVkIHNpemUgd2luZG93cyBvZiBXIGJpdHNcbiAqIC0gZXZlcnkgd2luZG93IHBvaW50IGlzIGNvbGxlY3RlZCBmcm9tIHdpbmRvdydzIHRhYmxlICYgYWRkZWQgdG8gYWNjdW11bGF0b3JcbiAqIC0gc2luY2Ugd2luZG93cyBhcmUgZGlmZmVyZW50LCBzYW1lIHBvaW50IGluc2lkZSB0YWJsZXMgd29uJ3QgYmUgYWNjZXNzZWQgbW9yZSB0aGFuIG9uY2UgcGVyIGNhbGNcbiAqIC0gZWFjaCBtdWx0aXBsaWNhdGlvbiBpcyAnTWF0aC5jZWlsKENVUlZFX09SREVSIC8gXHVEODM1XHVEQzRBKSArIDEnIHBvaW50IGFkZGl0aW9ucyAoZml4ZWQgZm9yIGFueSBzY2FsYXIpXG4gKiAtICsxIHdpbmRvdyBpcyBuZWNjZXNzYXJ5IGZvciB3TkFGXG4gKiAtIHdOQUYgcmVkdWNlcyB0YWJsZSBzaXplOiAyeCBsZXNzIG1lbW9yeSArIDJ4IGZhc3RlciBnZW5lcmF0aW9uLCBidXQgMTAlIHNsb3dlciBtdWx0aXBsaWNhdGlvblxuICpcbiAqIEB0b2RvIFJlc2VhcmNoIHJldHVybmluZyAyZCBKUyBhcnJheSBvZiB3aW5kb3dzLCBpbnN0ZWFkIG9mIGEgc2luZ2xlIHdpbmRvdy5cbiAqIFRoaXMgd291bGQgYWxsb3cgd2luZG93cyB0byBiZSBpbiBkaWZmZXJlbnQgbWVtb3J5IGxvY2F0aW9uc1xuICovXG5leHBvcnQgY2xhc3Mgd05BRjxQQyBleHRlbmRzIFBDX0FOWT4ge1xuICBwcml2YXRlIHJlYWRvbmx5IEJBU0U6IFBDX1A8UEM+O1xuICBwcml2YXRlIHJlYWRvbmx5IFpFUk86IFBDX1A8UEM+O1xuICBwcml2YXRlIHJlYWRvbmx5IEZuOiBQQ1snRm4nXTtcbiAgcmVhZG9ubHkgYml0czogbnVtYmVyO1xuXG4gIC8vIFBhcmFtZXRyaXplZCB3aXRoIGEgZ2l2ZW4gUG9pbnQgY2xhc3MgKG5vdCBpbmRpdmlkdWFsIHBvaW50KVxuICBjb25zdHJ1Y3RvcihQb2ludDogUEMsIGJpdHM6IG51bWJlcikge1xuICAgIHRoaXMuQkFTRSA9IFBvaW50LkJBU0U7XG4gICAgdGhpcy5aRVJPID0gUG9pbnQuWkVSTztcbiAgICB0aGlzLkZuID0gUG9pbnQuRm47XG4gICAgdGhpcy5iaXRzID0gYml0cztcbiAgfVxuXG4gIC8vIG5vbi1jb25zdCB0aW1lIG11bHRpcGxpY2F0aW9uIGxhZGRlclxuICBfdW5zYWZlTGFkZGVyKGVsbTogUENfUDxQQz4sIG46IGJpZ2ludCwgcDogUENfUDxQQz4gPSB0aGlzLlpFUk8pOiBQQ19QPFBDPiB7XG4gICAgbGV0IGQ6IFBDX1A8UEM+ID0gZWxtO1xuICAgIHdoaWxlIChuID4gXzBuKSB7XG4gICAgICBpZiAobiAmIF8xbikgcCA9IHAuYWRkKGQpO1xuICAgICAgZCA9IGQuZG91YmxlKCk7XG4gICAgICBuID4+PSBfMW47XG4gICAgfVxuICAgIHJldHVybiBwO1xuICB9XG5cbiAgLyoqXG4gICAqIENyZWF0ZXMgYSB3TkFGIHByZWNvbXB1dGF0aW9uIHdpbmRvdy4gVXNlZCBmb3IgY2FjaGluZy5cbiAgICogRGVmYXVsdCB3aW5kb3cgc2l6ZSBpcyBzZXQgYnkgYHV0aWxzLnByZWNvbXB1dGUoKWAgYW5kIGlzIGVxdWFsIHRvIDguXG4gICAqIE51bWJlciBvZiBwcmVjb21wdXRlZCBwb2ludHMgZGVwZW5kcyBvbiB0aGUgY3VydmUgc2l6ZTpcbiAgICogMl4oXHVEODM1XHVEQzRBXHUyMjEyMSkgKiAoTWF0aC5jZWlsKFx1RDgzNVx1REM1QiAvIFx1RDgzNVx1REM0QSkgKyAxKSwgd2hlcmU6XG4gICAqIC0gXHVEODM1XHVEQzRBIGlzIHRoZSB3aW5kb3cgc2l6ZVxuICAgKiAtIFx1RDgzNVx1REM1QiBpcyB0aGUgYml0bGVuZ3RoIG9mIHRoZSBjdXJ2ZSBvcmRlci5cbiAgICogRm9yIGEgMjU2LWJpdCBjdXJ2ZSBhbmQgd2luZG93IHNpemUgOCwgdGhlIG51bWJlciBvZiBwcmVjb21wdXRlZCBwb2ludHMgaXMgMTI4ICogMzMgPSA0MjI0LlxuICAgKiBAcGFyYW0gcG9pbnQgUG9pbnQgaW5zdGFuY2VcbiAgICogQHBhcmFtIFcgd2luZG93IHNpemVcbiAgICogQHJldHVybnMgcHJlY29tcHV0ZWQgcG9pbnQgdGFibGVzIGZsYXR0ZW5lZCB0byBhIHNpbmdsZSBhcnJheVxuICAgKi9cbiAgcHJpdmF0ZSBwcmVjb21wdXRlV2luZG93KHBvaW50OiBQQ19QPFBDPiwgVzogbnVtYmVyKTogUENfUDxQQz5bXSB7XG4gICAgY29uc3QgeyB3aW5kb3dzLCB3aW5kb3dTaXplIH0gPSBjYWxjV09wdHMoVywgdGhpcy5iaXRzKTtcbiAgICBjb25zdCBwb2ludHM6IFBDX1A8UEM+W10gPSBbXTtcbiAgICBsZXQgcDogUENfUDxQQz4gPSBwb2ludDtcbiAgICBsZXQgYmFzZSA9IHA7XG4gICAgZm9yIChsZXQgd2luZG93ID0gMDsgd2luZG93IDwgd2luZG93czsgd2luZG93KyspIHtcbiAgICAgIGJhc2UgPSBwO1xuICAgICAgcG9pbnRzLnB1c2goYmFzZSk7XG4gICAgICAvLyBpPTEsIGJjIHdlIHNraXAgMFxuICAgICAgZm9yIChsZXQgaSA9IDE7IGkgPCB3aW5kb3dTaXplOyBpKyspIHtcbiAgICAgICAgYmFzZSA9IGJhc2UuYWRkKHApO1xuICAgICAgICBwb2ludHMucHVzaChiYXNlKTtcbiAgICAgIH1cbiAgICAgIHAgPSBiYXNlLmRvdWJsZSgpO1xuICAgIH1cbiAgICByZXR1cm4gcG9pbnRzO1xuICB9XG5cbiAgLyoqXG4gICAqIEltcGxlbWVudHMgZWMgbXVsdGlwbGljYXRpb24gdXNpbmcgcHJlY29tcHV0ZWQgdGFibGVzIGFuZCB3LWFyeSBub24tYWRqYWNlbnQgZm9ybS5cbiAgICogTW9yZSBjb21wYWN0IGltcGxlbWVudGF0aW9uOlxuICAgKiBodHRwczovL2dpdGh1Yi5jb20vcGF1bG1pbGxyL25vYmxlLXNlY3AyNTZrMS9ibG9iLzQ3Y2IxNjY5YjZlNTA2YWQ2NmIzNWZlN2Q3NjEzMmFlOTc0NjVkYTIvaW5kZXgudHMjTDUwMi1MNTQxXG4gICAqIEByZXR1cm5zIHJlYWwgYW5kIGZha2UgKGZvciBjb25zdC10aW1lKSBwb2ludHNcbiAgICovXG4gIHByaXZhdGUgd05BRihXOiBudW1iZXIsIHByZWNvbXB1dGVzOiBQQ19QPFBDPltdLCBuOiBiaWdpbnQpOiB7IHA6IFBDX1A8UEM+OyBmOiBQQ19QPFBDPiB9IHtcbiAgICAvLyBTY2FsYXIgc2hvdWxkIGJlIHNtYWxsZXIgdGhhbiBmaWVsZCBvcmRlclxuICAgIGlmICghdGhpcy5Gbi5pc1ZhbGlkKG4pKSB0aHJvdyBuZXcgRXJyb3IoJ2ludmFsaWQgc2NhbGFyJyk7XG4gICAgLy8gQWNjdW11bGF0b3JzXG4gICAgbGV0IHAgPSB0aGlzLlpFUk87XG4gICAgbGV0IGYgPSB0aGlzLkJBU0U7XG4gICAgLy8gVGhpcyBjb2RlIHdhcyBmaXJzdCB3cml0dGVuIHdpdGggYXNzdW1wdGlvbiB0aGF0ICdmJyBhbmQgJ3AnIHdpbGwgbmV2ZXIgYmUgaW5maW5pdHkgcG9pbnQ6XG4gICAgLy8gc2luY2UgZWFjaCBhZGRpdGlvbiBpcyBtdWx0aXBsaWVkIGJ5IDIgKiogVywgaXQgY2Fubm90IGNhbmNlbCBlYWNoIG90aGVyLiBIb3dldmVyLFxuICAgIC8vIHRoZXJlIGlzIG5lZ2F0ZSBub3c6IGl0IGlzIHBvc3NpYmxlIHRoYXQgbmVnYXRlZCBlbGVtZW50IGZyb20gbG93IHZhbHVlXG4gICAgLy8gd291bGQgYmUgdGhlIHNhbWUgYXMgaGlnaCBlbGVtZW50LCB3aGljaCB3aWxsIGNyZWF0ZSBjYXJyeSBpbnRvIG5leHQgd2luZG93LlxuICAgIC8vIEl0J3Mgbm90IG9idmlvdXMgaG93IHRoaXMgY2FuIGZhaWwsIGJ1dCBzdGlsbCB3b3J0aCBpbnZlc3RpZ2F0aW5nIGxhdGVyLlxuICAgIGNvbnN0IHdvID0gY2FsY1dPcHRzKFcsIHRoaXMuYml0cyk7XG4gICAgZm9yIChsZXQgd2luZG93ID0gMDsgd2luZG93IDwgd28ud2luZG93czsgd2luZG93KyspIHtcbiAgICAgIC8vIChuID09PSBfMG4pIGlzIGhhbmRsZWQgYW5kIG5vdCBlYXJseS1leGl0ZWQuIGlzRXZlbiBhbmQgb2Zmc2V0RiBhcmUgdXNlZCBmb3Igbm9pc2VcbiAgICAgIGNvbnN0IHsgbmV4dE4sIG9mZnNldCwgaXNaZXJvLCBpc05lZywgaXNOZWdGLCBvZmZzZXRGIH0gPSBjYWxjT2Zmc2V0cyhuLCB3aW5kb3csIHdvKTtcbiAgICAgIG4gPSBuZXh0TjtcbiAgICAgIGlmIChpc1plcm8pIHtcbiAgICAgICAgLy8gYml0cyBhcmUgMDogYWRkIGdhcmJhZ2UgdG8gZmFrZSBwb2ludFxuICAgICAgICAvLyBJbXBvcnRhbnQgcGFydCBmb3IgY29uc3QtdGltZSBnZXRQdWJsaWNLZXk6IGFkZCByYW5kb20gXCJub2lzZVwiIHBvaW50IHRvIGYuXG4gICAgICAgIGYgPSBmLmFkZChuZWdhdGVDdChpc05lZ0YsIHByZWNvbXB1dGVzW29mZnNldEZdKSk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICAvLyBiaXRzIGFyZSAxOiBhZGQgdG8gcmVzdWx0IHBvaW50XG4gICAgICAgIHAgPSBwLmFkZChuZWdhdGVDdChpc05lZywgcHJlY29tcHV0ZXNbb2Zmc2V0XSkpO1xuICAgICAgfVxuICAgIH1cbiAgICBhc3NlcnQwKG4pO1xuICAgIC8vIFJldHVybiBib3RoIHJlYWwgYW5kIGZha2UgcG9pbnRzOiBKSVQgd29uJ3QgZWxpbWluYXRlIGYuXG4gICAgLy8gQXQgdGhpcyBwb2ludCB0aGVyZSBpcyBhIHdheSB0byBGIGJlIGluZmluaXR5LXBvaW50IGV2ZW4gaWYgcCBpcyBub3QsXG4gICAgLy8gd2hpY2ggbWFrZXMgaXQgbGVzcyBjb25zdC10aW1lOiBhcm91bmQgMSBiaWdpbnQgbXVsdGlwbHkuXG4gICAgcmV0dXJuIHsgcCwgZiB9O1xuICB9XG5cbiAgLyoqXG4gICAqIEltcGxlbWVudHMgZWMgdW5zYWZlIChub24gY29uc3QtdGltZSkgbXVsdGlwbGljYXRpb24gdXNpbmcgcHJlY29tcHV0ZWQgdGFibGVzIGFuZCB3LWFyeSBub24tYWRqYWNlbnQgZm9ybS5cbiAgICogQHBhcmFtIGFjYyBhY2N1bXVsYXRvciBwb2ludCB0byBhZGQgcmVzdWx0IG9mIG11bHRpcGxpY2F0aW9uXG4gICAqIEByZXR1cm5zIHBvaW50XG4gICAqL1xuICBwcml2YXRlIHdOQUZVbnNhZmUoXG4gICAgVzogbnVtYmVyLFxuICAgIHByZWNvbXB1dGVzOiBQQ19QPFBDPltdLFxuICAgIG46IGJpZ2ludCxcbiAgICBhY2M6IFBDX1A8UEM+ID0gdGhpcy5aRVJPXG4gICk6IFBDX1A8UEM+IHtcbiAgICBjb25zdCB3byA9IGNhbGNXT3B0cyhXLCB0aGlzLmJpdHMpO1xuICAgIGZvciAobGV0IHdpbmRvdyA9IDA7IHdpbmRvdyA8IHdvLndpbmRvd3M7IHdpbmRvdysrKSB7XG4gICAgICBpZiAobiA9PT0gXzBuKSBicmVhazsgLy8gRWFybHktZXhpdCwgc2tpcCAwIHZhbHVlXG4gICAgICBjb25zdCB7IG5leHROLCBvZmZzZXQsIGlzWmVybywgaXNOZWcgfSA9IGNhbGNPZmZzZXRzKG4sIHdpbmRvdywgd28pO1xuICAgICAgbiA9IG5leHROO1xuICAgICAgaWYgKGlzWmVybykge1xuICAgICAgICAvLyBXaW5kb3cgYml0cyBhcmUgMDogc2tpcCBwcm9jZXNzaW5nLlxuICAgICAgICAvLyBNb3ZlIHRvIG5leHQgd2luZG93LlxuICAgICAgICBjb250aW51ZTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIGNvbnN0IGl0ZW0gPSBwcmVjb21wdXRlc1tvZmZzZXRdO1xuICAgICAgICBhY2MgPSBhY2MuYWRkKGlzTmVnID8gaXRlbS5uZWdhdGUoKSA6IGl0ZW0pOyAvLyBSZS11c2luZyBhY2MgYWxsb3dzIHRvIHNhdmUgYWRkcyBpbiBNU01cbiAgICAgIH1cbiAgICB9XG4gICAgYXNzZXJ0MChuKTtcbiAgICByZXR1cm4gYWNjO1xuICB9XG5cbiAgcHJpdmF0ZSBnZXRQcmVjb21wdXRlcyhXOiBudW1iZXIsIHBvaW50OiBQQ19QPFBDPiwgdHJhbnNmb3JtPzogTWFwcGVyPFBDX1A8UEM+Pik6IFBDX1A8UEM+W10ge1xuICAgIC8vIENhbGN1bGF0ZSBwcmVjb21wdXRlcyBvbiBhIGZpcnN0IHJ1biwgcmV1c2UgdGhlbSBhZnRlclxuICAgIGxldCBjb21wID0gcG9pbnRQcmVjb21wdXRlcy5nZXQocG9pbnQpO1xuICAgIGlmICghY29tcCkge1xuICAgICAgY29tcCA9IHRoaXMucHJlY29tcHV0ZVdpbmRvdyhwb2ludCwgVykgYXMgUENfUDxQQz5bXTtcbiAgICAgIGlmIChXICE9PSAxKSB7XG4gICAgICAgIC8vIERvaW5nIHRyYW5zZm9ybSBvdXRzaWRlIG9mIGlmIGJyaW5ncyAxNSUgcGVyZiBoaXRcbiAgICAgICAgaWYgKHR5cGVvZiB0cmFuc2Zvcm0gPT09ICdmdW5jdGlvbicpIGNvbXAgPSB0cmFuc2Zvcm0oY29tcCk7XG4gICAgICAgIHBvaW50UHJlY29tcHV0ZXMuc2V0KHBvaW50LCBjb21wKTtcbiAgICAgIH1cbiAgICB9XG4gICAgcmV0dXJuIGNvbXA7XG4gIH1cblxuICBjYWNoZWQoXG4gICAgcG9pbnQ6IFBDX1A8UEM+LFxuICAgIHNjYWxhcjogYmlnaW50LFxuICAgIHRyYW5zZm9ybT86IE1hcHBlcjxQQ19QPFBDPj5cbiAgKTogeyBwOiBQQ19QPFBDPjsgZjogUENfUDxQQz4gfSB7XG4gICAgY29uc3QgVyA9IGdldFcocG9pbnQpO1xuICAgIHJldHVybiB0aGlzLndOQUYoVywgdGhpcy5nZXRQcmVjb21wdXRlcyhXLCBwb2ludCwgdHJhbnNmb3JtKSwgc2NhbGFyKTtcbiAgfVxuXG4gIHVuc2FmZShwb2ludDogUENfUDxQQz4sIHNjYWxhcjogYmlnaW50LCB0cmFuc2Zvcm0/OiBNYXBwZXI8UENfUDxQQz4+LCBwcmV2PzogUENfUDxQQz4pOiBQQ19QPFBDPiB7XG4gICAgY29uc3QgVyA9IGdldFcocG9pbnQpO1xuICAgIGlmIChXID09PSAxKSByZXR1cm4gdGhpcy5fdW5zYWZlTGFkZGVyKHBvaW50LCBzY2FsYXIsIHByZXYpOyAvLyBGb3IgVz0xIGxhZGRlciBpcyB+eDIgZmFzdGVyXG4gICAgcmV0dXJuIHRoaXMud05BRlVuc2FmZShXLCB0aGlzLmdldFByZWNvbXB1dGVzKFcsIHBvaW50LCB0cmFuc2Zvcm0pLCBzY2FsYXIsIHByZXYpO1xuICB9XG5cbiAgLy8gV2UgY2FsY3VsYXRlIHByZWNvbXB1dGVzIGZvciBlbGxpcHRpYyBjdXJ2ZSBwb2ludCBtdWx0aXBsaWNhdGlvblxuICAvLyB1c2luZyB3aW5kb3dlZCBtZXRob2QuIFRoaXMgc3BlY2lmaWVzIHdpbmRvdyBzaXplIGFuZFxuICAvLyBzdG9yZXMgcHJlY29tcHV0ZWQgdmFsdWVzLiBVc3VhbGx5IG9ubHkgYmFzZSBwb2ludCB3b3VsZCBiZSBwcmVjb21wdXRlZC5cbiAgY3JlYXRlQ2FjaGUoUDogUENfUDxQQz4sIFc6IG51bWJlcik6IHZvaWQge1xuICAgIHZhbGlkYXRlVyhXLCB0aGlzLmJpdHMpO1xuICAgIHBvaW50V2luZG93U2l6ZXMuc2V0KFAsIFcpO1xuICAgIHBvaW50UHJlY29tcHV0ZXMuZGVsZXRlKFApO1xuICB9XG5cbiAgaGFzQ2FjaGUoZWxtOiBQQ19QPFBDPik6IGJvb2xlYW4ge1xuICAgIHJldHVybiBnZXRXKGVsbSkgIT09IDE7XG4gIH1cbn1cblxuLyoqXG4gKiBFbmRvbW9ycGhpc20tc3BlY2lmaWMgbXVsdGlwbGljYXRpb24gZm9yIEtvYmxpdHogY3VydmVzLlxuICogQ29zdDogMTI4IGRibCwgMC0yNTYgYWRkcy5cbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIG11bEVuZG9VbnNhZmU8UCBleHRlbmRzIEN1cnZlUG9pbnQ8YW55LCBQPiwgUEMgZXh0ZW5kcyBDdXJ2ZVBvaW50Q29uczxQPj4oXG4gIFBvaW50OiBQQyxcbiAgcG9pbnQ6IFAsXG4gIGsxOiBiaWdpbnQsXG4gIGsyOiBiaWdpbnRcbik6IHsgcDE6IFA7IHAyOiBQIH0ge1xuICBsZXQgYWNjID0gcG9pbnQ7XG4gIGxldCBwMSA9IFBvaW50LlpFUk87XG4gIGxldCBwMiA9IFBvaW50LlpFUk87XG4gIHdoaWxlIChrMSA+IF8wbiB8fCBrMiA+IF8wbikge1xuICAgIGlmIChrMSAmIF8xbikgcDEgPSBwMS5hZGQoYWNjKTtcbiAgICBpZiAoazIgJiBfMW4pIHAyID0gcDIuYWRkKGFjYyk7XG4gICAgYWNjID0gYWNjLmRvdWJsZSgpO1xuICAgIGsxID4+PSBfMW47XG4gICAgazIgPj49IF8xbjtcbiAgfVxuICByZXR1cm4geyBwMSwgcDIgfTtcbn1cblxuLyoqXG4gKiBQaXBwZW5nZXIgYWxnb3JpdGhtIGZvciBtdWx0aS1zY2FsYXIgbXVsdGlwbGljYXRpb24gKE1TTSwgUGEgKyBRYiArIFJjICsgLi4uKS5cbiAqIDMweCBmYXN0ZXIgdnMgbmFpdmUgYWRkaXRpb24gb24gTD00MDk2LCAxMHggZmFzdGVyIHRoYW4gcHJlY29tcHV0ZXMuXG4gKiBGb3IgTj0yNTRiaXQsIEw9MSwgaXQgZG9lczogMTAyNCBBREQgKyAyNTQgREJMLiBGb3IgTD01OiAxNTM2IEFERCArIDI1NCBEQkwuXG4gKiBBbGdvcml0aG1pY2FsbHkgY29uc3RhbnQtdGltZSAoZm9yIHNhbWUgTCksIGV2ZW4gd2hlbiAxIHBvaW50ICsgc2NhbGFyLCBvciB3aGVuIHNjYWxhciA9IDAuXG4gKiBAcGFyYW0gYyBDdXJ2ZSBQb2ludCBjb25zdHJ1Y3RvclxuICogQHBhcmFtIGZpZWxkTiBmaWVsZCBvdmVyIENVUlZFLk4gLSBpbXBvcnRhbnQgdGhhdCBpdCdzIG5vdCBvdmVyIENVUlZFLlBcbiAqIEBwYXJhbSBwb2ludHMgYXJyYXkgb2YgTCBjdXJ2ZSBwb2ludHNcbiAqIEBwYXJhbSBzY2FsYXJzIGFycmF5IG9mIEwgc2NhbGFycyAoYWthIHNlY3JldCBrZXlzIC8gYmlnaW50cylcbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIHBpcHBlbmdlcjxQIGV4dGVuZHMgQ3VydmVQb2ludDxhbnksIFA+LCBQQyBleHRlbmRzIEN1cnZlUG9pbnRDb25zPFA+PihcbiAgYzogUEMsXG4gIGZpZWxkTjogSUZpZWxkPGJpZ2ludD4sXG4gIHBvaW50czogUFtdLFxuICBzY2FsYXJzOiBiaWdpbnRbXVxuKTogUCB7XG4gIC8vIElmIHdlIHNwbGl0IHNjYWxhcnMgYnkgc29tZSB3aW5kb3cgKGxldCdzIHNheSA4IGJpdHMpLCBldmVyeSBjaHVuayB3aWxsIG9ubHlcbiAgLy8gdGFrZSAyNTYgYnVja2V0cyBldmVuIGlmIHRoZXJlIGFyZSA0MDk2IHNjYWxhcnMsIGFsc28gcmUtdXNlcyBkb3VibGUuXG4gIC8vIFRPRE86XG4gIC8vIC0gaHR0cHM6Ly9lcHJpbnQuaWFjci5vcmcvMjAyNC83NTAucGRmXG4gIC8vIC0gaHR0cHM6Ly90Y2hlcy5pYWNyLm9yZy9pbmRleC5waHAvVENIRVMvYXJ0aWNsZS92aWV3LzEwMjg3XG4gIC8vIDAgaXMgYWNjZXB0ZWQgaW4gc2NhbGFyc1xuICB2YWxpZGF0ZU1TTVBvaW50cyhwb2ludHMsIGMpO1xuICB2YWxpZGF0ZU1TTVNjYWxhcnMoc2NhbGFycywgZmllbGROKTtcbiAgY29uc3QgcGxlbmd0aCA9IHBvaW50cy5sZW5ndGg7XG4gIGNvbnN0IHNsZW5ndGggPSBzY2FsYXJzLmxlbmd0aDtcbiAgaWYgKHBsZW5ndGggIT09IHNsZW5ndGgpIHRocm93IG5ldyBFcnJvcignYXJyYXlzIG9mIHBvaW50cyBhbmQgc2NhbGFycyBtdXN0IGhhdmUgZXF1YWwgbGVuZ3RoJyk7XG4gIC8vIGlmIChwbGVuZ3RoID09PSAwKSB0aHJvdyBuZXcgRXJyb3IoJ2FycmF5IG11c3QgYmUgb2YgbGVuZ3RoID49IDInKTtcbiAgY29uc3QgemVybyA9IGMuWkVSTztcbiAgY29uc3Qgd2JpdHMgPSBiaXRMZW4oQmlnSW50KHBsZW5ndGgpKTtcbiAgbGV0IHdpbmRvd1NpemUgPSAxOyAvLyBiaXRzXG4gIGlmICh3Yml0cyA+IDEyKSB3aW5kb3dTaXplID0gd2JpdHMgLSAzO1xuICBlbHNlIGlmICh3Yml0cyA+IDQpIHdpbmRvd1NpemUgPSB3Yml0cyAtIDI7XG4gIGVsc2UgaWYgKHdiaXRzID4gMCkgd2luZG93U2l6ZSA9IDI7XG4gIGNvbnN0IE1BU0sgPSBiaXRNYXNrKHdpbmRvd1NpemUpO1xuICBjb25zdCBidWNrZXRzID0gbmV3IEFycmF5KE51bWJlcihNQVNLKSArIDEpLmZpbGwoemVybyk7IC8vICsxIGZvciB6ZXJvIGFycmF5XG4gIGNvbnN0IGxhc3RCaXRzID0gTWF0aC5mbG9vcigoZmllbGROLkJJVFMgLSAxKSAvIHdpbmRvd1NpemUpICogd2luZG93U2l6ZTtcbiAgbGV0IHN1bSA9IHplcm87XG4gIGZvciAobGV0IGkgPSBsYXN0Qml0czsgaSA+PSAwOyBpIC09IHdpbmRvd1NpemUpIHtcbiAgICBidWNrZXRzLmZpbGwoemVybyk7XG4gICAgZm9yIChsZXQgaiA9IDA7IGogPCBzbGVuZ3RoOyBqKyspIHtcbiAgICAgIGNvbnN0IHNjYWxhciA9IHNjYWxhcnNbal07XG4gICAgICBjb25zdCB3Yml0cyA9IE51bWJlcigoc2NhbGFyID4+IEJpZ0ludChpKSkgJiBNQVNLKTtcbiAgICAgIGJ1Y2tldHNbd2JpdHNdID0gYnVja2V0c1t3Yml0c10uYWRkKHBvaW50c1tqXSk7XG4gICAgfVxuICAgIGxldCByZXNJID0gemVybzsgLy8gbm90IHVzaW5nIHRoaXMgd2lsbCBkbyBzbWFsbCBzcGVlZC11cCwgYnV0IHdpbGwgbG9zZSBjdFxuICAgIC8vIFNraXAgZmlyc3QgYnVja2V0LCBiZWNhdXNlIGl0IGlzIHplcm9cbiAgICBmb3IgKGxldCBqID0gYnVja2V0cy5sZW5ndGggLSAxLCBzdW1JID0gemVybzsgaiA+IDA7IGotLSkge1xuICAgICAgc3VtSSA9IHN1bUkuYWRkKGJ1Y2tldHNbal0pO1xuICAgICAgcmVzSSA9IHJlc0kuYWRkKHN1bUkpO1xuICAgIH1cbiAgICBzdW0gPSBzdW0uYWRkKHJlc0kpO1xuICAgIGlmIChpICE9PSAwKSBmb3IgKGxldCBqID0gMDsgaiA8IHdpbmRvd1NpemU7IGorKykgc3VtID0gc3VtLmRvdWJsZSgpO1xuICB9XG4gIHJldHVybiBzdW0gYXMgUDtcbn1cbi8qKlxuICogUHJlY29tcHV0ZWQgbXVsdGktc2NhbGFyIG11bHRpcGxpY2F0aW9uIChNU00sIFBhICsgUWIgKyBSYyArIC4uLikuXG4gKiBAcGFyYW0gYyBDdXJ2ZSBQb2ludCBjb25zdHJ1Y3RvclxuICogQHBhcmFtIGZpZWxkTiBmaWVsZCBvdmVyIENVUlZFLk4gLSBpbXBvcnRhbnQgdGhhdCBpdCdzIG5vdCBvdmVyIENVUlZFLlBcbiAqIEBwYXJhbSBwb2ludHMgYXJyYXkgb2YgTCBjdXJ2ZSBwb2ludHNcbiAqIEByZXR1cm5zIGZ1bmN0aW9uIHdoaWNoIG11bHRpcGxpZXMgcG9pbnRzIHdpdGggc2NhYXJzXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBwcmVjb21wdXRlTVNNVW5zYWZlPFAgZXh0ZW5kcyBDdXJ2ZVBvaW50PGFueSwgUD4sIFBDIGV4dGVuZHMgQ3VydmVQb2ludENvbnM8UD4+KFxuICBjOiBQQyxcbiAgZmllbGROOiBJRmllbGQ8YmlnaW50PixcbiAgcG9pbnRzOiBQW10sXG4gIHdpbmRvd1NpemU6IG51bWJlclxuKTogKHNjYWxhcnM6IGJpZ2ludFtdKSA9PiBQIHtcbiAgLyoqXG4gICAqIFBlcmZvcm1hbmNlIEFuYWx5c2lzIG9mIFdpbmRvdy1iYXNlZCBQcmVjb21wdXRhdGlvblxuICAgKlxuICAgKiBCYXNlIENhc2UgKDI1Ni1iaXQgc2NhbGFyLCA4LWJpdCB3aW5kb3cpOlxuICAgKiAtIFN0YW5kYXJkIHByZWNvbXB1dGF0aW9uIHJlcXVpcmVzOlxuICAgKiAgIC0gMzEgYWRkaXRpb25zIHBlciBzY2FsYXIgXHUwMEQ3IDI1NiBzY2FsYXJzID0gNyw5MzYgb3BzXG4gICAqICAgLSBQbHVzIDI1NSBzdW1tYXJ5IGFkZGl0aW9ucyA9IDgsMTkxIHRvdGFsIG9wc1xuICAgKiAgIE5vdGU6IFN1bW1hcnkgYWRkaXRpb25zIGNhbiBiZSBvcHRpbWl6ZWQgdmlhIGFjY3VtdWxhdG9yXG4gICAqXG4gICAqIENodW5rZWQgUHJlY29tcHV0YXRpb24gQW5hbHlzaXM6XG4gICAqIC0gVXNpbmcgMzIgY2h1bmtzIHJlcXVpcmVzOlxuICAgKiAgIC0gMjU1IGFkZGl0aW9ucyBwZXIgY2h1bmtcbiAgICogICAtIDI1NiBkb3VibGluZ3NcbiAgICogICAtIFRvdGFsOiAoMjU1IFx1MDBENyAzMikgKyAyNTYgPSA4LDQxNiBvcHNcbiAgICpcbiAgICogTWVtb3J5IFVzYWdlIENvbXBhcmlzb246XG4gICAqIFdpbmRvdyBTaXplIHwgU3RhbmRhcmQgUG9pbnRzIHwgQ2h1bmtlZCBQb2ludHNcbiAgICogLS0tLS0tLS0tLS0tfC0tLS0tLS0tLS0tLS0tLS0tfC0tLS0tLS0tLS0tLS0tLVxuICAgKiAgICAgNC1iaXQgICB8ICAgICA1MjAgICAgICAgICB8ICAgICAgMTVcbiAgICogICAgIDgtYml0ICAgfCAgICA0LDIyNCAgICAgICAgfCAgICAgMjU1XG4gICAqICAgIDEwLWJpdCAgIHwgICAxMyw4MjQgICAgICAgIHwgICAxLDAyM1xuICAgKiAgICAxNi1iaXQgICB8ICA1NTcsMDU2ICAgICAgICB8ICA2NSw1MzVcbiAgICpcbiAgICogS2V5IEFkdmFudGFnZXM6XG4gICAqIDEuIEVuYWJsZXMgbGFyZ2VyIHdpbmRvdyBzaXplcyBkdWUgdG8gcmVkdWNlZCBtZW1vcnkgb3ZlcmhlYWRcbiAgICogMi4gTW9yZSBlZmZpY2llbnQgZm9yIHNtYWxsZXIgc2NhbGFyIGNvdW50czpcbiAgICogICAgLSAxNiBjaHVua3M6ICgxNiBcdTAwRDcgMjU1KSArIDI1NiA9IDQsMzM2IG9wc1xuICAgKiAgICAtIH4yeCBmYXN0ZXIgdGhhbiBzdGFuZGFyZCA4LDE5MSBvcHNcbiAgICpcbiAgICogTGltaXRhdGlvbnM6XG4gICAqIC0gTm90IHN1aXRhYmxlIGZvciBwbGFpbiBwcmVjb21wdXRlcyAocmVxdWlyZXMgMjU2IGNvbnN0YW50IGRvdWJsaW5ncylcbiAgICogLSBQZXJmb3JtYW5jZSBkZWdyYWRlcyB3aXRoIGxhcmdlciBzY2FsYXIgY291bnRzOlxuICAgKiAgIC0gT3B0aW1hbCBmb3IgfjI1NiBzY2FsYXJzXG4gICAqICAgLSBMZXNzIGVmZmljaWVudCBmb3IgNDA5Nisgc2NhbGFycyAoUGlwcGVuZ2VyIHByZWZlcnJlZClcbiAgICovXG4gIHZhbGlkYXRlVyh3aW5kb3dTaXplLCBmaWVsZE4uQklUUyk7XG4gIHZhbGlkYXRlTVNNUG9pbnRzKHBvaW50cywgYyk7XG4gIGNvbnN0IHplcm8gPSBjLlpFUk87XG4gIGNvbnN0IHRhYmxlU2l6ZSA9IDIgKiogd2luZG93U2l6ZSAtIDE7IC8vIHRhYmxlIHNpemUgKHdpdGhvdXQgemVybylcbiAgY29uc3QgY2h1bmtzID0gTWF0aC5jZWlsKGZpZWxkTi5CSVRTIC8gd2luZG93U2l6ZSk7IC8vIGNodW5rcyBvZiBpdGVtXG4gIGNvbnN0IE1BU0sgPSBiaXRNYXNrKHdpbmRvd1NpemUpO1xuICBjb25zdCB0YWJsZXMgPSBwb2ludHMubWFwKChwOiBQKSA9PiB7XG4gICAgY29uc3QgcmVzID0gW107XG4gICAgZm9yIChsZXQgaSA9IDAsIGFjYyA9IHA7IGkgPCB0YWJsZVNpemU7IGkrKykge1xuICAgICAgcmVzLnB1c2goYWNjKTtcbiAgICAgIGFjYyA9IGFjYy5hZGQocCk7XG4gICAgfVxuICAgIHJldHVybiByZXM7XG4gIH0pO1xuICByZXR1cm4gKHNjYWxhcnM6IGJpZ2ludFtdKTogUCA9PiB7XG4gICAgdmFsaWRhdGVNU01TY2FsYXJzKHNjYWxhcnMsIGZpZWxkTik7XG4gICAgaWYgKHNjYWxhcnMubGVuZ3RoID4gcG9pbnRzLmxlbmd0aClcbiAgICAgIHRocm93IG5ldyBFcnJvcignYXJyYXkgb2Ygc2NhbGFycyBtdXN0IGJlIHNtYWxsZXIgdGhhbiBhcnJheSBvZiBwb2ludHMnKTtcbiAgICBsZXQgcmVzID0gemVybztcbiAgICBmb3IgKGxldCBpID0gMDsgaSA8IGNodW5rczsgaSsrKSB7XG4gICAgICAvLyBObyBuZWVkIHRvIGRvdWJsZSBpZiBhY2N1bXVsYXRvciBpcyBzdGlsbCB6ZXJvLlxuICAgICAgaWYgKHJlcyAhPT0gemVybykgZm9yIChsZXQgaiA9IDA7IGogPCB3aW5kb3dTaXplOyBqKyspIHJlcyA9IHJlcy5kb3VibGUoKTtcbiAgICAgIGNvbnN0IHNoaWZ0QnkgPSBCaWdJbnQoY2h1bmtzICogd2luZG93U2l6ZSAtIChpICsgMSkgKiB3aW5kb3dTaXplKTtcbiAgICAgIGZvciAobGV0IGogPSAwOyBqIDwgc2NhbGFycy5sZW5ndGg7IGorKykge1xuICAgICAgICBjb25zdCBuID0gc2NhbGFyc1tqXTtcbiAgICAgICAgY29uc3QgY3VyciA9IE51bWJlcigobiA+PiBzaGlmdEJ5KSAmIE1BU0spO1xuICAgICAgICBpZiAoIWN1cnIpIGNvbnRpbnVlOyAvLyBza2lwIHplcm8gc2NhbGFycyBjaHVua3NcbiAgICAgICAgcmVzID0gcmVzLmFkZCh0YWJsZXNbal1bY3VyciAtIDFdKTtcbiAgICAgIH1cbiAgICB9XG4gICAgcmV0dXJuIHJlcztcbiAgfTtcbn1cblxuLy8gVE9ETzogcmVtb3ZlXG4vKipcbiAqIEdlbmVyaWMgQmFzaWNDdXJ2ZSBpbnRlcmZhY2U6IHdvcmtzIGV2ZW4gZm9yIHBvbHlub21pYWwgZmllbGRzIChCTFMpOiBQLCBuLCBoIHdvdWxkIGJlIG9rLlxuICogVGhvdWdoIGdlbmVyYXRvciBjYW4gYmUgZGlmZmVyZW50IChGcDIgLyBGcDYgZm9yIEJMUykuXG4gKi9cbmV4cG9ydCB0eXBlIEJhc2ljQ3VydmU8VD4gPSB7XG4gIEZwOiBJRmllbGQ8VD47IC8vIEZpZWxkIG92ZXIgd2hpY2ggd2UnbGwgZG8gY2FsY3VsYXRpb25zIChGcClcbiAgbjogYmlnaW50OyAvLyBDdXJ2ZSBvcmRlciwgdG90YWwgY291bnQgb2YgdmFsaWQgcG9pbnRzIGluIHRoZSBmaWVsZFxuICBuQml0TGVuZ3RoPzogbnVtYmVyOyAvLyBiaXQgbGVuZ3RoIG9mIGN1cnZlIG9yZGVyXG4gIG5CeXRlTGVuZ3RoPzogbnVtYmVyOyAvLyBieXRlIGxlbmd0aCBvZiBjdXJ2ZSBvcmRlclxuICBoOiBiaWdpbnQ7IC8vIGNvZmFjdG9yLiB3ZSBjYW4gYXNzaWduIGRlZmF1bHQ9MSwgYnV0IHVzZXJzIHdpbGwganVzdCBpZ25vcmUgaXQgdy9vIHZhbGlkYXRpb25cbiAgaEVmZj86IGJpZ2ludDsgLy8gTnVtYmVyIHRvIG11bHRpcGx5IHRvIGNsZWFyIGNvZmFjdG9yXG4gIEd4OiBUOyAvLyBiYXNlIHBvaW50IFggY29vcmRpbmF0ZVxuICBHeTogVDsgLy8gYmFzZSBwb2ludCBZIGNvb3JkaW5hdGVcbiAgYWxsb3dJbmZpbml0eVBvaW50PzogYm9vbGVhbjsgLy8gYmxzMTItMzgxIHJlcXVpcmVzIGl0LiBaRVJPIHBvaW50IGlzIHZhbGlkLCBidXQgaW52YWxpZCBwdWJrZXlcbn07XG5cbi8vIFRPRE86IHJlbW92ZVxuLyoqIEBkZXByZWNhdGVkICovXG5leHBvcnQgZnVuY3Rpb24gdmFsaWRhdGVCYXNpYzxGUCwgVD4oXG4gIGN1cnZlOiBCYXNpY0N1cnZlPEZQPiAmIFRcbik6IFJlYWRvbmx5PFxuICB7XG4gICAgcmVhZG9ubHkgbkJpdExlbmd0aDogbnVtYmVyO1xuICAgIHJlYWRvbmx5IG5CeXRlTGVuZ3RoOiBudW1iZXI7XG4gIH0gJiBCYXNpY0N1cnZlPEZQPiAmXG4gICAgVCAmIHtcbiAgICAgIHA6IGJpZ2ludDtcbiAgICB9XG4+IHtcbiAgdmFsaWRhdGVGaWVsZChjdXJ2ZS5GcCk7XG4gIHZhbGlkYXRlT2JqZWN0KFxuICAgIGN1cnZlLFxuICAgIHtcbiAgICAgIG46ICdiaWdpbnQnLFxuICAgICAgaDogJ2JpZ2ludCcsXG4gICAgICBHeDogJ2ZpZWxkJyxcbiAgICAgIEd5OiAnZmllbGQnLFxuICAgIH0sXG4gICAge1xuICAgICAgbkJpdExlbmd0aDogJ2lzU2FmZUludGVnZXInLFxuICAgICAgbkJ5dGVMZW5ndGg6ICdpc1NhZmVJbnRlZ2VyJyxcbiAgICB9XG4gICk7XG4gIC8vIFNldCBkZWZhdWx0c1xuICByZXR1cm4gT2JqZWN0LmZyZWV6ZSh7XG4gICAgLi4ubkxlbmd0aChjdXJ2ZS5uLCBjdXJ2ZS5uQml0TGVuZ3RoKSxcbiAgICAuLi5jdXJ2ZSxcbiAgICAuLi57IHA6IGN1cnZlLkZwLk9SREVSIH0sXG4gIH0gYXMgY29uc3QpO1xufVxuXG5leHBvcnQgdHlwZSBWYWxpZEN1cnZlUGFyYW1zPFQ+ID0ge1xuICBwOiBiaWdpbnQ7XG4gIG46IGJpZ2ludDtcbiAgaDogYmlnaW50O1xuICBhOiBUO1xuICBiPzogVDtcbiAgZD86IFQ7XG4gIEd4OiBUO1xuICBHeTogVDtcbn07XG5cbmZ1bmN0aW9uIGNyZWF0ZUZpZWxkPFQ+KG9yZGVyOiBiaWdpbnQsIGZpZWxkPzogSUZpZWxkPFQ+LCBpc0xFPzogYm9vbGVhbik6IElGaWVsZDxUPiB7XG4gIGlmIChmaWVsZCkge1xuICAgIGlmIChmaWVsZC5PUkRFUiAhPT0gb3JkZXIpIHRocm93IG5ldyBFcnJvcignRmllbGQuT1JERVIgbXVzdCBtYXRjaCBvcmRlcjogRnAgPT0gcCwgRm4gPT0gbicpO1xuICAgIHZhbGlkYXRlRmllbGQoZmllbGQpO1xuICAgIHJldHVybiBmaWVsZDtcbiAgfSBlbHNlIHtcbiAgICByZXR1cm4gRmllbGQob3JkZXIsIHsgaXNMRSB9KSBhcyB1bmtub3duIGFzIElGaWVsZDxUPjtcbiAgfVxufVxuZXhwb3J0IHR5cGUgRnBGbjxUPiA9IHsgRnA6IElGaWVsZDxUPjsgRm46IElGaWVsZDxiaWdpbnQ+IH07XG5cbi8qKiBWYWxpZGF0ZXMgQ1VSVkUgb3B0cyBhbmQgY3JlYXRlcyBmaWVsZHMgKi9cbmV4cG9ydCBmdW5jdGlvbiBfY3JlYXRlQ3VydmVGaWVsZHM8VD4oXG4gIHR5cGU6ICd3ZWllcnN0cmFzcycgfCAnZWR3YXJkcycsXG4gIENVUlZFOiBWYWxpZEN1cnZlUGFyYW1zPFQ+LFxuICBjdXJ2ZU9wdHM6IFBhcnRpYWw8RnBGbjxUPj4gPSB7fSxcbiAgRnBGbkxFPzogYm9vbGVhblxuKTogRnBGbjxUPiAmIHsgQ1VSVkU6IFZhbGlkQ3VydmVQYXJhbXM8VD4gfSB7XG4gIGlmIChGcEZuTEUgPT09IHVuZGVmaW5lZCkgRnBGbkxFID0gdHlwZSA9PT0gJ2Vkd2FyZHMnO1xuICBpZiAoIUNVUlZFIHx8IHR5cGVvZiBDVVJWRSAhPT0gJ29iamVjdCcpIHRocm93IG5ldyBFcnJvcihgZXhwZWN0ZWQgdmFsaWQgJHt0eXBlfSBDVVJWRSBvYmplY3RgKTtcbiAgZm9yIChjb25zdCBwIG9mIFsncCcsICduJywgJ2gnXSBhcyBjb25zdCkge1xuICAgIGNvbnN0IHZhbCA9IENVUlZFW3BdO1xuICAgIGlmICghKHR5cGVvZiB2YWwgPT09ICdiaWdpbnQnICYmIHZhbCA+IF8wbikpXG4gICAgICB0aHJvdyBuZXcgRXJyb3IoYENVUlZFLiR7cH0gbXVzdCBiZSBwb3NpdGl2ZSBiaWdpbnRgKTtcbiAgfVxuICBjb25zdCBGcCA9IGNyZWF0ZUZpZWxkKENVUlZFLnAsIGN1cnZlT3B0cy5GcCwgRnBGbkxFKTtcbiAgY29uc3QgRm4gPSBjcmVhdGVGaWVsZChDVVJWRS5uLCBjdXJ2ZU9wdHMuRm4sIEZwRm5MRSk7XG4gIGNvbnN0IF9iOiAnYicgfCAnZCcgPSB0eXBlID09PSAnd2VpZXJzdHJhc3MnID8gJ2InIDogJ2QnO1xuICBjb25zdCBwYXJhbXMgPSBbJ0d4JywgJ0d5JywgJ2EnLCBfYl0gYXMgY29uc3Q7XG4gIGZvciAoY29uc3QgcCBvZiBwYXJhbXMpIHtcbiAgICAvLyBAdHMtaWdub3JlXG4gICAgaWYgKCFGcC5pc1ZhbGlkKENVUlZFW3BdKSlcbiAgICAgIHRocm93IG5ldyBFcnJvcihgQ1VSVkUuJHtwfSBtdXN0IGJlIHZhbGlkIGZpZWxkIGVsZW1lbnQgb2YgQ1VSVkUuRnBgKTtcbiAgfVxuICBDVVJWRSA9IE9iamVjdC5mcmVlemUoT2JqZWN0LmFzc2lnbih7fSwgQ1VSVkUpKTtcbiAgcmV0dXJuIHsgQ1VSVkUsIEZwLCBGbiB9O1xufVxuIiwgIi8qKlxuICogVHdpc3RlZCBFZHdhcmRzIGN1cnZlLiBUaGUgZm9ybXVsYSBpczogYXhcdTAwQjIgKyB5XHUwMEIyID0gMSArIGR4XHUwMEIyeVx1MDBCMi5cbiAqIEZvciBkZXNpZ24gcmF0aW9uYWxlIG9mIHR5cGVzIC8gZXhwb3J0cywgc2VlIHdlaWVyc3RyYXNzIG1vZHVsZSBkb2N1bWVudGF0aW9uLlxuICogVW50d2lzdGVkIEVkd2FyZHMgY3VydmVzIGV4aXN0LCBidXQgdGhleSBhcmVuJ3QgdXNlZCBpbiByZWFsLXdvcmxkIHByb3RvY29scy5cbiAqIEBtb2R1bGVcbiAqL1xuLyohIG5vYmxlLWN1cnZlcyAtIE1JVCBMaWNlbnNlIChjKSAyMDIyIFBhdWwgTWlsbGVyIChwYXVsbWlsbHIuY29tKSAqL1xuaW1wb3J0IHtcbiAgX3ZhbGlkYXRlT2JqZWN0LFxuICBfYWJvb2wyIGFzIGFib29sLFxuICBfYWJ5dGVzMiBhcyBhYnl0ZXMsXG4gIGFJblJhbmdlLFxuICBieXRlc1RvSGV4LFxuICBieXRlc1RvTnVtYmVyTEUsXG4gIGNvbmNhdEJ5dGVzLFxuICBjb3B5Qnl0ZXMsXG4gIGVuc3VyZUJ5dGVzLFxuICBpc0J5dGVzLFxuICBtZW1vaXplZCxcbiAgbm90SW1wbGVtZW50ZWQsXG4gIHJhbmRvbUJ5dGVzIGFzIHJhbmRvbUJ5dGVzV2ViLFxuICB0eXBlIEZIYXNoLFxuICB0eXBlIEhleCxcbn0gZnJvbSAnLi4vdXRpbHMudHMnO1xuaW1wb3J0IHtcbiAgX2NyZWF0ZUN1cnZlRmllbGRzLFxuICBub3JtYWxpemVaLFxuICBwaXBwZW5nZXIsXG4gIHdOQUYsXG4gIHR5cGUgQWZmaW5lUG9pbnQsXG4gIHR5cGUgQmFzaWNDdXJ2ZSxcbiAgdHlwZSBDdXJ2ZUxlbmd0aHMsXG4gIHR5cGUgQ3VydmVQb2ludCxcbiAgdHlwZSBDdXJ2ZVBvaW50Q29ucyxcbn0gZnJvbSAnLi9jdXJ2ZS50cyc7XG5pbXBvcnQgeyBGaWVsZCwgdHlwZSBJRmllbGQsIHR5cGUgTkxlbmd0aCB9IGZyb20gJy4vbW9kdWxhci50cyc7XG5cbi8vIEJlIGZyaWVuZGx5IHRvIGJhZCBFQ01BU2NyaXB0IHBhcnNlcnMgYnkgbm90IHVzaW5nIGJpZ2ludCBsaXRlcmFsc1xuLy8gcHJldHRpZXItaWdub3JlXG5jb25zdCBfMG4gPSBCaWdJbnQoMCksIF8xbiA9IEJpZ0ludCgxKSwgXzJuID0gQmlnSW50KDIpLCBfOG4gPSBCaWdJbnQoOCk7XG5cbmV4cG9ydCB0eXBlIFVWUmF0aW8gPSAodTogYmlnaW50LCB2OiBiaWdpbnQpID0+IHsgaXNWYWxpZDogYm9vbGVhbjsgdmFsdWU6IGJpZ2ludCB9O1xuXG4vKiogSW5zdGFuY2Ugb2YgRXh0ZW5kZWQgUG9pbnQgd2l0aCBjb29yZGluYXRlcyBpbiBYLCBZLCBaLCBULiAqL1xuZXhwb3J0IGludGVyZmFjZSBFZHdhcmRzUG9pbnQgZXh0ZW5kcyBDdXJ2ZVBvaW50PGJpZ2ludCwgRWR3YXJkc1BvaW50PiB7XG4gIC8qKiBleHRlbmRlZCBYIGNvb3JkaW5hdGUuIERpZmZlcmVudCBmcm9tIGFmZmluZSB4LiAqL1xuICByZWFkb25seSBYOiBiaWdpbnQ7XG4gIC8qKiBleHRlbmRlZCBZIGNvb3JkaW5hdGUuIERpZmZlcmVudCBmcm9tIGFmZmluZSB5LiAqL1xuICByZWFkb25seSBZOiBiaWdpbnQ7XG4gIC8qKiBleHRlbmRlZCBaIGNvb3JkaW5hdGUgKi9cbiAgcmVhZG9ubHkgWjogYmlnaW50O1xuICAvKiogZXh0ZW5kZWQgVCBjb29yZGluYXRlICovXG4gIHJlYWRvbmx5IFQ6IGJpZ2ludDtcblxuICAvKiogQGRlcHJlY2F0ZWQgdXNlIGB0b0J5dGVzYCAqL1xuICB0b1Jhd0J5dGVzKCk6IFVpbnQ4QXJyYXk7XG4gIC8qKiBAZGVwcmVjYXRlZCB1c2UgYHAucHJlY29tcHV0ZSh3aW5kb3dTaXplKWAgKi9cbiAgX3NldFdpbmRvd1NpemUod2luZG93U2l6ZTogbnVtYmVyKTogdm9pZDtcbiAgLyoqIEBkZXByZWNhdGVkIHVzZSAuWCAqL1xuICByZWFkb25seSBleDogYmlnaW50O1xuICAvKiogQGRlcHJlY2F0ZWQgdXNlIC5ZICovXG4gIHJlYWRvbmx5IGV5OiBiaWdpbnQ7XG4gIC8qKiBAZGVwcmVjYXRlZCB1c2UgLlogKi9cbiAgcmVhZG9ubHkgZXo6IGJpZ2ludDtcbiAgLyoqIEBkZXByZWNhdGVkIHVzZSAuVCAqL1xuICByZWFkb25seSBldDogYmlnaW50O1xufVxuLyoqIFN0YXRpYyBtZXRob2RzIG9mIEV4dGVuZGVkIFBvaW50IHdpdGggY29vcmRpbmF0ZXMgaW4gWCwgWSwgWiwgVC4gKi9cbmV4cG9ydCBpbnRlcmZhY2UgRWR3YXJkc1BvaW50Q29ucyBleHRlbmRzIEN1cnZlUG9pbnRDb25zPEVkd2FyZHNQb2ludD4ge1xuICBuZXcgKFg6IGJpZ2ludCwgWTogYmlnaW50LCBaOiBiaWdpbnQsIFQ6IGJpZ2ludCk6IEVkd2FyZHNQb2ludDtcbiAgQ1VSVkUoKTogRWR3YXJkc09wdHM7XG4gIGZyb21CeXRlcyhieXRlczogVWludDhBcnJheSwgemlwMjE1PzogYm9vbGVhbik6IEVkd2FyZHNQb2ludDtcbiAgZnJvbUhleChoZXg6IEhleCwgemlwMjE1PzogYm9vbGVhbik6IEVkd2FyZHNQb2ludDtcbiAgLyoqIEBkZXByZWNhdGVkIHVzZSBgaW1wb3J0IHsgcGlwcGVuZ2VyIH0gZnJvbSAnQG5vYmxlL2N1cnZlcy9hYnN0cmFjdC9jdXJ2ZS5qcyc7YCAqL1xuICBtc20ocG9pbnRzOiBFZHdhcmRzUG9pbnRbXSwgc2NhbGFyczogYmlnaW50W10pOiBFZHdhcmRzUG9pbnQ7XG59XG4vKiogQGRlcHJlY2F0ZWQgdXNlIEVkd2FyZHNQb2ludCAqL1xuZXhwb3J0IHR5cGUgRXh0UG9pbnRUeXBlID0gRWR3YXJkc1BvaW50O1xuLyoqIEBkZXByZWNhdGVkIHVzZSBFZHdhcmRzUG9pbnRDb25zICovXG5leHBvcnQgdHlwZSBFeHRQb2ludENvbnN0cnVjdG9yID0gRWR3YXJkc1BvaW50Q29ucztcblxuLyoqXG4gKiBUd2lzdGVkIEVkd2FyZHMgY3VydmUgb3B0aW9ucy5cbiAqXG4gKiAqIGE6IGZvcm11bGEgcGFyYW1cbiAqICogZDogZm9ybXVsYSBwYXJhbVxuICogKiBwOiBwcmltZSBjaGFyYWN0ZXJpc3RpYyAob3JkZXIpIG9mIGZpbml0ZSBmaWVsZCwgaW4gd2hpY2ggYXJpdGhtZXRpY3MgaXMgZG9uZVxuICogKiBuOiBvcmRlciBvZiBwcmltZSBzdWJncm91cCBhLmsuYSB0b3RhbCBhbW91bnQgb2YgdmFsaWQgY3VydmUgcG9pbnRzXG4gKiAqIGg6IGNvZmFjdG9yLiBoKm4gaXMgZ3JvdXAgb3JkZXI7IG4gaXMgc3ViZ3JvdXAgb3JkZXJcbiAqICogR3g6IHggY29vcmRpbmF0ZSBvZiBnZW5lcmF0b3IgcG9pbnQgYS5rLmEuIGJhc2UgcG9pbnRcbiAqICogR3k6IHkgY29vcmRpbmF0ZSBvZiBnZW5lcmF0b3IgcG9pbnRcbiAqL1xuZXhwb3J0IHR5cGUgRWR3YXJkc09wdHMgPSBSZWFkb25seTx7XG4gIHA6IGJpZ2ludDtcbiAgbjogYmlnaW50O1xuICBoOiBiaWdpbnQ7XG4gIGE6IGJpZ2ludDtcbiAgZDogYmlnaW50O1xuICBHeDogYmlnaW50O1xuICBHeTogYmlnaW50O1xufT47XG5cbi8qKlxuICogRXh0cmEgY3VydmUgb3B0aW9ucyBmb3IgVHdpc3RlZCBFZHdhcmRzLlxuICpcbiAqICogRnA6IHJlZGVmaW5lZCBGaWVsZCBvdmVyIGN1cnZlLnBcbiAqICogRm46IHJlZGVmaW5lZCBGaWVsZCBvdmVyIGN1cnZlLm5cbiAqICogdXZSYXRpbzogaGVscGVyIGZ1bmN0aW9uIGZvciBkZWNvbXByZXNzaW9uLCBjYWxjdWxhdGluZyBcdTIyMUEodS92KVxuICovXG5leHBvcnQgdHlwZSBFZHdhcmRzRXh0cmFPcHRzID0gUGFydGlhbDx7XG4gIEZwOiBJRmllbGQ8YmlnaW50PjtcbiAgRm46IElGaWVsZDxiaWdpbnQ+O1xuICBGcEZuTEU6IGJvb2xlYW47XG4gIHV2UmF0aW86ICh1OiBiaWdpbnQsIHY6IGJpZ2ludCkgPT4geyBpc1ZhbGlkOiBib29sZWFuOyB2YWx1ZTogYmlnaW50IH07XG59PjtcblxuLyoqXG4gKiBFZERTQSAoRWR3YXJkcyBEaWdpdGFsIFNpZ25hdHVyZSBhbGdvcml0aG0pIG9wdGlvbnMuXG4gKlxuICogKiBoYXNoOiBoYXNoIGZ1bmN0aW9uIHVzZWQgdG8gaGFzaCBzZWNyZXQga2V5cyBhbmQgbWVzc2FnZXNcbiAqICogYWRqdXN0U2NhbGFyQnl0ZXM6IGNsZWFycyBiaXRzIHRvIGdldCB2YWxpZCBmaWVsZCBlbGVtZW50XG4gKiAqIGRvbWFpbjogVXNlZCBmb3IgaGFzaGluZ1xuICogKiBtYXBUb0N1cnZlOiBmb3IgaGFzaC10by1jdXJ2ZSBzdGFuZGFyZFxuICogKiBwcmVoYXNoOiBSRkMgODAzMiBwcmUtaGFzaGluZyBvZiBtZXNzYWdlcyB0byBzaWduKCkgLyB2ZXJpZnkoKVxuICogKiByYW5kb21CeXRlczogZnVuY3Rpb24gZ2VuZXJhdGluZyByYW5kb20gYnl0ZXMsIHVzZWQgZm9yIHJhbmRvbVNlY3JldEtleVxuICovXG5leHBvcnQgdHlwZSBFZERTQU9wdHMgPSBQYXJ0aWFsPHtcbiAgYWRqdXN0U2NhbGFyQnl0ZXM6IChieXRlczogVWludDhBcnJheSkgPT4gVWludDhBcnJheTtcbiAgZG9tYWluOiAoZGF0YTogVWludDhBcnJheSwgY3R4OiBVaW50OEFycmF5LCBwaGZsYWc6IGJvb2xlYW4pID0+IFVpbnQ4QXJyYXk7XG4gIG1hcFRvQ3VydmU6IChzY2FsYXI6IGJpZ2ludFtdKSA9PiBBZmZpbmVQb2ludDxiaWdpbnQ+O1xuICBwcmVoYXNoOiBGSGFzaDtcbiAgcmFuZG9tQnl0ZXM6IChieXRlc0xlbmd0aD86IG51bWJlcikgPT4gVWludDhBcnJheTtcbn0+O1xuXG4vKipcbiAqIEVkRFNBIChFZHdhcmRzIERpZ2l0YWwgU2lnbmF0dXJlIGFsZ29yaXRobSkgaW50ZXJmYWNlLlxuICpcbiAqIEFsbG93cyB0byBjcmVhdGUgYW5kIHZlcmlmeSBzaWduYXR1cmVzLCBjcmVhdGUgcHVibGljIGFuZCBzZWNyZXQga2V5cy5cbiAqL1xuZXhwb3J0IGludGVyZmFjZSBFZERTQSB7XG4gIGtleWdlbjogKHNlZWQ/OiBVaW50OEFycmF5KSA9PiB7IHNlY3JldEtleTogVWludDhBcnJheTsgcHVibGljS2V5OiBVaW50OEFycmF5IH07XG4gIGdldFB1YmxpY0tleTogKHNlY3JldEtleTogSGV4KSA9PiBVaW50OEFycmF5O1xuICBzaWduOiAobWVzc2FnZTogSGV4LCBzZWNyZXRLZXk6IEhleCwgb3B0aW9ucz86IHsgY29udGV4dD86IEhleCB9KSA9PiBVaW50OEFycmF5O1xuICB2ZXJpZnk6IChcbiAgICBzaWc6IEhleCxcbiAgICBtZXNzYWdlOiBIZXgsXG4gICAgcHVibGljS2V5OiBIZXgsXG4gICAgb3B0aW9ucz86IHsgY29udGV4dD86IEhleDsgemlwMjE1OiBib29sZWFuIH1cbiAgKSA9PiBib29sZWFuO1xuICBQb2ludDogRWR3YXJkc1BvaW50Q29ucztcbiAgdXRpbHM6IHtcbiAgICByYW5kb21TZWNyZXRLZXk6IChzZWVkPzogVWludDhBcnJheSkgPT4gVWludDhBcnJheTtcbiAgICBpc1ZhbGlkU2VjcmV0S2V5OiAoc2VjcmV0S2V5OiBVaW50OEFycmF5KSA9PiBib29sZWFuO1xuICAgIGlzVmFsaWRQdWJsaWNLZXk6IChwdWJsaWNLZXk6IFVpbnQ4QXJyYXksIHppcDIxNT86IGJvb2xlYW4pID0+IGJvb2xlYW47XG5cbiAgICAvKipcbiAgICAgKiBDb252ZXJ0cyBlZCBwdWJsaWMga2V5IHRvIHggcHVibGljIGtleS5cbiAgICAgKlxuICAgICAqIFRoZXJlIGlzIE5PIGBmcm9tTW9udGdvbWVyeWA6XG4gICAgICogLSBUaGVyZSBhcmUgMiB2YWxpZCBlZDI1NTE5IHBvaW50cyBmb3IgZXZlcnkgeDI1NTE5LCB3aXRoIGZsaXBwZWQgY29vcmRpbmF0ZVxuICAgICAqIC0gU29tZXRpbWVzIHRoZXJlIGFyZSAwIHZhbGlkIGVkMjU1MTkgcG9pbnRzLCBiZWNhdXNlIHgyNTUxOSAqYWRkaXRpb25hbGx5KlxuICAgICAqICAgYWNjZXB0cyBpbnB1dHMgb24gdGhlIHF1YWRyYXRpYyB0d2lzdCwgd2hpY2ggY2FuJ3QgYmUgbW92ZWQgdG8gZWQyNTUxOVxuICAgICAqXG4gICAgICogQGV4YW1wbGVcbiAgICAgKiBgYGBqc1xuICAgICAqIGNvbnN0IHNvbWVvbmVzUHViID0gZWQyNTUxOS5nZXRQdWJsaWNLZXkoZWQyNTUxOS51dGlscy5yYW5kb21TZWNyZXRLZXkoKSk7XG4gICAgICogY29uc3QgYVByaXYgPSB4MjU1MTkudXRpbHMucmFuZG9tU2VjcmV0S2V5KCk7XG4gICAgICogeDI1NTE5LmdldFNoYXJlZFNlY3JldChhUHJpdiwgZWQyNTUxOS51dGlscy50b01vbnRnb21lcnkoc29tZW9uZXNQdWIpKVxuICAgICAqIGBgYFxuICAgICAqL1xuICAgIHRvTW9udGdvbWVyeTogKHB1YmxpY0tleTogVWludDhBcnJheSkgPT4gVWludDhBcnJheTtcbiAgICAvKipcbiAgICAgKiBDb252ZXJ0cyBlZCBzZWNyZXQga2V5IHRvIHggc2VjcmV0IGtleS5cbiAgICAgKiBAZXhhbXBsZVxuICAgICAqIGBgYGpzXG4gICAgICogY29uc3Qgc29tZW9uZXNQdWIgPSB4MjU1MTkuZ2V0UHVibGljS2V5KHgyNTUxOS51dGlscy5yYW5kb21TZWNyZXRLZXkoKSk7XG4gICAgICogY29uc3QgYVByaXYgPSBlZDI1NTE5LnV0aWxzLnJhbmRvbVNlY3JldEtleSgpO1xuICAgICAqIHgyNTUxOS5nZXRTaGFyZWRTZWNyZXQoZWQyNTUxOS51dGlscy50b01vbnRnb21lcnlTZWNyZXQoYVByaXYpLCBzb21lb25lc1B1YilcbiAgICAgKiBgYGBcbiAgICAgKi9cbiAgICB0b01vbnRnb21lcnlTZWNyZXQ6IChwcml2YXRlS2V5OiBVaW50OEFycmF5KSA9PiBVaW50OEFycmF5O1xuICAgIGdldEV4dGVuZGVkUHVibGljS2V5OiAoa2V5OiBIZXgpID0+IHtcbiAgICAgIGhlYWQ6IFVpbnQ4QXJyYXk7XG4gICAgICBwcmVmaXg6IFVpbnQ4QXJyYXk7XG4gICAgICBzY2FsYXI6IGJpZ2ludDtcbiAgICAgIHBvaW50OiBFZHdhcmRzUG9pbnQ7XG4gICAgICBwb2ludEJ5dGVzOiBVaW50OEFycmF5O1xuICAgIH07XG5cbiAgICAvKiogQGRlcHJlY2F0ZWQgdXNlIGByYW5kb21TZWNyZXRLZXlgICovXG4gICAgcmFuZG9tUHJpdmF0ZUtleTogKHNlZWQ/OiBVaW50OEFycmF5KSA9PiBVaW50OEFycmF5O1xuICAgIC8qKiBAZGVwcmVjYXRlZCB1c2UgYHBvaW50LnByZWNvbXB1dGUoKWAgKi9cbiAgICBwcmVjb21wdXRlOiAod2luZG93U2l6ZT86IG51bWJlciwgcG9pbnQ/OiBFZHdhcmRzUG9pbnQpID0+IEVkd2FyZHNQb2ludDtcbiAgfTtcbiAgbGVuZ3RoczogQ3VydmVMZW5ndGhzO1xufVxuXG5mdW5jdGlvbiBpc0VkVmFsaWRYWShGcDogSUZpZWxkPGJpZ2ludD4sIENVUlZFOiBFZHdhcmRzT3B0cywgeDogYmlnaW50LCB5OiBiaWdpbnQpOiBib29sZWFuIHtcbiAgY29uc3QgeDIgPSBGcC5zcXIoeCk7XG4gIGNvbnN0IHkyID0gRnAuc3FyKHkpO1xuICBjb25zdCBsZWZ0ID0gRnAuYWRkKEZwLm11bChDVVJWRS5hLCB4MiksIHkyKTtcbiAgY29uc3QgcmlnaHQgPSBGcC5hZGQoRnAuT05FLCBGcC5tdWwoQ1VSVkUuZCwgRnAubXVsKHgyLCB5MikpKTtcbiAgcmV0dXJuIEZwLmVxbChsZWZ0LCByaWdodCk7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBlZHdhcmRzKHBhcmFtczogRWR3YXJkc09wdHMsIGV4dHJhT3B0czogRWR3YXJkc0V4dHJhT3B0cyA9IHt9KTogRWR3YXJkc1BvaW50Q29ucyB7XG4gIGNvbnN0IHZhbGlkYXRlZCA9IF9jcmVhdGVDdXJ2ZUZpZWxkcygnZWR3YXJkcycsIHBhcmFtcywgZXh0cmFPcHRzLCBleHRyYU9wdHMuRnBGbkxFKTtcbiAgY29uc3QgeyBGcCwgRm4gfSA9IHZhbGlkYXRlZDtcbiAgbGV0IENVUlZFID0gdmFsaWRhdGVkLkNVUlZFIGFzIEVkd2FyZHNPcHRzO1xuICBjb25zdCB7IGg6IGNvZmFjdG9yIH0gPSBDVVJWRTtcbiAgX3ZhbGlkYXRlT2JqZWN0KGV4dHJhT3B0cywge30sIHsgdXZSYXRpbzogJ2Z1bmN0aW9uJyB9KTtcblxuICAvLyBJbXBvcnRhbnQ6XG4gIC8vIFRoZXJlIGFyZSBzb21lIHBsYWNlcyB3aGVyZSBGcC5CWVRFUyBpcyB1c2VkIGluc3RlYWQgb2YgbkJ5dGVMZW5ndGguXG4gIC8vIFNvIGZhciwgZXZlcnl0aGluZyBoYXMgYmVlbiB0ZXN0ZWQgd2l0aCBjdXJ2ZXMgb2YgRnAuQllURVMgPT0gbkJ5dGVMZW5ndGguXG4gIC8vIFRPRE86IHRlc3QgYW5kIGZpbmQgY3VydmVzIHdoaWNoIGJlaGF2ZSBvdGhlcndpc2UuXG4gIGNvbnN0IE1BU0sgPSBfMm4gPDwgKEJpZ0ludChGbi5CWVRFUyAqIDgpIC0gXzFuKTtcbiAgY29uc3QgbW9kUCA9IChuOiBiaWdpbnQpID0+IEZwLmNyZWF0ZShuKTsgLy8gRnVuY3Rpb24gb3ZlcnJpZGVzXG5cbiAgLy8gc3FydCh1L3YpXG4gIGNvbnN0IHV2UmF0aW8gPVxuICAgIGV4dHJhT3B0cy51dlJhdGlvIHx8XG4gICAgKCh1OiBiaWdpbnQsIHY6IGJpZ2ludCkgPT4ge1xuICAgICAgdHJ5IHtcbiAgICAgICAgcmV0dXJuIHsgaXNWYWxpZDogdHJ1ZSwgdmFsdWU6IEZwLnNxcnQoRnAuZGl2KHUsIHYpKSB9O1xuICAgICAgfSBjYXRjaCAoZSkge1xuICAgICAgICByZXR1cm4geyBpc1ZhbGlkOiBmYWxzZSwgdmFsdWU6IF8wbiB9O1xuICAgICAgfVxuICAgIH0pO1xuXG4gIC8vIFZhbGlkYXRlIHdoZXRoZXIgdGhlIHBhc3NlZCBjdXJ2ZSBwYXJhbXMgYXJlIHZhbGlkLlxuICAvLyBlcXVhdGlvbiBheFx1MDBCMiArIHlcdTAwQjIgPSAxICsgZHhcdTAwQjJ5XHUwMEIyIHNob3VsZCB3b3JrIGZvciBnZW5lcmF0b3IgcG9pbnQuXG4gIGlmICghaXNFZFZhbGlkWFkoRnAsIENVUlZFLCBDVVJWRS5HeCwgQ1VSVkUuR3kpKVxuICAgIHRocm93IG5ldyBFcnJvcignYmFkIGN1cnZlIHBhcmFtczogZ2VuZXJhdG9yIHBvaW50Jyk7XG5cbiAgLyoqXG4gICAqIEFzc2VydHMgY29vcmRpbmF0ZSBpcyB2YWxpZDogMCA8PSBuIDwgTUFTSy5cbiAgICogQ29vcmRpbmF0ZXMgPj0gRnAuT1JERVIgYXJlIGFsbG93ZWQgZm9yIHppcDIxNS5cbiAgICovXG4gIGZ1bmN0aW9uIGFjb29yZCh0aXRsZTogc3RyaW5nLCBuOiBiaWdpbnQsIGJhblplcm8gPSBmYWxzZSkge1xuICAgIGNvbnN0IG1pbiA9IGJhblplcm8gPyBfMW4gOiBfMG47XG4gICAgYUluUmFuZ2UoJ2Nvb3JkaW5hdGUgJyArIHRpdGxlLCBuLCBtaW4sIE1BU0spO1xuICAgIHJldHVybiBuO1xuICB9XG5cbiAgZnVuY3Rpb24gYWV4dHBvaW50KG90aGVyOiB1bmtub3duKSB7XG4gICAgaWYgKCEob3RoZXIgaW5zdGFuY2VvZiBQb2ludCkpIHRocm93IG5ldyBFcnJvcignRXh0ZW5kZWRQb2ludCBleHBlY3RlZCcpO1xuICB9XG4gIC8vIENvbnZlcnRzIEV4dGVuZGVkIHBvaW50IHRvIGRlZmF1bHQgKHgsIHkpIGNvb3JkaW5hdGVzLlxuICAvLyBDYW4gYWNjZXB0IHByZWNvbXB1dGVkIFpeLTEgLSBmb3IgZXhhbXBsZSwgZnJvbSBpbnZlcnRCYXRjaC5cbiAgY29uc3QgdG9BZmZpbmVNZW1vID0gbWVtb2l6ZWQoKHA6IFBvaW50LCBpej86IGJpZ2ludCk6IEFmZmluZVBvaW50PGJpZ2ludD4gPT4ge1xuICAgIGNvbnN0IHsgWCwgWSwgWiB9ID0gcDtcbiAgICBjb25zdCBpczAgPSBwLmlzMCgpO1xuICAgIGlmIChpeiA9PSBudWxsKSBpeiA9IGlzMCA/IF84biA6IChGcC5pbnYoWikgYXMgYmlnaW50KTsgLy8gOCB3YXMgY2hvc2VuIGFyYml0cmFyaWx5XG4gICAgY29uc3QgeCA9IG1vZFAoWCAqIGl6KTtcbiAgICBjb25zdCB5ID0gbW9kUChZICogaXopO1xuICAgIGNvbnN0IHp6ID0gRnAubXVsKFosIGl6KTtcbiAgICBpZiAoaXMwKSByZXR1cm4geyB4OiBfMG4sIHk6IF8xbiB9O1xuICAgIGlmICh6eiAhPT0gXzFuKSB0aHJvdyBuZXcgRXJyb3IoJ2ludlogd2FzIGludmFsaWQnKTtcbiAgICByZXR1cm4geyB4LCB5IH07XG4gIH0pO1xuICBjb25zdCBhc3NlcnRWYWxpZE1lbW8gPSBtZW1vaXplZCgocDogUG9pbnQpID0+IHtcbiAgICBjb25zdCB7IGEsIGQgfSA9IENVUlZFO1xuICAgIGlmIChwLmlzMCgpKSB0aHJvdyBuZXcgRXJyb3IoJ2JhZCBwb2ludDogWkVSTycpOyAvLyBUT0RPOiBvcHRpbWl6ZSwgd2l0aCB2YXJzIGJlbG93P1xuICAgIC8vIEVxdWF0aW9uIGluIGFmZmluZSBjb29yZGluYXRlczogYXhcdTAwQjIgKyB5XHUwMEIyID0gMSArIGR4XHUwMEIyeVx1MDBCMlxuICAgIC8vIEVxdWF0aW9uIGluIHByb2plY3RpdmUgY29vcmRpbmF0ZXMgKFgvWiwgWS9aLCBaKTogIChhWFx1MDBCMiArIFlcdTAwQjIpWlx1MDBCMiA9IFpcdTIwNzQgKyBkWFx1MDBCMllcdTAwQjJcbiAgICBjb25zdCB7IFgsIFksIFosIFQgfSA9IHA7XG4gICAgY29uc3QgWDIgPSBtb2RQKFggKiBYKTsgLy8gWFx1MDBCMlxuICAgIGNvbnN0IFkyID0gbW9kUChZICogWSk7IC8vIFlcdTAwQjJcbiAgICBjb25zdCBaMiA9IG1vZFAoWiAqIFopOyAvLyBaXHUwMEIyXG4gICAgY29uc3QgWjQgPSBtb2RQKFoyICogWjIpOyAvLyBaXHUyMDc0XG4gICAgY29uc3QgYVgyID0gbW9kUChYMiAqIGEpOyAvLyBhWFx1MDBCMlxuICAgIGNvbnN0IGxlZnQgPSBtb2RQKFoyICogbW9kUChhWDIgKyBZMikpOyAvLyAoYVhcdTAwQjIgKyBZXHUwMEIyKVpcdTAwQjJcbiAgICBjb25zdCByaWdodCA9IG1vZFAoWjQgKyBtb2RQKGQgKiBtb2RQKFgyICogWTIpKSk7IC8vIFpcdTIwNzQgKyBkWFx1MDBCMllcdTAwQjJcbiAgICBpZiAobGVmdCAhPT0gcmlnaHQpIHRocm93IG5ldyBFcnJvcignYmFkIHBvaW50OiBlcXVhdGlvbiBsZWZ0ICE9IHJpZ2h0ICgxKScpO1xuICAgIC8vIEluIEV4dGVuZGVkIGNvb3JkaW5hdGVzIHdlIGFsc28gaGF2ZSBULCB3aGljaCBpcyB4Knk9VC9aOiBjaGVjayBYKlkgPT0gWipUXG4gICAgY29uc3QgWFkgPSBtb2RQKFggKiBZKTtcbiAgICBjb25zdCBaVCA9IG1vZFAoWiAqIFQpO1xuICAgIGlmIChYWSAhPT0gWlQpIHRocm93IG5ldyBFcnJvcignYmFkIHBvaW50OiBlcXVhdGlvbiBsZWZ0ICE9IHJpZ2h0ICgyKScpO1xuICAgIHJldHVybiB0cnVlO1xuICB9KTtcblxuICAvLyBFeHRlbmRlZCBQb2ludCB3b3JrcyBpbiBleHRlbmRlZCBjb29yZGluYXRlczogKFgsIFksIFosIFQpIFx1MjIwQiAoeD1YL1osIHk9WS9aLCBUPXh5KS5cbiAgLy8gaHR0cHM6Ly9lbi53aWtpcGVkaWEub3JnL3dpa2kvVHdpc3RlZF9FZHdhcmRzX2N1cnZlI0V4dGVuZGVkX2Nvb3JkaW5hdGVzXG4gIGNsYXNzIFBvaW50IGltcGxlbWVudHMgRWR3YXJkc1BvaW50IHtcbiAgICAvLyBiYXNlIC8gZ2VuZXJhdG9yIHBvaW50XG4gICAgc3RhdGljIHJlYWRvbmx5IEJBU0UgPSBuZXcgUG9pbnQoQ1VSVkUuR3gsIENVUlZFLkd5LCBfMW4sIG1vZFAoQ1VSVkUuR3ggKiBDVVJWRS5HeSkpO1xuICAgIC8vIHplcm8gLyBpbmZpbml0eSAvIGlkZW50aXR5IHBvaW50XG4gICAgc3RhdGljIHJlYWRvbmx5IFpFUk8gPSBuZXcgUG9pbnQoXzBuLCBfMW4sIF8xbiwgXzBuKTsgLy8gMCwgMSwgMSwgMFxuICAgIC8vIG1hdGggZmllbGRcbiAgICBzdGF0aWMgcmVhZG9ubHkgRnAgPSBGcDtcbiAgICAvLyBzY2FsYXIgZmllbGRcbiAgICBzdGF0aWMgcmVhZG9ubHkgRm4gPSBGbjtcblxuICAgIHJlYWRvbmx5IFg6IGJpZ2ludDtcbiAgICByZWFkb25seSBZOiBiaWdpbnQ7XG4gICAgcmVhZG9ubHkgWjogYmlnaW50O1xuICAgIHJlYWRvbmx5IFQ6IGJpZ2ludDtcblxuICAgIGNvbnN0cnVjdG9yKFg6IGJpZ2ludCwgWTogYmlnaW50LCBaOiBiaWdpbnQsIFQ6IGJpZ2ludCkge1xuICAgICAgdGhpcy5YID0gYWNvb3JkKCd4JywgWCk7XG4gICAgICB0aGlzLlkgPSBhY29vcmQoJ3knLCBZKTtcbiAgICAgIHRoaXMuWiA9IGFjb29yZCgneicsIFosIHRydWUpO1xuICAgICAgdGhpcy5UID0gYWNvb3JkKCd0JywgVCk7XG4gICAgICBPYmplY3QuZnJlZXplKHRoaXMpO1xuICAgIH1cblxuICAgIHN0YXRpYyBDVVJWRSgpOiBFZHdhcmRzT3B0cyB7XG4gICAgICByZXR1cm4gQ1VSVkU7XG4gICAgfVxuXG4gICAgc3RhdGljIGZyb21BZmZpbmUocDogQWZmaW5lUG9pbnQ8YmlnaW50Pik6IFBvaW50IHtcbiAgICAgIGlmIChwIGluc3RhbmNlb2YgUG9pbnQpIHRocm93IG5ldyBFcnJvcignZXh0ZW5kZWQgcG9pbnQgbm90IGFsbG93ZWQnKTtcbiAgICAgIGNvbnN0IHsgeCwgeSB9ID0gcCB8fCB7fTtcbiAgICAgIGFjb29yZCgneCcsIHgpO1xuICAgICAgYWNvb3JkKCd5JywgeSk7XG4gICAgICByZXR1cm4gbmV3IFBvaW50KHgsIHksIF8xbiwgbW9kUCh4ICogeSkpO1xuICAgIH1cblxuICAgIC8vIFVzZXMgYWxnbyBmcm9tIFJGQzgwMzIgNS4xLjMuXG4gICAgc3RhdGljIGZyb21CeXRlcyhieXRlczogVWludDhBcnJheSwgemlwMjE1ID0gZmFsc2UpOiBQb2ludCB7XG4gICAgICBjb25zdCBsZW4gPSBGcC5CWVRFUztcbiAgICAgIGNvbnN0IHsgYSwgZCB9ID0gQ1VSVkU7XG4gICAgICBieXRlcyA9IGNvcHlCeXRlcyhhYnl0ZXMoYnl0ZXMsIGxlbiwgJ3BvaW50JykpO1xuICAgICAgYWJvb2woemlwMjE1LCAnemlwMjE1Jyk7XG4gICAgICBjb25zdCBub3JtZWQgPSBjb3B5Qnl0ZXMoYnl0ZXMpOyAvLyBjb3B5IGFnYWluLCB3ZSdsbCBtYW5pcHVsYXRlIGl0XG4gICAgICBjb25zdCBsYXN0Qnl0ZSA9IGJ5dGVzW2xlbiAtIDFdOyAvLyBzZWxlY3QgbGFzdCBieXRlXG4gICAgICBub3JtZWRbbGVuIC0gMV0gPSBsYXN0Qnl0ZSAmIH4weDgwOyAvLyBjbGVhciBsYXN0IGJpdFxuICAgICAgY29uc3QgeSA9IGJ5dGVzVG9OdW1iZXJMRShub3JtZWQpO1xuXG4gICAgICAvLyB6aXAyMTU9dHJ1ZSBpcyBnb29kIGZvciBjb25zZW5zdXMtY3JpdGljYWwgYXBwcy4gPWZhbHNlIGZvbGxvd3MgUkZDODAzMiAvIE5JU1QxODYtNS5cbiAgICAgIC8vIFJGQzgwMzIgcHJvaGliaXRzID49IHAsIGJ1dCBaSVAyMTUgZG9lc24ndFxuICAgICAgLy8gemlwMjE1PXRydWU6ICAwIDw9IHkgPCBNQVNLICgyXjI1NiBmb3IgZWQyNTUxOSlcbiAgICAgIC8vIHppcDIxNT1mYWxzZTogMCA8PSB5IDwgUCAoMl4yNTUtMTkgZm9yIGVkMjU1MTkpXG4gICAgICBjb25zdCBtYXggPSB6aXAyMTUgPyBNQVNLIDogRnAuT1JERVI7XG4gICAgICBhSW5SYW5nZSgncG9pbnQueScsIHksIF8wbiwgbWF4KTtcblxuICAgICAgLy8gRWQyNTUxOTogeFx1MDBCMiA9ICh5XHUwMEIyLTEpLyhkeVx1MDBCMisxKSBtb2QgcC4gRWQ0NDg6IHhcdTAwQjIgPSAoeVx1MDBCMi0xKS8oZHlcdTAwQjItMSkgbW9kIHAuIEdlbmVyaWMgY2FzZTpcbiAgICAgIC8vIGF4XHUwMEIyK3lcdTAwQjI9MStkeFx1MDBCMnlcdTAwQjIgPT4geVx1MDBCMi0xPWR4XHUwMEIyeVx1MDBCMi1heFx1MDBCMiA9PiB5XHUwMEIyLTE9eFx1MDBCMihkeVx1MDBCMi1hKSA9PiB4XHUwMEIyPSh5XHUwMEIyLTEpLyhkeVx1MDBCMi1hKVxuICAgICAgY29uc3QgeTIgPSBtb2RQKHkgKiB5KTsgLy8gZGVub21pbmF0b3IgaXMgYWx3YXlzIG5vbi0wIG1vZCBwLlxuICAgICAgY29uc3QgdSA9IG1vZFAoeTIgLSBfMW4pOyAvLyB1ID0geVx1MDBCMiAtIDFcbiAgICAgIGNvbnN0IHYgPSBtb2RQKGQgKiB5MiAtIGEpOyAvLyB2ID0gZCB5XHUwMEIyICsgMS5cbiAgICAgIGxldCB7IGlzVmFsaWQsIHZhbHVlOiB4IH0gPSB1dlJhdGlvKHUsIHYpOyAvLyBcdTIyMUEodS92KVxuICAgICAgaWYgKCFpc1ZhbGlkKSB0aHJvdyBuZXcgRXJyb3IoJ2JhZCBwb2ludDogaW52YWxpZCB5IGNvb3JkaW5hdGUnKTtcbiAgICAgIGNvbnN0IGlzWE9kZCA9ICh4ICYgXzFuKSA9PT0gXzFuOyAvLyBUaGVyZSBhcmUgMiBzcXVhcmUgcm9vdHMuIFVzZSB4XzAgYml0IHRvIHNlbGVjdCBwcm9wZXJcbiAgICAgIGNvbnN0IGlzTGFzdEJ5dGVPZGQgPSAobGFzdEJ5dGUgJiAweDgwKSAhPT0gMDsgLy8geF8wLCBsYXN0IGJpdFxuICAgICAgaWYgKCF6aXAyMTUgJiYgeCA9PT0gXzBuICYmIGlzTGFzdEJ5dGVPZGQpXG4gICAgICAgIC8vIGlmIHg9MCBhbmQgeF8wID0gMSwgZmFpbFxuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ2JhZCBwb2ludDogeD0wIGFuZCB4XzA9MScpO1xuICAgICAgaWYgKGlzTGFzdEJ5dGVPZGQgIT09IGlzWE9kZCkgeCA9IG1vZFAoLXgpOyAvLyBpZiB4XzAgIT0geCBtb2QgMiwgc2V0IHggPSBwLXhcbiAgICAgIHJldHVybiBQb2ludC5mcm9tQWZmaW5lKHsgeCwgeSB9KTtcbiAgICB9XG4gICAgc3RhdGljIGZyb21IZXgoYnl0ZXM6IFVpbnQ4QXJyYXksIHppcDIxNSA9IGZhbHNlKTogUG9pbnQge1xuICAgICAgcmV0dXJuIFBvaW50LmZyb21CeXRlcyhlbnN1cmVCeXRlcygncG9pbnQnLCBieXRlcyksIHppcDIxNSk7XG4gICAgfVxuXG4gICAgZ2V0IHgoKTogYmlnaW50IHtcbiAgICAgIHJldHVybiB0aGlzLnRvQWZmaW5lKCkueDtcbiAgICB9XG4gICAgZ2V0IHkoKTogYmlnaW50IHtcbiAgICAgIHJldHVybiB0aGlzLnRvQWZmaW5lKCkueTtcbiAgICB9XG5cbiAgICBwcmVjb21wdXRlKHdpbmRvd1NpemU6IG51bWJlciA9IDgsIGlzTGF6eSA9IHRydWUpIHtcbiAgICAgIHduYWYuY3JlYXRlQ2FjaGUodGhpcywgd2luZG93U2l6ZSk7XG4gICAgICBpZiAoIWlzTGF6eSkgdGhpcy5tdWx0aXBseShfMm4pOyAvLyByYW5kb20gbnVtYmVyXG4gICAgICByZXR1cm4gdGhpcztcbiAgICB9XG5cbiAgICAvLyBVc2VmdWwgaW4gZnJvbUFmZmluZSgpIC0gbm90IGZvciBmcm9tQnl0ZXMoKSwgd2hpY2ggYWx3YXlzIGNyZWF0ZWQgdmFsaWQgcG9pbnRzLlxuICAgIGFzc2VydFZhbGlkaXR5KCk6IHZvaWQge1xuICAgICAgYXNzZXJ0VmFsaWRNZW1vKHRoaXMpO1xuICAgIH1cblxuICAgIC8vIENvbXBhcmUgb25lIHBvaW50IHRvIGFub3RoZXIuXG4gICAgZXF1YWxzKG90aGVyOiBQb2ludCk6IGJvb2xlYW4ge1xuICAgICAgYWV4dHBvaW50KG90aGVyKTtcbiAgICAgIGNvbnN0IHsgWDogWDEsIFk6IFkxLCBaOiBaMSB9ID0gdGhpcztcbiAgICAgIGNvbnN0IHsgWDogWDIsIFk6IFkyLCBaOiBaMiB9ID0gb3RoZXI7XG4gICAgICBjb25zdCBYMVoyID0gbW9kUChYMSAqIFoyKTtcbiAgICAgIGNvbnN0IFgyWjEgPSBtb2RQKFgyICogWjEpO1xuICAgICAgY29uc3QgWTFaMiA9IG1vZFAoWTEgKiBaMik7XG4gICAgICBjb25zdCBZMloxID0gbW9kUChZMiAqIFoxKTtcbiAgICAgIHJldHVybiBYMVoyID09PSBYMloxICYmIFkxWjIgPT09IFkyWjE7XG4gICAgfVxuXG4gICAgaXMwKCk6IGJvb2xlYW4ge1xuICAgICAgcmV0dXJuIHRoaXMuZXF1YWxzKFBvaW50LlpFUk8pO1xuICAgIH1cblxuICAgIG5lZ2F0ZSgpOiBQb2ludCB7XG4gICAgICAvLyBGbGlwcyBwb2ludCBzaWduIHRvIGEgbmVnYXRpdmUgb25lICgteCwgeSBpbiBhZmZpbmUgY29vcmRzKVxuICAgICAgcmV0dXJuIG5ldyBQb2ludChtb2RQKC10aGlzLlgpLCB0aGlzLlksIHRoaXMuWiwgbW9kUCgtdGhpcy5UKSk7XG4gICAgfVxuXG4gICAgLy8gRmFzdCBhbGdvIGZvciBkb3VibGluZyBFeHRlbmRlZCBQb2ludC5cbiAgICAvLyBodHRwczovL2h5cGVyZWxsaXB0aWMub3JnL0VGRC9nMXAvYXV0by10d2lzdGVkLWV4dGVuZGVkLmh0bWwjZG91YmxpbmctZGJsLTIwMDgtaHdjZFxuICAgIC8vIENvc3Q6IDRNICsgNFMgKyAxKmEgKyA2YWRkICsgMSoyLlxuICAgIGRvdWJsZSgpOiBQb2ludCB7XG4gICAgICBjb25zdCB7IGEgfSA9IENVUlZFO1xuICAgICAgY29uc3QgeyBYOiBYMSwgWTogWTEsIFo6IFoxIH0gPSB0aGlzO1xuICAgICAgY29uc3QgQSA9IG1vZFAoWDEgKiBYMSk7IC8vIEEgPSBYMTJcbiAgICAgIGNvbnN0IEIgPSBtb2RQKFkxICogWTEpOyAvLyBCID0gWTEyXG4gICAgICBjb25zdCBDID0gbW9kUChfMm4gKiBtb2RQKFoxICogWjEpKTsgLy8gQyA9IDIqWjEyXG4gICAgICBjb25zdCBEID0gbW9kUChhICogQSk7IC8vIEQgPSBhKkFcbiAgICAgIGNvbnN0IHgxeTEgPSBYMSArIFkxO1xuICAgICAgY29uc3QgRSA9IG1vZFAobW9kUCh4MXkxICogeDF5MSkgLSBBIC0gQik7IC8vIEUgPSAoWDErWTEpMi1BLUJcbiAgICAgIGNvbnN0IEcgPSBEICsgQjsgLy8gRyA9IEQrQlxuICAgICAgY29uc3QgRiA9IEcgLSBDOyAvLyBGID0gRy1DXG4gICAgICBjb25zdCBIID0gRCAtIEI7IC8vIEggPSBELUJcbiAgICAgIGNvbnN0IFgzID0gbW9kUChFICogRik7IC8vIFgzID0gRSpGXG4gICAgICBjb25zdCBZMyA9IG1vZFAoRyAqIEgpOyAvLyBZMyA9IEcqSFxuICAgICAgY29uc3QgVDMgPSBtb2RQKEUgKiBIKTsgLy8gVDMgPSBFKkhcbiAgICAgIGNvbnN0IFozID0gbW9kUChGICogRyk7IC8vIFozID0gRipHXG4gICAgICByZXR1cm4gbmV3IFBvaW50KFgzLCBZMywgWjMsIFQzKTtcbiAgICB9XG5cbiAgICAvLyBGYXN0IGFsZ28gZm9yIGFkZGluZyAyIEV4dGVuZGVkIFBvaW50cy5cbiAgICAvLyBodHRwczovL2h5cGVyZWxsaXB0aWMub3JnL0VGRC9nMXAvYXV0by10d2lzdGVkLWV4dGVuZGVkLmh0bWwjYWRkaXRpb24tYWRkLTIwMDgtaHdjZFxuICAgIC8vIENvc3Q6IDlNICsgMSphICsgMSpkICsgN2FkZC5cbiAgICBhZGQob3RoZXI6IFBvaW50KSB7XG4gICAgICBhZXh0cG9pbnQob3RoZXIpO1xuICAgICAgY29uc3QgeyBhLCBkIH0gPSBDVVJWRTtcbiAgICAgIGNvbnN0IHsgWDogWDEsIFk6IFkxLCBaOiBaMSwgVDogVDEgfSA9IHRoaXM7XG4gICAgICBjb25zdCB7IFg6IFgyLCBZOiBZMiwgWjogWjIsIFQ6IFQyIH0gPSBvdGhlcjtcbiAgICAgIGNvbnN0IEEgPSBtb2RQKFgxICogWDIpOyAvLyBBID0gWDEqWDJcbiAgICAgIGNvbnN0IEIgPSBtb2RQKFkxICogWTIpOyAvLyBCID0gWTEqWTJcbiAgICAgIGNvbnN0IEMgPSBtb2RQKFQxICogZCAqIFQyKTsgLy8gQyA9IFQxKmQqVDJcbiAgICAgIGNvbnN0IEQgPSBtb2RQKFoxICogWjIpOyAvLyBEID0gWjEqWjJcbiAgICAgIGNvbnN0IEUgPSBtb2RQKChYMSArIFkxKSAqIChYMiArIFkyKSAtIEEgLSBCKTsgLy8gRSA9IChYMStZMSkqKFgyK1kyKS1BLUJcbiAgICAgIGNvbnN0IEYgPSBEIC0gQzsgLy8gRiA9IEQtQ1xuICAgICAgY29uc3QgRyA9IEQgKyBDOyAvLyBHID0gRCtDXG4gICAgICBjb25zdCBIID0gbW9kUChCIC0gYSAqIEEpOyAvLyBIID0gQi1hKkFcbiAgICAgIGNvbnN0IFgzID0gbW9kUChFICogRik7IC8vIFgzID0gRSpGXG4gICAgICBjb25zdCBZMyA9IG1vZFAoRyAqIEgpOyAvLyBZMyA9IEcqSFxuICAgICAgY29uc3QgVDMgPSBtb2RQKEUgKiBIKTsgLy8gVDMgPSBFKkhcbiAgICAgIGNvbnN0IFozID0gbW9kUChGICogRyk7IC8vIFozID0gRipHXG4gICAgICByZXR1cm4gbmV3IFBvaW50KFgzLCBZMywgWjMsIFQzKTtcbiAgICB9XG5cbiAgICBzdWJ0cmFjdChvdGhlcjogUG9pbnQpOiBQb2ludCB7XG4gICAgICByZXR1cm4gdGhpcy5hZGQob3RoZXIubmVnYXRlKCkpO1xuICAgIH1cblxuICAgIC8vIENvbnN0YW50LXRpbWUgbXVsdGlwbGljYXRpb24uXG4gICAgbXVsdGlwbHkoc2NhbGFyOiBiaWdpbnQpOiBQb2ludCB7XG4gICAgICAvLyAxIDw9IHNjYWxhciA8IExcbiAgICAgIGlmICghRm4uaXNWYWxpZE5vdDAoc2NhbGFyKSkgdGhyb3cgbmV3IEVycm9yKCdpbnZhbGlkIHNjYWxhcjogZXhwZWN0ZWQgMSA8PSBzYyA8IGN1cnZlLm4nKTtcbiAgICAgIGNvbnN0IHsgcCwgZiB9ID0gd25hZi5jYWNoZWQodGhpcywgc2NhbGFyLCAocCkgPT4gbm9ybWFsaXplWihQb2ludCwgcCkpO1xuICAgICAgcmV0dXJuIG5vcm1hbGl6ZVooUG9pbnQsIFtwLCBmXSlbMF07XG4gICAgfVxuXG4gICAgLy8gTm9uLWNvbnN0YW50LXRpbWUgbXVsdGlwbGljYXRpb24uIFVzZXMgZG91YmxlLWFuZC1hZGQgYWxnb3JpdGhtLlxuICAgIC8vIEl0J3MgZmFzdGVyLCBidXQgc2hvdWxkIG9ubHkgYmUgdXNlZCB3aGVuIHlvdSBkb24ndCBjYXJlIGFib3V0XG4gICAgLy8gYW4gZXhwb3NlZCBwcml2YXRlIGtleSBlLmcuIHNpZyB2ZXJpZmljYXRpb24uXG4gICAgLy8gRG9lcyBOT1QgYWxsb3cgc2NhbGFycyBoaWdoZXIgdGhhbiBDVVJWRS5uLlxuICAgIC8vIEFjY2VwdHMgb3B0aW9uYWwgYWNjdW11bGF0b3IgdG8gbWVyZ2Ugd2l0aCBtdWx0aXBseSAoaW1wb3J0YW50IGZvciBzcGFyc2Ugc2NhbGFycylcbiAgICBtdWx0aXBseVVuc2FmZShzY2FsYXI6IGJpZ2ludCwgYWNjID0gUG9pbnQuWkVSTyk6IFBvaW50IHtcbiAgICAgIC8vIDAgPD0gc2NhbGFyIDwgTFxuICAgICAgaWYgKCFGbi5pc1ZhbGlkKHNjYWxhcikpIHRocm93IG5ldyBFcnJvcignaW52YWxpZCBzY2FsYXI6IGV4cGVjdGVkIDAgPD0gc2MgPCBjdXJ2ZS5uJyk7XG4gICAgICBpZiAoc2NhbGFyID09PSBfMG4pIHJldHVybiBQb2ludC5aRVJPO1xuICAgICAgaWYgKHRoaXMuaXMwKCkgfHwgc2NhbGFyID09PSBfMW4pIHJldHVybiB0aGlzO1xuICAgICAgcmV0dXJuIHduYWYudW5zYWZlKHRoaXMsIHNjYWxhciwgKHApID0+IG5vcm1hbGl6ZVooUG9pbnQsIHApLCBhY2MpO1xuICAgIH1cblxuICAgIC8vIENoZWNrcyBpZiBwb2ludCBpcyBvZiBzbWFsbCBvcmRlci5cbiAgICAvLyBJZiB5b3UgYWRkIHNvbWV0aGluZyB0byBzbWFsbCBvcmRlciBwb2ludCwgeW91IHdpbGwgaGF2ZSBcImRpcnR5XCJcbiAgICAvLyBwb2ludCB3aXRoIHRvcnNpb24gY29tcG9uZW50LlxuICAgIC8vIE11bHRpcGxpZXMgcG9pbnQgYnkgY29mYWN0b3IgYW5kIGNoZWNrcyBpZiB0aGUgcmVzdWx0IGlzIDAuXG4gICAgaXNTbWFsbE9yZGVyKCk6IGJvb2xlYW4ge1xuICAgICAgcmV0dXJuIHRoaXMubXVsdGlwbHlVbnNhZmUoY29mYWN0b3IpLmlzMCgpO1xuICAgIH1cblxuICAgIC8vIE11bHRpcGxpZXMgcG9pbnQgYnkgY3VydmUgb3JkZXIgYW5kIGNoZWNrcyBpZiB0aGUgcmVzdWx0IGlzIDAuXG4gICAgLy8gUmV0dXJucyBgZmFsc2VgIGlzIHRoZSBwb2ludCBpcyBkaXJ0eS5cbiAgICBpc1RvcnNpb25GcmVlKCk6IGJvb2xlYW4ge1xuICAgICAgcmV0dXJuIHduYWYudW5zYWZlKHRoaXMsIENVUlZFLm4pLmlzMCgpO1xuICAgIH1cblxuICAgIC8vIENvbnZlcnRzIEV4dGVuZGVkIHBvaW50IHRvIGRlZmF1bHQgKHgsIHkpIGNvb3JkaW5hdGVzLlxuICAgIC8vIENhbiBhY2NlcHQgcHJlY29tcHV0ZWQgWl4tMSAtIGZvciBleGFtcGxlLCBmcm9tIGludmVydEJhdGNoLlxuICAgIHRvQWZmaW5lKGludmVydGVkWj86IGJpZ2ludCk6IEFmZmluZVBvaW50PGJpZ2ludD4ge1xuICAgICAgcmV0dXJuIHRvQWZmaW5lTWVtbyh0aGlzLCBpbnZlcnRlZFopO1xuICAgIH1cblxuICAgIGNsZWFyQ29mYWN0b3IoKTogUG9pbnQge1xuICAgICAgaWYgKGNvZmFjdG9yID09PSBfMW4pIHJldHVybiB0aGlzO1xuICAgICAgcmV0dXJuIHRoaXMubXVsdGlwbHlVbnNhZmUoY29mYWN0b3IpO1xuICAgIH1cblxuICAgIHRvQnl0ZXMoKTogVWludDhBcnJheSB7XG4gICAgICBjb25zdCB7IHgsIHkgfSA9IHRoaXMudG9BZmZpbmUoKTtcbiAgICAgIC8vIEZwLnRvQnl0ZXMoKSBhbGxvd3Mgbm9uLWNhbm9uaWNhbCBlbmNvZGluZyBvZiB5ICg+PSBwKS5cbiAgICAgIGNvbnN0IGJ5dGVzID0gRnAudG9CeXRlcyh5KTtcbiAgICAgIC8vIEVhY2ggeSBoYXMgMiB2YWxpZCBwb2ludHM6ICh4LCB5KSwgKHgsLXkpLlxuICAgICAgLy8gV2hlbiBjb21wcmVzc2luZywgaXQncyBlbm91Z2ggdG8gc3RvcmUgeSBhbmQgdXNlIHRoZSBsYXN0IGJ5dGUgdG8gZW5jb2RlIHNpZ24gb2YgeFxuICAgICAgYnl0ZXNbYnl0ZXMubGVuZ3RoIC0gMV0gfD0geCAmIF8xbiA/IDB4ODAgOiAwO1xuICAgICAgcmV0dXJuIGJ5dGVzO1xuICAgIH1cbiAgICB0b0hleCgpOiBzdHJpbmcge1xuICAgICAgcmV0dXJuIGJ5dGVzVG9IZXgodGhpcy50b0J5dGVzKCkpO1xuICAgIH1cblxuICAgIHRvU3RyaW5nKCkge1xuICAgICAgcmV0dXJuIGA8UG9pbnQgJHt0aGlzLmlzMCgpID8gJ1pFUk8nIDogdGhpcy50b0hleCgpfT5gO1xuICAgIH1cblxuICAgIC8vIFRPRE86IHJlbW92ZVxuICAgIGdldCBleCgpOiBiaWdpbnQge1xuICAgICAgcmV0dXJuIHRoaXMuWDtcbiAgICB9XG4gICAgZ2V0IGV5KCk6IGJpZ2ludCB7XG4gICAgICByZXR1cm4gdGhpcy5ZO1xuICAgIH1cbiAgICBnZXQgZXooKTogYmlnaW50IHtcbiAgICAgIHJldHVybiB0aGlzLlo7XG4gICAgfVxuICAgIGdldCBldCgpOiBiaWdpbnQge1xuICAgICAgcmV0dXJuIHRoaXMuVDtcbiAgICB9XG4gICAgc3RhdGljIG5vcm1hbGl6ZVoocG9pbnRzOiBQb2ludFtdKTogUG9pbnRbXSB7XG4gICAgICByZXR1cm4gbm9ybWFsaXplWihQb2ludCwgcG9pbnRzKTtcbiAgICB9XG4gICAgc3RhdGljIG1zbShwb2ludHM6IFBvaW50W10sIHNjYWxhcnM6IGJpZ2ludFtdKTogUG9pbnQge1xuICAgICAgcmV0dXJuIHBpcHBlbmdlcihQb2ludCwgRm4sIHBvaW50cywgc2NhbGFycyk7XG4gICAgfVxuICAgIF9zZXRXaW5kb3dTaXplKHdpbmRvd1NpemU6IG51bWJlcikge1xuICAgICAgdGhpcy5wcmVjb21wdXRlKHdpbmRvd1NpemUpO1xuICAgIH1cbiAgICB0b1Jhd0J5dGVzKCk6IFVpbnQ4QXJyYXkge1xuICAgICAgcmV0dXJuIHRoaXMudG9CeXRlcygpO1xuICAgIH1cbiAgfVxuICBjb25zdCB3bmFmID0gbmV3IHdOQUYoUG9pbnQsIEZuLkJJVFMpO1xuICBQb2ludC5CQVNFLnByZWNvbXB1dGUoOCk7IC8vIEVuYWJsZSBwcmVjb21wdXRlcy4gU2xvd3MgZG93biBmaXJzdCBwdWJsaWNLZXkgY29tcHV0YXRpb24gYnkgMjBtcy5cbiAgcmV0dXJuIFBvaW50O1xufVxuXG4vKipcbiAqIEJhc2UgY2xhc3MgZm9yIHByaW1lLW9yZGVyIHBvaW50cyBsaWtlIFJpc3RyZXR0bzI1NSBhbmQgRGVjYWY0NDguXG4gKiBUaGVzZSBwb2ludHMgZWxpbWluYXRlIGNvZmFjdG9yIGlzc3VlcyBieSByZXByZXNlbnRpbmcgZXF1aXZhbGVuY2UgY2xhc3Nlc1xuICogb2YgRWR3YXJkcyBjdXJ2ZSBwb2ludHMuXG4gKi9cbmV4cG9ydCBhYnN0cmFjdCBjbGFzcyBQcmltZUVkd2FyZHNQb2ludDxUIGV4dGVuZHMgUHJpbWVFZHdhcmRzUG9pbnQ8VD4+XG4gIGltcGxlbWVudHMgQ3VydmVQb2ludDxiaWdpbnQsIFQ+XG57XG4gIHN0YXRpYyBCQVNFOiBQcmltZUVkd2FyZHNQb2ludDxhbnk+O1xuICBzdGF0aWMgWkVSTzogUHJpbWVFZHdhcmRzUG9pbnQ8YW55PjtcbiAgc3RhdGljIEZwOiBJRmllbGQ8YmlnaW50PjtcbiAgc3RhdGljIEZuOiBJRmllbGQ8YmlnaW50PjtcblxuICBwcm90ZWN0ZWQgcmVhZG9ubHkgZXA6IEVkd2FyZHNQb2ludDtcblxuICBjb25zdHJ1Y3RvcihlcDogRWR3YXJkc1BvaW50KSB7XG4gICAgdGhpcy5lcCA9IGVwO1xuICB9XG5cbiAgLy8gQWJzdHJhY3QgbWV0aG9kcyB0aGF0IG11c3QgYmUgaW1wbGVtZW50ZWQgYnkgc3ViY2xhc3Nlc1xuICBhYnN0cmFjdCB0b0J5dGVzKCk6IFVpbnQ4QXJyYXk7XG4gIGFic3RyYWN0IGVxdWFscyhvdGhlcjogVCk6IGJvb2xlYW47XG5cbiAgLy8gU3RhdGljIG1ldGhvZHMgdGhhdCBtdXN0IGJlIGltcGxlbWVudGVkIGJ5IHN1YmNsYXNzZXNcbiAgc3RhdGljIGZyb21CeXRlcyhfYnl0ZXM6IFVpbnQ4QXJyYXkpOiBhbnkge1xuICAgIG5vdEltcGxlbWVudGVkKCk7XG4gIH1cblxuICBzdGF0aWMgZnJvbUhleChfaGV4OiBIZXgpOiBhbnkge1xuICAgIG5vdEltcGxlbWVudGVkKCk7XG4gIH1cblxuICBnZXQgeCgpOiBiaWdpbnQge1xuICAgIHJldHVybiB0aGlzLnRvQWZmaW5lKCkueDtcbiAgfVxuICBnZXQgeSgpOiBiaWdpbnQge1xuICAgIHJldHVybiB0aGlzLnRvQWZmaW5lKCkueTtcbiAgfVxuXG4gIC8vIENvbW1vbiBpbXBsZW1lbnRhdGlvbnNcbiAgY2xlYXJDb2ZhY3RvcigpOiBUIHtcbiAgICAvLyBuby1vcCBmb3IgcHJpbWUtb3JkZXIgZ3JvdXBzXG4gICAgcmV0dXJuIHRoaXMgYXMgYW55O1xuICB9XG5cbiAgYXNzZXJ0VmFsaWRpdHkoKTogdm9pZCB7XG4gICAgdGhpcy5lcC5hc3NlcnRWYWxpZGl0eSgpO1xuICB9XG5cbiAgdG9BZmZpbmUoaW52ZXJ0ZWRaPzogYmlnaW50KTogQWZmaW5lUG9pbnQ8YmlnaW50PiB7XG4gICAgcmV0dXJuIHRoaXMuZXAudG9BZmZpbmUoaW52ZXJ0ZWRaKTtcbiAgfVxuXG4gIHRvSGV4KCk6IHN0cmluZyB7XG4gICAgcmV0dXJuIGJ5dGVzVG9IZXgodGhpcy50b0J5dGVzKCkpO1xuICB9XG5cbiAgdG9TdHJpbmcoKTogc3RyaW5nIHtcbiAgICByZXR1cm4gdGhpcy50b0hleCgpO1xuICB9XG5cbiAgaXNUb3JzaW9uRnJlZSgpOiBib29sZWFuIHtcbiAgICByZXR1cm4gdHJ1ZTtcbiAgfVxuXG4gIGlzU21hbGxPcmRlcigpOiBib29sZWFuIHtcbiAgICByZXR1cm4gZmFsc2U7XG4gIH1cblxuICBhZGQob3RoZXI6IFQpOiBUIHtcbiAgICB0aGlzLmFzc2VydFNhbWUob3RoZXIpO1xuICAgIHJldHVybiB0aGlzLmluaXQodGhpcy5lcC5hZGQob3RoZXIuZXApKTtcbiAgfVxuXG4gIHN1YnRyYWN0KG90aGVyOiBUKTogVCB7XG4gICAgdGhpcy5hc3NlcnRTYW1lKG90aGVyKTtcbiAgICByZXR1cm4gdGhpcy5pbml0KHRoaXMuZXAuc3VidHJhY3Qob3RoZXIuZXApKTtcbiAgfVxuXG4gIG11bHRpcGx5KHNjYWxhcjogYmlnaW50KTogVCB7XG4gICAgcmV0dXJuIHRoaXMuaW5pdCh0aGlzLmVwLm11bHRpcGx5KHNjYWxhcikpO1xuICB9XG5cbiAgbXVsdGlwbHlVbnNhZmUoc2NhbGFyOiBiaWdpbnQpOiBUIHtcbiAgICByZXR1cm4gdGhpcy5pbml0KHRoaXMuZXAubXVsdGlwbHlVbnNhZmUoc2NhbGFyKSk7XG4gIH1cblxuICBkb3VibGUoKTogVCB7XG4gICAgcmV0dXJuIHRoaXMuaW5pdCh0aGlzLmVwLmRvdWJsZSgpKTtcbiAgfVxuXG4gIG5lZ2F0ZSgpOiBUIHtcbiAgICByZXR1cm4gdGhpcy5pbml0KHRoaXMuZXAubmVnYXRlKCkpO1xuICB9XG5cbiAgcHJlY29tcHV0ZSh3aW5kb3dTaXplPzogbnVtYmVyLCBpc0xhenk/OiBib29sZWFuKTogVCB7XG4gICAgcmV0dXJuIHRoaXMuaW5pdCh0aGlzLmVwLnByZWNvbXB1dGUod2luZG93U2l6ZSwgaXNMYXp5KSk7XG4gIH1cblxuICAvLyBIZWxwZXIgbWV0aG9kc1xuICBhYnN0cmFjdCBpczAoKTogYm9vbGVhbjtcbiAgcHJvdGVjdGVkIGFic3RyYWN0IGFzc2VydFNhbWUob3RoZXI6IFQpOiB2b2lkO1xuICBwcm90ZWN0ZWQgYWJzdHJhY3QgaW5pdChlcDogRWR3YXJkc1BvaW50KTogVDtcblxuICAvKiogQGRlcHJlY2F0ZWQgdXNlIGB0b0J5dGVzYCAqL1xuICB0b1Jhd0J5dGVzKCk6IFVpbnQ4QXJyYXkge1xuICAgIHJldHVybiB0aGlzLnRvQnl0ZXMoKTtcbiAgfVxufVxuXG4vKipcbiAqIEluaXRpYWxpemVzIEVkRFNBIHNpZ25hdHVyZXMgb3ZlciBnaXZlbiBFZHdhcmRzIGN1cnZlLlxuICovXG5leHBvcnQgZnVuY3Rpb24gZWRkc2EoUG9pbnQ6IEVkd2FyZHNQb2ludENvbnMsIGNIYXNoOiBGSGFzaCwgZWRkc2FPcHRzOiBFZERTQU9wdHMgPSB7fSk6IEVkRFNBIHtcbiAgaWYgKHR5cGVvZiBjSGFzaCAhPT0gJ2Z1bmN0aW9uJykgdGhyb3cgbmV3IEVycm9yKCdcImhhc2hcIiBmdW5jdGlvbiBwYXJhbSBpcyByZXF1aXJlZCcpO1xuICBfdmFsaWRhdGVPYmplY3QoXG4gICAgZWRkc2FPcHRzLFxuICAgIHt9LFxuICAgIHtcbiAgICAgIGFkanVzdFNjYWxhckJ5dGVzOiAnZnVuY3Rpb24nLFxuICAgICAgcmFuZG9tQnl0ZXM6ICdmdW5jdGlvbicsXG4gICAgICBkb21haW46ICdmdW5jdGlvbicsXG4gICAgICBwcmVoYXNoOiAnZnVuY3Rpb24nLFxuICAgICAgbWFwVG9DdXJ2ZTogJ2Z1bmN0aW9uJyxcbiAgICB9XG4gICk7XG5cbiAgY29uc3QgeyBwcmVoYXNoIH0gPSBlZGRzYU9wdHM7XG4gIGNvbnN0IHsgQkFTRSwgRnAsIEZuIH0gPSBQb2ludDtcblxuICBjb25zdCByYW5kb21CeXRlcyA9IGVkZHNhT3B0cy5yYW5kb21CeXRlcyB8fCByYW5kb21CeXRlc1dlYjtcbiAgY29uc3QgYWRqdXN0U2NhbGFyQnl0ZXMgPSBlZGRzYU9wdHMuYWRqdXN0U2NhbGFyQnl0ZXMgfHwgKChieXRlczogVWludDhBcnJheSkgPT4gYnl0ZXMpO1xuICBjb25zdCBkb21haW4gPVxuICAgIGVkZHNhT3B0cy5kb21haW4gfHxcbiAgICAoKGRhdGE6IFVpbnQ4QXJyYXksIGN0eDogVWludDhBcnJheSwgcGhmbGFnOiBib29sZWFuKSA9PiB7XG4gICAgICBhYm9vbChwaGZsYWcsICdwaGZsYWcnKTtcbiAgICAgIGlmIChjdHgubGVuZ3RoIHx8IHBoZmxhZykgdGhyb3cgbmV3IEVycm9yKCdDb250ZXh0cy9wcmUtaGFzaCBhcmUgbm90IHN1cHBvcnRlZCcpO1xuICAgICAgcmV0dXJuIGRhdGE7XG4gICAgfSk7IC8vIE5PT1BcblxuICAvLyBMaXR0bGUtZW5kaWFuIFNIQTUxMiB3aXRoIG1vZHVsbyBuXG4gIGZ1bmN0aW9uIG1vZE5fTEUoaGFzaDogVWludDhBcnJheSk6IGJpZ2ludCB7XG4gICAgcmV0dXJuIEZuLmNyZWF0ZShieXRlc1RvTnVtYmVyTEUoaGFzaCkpOyAvLyBOb3QgRm4uZnJvbUJ5dGVzOiBpdCBoYXMgbGVuZ3RoIGxpbWl0XG4gIH1cblxuICAvLyBHZXQgdGhlIGhhc2hlZCBwcml2YXRlIHNjYWxhciBwZXIgUkZDODAzMiA1LjEuNVxuICBmdW5jdGlvbiBnZXRQcml2YXRlU2NhbGFyKGtleTogSGV4KSB7XG4gICAgY29uc3QgbGVuID0gbGVuZ3Rocy5zZWNyZXRLZXk7XG4gICAga2V5ID0gZW5zdXJlQnl0ZXMoJ3ByaXZhdGUga2V5Jywga2V5LCBsZW4pO1xuICAgIC8vIEhhc2ggcHJpdmF0ZSBrZXkgd2l0aCBjdXJ2ZSdzIGhhc2ggZnVuY3Rpb24gdG8gcHJvZHVjZSB1bmlmb3JtaW5nbHkgcmFuZG9tIGlucHV0XG4gICAgLy8gQ2hlY2sgYnl0ZSBsZW5ndGhzOiBlbnN1cmUoNjQsIGgoZW5zdXJlKDMyLCBrZXkpKSlcbiAgICBjb25zdCBoYXNoZWQgPSBlbnN1cmVCeXRlcygnaGFzaGVkIHByaXZhdGUga2V5JywgY0hhc2goa2V5KSwgMiAqIGxlbik7XG4gICAgY29uc3QgaGVhZCA9IGFkanVzdFNjYWxhckJ5dGVzKGhhc2hlZC5zbGljZSgwLCBsZW4pKTsgLy8gY2xlYXIgZmlyc3QgaGFsZiBiaXRzLCBwcm9kdWNlIEZFXG4gICAgY29uc3QgcHJlZml4ID0gaGFzaGVkLnNsaWNlKGxlbiwgMiAqIGxlbik7IC8vIHNlY29uZCBoYWxmIGlzIGNhbGxlZCBrZXkgcHJlZml4ICg1LjEuNilcbiAgICBjb25zdCBzY2FsYXIgPSBtb2ROX0xFKGhlYWQpOyAvLyBUaGUgYWN0dWFsIHByaXZhdGUgc2NhbGFyXG4gICAgcmV0dXJuIHsgaGVhZCwgcHJlZml4LCBzY2FsYXIgfTtcbiAgfVxuXG4gIC8qKiBDb252ZW5pZW5jZSBtZXRob2QgdGhhdCBjcmVhdGVzIHB1YmxpYyBrZXkgZnJvbSBzY2FsYXIuIFJGQzgwMzIgNS4xLjUgKi9cbiAgZnVuY3Rpb24gZ2V0RXh0ZW5kZWRQdWJsaWNLZXkoc2VjcmV0S2V5OiBIZXgpIHtcbiAgICBjb25zdCB7IGhlYWQsIHByZWZpeCwgc2NhbGFyIH0gPSBnZXRQcml2YXRlU2NhbGFyKHNlY3JldEtleSk7XG4gICAgY29uc3QgcG9pbnQgPSBCQVNFLm11bHRpcGx5KHNjYWxhcik7IC8vIFBvaW50IG9uIEVkd2FyZHMgY3VydmUgYWthIHB1YmxpYyBrZXlcbiAgICBjb25zdCBwb2ludEJ5dGVzID0gcG9pbnQudG9CeXRlcygpO1xuICAgIHJldHVybiB7IGhlYWQsIHByZWZpeCwgc2NhbGFyLCBwb2ludCwgcG9pbnRCeXRlcyB9O1xuICB9XG5cbiAgLyoqIENhbGN1bGF0ZXMgRWREU0EgcHViIGtleS4gUkZDODAzMiA1LjEuNS4gKi9cbiAgZnVuY3Rpb24gZ2V0UHVibGljS2V5KHNlY3JldEtleTogSGV4KTogVWludDhBcnJheSB7XG4gICAgcmV0dXJuIGdldEV4dGVuZGVkUHVibGljS2V5KHNlY3JldEtleSkucG9pbnRCeXRlcztcbiAgfVxuXG4gIC8vIGludCgnTEUnLCBTSEE1MTIoZG9tMihGLCBDKSB8fCBtc2dzKSkgbW9kIE5cbiAgZnVuY3Rpb24gaGFzaERvbWFpblRvU2NhbGFyKGNvbnRleHQ6IEhleCA9IFVpbnQ4QXJyYXkub2YoKSwgLi4ubXNnczogVWludDhBcnJheVtdKSB7XG4gICAgY29uc3QgbXNnID0gY29uY2F0Qnl0ZXMoLi4ubXNncyk7XG4gICAgcmV0dXJuIG1vZE5fTEUoY0hhc2goZG9tYWluKG1zZywgZW5zdXJlQnl0ZXMoJ2NvbnRleHQnLCBjb250ZXh0KSwgISFwcmVoYXNoKSkpO1xuICB9XG5cbiAgLyoqIFNpZ25zIG1lc3NhZ2Ugd2l0aCBwcml2YXRlS2V5LiBSRkM4MDMyIDUuMS42ICovXG4gIGZ1bmN0aW9uIHNpZ24obXNnOiBIZXgsIHNlY3JldEtleTogSGV4LCBvcHRpb25zOiB7IGNvbnRleHQ/OiBIZXggfSA9IHt9KTogVWludDhBcnJheSB7XG4gICAgbXNnID0gZW5zdXJlQnl0ZXMoJ21lc3NhZ2UnLCBtc2cpO1xuICAgIGlmIChwcmVoYXNoKSBtc2cgPSBwcmVoYXNoKG1zZyk7IC8vIGZvciBlZDI1NTE5cGggZXRjLlxuICAgIGNvbnN0IHsgcHJlZml4LCBzY2FsYXIsIHBvaW50Qnl0ZXMgfSA9IGdldEV4dGVuZGVkUHVibGljS2V5KHNlY3JldEtleSk7XG4gICAgY29uc3QgciA9IGhhc2hEb21haW5Ub1NjYWxhcihvcHRpb25zLmNvbnRleHQsIHByZWZpeCwgbXNnKTsgLy8gciA9IGRvbTIoRiwgQykgfHwgcHJlZml4IHx8IFBIKE0pXG4gICAgY29uc3QgUiA9IEJBU0UubXVsdGlwbHkocikudG9CeXRlcygpOyAvLyBSID0gckdcbiAgICBjb25zdCBrID0gaGFzaERvbWFpblRvU2NhbGFyKG9wdGlvbnMuY29udGV4dCwgUiwgcG9pbnRCeXRlcywgbXNnKTsgLy8gUiB8fCBBIHx8IFBIKE0pXG4gICAgY29uc3QgcyA9IEZuLmNyZWF0ZShyICsgayAqIHNjYWxhcik7IC8vIFMgPSAociArIGsgKiBzKSBtb2QgTFxuICAgIGlmICghRm4uaXNWYWxpZChzKSkgdGhyb3cgbmV3IEVycm9yKCdzaWduIGZhaWxlZDogaW52YWxpZCBzJyk7IC8vIDAgPD0gcyA8IExcbiAgICBjb25zdCBycyA9IGNvbmNhdEJ5dGVzKFIsIEZuLnRvQnl0ZXMocykpO1xuICAgIHJldHVybiBhYnl0ZXMocnMsIGxlbmd0aHMuc2lnbmF0dXJlLCAncmVzdWx0Jyk7XG4gIH1cblxuICAvLyB2ZXJpZmljYXRpb24gcnVsZSBpcyBlaXRoZXIgemlwMjE1IG9yIHJmYzgwMzIgLyBuaXN0MTg2LTUuIENvbnN1bHQgZnJvbUhleDpcbiAgY29uc3QgdmVyaWZ5T3B0czogeyBjb250ZXh0PzogSGV4OyB6aXAyMTU/OiBib29sZWFuIH0gPSB7IHppcDIxNTogdHJ1ZSB9O1xuXG4gIC8qKlxuICAgKiBWZXJpZmllcyBFZERTQSBzaWduYXR1cmUgYWdhaW5zdCBtZXNzYWdlIGFuZCBwdWJsaWMga2V5LiBSRkM4MDMyIDUuMS43LlxuICAgKiBBbiBleHRlbmRlZCBncm91cCBlcXVhdGlvbiBpcyBjaGVja2VkLlxuICAgKi9cbiAgZnVuY3Rpb24gdmVyaWZ5KHNpZzogSGV4LCBtc2c6IEhleCwgcHVibGljS2V5OiBIZXgsIG9wdGlvbnMgPSB2ZXJpZnlPcHRzKTogYm9vbGVhbiB7XG4gICAgY29uc3QgeyBjb250ZXh0LCB6aXAyMTUgfSA9IG9wdGlvbnM7XG4gICAgY29uc3QgbGVuID0gbGVuZ3Rocy5zaWduYXR1cmU7XG4gICAgc2lnID0gZW5zdXJlQnl0ZXMoJ3NpZ25hdHVyZScsIHNpZywgbGVuKTtcbiAgICBtc2cgPSBlbnN1cmVCeXRlcygnbWVzc2FnZScsIG1zZyk7XG4gICAgcHVibGljS2V5ID0gZW5zdXJlQnl0ZXMoJ3B1YmxpY0tleScsIHB1YmxpY0tleSwgbGVuZ3Rocy5wdWJsaWNLZXkpO1xuICAgIGlmICh6aXAyMTUgIT09IHVuZGVmaW5lZCkgYWJvb2woemlwMjE1LCAnemlwMjE1Jyk7XG4gICAgaWYgKHByZWhhc2gpIG1zZyA9IHByZWhhc2gobXNnKTsgLy8gZm9yIGVkMjU1MTlwaCwgZXRjXG5cbiAgICBjb25zdCBtaWQgPSBsZW4gLyAyO1xuICAgIGNvbnN0IHIgPSBzaWcuc3ViYXJyYXkoMCwgbWlkKTtcbiAgICBjb25zdCBzID0gYnl0ZXNUb051bWJlckxFKHNpZy5zdWJhcnJheShtaWQsIGxlbikpO1xuICAgIGxldCBBLCBSLCBTQjtcbiAgICB0cnkge1xuICAgICAgLy8gemlwMjE1PXRydWUgaXMgZ29vZCBmb3IgY29uc2Vuc3VzLWNyaXRpY2FsIGFwcHMuID1mYWxzZSBmb2xsb3dzIFJGQzgwMzIgLyBOSVNUMTg2LTUuXG4gICAgICAvLyB6aXAyMTU9dHJ1ZTogIDAgPD0geSA8IE1BU0sgKDJeMjU2IGZvciBlZDI1NTE5KVxuICAgICAgLy8gemlwMjE1PWZhbHNlOiAwIDw9IHkgPCBQICgyXjI1NS0xOSBmb3IgZWQyNTUxOSlcbiAgICAgIEEgPSBQb2ludC5mcm9tQnl0ZXMocHVibGljS2V5LCB6aXAyMTUpO1xuICAgICAgUiA9IFBvaW50LmZyb21CeXRlcyhyLCB6aXAyMTUpO1xuICAgICAgU0IgPSBCQVNFLm11bHRpcGx5VW5zYWZlKHMpOyAvLyAwIDw9IHMgPCBsIGlzIGRvbmUgaW5zaWRlXG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9XG4gICAgaWYgKCF6aXAyMTUgJiYgQS5pc1NtYWxsT3JkZXIoKSkgcmV0dXJuIGZhbHNlOyAvLyB6aXAyMTUgYWxsb3dzIHB1YmxpYyBrZXlzIG9mIHNtYWxsIG9yZGVyXG5cbiAgICBjb25zdCBrID0gaGFzaERvbWFpblRvU2NhbGFyKGNvbnRleHQsIFIudG9CeXRlcygpLCBBLnRvQnl0ZXMoKSwgbXNnKTtcbiAgICBjb25zdCBSa0EgPSBSLmFkZChBLm11bHRpcGx5VW5zYWZlKGspKTtcbiAgICAvLyBFeHRlbmRlZCBncm91cCBlcXVhdGlvblxuICAgIC8vIFs4XVtTXUIgPSBbOF1SICsgWzhdW2tdQSdcbiAgICByZXR1cm4gUmtBLnN1YnRyYWN0KFNCKS5jbGVhckNvZmFjdG9yKCkuaXMwKCk7XG4gIH1cblxuICBjb25zdCBfc2l6ZSA9IEZwLkJZVEVTOyAvLyAzMiBmb3IgZWQyNTUxOSwgNTcgZm9yIGVkNDQ4XG4gIGNvbnN0IGxlbmd0aHMgPSB7XG4gICAgc2VjcmV0S2V5OiBfc2l6ZSxcbiAgICBwdWJsaWNLZXk6IF9zaXplLFxuICAgIHNpZ25hdHVyZTogMiAqIF9zaXplLFxuICAgIHNlZWQ6IF9zaXplLFxuICB9O1xuICBmdW5jdGlvbiByYW5kb21TZWNyZXRLZXkoc2VlZCA9IHJhbmRvbUJ5dGVzKGxlbmd0aHMuc2VlZCkpOiBVaW50OEFycmF5IHtcbiAgICByZXR1cm4gYWJ5dGVzKHNlZWQsIGxlbmd0aHMuc2VlZCwgJ3NlZWQnKTtcbiAgfVxuICBmdW5jdGlvbiBrZXlnZW4oc2VlZD86IFVpbnQ4QXJyYXkpIHtcbiAgICBjb25zdCBzZWNyZXRLZXkgPSB1dGlscy5yYW5kb21TZWNyZXRLZXkoc2VlZCk7XG4gICAgcmV0dXJuIHsgc2VjcmV0S2V5LCBwdWJsaWNLZXk6IGdldFB1YmxpY0tleShzZWNyZXRLZXkpIH07XG4gIH1cbiAgZnVuY3Rpb24gaXNWYWxpZFNlY3JldEtleShrZXk6IFVpbnQ4QXJyYXkpOiBib29sZWFuIHtcbiAgICByZXR1cm4gaXNCeXRlcyhrZXkpICYmIGtleS5sZW5ndGggPT09IEZuLkJZVEVTO1xuICB9XG4gIGZ1bmN0aW9uIGlzVmFsaWRQdWJsaWNLZXkoa2V5OiBVaW50OEFycmF5LCB6aXAyMTU/OiBib29sZWFuKTogYm9vbGVhbiB7XG4gICAgdHJ5IHtcbiAgICAgIHJldHVybiAhIVBvaW50LmZyb21CeXRlcyhrZXksIHppcDIxNSk7XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9XG4gIH1cblxuICBjb25zdCB1dGlscyA9IHtcbiAgICBnZXRFeHRlbmRlZFB1YmxpY0tleSxcbiAgICByYW5kb21TZWNyZXRLZXksXG4gICAgaXNWYWxpZFNlY3JldEtleSxcbiAgICBpc1ZhbGlkUHVibGljS2V5LFxuICAgIC8qKlxuICAgICAqIENvbnZlcnRzIGVkIHB1YmxpYyBrZXkgdG8geCBwdWJsaWMga2V5LiBVc2VzIGZvcm11bGE6XG4gICAgICogLSBlZDI1NTE5OlxuICAgICAqICAgLSBgKHUsIHYpID0gKCgxK3kpLygxLXkpLCBzcXJ0KC00ODY2NjQpKnUveClgXG4gICAgICogICAtIGAoeCwgeSkgPSAoc3FydCgtNDg2NjY0KSp1L3YsICh1LTEpLyh1KzEpKWBcbiAgICAgKiAtIGVkNDQ4OlxuICAgICAqICAgLSBgKHUsIHYpID0gKCh5LTEpLyh5KzEpLCBzcXJ0KDE1NjMyNCkqdS94KWBcbiAgICAgKiAgIC0gYCh4LCB5KSA9IChzcXJ0KDE1NjMyNCkqdS92LCAoMSt1KS8oMS11KSlgXG4gICAgICovXG4gICAgdG9Nb250Z29tZXJ5KHB1YmxpY0tleTogVWludDhBcnJheSk6IFVpbnQ4QXJyYXkge1xuICAgICAgY29uc3QgeyB5IH0gPSBQb2ludC5mcm9tQnl0ZXMocHVibGljS2V5KTtcbiAgICAgIGNvbnN0IHNpemUgPSBsZW5ndGhzLnB1YmxpY0tleTtcbiAgICAgIGNvbnN0IGlzMjU1MTkgPSBzaXplID09PSAzMjtcbiAgICAgIGlmICghaXMyNTUxOSAmJiBzaXplICE9PSA1NykgdGhyb3cgbmV3IEVycm9yKCdvbmx5IGRlZmluZWQgZm9yIDI1NTE5IGFuZCA0NDgnKTtcbiAgICAgIGNvbnN0IHUgPSBpczI1NTE5ID8gRnAuZGl2KF8xbiArIHksIF8xbiAtIHkpIDogRnAuZGl2KHkgLSBfMW4sIHkgKyBfMW4pO1xuICAgICAgcmV0dXJuIEZwLnRvQnl0ZXModSk7XG4gICAgfSxcblxuICAgIHRvTW9udGdvbWVyeVNlY3JldChzZWNyZXRLZXk6IFVpbnQ4QXJyYXkpOiBVaW50OEFycmF5IHtcbiAgICAgIGNvbnN0IHNpemUgPSBsZW5ndGhzLnNlY3JldEtleTtcbiAgICAgIGFieXRlcyhzZWNyZXRLZXksIHNpemUpO1xuICAgICAgY29uc3QgaGFzaGVkID0gY0hhc2goc2VjcmV0S2V5LnN1YmFycmF5KDAsIHNpemUpKTtcbiAgICAgIHJldHVybiBhZGp1c3RTY2FsYXJCeXRlcyhoYXNoZWQpLnN1YmFycmF5KDAsIHNpemUpO1xuICAgIH0sXG5cbiAgICAvKiogQGRlcHJlY2F0ZWQgKi9cbiAgICByYW5kb21Qcml2YXRlS2V5OiByYW5kb21TZWNyZXRLZXksXG4gICAgLyoqIEBkZXByZWNhdGVkICovXG4gICAgcHJlY29tcHV0ZSh3aW5kb3dTaXplID0gOCwgcG9pbnQ6IEVkd2FyZHNQb2ludCA9IFBvaW50LkJBU0UpOiBFZHdhcmRzUG9pbnQge1xuICAgICAgcmV0dXJuIHBvaW50LnByZWNvbXB1dGUod2luZG93U2l6ZSwgZmFsc2UpO1xuICAgIH0sXG4gIH07XG5cbiAgcmV0dXJuIE9iamVjdC5mcmVlemUoe1xuICAgIGtleWdlbixcbiAgICBnZXRQdWJsaWNLZXksXG4gICAgc2lnbixcbiAgICB2ZXJpZnksXG4gICAgdXRpbHMsXG4gICAgUG9pbnQsXG4gICAgbGVuZ3RocyxcbiAgfSk7XG59XG5cbi8vIFRPRE86IHJlbW92ZSBldmVyeXRoaW5nIGJlbG93XG5leHBvcnQgdHlwZSBDdXJ2ZVR5cGUgPSBCYXNpY0N1cnZlPGJpZ2ludD4gJiB7XG4gIGE6IGJpZ2ludDsgLy8gY3VydmUgcGFyYW0gYVxuICBkOiBiaWdpbnQ7IC8vIGN1cnZlIHBhcmFtIGRcbiAgLyoqIEBkZXByZWNhdGVkIHRoZSBwcm9wZXJ0eSB3aWxsIGJlIHJlbW92ZWQgaW4gbmV4dCByZWxlYXNlICovXG4gIGhhc2g6IEZIYXNoOyAvLyBIYXNoaW5nXG4gIHJhbmRvbUJ5dGVzPzogKGJ5dGVzTGVuZ3RoPzogbnVtYmVyKSA9PiBVaW50OEFycmF5OyAvLyBDU1BSTkdcbiAgYWRqdXN0U2NhbGFyQnl0ZXM/OiAoYnl0ZXM6IFVpbnQ4QXJyYXkpID0+IFVpbnQ4QXJyYXk7IC8vIGNsZWFycyBiaXRzIHRvIGdldCB2YWxpZCBmaWVsZCBlbGVtdG5cbiAgZG9tYWluPzogKGRhdGE6IFVpbnQ4QXJyYXksIGN0eDogVWludDhBcnJheSwgcGhmbGFnOiBib29sZWFuKSA9PiBVaW50OEFycmF5OyAvLyBVc2VkIGZvciBoYXNoaW5nXG4gIHV2UmF0aW8/OiBVVlJhdGlvOyAvLyBSYXRpbyBcdTIyMUEodS92KVxuICBwcmVoYXNoPzogRkhhc2g7IC8vIFJGQyA4MDMyIHByZS1oYXNoaW5nIG9mIG1lc3NhZ2VzIHRvIHNpZ24oKSAvIHZlcmlmeSgpXG4gIG1hcFRvQ3VydmU/OiAoc2NhbGFyOiBiaWdpbnRbXSkgPT4gQWZmaW5lUG9pbnQ8YmlnaW50PjsgLy8gZm9yIGhhc2gtdG8tY3VydmUgc3RhbmRhcmRcbn07XG5leHBvcnQgdHlwZSBDdXJ2ZVR5cGVXaXRoTGVuZ3RoID0gUmVhZG9ubHk8Q3VydmVUeXBlICYgUGFydGlhbDxOTGVuZ3RoPj47XG5leHBvcnQgdHlwZSBDdXJ2ZUZuID0ge1xuICAvKiogQGRlcHJlY2F0ZWQgdGhlIHByb3BlcnR5IHdpbGwgYmUgcmVtb3ZlZCBpbiBuZXh0IHJlbGVhc2UgKi9cbiAgQ1VSVkU6IEN1cnZlVHlwZTtcbiAga2V5Z2VuOiBFZERTQVsna2V5Z2VuJ107XG4gIGdldFB1YmxpY0tleTogRWREU0FbJ2dldFB1YmxpY0tleSddO1xuICBzaWduOiBFZERTQVsnc2lnbiddO1xuICB2ZXJpZnk6IEVkRFNBWyd2ZXJpZnknXTtcbiAgUG9pbnQ6IEVkd2FyZHNQb2ludENvbnM7XG4gIC8qKiBAZGVwcmVjYXRlZCB1c2UgYFBvaW50YCAqL1xuICBFeHRlbmRlZFBvaW50OiBFZHdhcmRzUG9pbnRDb25zO1xuICB1dGlsczogRWREU0FbJ3V0aWxzJ107XG4gIGxlbmd0aHM6IEN1cnZlTGVuZ3Rocztcbn07XG5leHBvcnQgdHlwZSBFZENvbXBvc2VkID0ge1xuICBDVVJWRTogRWR3YXJkc09wdHM7XG4gIGN1cnZlT3B0czogRWR3YXJkc0V4dHJhT3B0cztcbiAgaGFzaDogRkhhc2g7XG4gIGVkZHNhT3B0czogRWREU0FPcHRzO1xufTtcbmZ1bmN0aW9uIF9lZGRzYV9sZWdhY3lfb3B0c190b19uZXcoYzogQ3VydmVUeXBlV2l0aExlbmd0aCk6IEVkQ29tcG9zZWQge1xuICBjb25zdCBDVVJWRTogRWR3YXJkc09wdHMgPSB7XG4gICAgYTogYy5hLFxuICAgIGQ6IGMuZCxcbiAgICBwOiBjLkZwLk9SREVSLFxuICAgIG46IGMubixcbiAgICBoOiBjLmgsXG4gICAgR3g6IGMuR3gsXG4gICAgR3k6IGMuR3ksXG4gIH07XG4gIGNvbnN0IEZwID0gYy5GcDtcbiAgY29uc3QgRm4gPSBGaWVsZChDVVJWRS5uLCBjLm5CaXRMZW5ndGgsIHRydWUpO1xuICBjb25zdCBjdXJ2ZU9wdHM6IEVkd2FyZHNFeHRyYU9wdHMgPSB7IEZwLCBGbiwgdXZSYXRpbzogYy51dlJhdGlvIH07XG4gIGNvbnN0IGVkZHNhT3B0czogRWREU0FPcHRzID0ge1xuICAgIHJhbmRvbUJ5dGVzOiBjLnJhbmRvbUJ5dGVzLFxuICAgIGFkanVzdFNjYWxhckJ5dGVzOiBjLmFkanVzdFNjYWxhckJ5dGVzLFxuICAgIGRvbWFpbjogYy5kb21haW4sXG4gICAgcHJlaGFzaDogYy5wcmVoYXNoLFxuICAgIG1hcFRvQ3VydmU6IGMubWFwVG9DdXJ2ZSxcbiAgfTtcbiAgcmV0dXJuIHsgQ1VSVkUsIGN1cnZlT3B0cywgaGFzaDogYy5oYXNoLCBlZGRzYU9wdHMgfTtcbn1cbmZ1bmN0aW9uIF9lZGRzYV9uZXdfb3V0cHV0X3RvX2xlZ2FjeShjOiBDdXJ2ZVR5cGVXaXRoTGVuZ3RoLCBlZGRzYTogRWREU0EpOiBDdXJ2ZUZuIHtcbiAgY29uc3QgUG9pbnQgPSBlZGRzYS5Qb2ludDtcbiAgY29uc3QgbGVnYWN5ID0gT2JqZWN0LmFzc2lnbih7fSwgZWRkc2EsIHtcbiAgICBFeHRlbmRlZFBvaW50OiBQb2ludCxcbiAgICBDVVJWRTogYyxcbiAgICBuQml0TGVuZ3RoOiBQb2ludC5Gbi5CSVRTLFxuICAgIG5CeXRlTGVuZ3RoOiBQb2ludC5Gbi5CWVRFUyxcbiAgfSk7XG4gIHJldHVybiBsZWdhY3k7XG59XG4vLyBUT0RPOiByZW1vdmUuIFVzZSBlZGRzYVxuZXhwb3J0IGZ1bmN0aW9uIHR3aXN0ZWRFZHdhcmRzKGM6IEN1cnZlVHlwZVdpdGhMZW5ndGgpOiBDdXJ2ZUZuIHtcbiAgY29uc3QgeyBDVVJWRSwgY3VydmVPcHRzLCBoYXNoLCBlZGRzYU9wdHMgfSA9IF9lZGRzYV9sZWdhY3lfb3B0c190b19uZXcoYyk7XG4gIGNvbnN0IFBvaW50ID0gZWR3YXJkcyhDVVJWRSwgY3VydmVPcHRzKTtcbiAgY29uc3QgRUREU0EgPSBlZGRzYShQb2ludCwgaGFzaCwgZWRkc2FPcHRzKTtcbiAgcmV0dXJuIF9lZGRzYV9uZXdfb3V0cHV0X3RvX2xlZ2FjeShjLCBFRERTQSk7XG59XG4iLCAiLyoqXG4gKiBNb250Z29tZXJ5IGN1cnZlIG1ldGhvZHMuIEl0J3Mgbm90IHJlYWxseSB3aG9sZSBtb250Z29tZXJ5IGN1cnZlLFxuICoganVzdCBidW5jaCBvZiB2ZXJ5IHNwZWNpZmljIG1ldGhvZHMgZm9yIFgyNTUxOSAvIFg0NDggZnJvbVxuICogW1JGQyA3NzQ4XShodHRwczovL3d3dy5yZmMtZWRpdG9yLm9yZy9yZmMvcmZjNzc0OClcbiAqIEBtb2R1bGVcbiAqL1xuLyohIG5vYmxlLWN1cnZlcyAtIE1JVCBMaWNlbnNlIChjKSAyMDIyIFBhdWwgTWlsbGVyIChwYXVsbWlsbHIuY29tKSAqL1xuaW1wb3J0IHtcbiAgX3ZhbGlkYXRlT2JqZWN0LFxuICBhYnl0ZXMsXG4gIGFJblJhbmdlLFxuICBieXRlc1RvTnVtYmVyTEUsXG4gIGVuc3VyZUJ5dGVzLFxuICBudW1iZXJUb0J5dGVzTEUsXG4gIHJhbmRvbUJ5dGVzLFxufSBmcm9tICcuLi91dGlscy50cyc7XG5pbXBvcnQgdHlwZSB7IEN1cnZlTGVuZ3RocyB9IGZyb20gJy4vY3VydmUudHMnO1xuaW1wb3J0IHsgbW9kIH0gZnJvbSAnLi9tb2R1bGFyLnRzJztcblxuY29uc3QgXzBuID0gQmlnSW50KDApO1xuY29uc3QgXzFuID0gQmlnSW50KDEpO1xuY29uc3QgXzJuID0gQmlnSW50KDIpO1xudHlwZSBIZXggPSBzdHJpbmcgfCBVaW50OEFycmF5O1xuXG5leHBvcnQgdHlwZSBDdXJ2ZVR5cGUgPSB7XG4gIFA6IGJpZ2ludDsgLy8gZmluaXRlIGZpZWxkIHByaW1lXG4gIHR5cGU6ICd4MjU1MTknIHwgJ3g0NDgnO1xuICBhZGp1c3RTY2FsYXJCeXRlczogKGJ5dGVzOiBVaW50OEFycmF5KSA9PiBVaW50OEFycmF5O1xuICBwb3dQbWludXMyOiAoeDogYmlnaW50KSA9PiBiaWdpbnQ7XG4gIHJhbmRvbUJ5dGVzPzogKGJ5dGVzTGVuZ3RoPzogbnVtYmVyKSA9PiBVaW50OEFycmF5O1xufTtcblxuZXhwb3J0IHR5cGUgTW9udGdvbWVyeUVDREggPSB7XG4gIHNjYWxhck11bHQ6IChzY2FsYXI6IEhleCwgdTogSGV4KSA9PiBVaW50OEFycmF5O1xuICBzY2FsYXJNdWx0QmFzZTogKHNjYWxhcjogSGV4KSA9PiBVaW50OEFycmF5O1xuICBnZXRTaGFyZWRTZWNyZXQ6IChzZWNyZXRLZXlBOiBIZXgsIHB1YmxpY0tleUI6IEhleCkgPT4gVWludDhBcnJheTtcbiAgZ2V0UHVibGljS2V5OiAoc2VjcmV0S2V5OiBIZXgpID0+IFVpbnQ4QXJyYXk7XG4gIHV0aWxzOiB7XG4gICAgcmFuZG9tU2VjcmV0S2V5OiAoKSA9PiBVaW50OEFycmF5O1xuICAgIC8qKiBAZGVwcmVjYXRlZCB1c2UgYHJhbmRvbVNlY3JldEtleWAgKi9cbiAgICByYW5kb21Qcml2YXRlS2V5OiAoKSA9PiBVaW50OEFycmF5O1xuICB9O1xuICBHdUJ5dGVzOiBVaW50OEFycmF5O1xuICBsZW5ndGhzOiBDdXJ2ZUxlbmd0aHM7XG4gIGtleWdlbjogKHNlZWQ/OiBVaW50OEFycmF5KSA9PiB7IHNlY3JldEtleTogVWludDhBcnJheTsgcHVibGljS2V5OiBVaW50OEFycmF5IH07XG59O1xuZXhwb3J0IHR5cGUgQ3VydmVGbiA9IE1vbnRnb21lcnlFQ0RIO1xuXG5mdW5jdGlvbiB2YWxpZGF0ZU9wdHMoY3VydmU6IEN1cnZlVHlwZSkge1xuICBfdmFsaWRhdGVPYmplY3QoY3VydmUsIHtcbiAgICBhZGp1c3RTY2FsYXJCeXRlczogJ2Z1bmN0aW9uJyxcbiAgICBwb3dQbWludXMyOiAnZnVuY3Rpb24nLFxuICB9KTtcbiAgcmV0dXJuIE9iamVjdC5mcmVlemUoeyAuLi5jdXJ2ZSB9IGFzIGNvbnN0KTtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIG1vbnRnb21lcnkoY3VydmVEZWY6IEN1cnZlVHlwZSk6IE1vbnRnb21lcnlFQ0RIIHtcbiAgY29uc3QgQ1VSVkUgPSB2YWxpZGF0ZU9wdHMoY3VydmVEZWYpO1xuICBjb25zdCB7IFAsIHR5cGUsIGFkanVzdFNjYWxhckJ5dGVzLCBwb3dQbWludXMyLCByYW5kb21CeXRlczogcmFuZCB9ID0gQ1VSVkU7XG4gIGNvbnN0IGlzMjU1MTkgPSB0eXBlID09PSAneDI1NTE5JztcbiAgaWYgKCFpczI1NTE5ICYmIHR5cGUgIT09ICd4NDQ4JykgdGhyb3cgbmV3IEVycm9yKCdpbnZhbGlkIHR5cGUnKTtcbiAgY29uc3QgcmFuZG9tQnl0ZXNfID0gcmFuZCB8fCByYW5kb21CeXRlcztcblxuICBjb25zdCBtb250Z29tZXJ5Qml0cyA9IGlzMjU1MTkgPyAyNTUgOiA0NDg7XG4gIGNvbnN0IGZpZWxkTGVuID0gaXMyNTUxOSA/IDMyIDogNTY7XG4gIGNvbnN0IEd1ID0gaXMyNTUxOSA/IEJpZ0ludCg5KSA6IEJpZ0ludCg1KTtcbiAgLy8gUkZDIDc3NDggIzU6XG4gIC8vIFRoZSBjb25zdGFudCBhMjQgaXMgKDQ4NjY2MiAtIDIpIC8gNCA9IDEyMTY2NSBmb3IgY3VydmUyNTUxOS9YMjU1MTkgYW5kXG4gIC8vICgxNTYzMjYgLSAyKSAvIDQgPSAzOTA4MSBmb3IgY3VydmU0NDgvWDQ0OFxuICAvLyBjb25zdCBhID0gaXMyNTUxOSA/IDE1NjMyNm4gOiA0ODY2NjJuO1xuICBjb25zdCBhMjQgPSBpczI1NTE5ID8gQmlnSW50KDEyMTY2NSkgOiBCaWdJbnQoMzkwODEpO1xuICAvLyBSRkM6IHgyNTUxOSBcInRoZSByZXN1bHRpbmcgaW50ZWdlciBpcyBvZiB0aGUgZm9ybSAyXjI1NCBwbHVzXG4gIC8vIGVpZ2h0IHRpbWVzIGEgdmFsdWUgYmV0d2VlbiAwIGFuZCAyXjI1MSAtIDEgKGluY2x1c2l2ZSlcIlxuICAvLyB4NDQ4OiBcIjJeNDQ3IHBsdXMgZm91ciB0aW1lcyBhIHZhbHVlIGJldHdlZW4gMCBhbmQgMl40NDUgLSAxIChpbmNsdXNpdmUpXCJcbiAgY29uc3QgbWluU2NhbGFyID0gaXMyNTUxOSA/IF8ybiAqKiBCaWdJbnQoMjU0KSA6IF8ybiAqKiBCaWdJbnQoNDQ3KTtcbiAgY29uc3QgbWF4QWRkZWQgPSBpczI1NTE5XG4gICAgPyBCaWdJbnQoOCkgKiBfMm4gKiogQmlnSW50KDI1MSkgLSBfMW5cbiAgICA6IEJpZ0ludCg0KSAqIF8ybiAqKiBCaWdJbnQoNDQ1KSAtIF8xbjtcbiAgY29uc3QgbWF4U2NhbGFyID0gbWluU2NhbGFyICsgbWF4QWRkZWQgKyBfMW47IC8vIChpbmNsdXNpdmUpXG4gIGNvbnN0IG1vZFAgPSAobjogYmlnaW50KSA9PiBtb2QobiwgUCk7XG4gIGNvbnN0IEd1Qnl0ZXMgPSBlbmNvZGVVKEd1KTtcbiAgZnVuY3Rpb24gZW5jb2RlVSh1OiBiaWdpbnQpOiBVaW50OEFycmF5IHtcbiAgICByZXR1cm4gbnVtYmVyVG9CeXRlc0xFKG1vZFAodSksIGZpZWxkTGVuKTtcbiAgfVxuICBmdW5jdGlvbiBkZWNvZGVVKHU6IEhleCk6IGJpZ2ludCB7XG4gICAgY29uc3QgX3UgPSBlbnN1cmVCeXRlcygndSBjb29yZGluYXRlJywgdSwgZmllbGRMZW4pO1xuICAgIC8vIFJGQzogV2hlbiByZWNlaXZpbmcgc3VjaCBhbiBhcnJheSwgaW1wbGVtZW50YXRpb25zIG9mIFgyNTUxOVxuICAgIC8vIChidXQgbm90IFg0NDgpIE1VU1QgbWFzayB0aGUgbW9zdCBzaWduaWZpY2FudCBiaXQgaW4gdGhlIGZpbmFsIGJ5dGUuXG4gICAgaWYgKGlzMjU1MTkpIF91WzMxXSAmPSAxMjc7IC8vIDBiMDExMV8xMTExXG4gICAgLy8gUkZDOiBJbXBsZW1lbnRhdGlvbnMgTVVTVCBhY2NlcHQgbm9uLWNhbm9uaWNhbCB2YWx1ZXMgYW5kIHByb2Nlc3MgdGhlbSBhc1xuICAgIC8vIGlmIHRoZXkgaGFkIGJlZW4gcmVkdWNlZCBtb2R1bG8gdGhlIGZpZWxkIHByaW1lLiAgVGhlIG5vbi1jYW5vbmljYWxcbiAgICAvLyB2YWx1ZXMgYXJlIDJeMjU1IC0gMTkgdGhyb3VnaCAyXjI1NSAtIDEgZm9yIFgyNTUxOSBhbmQgMl40NDggLSAyXjIyNFxuICAgIC8vIC0gMSB0aHJvdWdoIDJeNDQ4IC0gMSBmb3IgWDQ0OC5cbiAgICByZXR1cm4gbW9kUChieXRlc1RvTnVtYmVyTEUoX3UpKTtcbiAgfVxuICBmdW5jdGlvbiBkZWNvZGVTY2FsYXIoc2NhbGFyOiBIZXgpOiBiaWdpbnQge1xuICAgIHJldHVybiBieXRlc1RvTnVtYmVyTEUoYWRqdXN0U2NhbGFyQnl0ZXMoZW5zdXJlQnl0ZXMoJ3NjYWxhcicsIHNjYWxhciwgZmllbGRMZW4pKSk7XG4gIH1cbiAgZnVuY3Rpb24gc2NhbGFyTXVsdChzY2FsYXI6IEhleCwgdTogSGV4KTogVWludDhBcnJheSB7XG4gICAgY29uc3QgcHUgPSBtb250Z29tZXJ5TGFkZGVyKGRlY29kZVUodSksIGRlY29kZVNjYWxhcihzY2FsYXIpKTtcbiAgICAvLyBTb21lIHB1YmxpYyBrZXlzIGFyZSB1c2VsZXNzLCBvZiBsb3ctb3JkZXIuIEN1cnZlIGF1dGhvciBkb2Vzbid0IHRoaW5rXG4gICAgLy8gaXQgbmVlZHMgdG8gYmUgdmFsaWRhdGVkLCBidXQgd2UgZG8gaXQgbm9uZXRoZWxlc3MuXG4gICAgLy8gaHR0cHM6Ly9jci55cC50by9lY2RoLmh0bWwjdmFsaWRhdGVcbiAgICBpZiAocHUgPT09IF8wbikgdGhyb3cgbmV3IEVycm9yKCdpbnZhbGlkIHByaXZhdGUgb3IgcHVibGljIGtleSByZWNlaXZlZCcpO1xuICAgIHJldHVybiBlbmNvZGVVKHB1KTtcbiAgfVxuICAvLyBDb21wdXRlcyBwdWJsaWMga2V5IGZyb20gcHJpdmF0ZS4gQnkgZG9pbmcgc2NhbGFyIG11bHRpcGxpY2F0aW9uIG9mIGJhc2UgcG9pbnQuXG4gIGZ1bmN0aW9uIHNjYWxhck11bHRCYXNlKHNjYWxhcjogSGV4KTogVWludDhBcnJheSB7XG4gICAgcmV0dXJuIHNjYWxhck11bHQoc2NhbGFyLCBHdUJ5dGVzKTtcbiAgfVxuXG4gIC8vIGNzd2FwIGZyb20gUkZDNzc0OCBcImV4YW1wbGUgY29kZVwiXG4gIGZ1bmN0aW9uIGNzd2FwKHN3YXA6IGJpZ2ludCwgeF8yOiBiaWdpbnQsIHhfMzogYmlnaW50KTogeyB4XzI6IGJpZ2ludDsgeF8zOiBiaWdpbnQgfSB7XG4gICAgLy8gZHVtbXkgPSBtYXNrKHN3YXApIEFORCAoeF8yIFhPUiB4XzMpXG4gICAgLy8gV2hlcmUgbWFzayhzd2FwKSBpcyB0aGUgYWxsLTEgb3IgYWxsLTAgd29yZCBvZiB0aGUgc2FtZSBsZW5ndGggYXMgeF8yXG4gICAgLy8gYW5kIHhfMywgY29tcHV0ZWQsIGUuZy4sIGFzIG1hc2soc3dhcCkgPSAwIC0gc3dhcC5cbiAgICBjb25zdCBkdW1teSA9IG1vZFAoc3dhcCAqICh4XzIgLSB4XzMpKTtcbiAgICB4XzIgPSBtb2RQKHhfMiAtIGR1bW15KTsgLy8geF8yID0geF8yIFhPUiBkdW1teVxuICAgIHhfMyA9IG1vZFAoeF8zICsgZHVtbXkpOyAvLyB4XzMgPSB4XzMgWE9SIGR1bW15XG4gICAgcmV0dXJuIHsgeF8yLCB4XzMgfTtcbiAgfVxuXG4gIC8qKlxuICAgKiBNb250Z29tZXJ5IHgtb25seSBtdWx0aXBsaWNhdGlvbiBsYWRkZXIuXG4gICAqIEBwYXJhbSBwb2ludFUgdSBjb29yZGluYXRlICh4KSBvbiBNb250Z29tZXJ5IEN1cnZlIDI1NTE5XG4gICAqIEBwYXJhbSBzY2FsYXIgYnkgd2hpY2ggdGhlIHBvaW50IHdvdWxkIGJlIG11bHRpcGxpZWRcbiAgICogQHJldHVybnMgbmV3IFBvaW50IG9uIE1vbnRnb21lcnkgY3VydmVcbiAgICovXG4gIGZ1bmN0aW9uIG1vbnRnb21lcnlMYWRkZXIodTogYmlnaW50LCBzY2FsYXI6IGJpZ2ludCk6IGJpZ2ludCB7XG4gICAgYUluUmFuZ2UoJ3UnLCB1LCBfMG4sIFApO1xuICAgIGFJblJhbmdlKCdzY2FsYXInLCBzY2FsYXIsIG1pblNjYWxhciwgbWF4U2NhbGFyKTtcbiAgICBjb25zdCBrID0gc2NhbGFyO1xuICAgIGNvbnN0IHhfMSA9IHU7XG4gICAgbGV0IHhfMiA9IF8xbjtcbiAgICBsZXQgel8yID0gXzBuO1xuICAgIGxldCB4XzMgPSB1O1xuICAgIGxldCB6XzMgPSBfMW47XG4gICAgbGV0IHN3YXAgPSBfMG47XG4gICAgZm9yIChsZXQgdCA9IEJpZ0ludChtb250Z29tZXJ5Qml0cyAtIDEpOyB0ID49IF8wbjsgdC0tKSB7XG4gICAgICBjb25zdCBrX3QgPSAoayA+PiB0KSAmIF8xbjtcbiAgICAgIHN3YXAgXj0ga190O1xuICAgICAgKHsgeF8yLCB4XzMgfSA9IGNzd2FwKHN3YXAsIHhfMiwgeF8zKSk7XG4gICAgICAoeyB4XzI6IHpfMiwgeF8zOiB6XzMgfSA9IGNzd2FwKHN3YXAsIHpfMiwgel8zKSk7XG4gICAgICBzd2FwID0ga190O1xuXG4gICAgICBjb25zdCBBID0geF8yICsgel8yO1xuICAgICAgY29uc3QgQUEgPSBtb2RQKEEgKiBBKTtcbiAgICAgIGNvbnN0IEIgPSB4XzIgLSB6XzI7XG4gICAgICBjb25zdCBCQiA9IG1vZFAoQiAqIEIpO1xuICAgICAgY29uc3QgRSA9IEFBIC0gQkI7XG4gICAgICBjb25zdCBDID0geF8zICsgel8zO1xuICAgICAgY29uc3QgRCA9IHhfMyAtIHpfMztcbiAgICAgIGNvbnN0IERBID0gbW9kUChEICogQSk7XG4gICAgICBjb25zdCBDQiA9IG1vZFAoQyAqIEIpO1xuICAgICAgY29uc3QgZGFjYiA9IERBICsgQ0I7XG4gICAgICBjb25zdCBkYV9jYiA9IERBIC0gQ0I7XG4gICAgICB4XzMgPSBtb2RQKGRhY2IgKiBkYWNiKTtcbiAgICAgIHpfMyA9IG1vZFAoeF8xICogbW9kUChkYV9jYiAqIGRhX2NiKSk7XG4gICAgICB4XzIgPSBtb2RQKEFBICogQkIpO1xuICAgICAgel8yID0gbW9kUChFICogKEFBICsgbW9kUChhMjQgKiBFKSkpO1xuICAgIH1cbiAgICAoeyB4XzIsIHhfMyB9ID0gY3N3YXAoc3dhcCwgeF8yLCB4XzMpKTtcbiAgICAoeyB4XzI6IHpfMiwgeF8zOiB6XzMgfSA9IGNzd2FwKHN3YXAsIHpfMiwgel8zKSk7XG4gICAgY29uc3QgejIgPSBwb3dQbWludXMyKHpfMik7IC8vIGBGcC5wb3coeCwgUCAtIF8ybilgIGlzIG11Y2ggc2xvd2VyIGVxdWl2YWxlbnRcbiAgICByZXR1cm4gbW9kUCh4XzIgKiB6Mik7IC8vIFJldHVybiB4XzIgKiAoel8yXihwIC0gMikpXG4gIH1cbiAgY29uc3QgbGVuZ3RocyA9IHtcbiAgICBzZWNyZXRLZXk6IGZpZWxkTGVuLFxuICAgIHB1YmxpY0tleTogZmllbGRMZW4sXG4gICAgc2VlZDogZmllbGRMZW4sXG4gIH07XG4gIGNvbnN0IHJhbmRvbVNlY3JldEtleSA9IChzZWVkID0gcmFuZG9tQnl0ZXNfKGZpZWxkTGVuKSkgPT4ge1xuICAgIGFieXRlcyhzZWVkLCBsZW5ndGhzLnNlZWQpO1xuICAgIHJldHVybiBzZWVkO1xuICB9O1xuICBmdW5jdGlvbiBrZXlnZW4oc2VlZD86IFVpbnQ4QXJyYXkpIHtcbiAgICBjb25zdCBzZWNyZXRLZXkgPSByYW5kb21TZWNyZXRLZXkoc2VlZCk7XG4gICAgcmV0dXJuIHsgc2VjcmV0S2V5LCBwdWJsaWNLZXk6IHNjYWxhck11bHRCYXNlKHNlY3JldEtleSkgfTtcbiAgfVxuICBjb25zdCB1dGlscyA9IHtcbiAgICByYW5kb21TZWNyZXRLZXksXG4gICAgcmFuZG9tUHJpdmF0ZUtleTogcmFuZG9tU2VjcmV0S2V5LFxuICB9O1xuICByZXR1cm4ge1xuICAgIGtleWdlbixcbiAgICBnZXRTaGFyZWRTZWNyZXQ6IChzZWNyZXRLZXk6IEhleCwgcHVibGljS2V5OiBIZXgpID0+IHNjYWxhck11bHQoc2VjcmV0S2V5LCBwdWJsaWNLZXkpLFxuICAgIGdldFB1YmxpY0tleTogKHNlY3JldEtleTogSGV4KTogVWludDhBcnJheSA9PiBzY2FsYXJNdWx0QmFzZShzZWNyZXRLZXkpLFxuICAgIHNjYWxhck11bHQsXG4gICAgc2NhbGFyTXVsdEJhc2UsXG4gICAgdXRpbHMsXG4gICAgR3VCeXRlczogR3VCeXRlcy5zbGljZSgpLFxuICAgIGxlbmd0aHMsXG4gIH07XG59XG4iLCAiLyoqXG4gKiBlZDI1NTE5IFR3aXN0ZWQgRWR3YXJkcyBjdXJ2ZSB3aXRoIGZvbGxvd2luZyBhZGRvbnM6XG4gKiAtIFgyNTUxOSBFQ0RIXG4gKiAtIFJpc3RyZXR0byBjb2ZhY3RvciBlbGltaW5hdGlvblxuICogLSBFbGxpZ2F0b3IgaGFzaC10by1ncm91cCAvIHBvaW50IGluZGlzdGluZ3Vpc2hhYmlsaXR5XG4gKiBAbW9kdWxlXG4gKi9cbi8qISBub2JsZS1jdXJ2ZXMgLSBNSVQgTGljZW5zZSAoYykgMjAyMiBQYXVsIE1pbGxlciAocGF1bG1pbGxyLmNvbSkgKi9cbmltcG9ydCB7IHNoYTUxMiB9IGZyb20gJ0Bub2JsZS9oYXNoZXMvc2hhMi5qcyc7XG5pbXBvcnQgeyBhYnl0ZXMsIGNvbmNhdEJ5dGVzLCB1dGY4VG9CeXRlcyB9IGZyb20gJ0Bub2JsZS9oYXNoZXMvdXRpbHMuanMnO1xuaW1wb3J0IHsgcGlwcGVuZ2VyLCB0eXBlIEFmZmluZVBvaW50IH0gZnJvbSAnLi9hYnN0cmFjdC9jdXJ2ZS50cyc7XG5pbXBvcnQge1xuICBQcmltZUVkd2FyZHNQb2ludCxcbiAgdHdpc3RlZEVkd2FyZHMsXG4gIHR5cGUgQ3VydmVGbixcbiAgdHlwZSBFZHdhcmRzT3B0cyxcbiAgdHlwZSBFZHdhcmRzUG9pbnQsXG59IGZyb20gJy4vYWJzdHJhY3QvZWR3YXJkcy50cyc7XG5pbXBvcnQge1xuICBfRFNUX3NjYWxhcixcbiAgY3JlYXRlSGFzaGVyLFxuICBleHBhbmRfbWVzc2FnZV94bWQsXG4gIHR5cGUgSDJDSGFzaGVyLFxuICB0eXBlIEgyQ0hhc2hlckJhc2UsXG4gIHR5cGUgSDJDTWV0aG9kLFxuICB0eXBlIGh0ZkJhc2ljT3B0cyxcbn0gZnJvbSAnLi9hYnN0cmFjdC9oYXNoLXRvLWN1cnZlLnRzJztcbmltcG9ydCB7XG4gIEZpZWxkLFxuICBGcEludmVydEJhdGNoLFxuICBGcFNxcnRFdmVuLFxuICBpc05lZ2F0aXZlTEUsXG4gIG1vZCxcbiAgcG93MixcbiAgdHlwZSBJRmllbGQsXG59IGZyb20gJy4vYWJzdHJhY3QvbW9kdWxhci50cyc7XG5pbXBvcnQgeyBtb250Z29tZXJ5LCB0eXBlIE1vbnRnb21lcnlFQ0RIIGFzIFhDdXJ2ZUZuIH0gZnJvbSAnLi9hYnN0cmFjdC9tb250Z29tZXJ5LnRzJztcbmltcG9ydCB7IGJ5dGVzVG9OdW1iZXJMRSwgZW5zdXJlQnl0ZXMsIGVxdWFsQnl0ZXMsIHR5cGUgSGV4IH0gZnJvbSAnLi91dGlscy50cyc7XG5cbi8vIHByZXR0aWVyLWlnbm9yZVxuY29uc3QgXzBuID0gLyogQF9fUFVSRV9fICovIEJpZ0ludCgwKSwgXzFuID0gQmlnSW50KDEpLCBfMm4gPSBCaWdJbnQoMiksIF8zbiA9IEJpZ0ludCgzKTtcbi8vIHByZXR0aWVyLWlnbm9yZVxuY29uc3QgXzVuID0gQmlnSW50KDUpLCBfOG4gPSBCaWdJbnQoOCk7XG5cbi8vIFAgPSAybioqMjU1bi0xOW5cbmNvbnN0IGVkMjU1MTlfQ1VSVkVfcCA9IEJpZ0ludChcbiAgJzB4N2ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZlZCdcbik7XG5cbi8vIE4gPSAybioqMjUybiArIDI3NzQyMzE3Nzc3MzcyMzUzNTM1ODUxOTM3NzkwODgzNjQ4NDkzblxuLy8gYSA9IEZwLmNyZWF0ZShCaWdJbnQoLTEpKVxuLy8gZCA9IC0xMjE2NjUvMTIxNjY2IGEuay5hLiBGcC5uZWcoMTIxNjY1ICogRnAuaW52KDEyMTY2NikpXG5jb25zdCBlZDI1NTE5X0NVUlZFOiBFZHdhcmRzT3B0cyA9IC8qIEBfX1BVUkVfXyAqLyAoKCkgPT4gKHtcbiAgcDogZWQyNTUxOV9DVVJWRV9wLFxuICBuOiBCaWdJbnQoJzB4MTAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAxNGRlZjlkZWEyZjc5Y2Q2NTgxMjYzMWE1Y2Y1ZDNlZCcpLFxuICBoOiBfOG4sXG4gIGE6IEJpZ0ludCgnMHg3ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmVjJyksXG4gIGQ6IEJpZ0ludCgnMHg1MjAzNmNlZTJiNmZmZTczOGNjNzQwNzk3Nzc5ZTg5ODAwNzAwYTRkNDE0MWQ4YWI3NWViNGRjYTEzNTk3OGEzJyksXG4gIEd4OiBCaWdJbnQoJzB4MjE2OTM2ZDNjZDZlNTNmZWMwYTRlMjMxZmRkNmRjNWM2OTJjYzc2MDk1MjVhN2IyYzk1NjJkNjA4ZjI1ZDUxYScpLFxuICBHeTogQmlnSW50KCcweDY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NTgnKSxcbn0pKSgpO1xuXG5mdW5jdGlvbiBlZDI1NTE5X3Bvd18yXzI1Ml8zKHg6IGJpZ2ludCkge1xuICAvLyBwcmV0dGllci1pZ25vcmVcbiAgY29uc3QgXzEwbiA9IEJpZ0ludCgxMCksIF8yMG4gPSBCaWdJbnQoMjApLCBfNDBuID0gQmlnSW50KDQwKSwgXzgwbiA9IEJpZ0ludCg4MCk7XG4gIGNvbnN0IFAgPSBlZDI1NTE5X0NVUlZFX3A7XG4gIGNvbnN0IHgyID0gKHggKiB4KSAlIFA7XG4gIGNvbnN0IGIyID0gKHgyICogeCkgJSBQOyAvLyB4XjMsIDExXG4gIGNvbnN0IGI0ID0gKHBvdzIoYjIsIF8ybiwgUCkgKiBiMikgJSBQOyAvLyB4XjE1LCAxMTExXG4gIGNvbnN0IGI1ID0gKHBvdzIoYjQsIF8xbiwgUCkgKiB4KSAlIFA7IC8vIHheMzFcbiAgY29uc3QgYjEwID0gKHBvdzIoYjUsIF81biwgUCkgKiBiNSkgJSBQO1xuICBjb25zdCBiMjAgPSAocG93MihiMTAsIF8xMG4sIFApICogYjEwKSAlIFA7XG4gIGNvbnN0IGI0MCA9IChwb3cyKGIyMCwgXzIwbiwgUCkgKiBiMjApICUgUDtcbiAgY29uc3QgYjgwID0gKHBvdzIoYjQwLCBfNDBuLCBQKSAqIGI0MCkgJSBQO1xuICBjb25zdCBiMTYwID0gKHBvdzIoYjgwLCBfODBuLCBQKSAqIGI4MCkgJSBQO1xuICBjb25zdCBiMjQwID0gKHBvdzIoYjE2MCwgXzgwbiwgUCkgKiBiODApICUgUDtcbiAgY29uc3QgYjI1MCA9IChwb3cyKGIyNDAsIF8xMG4sIFApICogYjEwKSAlIFA7XG4gIGNvbnN0IHBvd19wXzVfOCA9IChwb3cyKGIyNTAsIF8ybiwgUCkgKiB4KSAlIFA7XG4gIC8vIF4gVG8gcG93IHRvIChwKzMpLzgsIG11bHRpcGx5IGl0IGJ5IHguXG4gIHJldHVybiB7IHBvd19wXzVfOCwgYjIgfTtcbn1cblxuZnVuY3Rpb24gYWRqdXN0U2NhbGFyQnl0ZXMoYnl0ZXM6IFVpbnQ4QXJyYXkpOiBVaW50OEFycmF5IHtcbiAgLy8gU2VjdGlvbiA1OiBGb3IgWDI1NTE5LCBpbiBvcmRlciB0byBkZWNvZGUgMzIgcmFuZG9tIGJ5dGVzIGFzIGFuIGludGVnZXIgc2NhbGFyLFxuICAvLyBzZXQgdGhlIHRocmVlIGxlYXN0IHNpZ25pZmljYW50IGJpdHMgb2YgdGhlIGZpcnN0IGJ5dGVcbiAgYnl0ZXNbMF0gJj0gMjQ4OyAvLyAwYjExMTFfMTAwMFxuICAvLyBhbmQgdGhlIG1vc3Qgc2lnbmlmaWNhbnQgYml0IG9mIHRoZSBsYXN0IHRvIHplcm8sXG4gIGJ5dGVzWzMxXSAmPSAxMjc7IC8vIDBiMDExMV8xMTExXG4gIC8vIHNldCB0aGUgc2Vjb25kIG1vc3Qgc2lnbmlmaWNhbnQgYml0IG9mIHRoZSBsYXN0IGJ5dGUgdG8gMVxuICBieXRlc1szMV0gfD0gNjQ7IC8vIDBiMDEwMF8wMDAwXG4gIHJldHVybiBieXRlcztcbn1cblxuLy8gXHUyMjFBKC0xKSBha2EgXHUyMjFBKGEpIGFrYSAyXigocC0xKS80KVxuLy8gRnAuc3FydChGcC5uZWcoMSkpXG5jb25zdCBFRDI1NTE5X1NRUlRfTTEgPSAvKiBAX19QVVJFX18gKi8gQmlnSW50KFxuICAnMTk2ODExNjEzNzY3MDc1MDU5NTY4MDcwNzkzMDQ5ODg1NDIwMTU0NDYwNjY1MTU5MjM4OTAxNjI3NDQwMjEwNzMxMjM4Mjk3ODQ3NTInXG4pO1xuLy8gc3FydCh1L3YpXG5mdW5jdGlvbiB1dlJhdGlvKHU6IGJpZ2ludCwgdjogYmlnaW50KTogeyBpc1ZhbGlkOiBib29sZWFuOyB2YWx1ZTogYmlnaW50IH0ge1xuICBjb25zdCBQID0gZWQyNTUxOV9DVVJWRV9wO1xuICBjb25zdCB2MyA9IG1vZCh2ICogdiAqIHYsIFApOyAvLyB2XHUwMEIzXG4gIGNvbnN0IHY3ID0gbW9kKHYzICogdjMgKiB2LCBQKTsgLy8gdlx1MjA3N1xuICAvLyAocCszKS84IGFuZCAocC01KS84XG4gIGNvbnN0IHBvdyA9IGVkMjU1MTlfcG93XzJfMjUyXzModSAqIHY3KS5wb3dfcF81Xzg7XG4gIGxldCB4ID0gbW9kKHUgKiB2MyAqIHBvdywgUCk7IC8vICh1dlx1MDBCMykodXZcdTIwNzcpXihwLTUpLzhcbiAgY29uc3QgdngyID0gbW9kKHYgKiB4ICogeCwgUCk7IC8vIHZ4XHUwMEIyXG4gIGNvbnN0IHJvb3QxID0geDsgLy8gRmlyc3Qgcm9vdCBjYW5kaWRhdGVcbiAgY29uc3Qgcm9vdDIgPSBtb2QoeCAqIEVEMjU1MTlfU1FSVF9NMSwgUCk7IC8vIFNlY29uZCByb290IGNhbmRpZGF0ZVxuICBjb25zdCB1c2VSb290MSA9IHZ4MiA9PT0gdTsgLy8gSWYgdnhcdTAwQjIgPSB1IChtb2QgcCksIHggaXMgYSBzcXVhcmUgcm9vdFxuICBjb25zdCB1c2VSb290MiA9IHZ4MiA9PT0gbW9kKC11LCBQKTsgLy8gSWYgdnhcdTAwQjIgPSAtdSwgc2V0IHggPC0tIHggKiAyXigocC0xKS80KVxuICBjb25zdCBub1Jvb3QgPSB2eDIgPT09IG1vZCgtdSAqIEVEMjU1MTlfU1FSVF9NMSwgUCk7IC8vIFRoZXJlIGlzIG5vIHZhbGlkIHJvb3QsIHZ4XHUwMEIyID0gLXVcdTIyMUEoLTEpXG4gIGlmICh1c2VSb290MSkgeCA9IHJvb3QxO1xuICBpZiAodXNlUm9vdDIgfHwgbm9Sb290KSB4ID0gcm9vdDI7IC8vIFdlIHJldHVybiByb290MiBhbnl3YXksIGZvciBjb25zdC10aW1lXG4gIGlmIChpc05lZ2F0aXZlTEUoeCwgUCkpIHggPSBtb2QoLXgsIFApO1xuICByZXR1cm4geyBpc1ZhbGlkOiB1c2VSb290MSB8fCB1c2VSb290MiwgdmFsdWU6IHggfTtcbn1cblxuY29uc3QgRnAgPSAvKiBAX19QVVJFX18gKi8gKCgpID0+IEZpZWxkKGVkMjU1MTlfQ1VSVkUucCwgeyBpc0xFOiB0cnVlIH0pKSgpO1xuY29uc3QgRm4gPSAvKiBAX19QVVJFX18gKi8gKCgpID0+IEZpZWxkKGVkMjU1MTlfQ1VSVkUubiwgeyBpc0xFOiB0cnVlIH0pKSgpO1xuXG5jb25zdCBlZDI1NTE5RGVmYXVsdHMgPSAvKiBAX19QVVJFX18gKi8gKCgpID0+ICh7XG4gIC4uLmVkMjU1MTlfQ1VSVkUsXG4gIEZwLFxuICBoYXNoOiBzaGE1MTIsXG4gIGFkanVzdFNjYWxhckJ5dGVzLFxuICAvLyBkb20yXG4gIC8vIFJhdGlvIG9mIHUgdG8gdi4gQWxsb3dzIHVzIHRvIGNvbWJpbmUgaW52ZXJzaW9uIGFuZCBzcXVhcmUgcm9vdC4gVXNlcyBhbGdvIGZyb20gUkZDODAzMiA1LjEuMy5cbiAgLy8gQ29uc3RhbnQtdGltZSwgdS9cdTIyMUF2XG4gIHV2UmF0aW8sXG59KSkoKTtcblxuLyoqXG4gKiBlZDI1NTE5IGN1cnZlIHdpdGggRWREU0Egc2lnbmF0dXJlcy5cbiAqIEBleGFtcGxlXG4gKiBpbXBvcnQgeyBlZDI1NTE5IH0gZnJvbSAnQG5vYmxlL2N1cnZlcy9lZDI1NTE5JztcbiAqIGNvbnN0IHsgc2VjcmV0S2V5LCBwdWJsaWNLZXkgfSA9IGVkMjU1MTkua2V5Z2VuKCk7XG4gKiBjb25zdCBtc2cgPSBuZXcgVGV4dEVuY29kZXIoKS5lbmNvZGUoJ2hlbGxvJyk7XG4gKiBjb25zdCBzaWcgPSBlZDI1NTE5LnNpZ24obXNnLCBwcml2KTtcbiAqIGVkMjU1MTkudmVyaWZ5KHNpZywgbXNnLCBwdWIpOyAvLyBEZWZhdWx0IG1vZGU6IGZvbGxvd3MgWklQMjE1XG4gKiBlZDI1NTE5LnZlcmlmeShzaWcsIG1zZywgcHViLCB7IHppcDIxNTogZmFsc2UgfSk7IC8vIFJGQzgwMzIgLyBGSVBTIDE4Ni01XG4gKi9cbmV4cG9ydCBjb25zdCBlZDI1NTE5OiBDdXJ2ZUZuID0gLyogQF9fUFVSRV9fICovICgoKSA9PiB0d2lzdGVkRWR3YXJkcyhlZDI1NTE5RGVmYXVsdHMpKSgpO1xuXG5mdW5jdGlvbiBlZDI1NTE5X2RvbWFpbihkYXRhOiBVaW50OEFycmF5LCBjdHg6IFVpbnQ4QXJyYXksIHBoZmxhZzogYm9vbGVhbikge1xuICBpZiAoY3R4Lmxlbmd0aCA+IDI1NSkgdGhyb3cgbmV3IEVycm9yKCdDb250ZXh0IGlzIHRvbyBiaWcnKTtcbiAgcmV0dXJuIGNvbmNhdEJ5dGVzKFxuICAgIHV0ZjhUb0J5dGVzKCdTaWdFZDI1NTE5IG5vIEVkMjU1MTkgY29sbGlzaW9ucycpLFxuICAgIG5ldyBVaW50OEFycmF5KFtwaGZsYWcgPyAxIDogMCwgY3R4Lmxlbmd0aF0pLFxuICAgIGN0eCxcbiAgICBkYXRhXG4gICk7XG59XG5cbi8qKiBDb250ZXh0IG9mIGVkMjU1MTkuIFVzZXMgY29udGV4dCBmb3IgZG9tYWluIHNlcGFyYXRpb24uICovXG5leHBvcnQgY29uc3QgZWQyNTUxOWN0eDogQ3VydmVGbiA9IC8qIEBfX1BVUkVfXyAqLyAoKCkgPT5cbiAgdHdpc3RlZEVkd2FyZHMoe1xuICAgIC4uLmVkMjU1MTlEZWZhdWx0cyxcbiAgICBkb21haW46IGVkMjU1MTlfZG9tYWluLFxuICB9KSkoKTtcblxuLyoqIFByZWhhc2hlZCB2ZXJzaW9uIG9mIGVkMjU1MTkuIEFjY2VwdHMgYWxyZWFkeS1oYXNoZWQgbWVzc2FnZXMgaW4gc2lnbigpIGFuZCB2ZXJpZnkoKS4gKi9cbmV4cG9ydCBjb25zdCBlZDI1NTE5cGg6IEN1cnZlRm4gPSAvKiBAX19QVVJFX18gKi8gKCgpID0+XG4gIHR3aXN0ZWRFZHdhcmRzKFxuICAgIE9iamVjdC5hc3NpZ24oe30sIGVkMjU1MTlEZWZhdWx0cywge1xuICAgICAgZG9tYWluOiBlZDI1NTE5X2RvbWFpbixcbiAgICAgIHByZWhhc2g6IHNoYTUxMixcbiAgICB9KVxuICApKSgpO1xuXG4vKipcbiAqIEVDREggdXNpbmcgY3VydmUyNTUxOSBha2EgeDI1NTE5LlxuICogQGV4YW1wbGVcbiAqIGltcG9ydCB7IHgyNTUxOSB9IGZyb20gJ0Bub2JsZS9jdXJ2ZXMvZWQyNTUxOSc7XG4gKiBjb25zdCBwcml2ID0gJ2E1NDZlMzZiZjA1MjdjOWQzYjE2MTU0YjgyNDY1ZWRkNjIxNDRjMGFjMWZjNWExODUwNmEyMjQ0YmE0NDlhYzQnO1xuICogY29uc3QgcHViID0gJ2U2ZGI2ODY3NTgzMDMwZGIzNTk0YzFhNDI0YjE1ZjdjNzI2NjI0ZWMyNmIzMzUzYjEwYTkwM2E2ZDBhYjFjNGMnO1xuICogeDI1NTE5LmdldFNoYXJlZFNlY3JldChwcml2LCBwdWIpID09PSB4MjU1MTkuc2NhbGFyTXVsdChwcml2LCBwdWIpOyAvLyBhbGlhc2VzXG4gKiB4MjU1MTkuZ2V0UHVibGljS2V5KHByaXYpID09PSB4MjU1MTkuc2NhbGFyTXVsdEJhc2UocHJpdik7XG4gKiB4MjU1MTkuZ2V0UHVibGljS2V5KHgyNTUxOS51dGlscy5yYW5kb21TZWNyZXRLZXkoKSk7XG4gKi9cbmV4cG9ydCBjb25zdCB4MjU1MTk6IFhDdXJ2ZUZuID0gLyogQF9fUFVSRV9fICovICgoKSA9PiB7XG4gIGNvbnN0IFAgPSBGcC5PUkRFUjtcbiAgcmV0dXJuIG1vbnRnb21lcnkoe1xuICAgIFAsXG4gICAgdHlwZTogJ3gyNTUxOScsXG4gICAgcG93UG1pbnVzMjogKHg6IGJpZ2ludCk6IGJpZ2ludCA9PiB7XG4gICAgICAvLyB4XihwLTIpIGFrYSB4XigyXjI1NS0yMSlcbiAgICAgIGNvbnN0IHsgcG93X3BfNV84LCBiMiB9ID0gZWQyNTUxOV9wb3dfMl8yNTJfMyh4KTtcbiAgICAgIHJldHVybiBtb2QocG93Mihwb3dfcF81XzgsIF8zbiwgUCkgKiBiMiwgUCk7XG4gICAgfSxcbiAgICBhZGp1c3RTY2FsYXJCeXRlcyxcbiAgfSk7XG59KSgpO1xuXG4vLyBIYXNoIFRvIEN1cnZlIEVsbGlnYXRvcjIgTWFwIChOT1RFOiBkaWZmZXJlbnQgZnJvbSByaXN0cmV0dG8yNTUgZWxsaWdhdG9yKVxuLy8gTk9URTogdmVyeSBpbXBvcnRhbnQgcGFydCBpcyB1c2FnZSBvZiBGcFNxcnRFdmVuIGZvciBFTEwyX0MxX0VEV0FSRFMsIHNpbmNlXG4vLyBTYWdlTWF0aCByZXR1cm5zIGRpZmZlcmVudCByb290IGZpcnN0IGFuZCBldmVyeXRoaW5nIGZhbGxzIGFwYXJ0XG5jb25zdCBFTEwyX0MxID0gLyogQF9fUFVSRV9fICovICgoKSA9PiAoZWQyNTUxOV9DVVJWRV9wICsgXzNuKSAvIF84bikoKTsgLy8gMS4gYzEgPSAocSArIDMpIC8gOCAgICAgICAjIEludGVnZXIgYXJpdGhtZXRpY1xuY29uc3QgRUxMMl9DMiA9IC8qIEBfX1BVUkVfXyAqLyAoKCkgPT4gRnAucG93KF8ybiwgRUxMMl9DMSkpKCk7IC8vIDIuIGMyID0gMl5jMVxuY29uc3QgRUxMMl9DMyA9IC8qIEBfX1BVUkVfXyAqLyAoKCkgPT4gRnAuc3FydChGcC5uZWcoRnAuT05FKSkpKCk7IC8vIDMuIGMzID0gc3FydCgtMSlcblxuLy8gcHJldHRpZXItaWdub3JlXG5mdW5jdGlvbiBtYXBfdG9fY3VydmVfZWxsaWdhdG9yMl9jdXJ2ZTI1NTE5KHU6IGJpZ2ludCkge1xuICBjb25zdCBFTEwyX0M0ID0gKGVkMjU1MTlfQ1VSVkVfcCAtIF81bikgLyBfOG47IC8vIDQuIGM0ID0gKHEgLSA1KSAvIDggICAgICAgIyBJbnRlZ2VyIGFyaXRobWV0aWNcbiAgY29uc3QgRUxMMl9KID0gQmlnSW50KDQ4NjY2Mik7XG5cbiAgbGV0IHR2MSA9IEZwLnNxcih1KTsgICAgICAgICAgLy8gIDEuICB0djEgPSB1XjJcbiAgdHYxID0gRnAubXVsKHR2MSwgXzJuKTsgICAgICAgLy8gIDIuICB0djEgPSAyICogdHYxXG4gIGxldCB4ZCA9IEZwLmFkZCh0djEsIEZwLk9ORSk7IC8vICAzLiAgIHhkID0gdHYxICsgMSAgICAgICAgICMgTm9uemVybzogLTEgaXMgc3F1YXJlIChtb2QgcCksIHR2MSBpcyBub3RcbiAgbGV0IHgxbiA9IEZwLm5lZyhFTEwyX0opOyAgICAgLy8gIDQuICB4MW4gPSAtSiAgICAgICAgICAgICAgIyB4MSA9IHgxbiAvIHhkID0gLUogLyAoMSArIDIgKiB1XjIpXG4gIGxldCB0djIgPSBGcC5zcXIoeGQpOyAgICAgICAgIC8vICA1LiAgdHYyID0geGReMlxuICBsZXQgZ3hkID0gRnAubXVsKHR2MiwgeGQpOyAgICAvLyAgNi4gIGd4ZCA9IHR2MiAqIHhkICAgICAgICAjIGd4ZCA9IHhkXjNcbiAgbGV0IGd4MSA9IEZwLm11bCh0djEsIEVMTDJfSik7Ly8gIDcuICBneDEgPSBKICogdHYxICAgICAgICAgIyB4MW4gKyBKICogeGRcbiAgZ3gxID0gRnAubXVsKGd4MSwgeDFuKTsgICAgICAgLy8gIDguICBneDEgPSBneDEgKiB4MW4gICAgICAgIyB4MW5eMiArIEogKiB4MW4gKiB4ZFxuICBneDEgPSBGcC5hZGQoZ3gxLCB0djIpOyAgICAgICAvLyAgOS4gIGd4MSA9IGd4MSArIHR2MiAgICAgICAjIHgxbl4yICsgSiAqIHgxbiAqIHhkICsgeGReMlxuICBneDEgPSBGcC5tdWwoZ3gxLCB4MW4pOyAgICAgICAvLyAgMTAuIGd4MSA9IGd4MSAqIHgxbiAgICAgICAjIHgxbl4zICsgSiAqIHgxbl4yICogeGQgKyB4MW4gKiB4ZF4yXG4gIGxldCB0djMgPSBGcC5zcXIoZ3hkKTsgICAgICAgIC8vICAxMS4gdHYzID0gZ3hkXjJcbiAgdHYyID0gRnAuc3FyKHR2Myk7ICAgICAgICAgICAgLy8gIDEyLiB0djIgPSB0djNeMiAgICAgICAgICAgIyBneGReNFxuICB0djMgPSBGcC5tdWwodHYzLCBneGQpOyAgICAgICAvLyAgMTMuIHR2MyA9IHR2MyAqIGd4ZCAgICAgICAjIGd4ZF4zXG4gIHR2MyA9IEZwLm11bCh0djMsIGd4MSk7ICAgICAgIC8vICAxNC4gdHYzID0gdHYzICogZ3gxICAgICAgICMgZ3gxICogZ3hkXjNcbiAgdHYyID0gRnAubXVsKHR2MiwgdHYzKTsgICAgICAgLy8gIDE1LiB0djIgPSB0djIgKiB0djMgICAgICAgIyBneDEgKiBneGReN1xuICBsZXQgeTExID0gRnAucG93KHR2MiwgRUxMMl9DNCk7IC8vICAxNi4geTExID0gdHYyXmM0ICAgICAgICAjIChneDEgKiBneGReNyleKChwIC0gNSkgLyA4KVxuICB5MTEgPSBGcC5tdWwoeTExLCB0djMpOyAgICAgICAvLyAgMTcuIHkxMSA9IHkxMSAqIHR2MyAgICAgICAjIGd4MSpneGReMyooZ3gxKmd4ZF43KV4oKHAtNSkvOClcbiAgbGV0IHkxMiA9IEZwLm11bCh5MTEsIEVMTDJfQzMpOyAvLyAgMTguIHkxMiA9IHkxMSAqIGMzXG4gIHR2MiA9IEZwLnNxcih5MTEpOyAgICAgICAgICAgIC8vICAxOS4gdHYyID0geTExXjJcbiAgdHYyID0gRnAubXVsKHR2MiwgZ3hkKTsgICAgICAgLy8gIDIwLiB0djIgPSB0djIgKiBneGRcbiAgbGV0IGUxID0gRnAuZXFsKHR2MiwgZ3gxKTsgICAgLy8gIDIxLiAgZTEgPSB0djIgPT0gZ3gxXG4gIGxldCB5MSA9IEZwLmNtb3YoeTEyLCB5MTEsIGUxKTsgLy8gIDIyLiAgeTEgPSBDTU9WKHkxMiwgeTExLCBlMSkgICMgSWYgZyh4MSkgaXMgc3F1YXJlLCB0aGlzIGlzIGl0cyBzcXJ0XG4gIGxldCB4Mm4gPSBGcC5tdWwoeDFuLCB0djEpOyAgIC8vICAyMy4geDJuID0geDFuICogdHYxICAgICAgICMgeDIgPSB4Mm4gLyB4ZCA9IDIgKiB1XjIgKiB4MW4gLyB4ZFxuICBsZXQgeTIxID0gRnAubXVsKHkxMSwgdSk7ICAgICAvLyAgMjQuIHkyMSA9IHkxMSAqIHVcbiAgeTIxID0gRnAubXVsKHkyMSwgRUxMMl9DMik7ICAgLy8gIDI1LiB5MjEgPSB5MjEgKiBjMlxuICBsZXQgeTIyID0gRnAubXVsKHkyMSwgRUxMMl9DMyk7IC8vICAyNi4geTIyID0geTIxICogYzNcbiAgbGV0IGd4MiA9IEZwLm11bChneDEsIHR2MSk7ICAgLy8gIDI3LiBneDIgPSBneDEgKiB0djEgICAgICAgIyBnKHgyKSA9IGd4MiAvIGd4ZCA9IDIgKiB1XjIgKiBnKHgxKVxuICB0djIgPSBGcC5zcXIoeTIxKTsgICAgICAgICAgICAvLyAgMjguIHR2MiA9IHkyMV4yXG4gIHR2MiA9IEZwLm11bCh0djIsIGd4ZCk7ICAgICAgIC8vICAyOS4gdHYyID0gdHYyICogZ3hkXG4gIGxldCBlMiA9IEZwLmVxbCh0djIsIGd4Mik7ICAgIC8vICAzMC4gIGUyID0gdHYyID09IGd4MlxuICBsZXQgeTIgPSBGcC5jbW92KHkyMiwgeTIxLCBlMik7IC8vICAzMS4gIHkyID0gQ01PVih5MjIsIHkyMSwgZTIpICAjIElmIGcoeDIpIGlzIHNxdWFyZSwgdGhpcyBpcyBpdHMgc3FydFxuICB0djIgPSBGcC5zcXIoeTEpOyAgICAgICAgICAgICAvLyAgMzIuIHR2MiA9IHkxXjJcbiAgdHYyID0gRnAubXVsKHR2MiwgZ3hkKTsgICAgICAgLy8gIDMzLiB0djIgPSB0djIgKiBneGRcbiAgbGV0IGUzID0gRnAuZXFsKHR2MiwgZ3gxKTsgICAgLy8gIDM0LiAgZTMgPSB0djIgPT0gZ3gxXG4gIGxldCB4biA9IEZwLmNtb3YoeDJuLCB4MW4sIGUzKTsgLy8gIDM1LiAgeG4gPSBDTU9WKHgybiwgeDFuLCBlMykgICMgSWYgZTMsIHggPSB4MSwgZWxzZSB4ID0geDJcbiAgbGV0IHkgPSBGcC5jbW92KHkyLCB5MSwgZTMpOyAgLy8gIDM2LiAgIHkgPSBDTU9WKHkyLCB5MSwgZTMpICAgICMgSWYgZTMsIHkgPSB5MSwgZWxzZSB5ID0geTJcbiAgbGV0IGU0ID0gRnAuaXNPZGQhKHkpOyAgICAgICAgIC8vICAzNy4gIGU0ID0gc2duMCh5KSA9PSAxICAgICAgICAjIEZpeCBzaWduIG9mIHlcbiAgeSA9IEZwLmNtb3YoeSwgRnAubmVnKHkpLCBlMyAhPT0gZTQpOyAvLyAgMzguICAgeSA9IENNT1YoeSwgLXksIGUzIFhPUiBlNClcbiAgcmV0dXJuIHsgeE1uOiB4biwgeE1kOiB4ZCwgeU1uOiB5LCB5TWQ6IF8xbiB9OyAvLyAgMzkuIHJldHVybiAoeG4sIHhkLCB5LCAxKVxufVxuXG5jb25zdCBFTEwyX0MxX0VEV0FSRFMgPSAvKiBAX19QVVJFX18gKi8gKCgpID0+IEZwU3FydEV2ZW4oRnAsIEZwLm5lZyhCaWdJbnQoNDg2NjY0KSkpKSgpOyAvLyBzZ24wKGMxKSBNVVNUIGVxdWFsIDBcbmZ1bmN0aW9uIG1hcF90b19jdXJ2ZV9lbGxpZ2F0b3IyX2Vkd2FyZHMyNTUxOSh1OiBiaWdpbnQpIHtcbiAgY29uc3QgeyB4TW4sIHhNZCwgeU1uLCB5TWQgfSA9IG1hcF90b19jdXJ2ZV9lbGxpZ2F0b3IyX2N1cnZlMjU1MTkodSk7IC8vICAxLiAgKHhNbiwgeE1kLCB5TW4sIHlNZCkgPVxuICAvLyBtYXBfdG9fY3VydmVfZWxsaWdhdG9yMl9jdXJ2ZTI1NTE5KHUpXG4gIGxldCB4biA9IEZwLm11bCh4TW4sIHlNZCk7IC8vICAyLiAgeG4gPSB4TW4gKiB5TWRcbiAgeG4gPSBGcC5tdWwoeG4sIEVMTDJfQzFfRURXQVJEUyk7IC8vICAzLiAgeG4gPSB4biAqIGMxXG4gIGxldCB4ZCA9IEZwLm11bCh4TWQsIHlNbik7IC8vICA0LiAgeGQgPSB4TWQgKiB5TW4gICAgIyB4biAvIHhkID0gYzEgKiB4TSAvIHlNXG4gIGxldCB5biA9IEZwLnN1Yih4TW4sIHhNZCk7IC8vICA1LiAgeW4gPSB4TW4gLSB4TWRcbiAgbGV0IHlkID0gRnAuYWRkKHhNbiwgeE1kKTsgLy8gIDYuICB5ZCA9IHhNbiArIHhNZCAgICAjIChuIC8gZCAtIDEpIC8gKG4gLyBkICsgMSkgPSAobiAtIGQpIC8gKG4gKyBkKVxuICBsZXQgdHYxID0gRnAubXVsKHhkLCB5ZCk7IC8vICA3LiB0djEgPSB4ZCAqIHlkXG4gIGxldCBlID0gRnAuZXFsKHR2MSwgRnAuWkVSTyk7IC8vICA4LiAgIGUgPSB0djEgPT0gMFxuICB4biA9IEZwLmNtb3YoeG4sIEZwLlpFUk8sIGUpOyAvLyAgOS4gIHhuID0gQ01PVih4biwgMCwgZSlcbiAgeGQgPSBGcC5jbW92KHhkLCBGcC5PTkUsIGUpOyAvLyAgMTAuIHhkID0gQ01PVih4ZCwgMSwgZSlcbiAgeW4gPSBGcC5jbW92KHluLCBGcC5PTkUsIGUpOyAvLyAgMTEuIHluID0gQ01PVih5biwgMSwgZSlcbiAgeWQgPSBGcC5jbW92KHlkLCBGcC5PTkUsIGUpOyAvLyAgMTIuIHlkID0gQ01PVih5ZCwgMSwgZSlcbiAgY29uc3QgW3hkX2ludiwgeWRfaW52XSA9IEZwSW52ZXJ0QmF0Y2goRnAsIFt4ZCwgeWRdLCB0cnVlKTsgLy8gYmF0Y2ggZGl2aXNpb25cbiAgcmV0dXJuIHsgeDogRnAubXVsKHhuLCB4ZF9pbnYpLCB5OiBGcC5tdWwoeW4sIHlkX2ludikgfTsgLy8gIDEzLiByZXR1cm4gKHhuLCB4ZCwgeW4sIHlkKVxufVxuXG4vKiogSGFzaGluZyB0byBlZDI1NTE5IHBvaW50cyAvIGZpZWxkLiBSRkMgOTM4MCBtZXRob2RzLiAqL1xuZXhwb3J0IGNvbnN0IGVkMjU1MTlfaGFzaGVyOiBIMkNIYXNoZXI8YmlnaW50PiA9IC8qIEBfX1BVUkVfXyAqLyAoKCkgPT5cbiAgY3JlYXRlSGFzaGVyKFxuICAgIGVkMjU1MTkuUG9pbnQsXG4gICAgKHNjYWxhcnM6IGJpZ2ludFtdKSA9PiBtYXBfdG9fY3VydmVfZWxsaWdhdG9yMl9lZHdhcmRzMjU1MTkoc2NhbGFyc1swXSksXG4gICAge1xuICAgICAgRFNUOiAnZWR3YXJkczI1NTE5X1hNRDpTSEEtNTEyX0VMTDJfUk9fJyxcbiAgICAgIGVuY29kZURTVDogJ2Vkd2FyZHMyNTUxOV9YTUQ6U0hBLTUxMl9FTEwyX05VXycsXG4gICAgICBwOiBlZDI1NTE5X0NVUlZFX3AsXG4gICAgICBtOiAxLFxuICAgICAgazogMTI4LFxuICAgICAgZXhwYW5kOiAneG1kJyxcbiAgICAgIGhhc2g6IHNoYTUxMixcbiAgICB9XG4gICkpKCk7XG5cbi8vIFx1MjIxQSgtMSkgYWthIFx1MjIxQShhKSBha2EgMl4oKHAtMSkvNClcbmNvbnN0IFNRUlRfTTEgPSBFRDI1NTE5X1NRUlRfTTE7XG4vLyBcdTIyMUEoYWQgLSAxKVxuY29uc3QgU1FSVF9BRF9NSU5VU19PTkUgPSAvKiBAX19QVVJFX18gKi8gQmlnSW50KFxuICAnMjUwNjMwNjg5NTMzODQ2MjM0NzQxMTE0MTQxNTg3MDIxNTI3MDEyNDQ1MzE1MDI0OTI2NTY0NjAwNzkyMTA0ODI2MTA0MzA3NTAyMzUnXG4pO1xuLy8gMSAvIFx1MjIxQShhLWQpXG5jb25zdCBJTlZTUVJUX0FfTUlOVVNfRCA9IC8qIEBfX1BVUkVfXyAqLyBCaWdJbnQoXG4gICc1NDQ2OTMwNzAwODkwOTMxNjkyMDk5NTgxMzg2ODc0NTE0MTYwNTM5MzU5NzI5MjkyNzQ1NjkyMTIwNTMxMjg5NjMxMTcyMTAxNzU3OCdcbik7XG4vLyAxLWRcdTAwQjJcbmNvbnN0IE9ORV9NSU5VU19EX1NRID0gLyogQF9fUFVSRV9fICovIEJpZ0ludChcbiAgJzExNTk4NDMwMjE2Njg3Nzk4NzkxOTM3NzU1MjE4NTU1ODY2NDc5MzczNTc3NTk3MTU0MTc2NTQ0Mzk4Nzk3MjA4NzYxMTE4MDY4MzgnXG4pO1xuLy8gKGQtMSlcdTAwQjJcbmNvbnN0IERfTUlOVVNfT05FX1NRID0gLyogQF9fUFVSRV9fICovIEJpZ0ludChcbiAgJzQwNDQwODM0MzQ2MzA4NTM2ODU4MTAxMDQyNDY5MzIzMTkwODI2MjQ4Mzk5MTQ2MjM4NzA4MzUyMjQwMTMzMjIwODY1MTM3MjY1OTUyJ1xuKTtcbi8vIENhbGN1bGF0ZXMgMS9cdTIyMUEobnVtYmVyKVxuY29uc3QgaW52ZXJ0U3FydCA9IChudW1iZXI6IGJpZ2ludCkgPT4gdXZSYXRpbyhfMW4sIG51bWJlcik7XG5cbmNvbnN0IE1BWF8yNTVCID0gLyogQF9fUFVSRV9fICovIEJpZ0ludChcbiAgJzB4N2ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZidcbik7XG5jb25zdCBieXRlczI1NVRvTnVtYmVyTEUgPSAoYnl0ZXM6IFVpbnQ4QXJyYXkpID0+XG4gIGVkMjU1MTkuUG9pbnQuRnAuY3JlYXRlKGJ5dGVzVG9OdW1iZXJMRShieXRlcykgJiBNQVhfMjU1Qik7XG5cbnR5cGUgRXh0ZW5kZWRQb2ludCA9IEVkd2FyZHNQb2ludDtcblxuLyoqXG4gKiBDb21wdXRlcyBFbGxpZ2F0b3IgbWFwIGZvciBSaXN0cmV0dG8yNTUuXG4gKiBEZXNjcmliZWQgaW4gW1JGQzkzODBdKGh0dHBzOi8vd3d3LnJmYy1lZGl0b3Iub3JnL3JmYy9yZmM5MzgwI2FwcGVuZGl4LUIpIGFuZCBvblxuICogdGhlIFt3ZWJzaXRlXShodHRwczovL3Jpc3RyZXR0by5ncm91cC9mb3JtdWxhcy9lbGxpZ2F0b3IuaHRtbCkuXG4gKi9cbmZ1bmN0aW9uIGNhbGNFbGxpZ2F0b3JSaXN0cmV0dG9NYXAocjA6IGJpZ2ludCk6IEV4dGVuZGVkUG9pbnQge1xuICBjb25zdCB7IGQgfSA9IGVkMjU1MTlfQ1VSVkU7XG4gIGNvbnN0IFAgPSBlZDI1NTE5X0NVUlZFX3A7XG4gIGNvbnN0IG1vZCA9IChuOiBiaWdpbnQpID0+IEZwLmNyZWF0ZShuKTtcbiAgY29uc3QgciA9IG1vZChTUVJUX00xICogcjAgKiByMCk7IC8vIDFcbiAgY29uc3QgTnMgPSBtb2QoKHIgKyBfMW4pICogT05FX01JTlVTX0RfU1EpOyAvLyAyXG4gIGxldCBjID0gQmlnSW50KC0xKTsgLy8gM1xuICBjb25zdCBEID0gbW9kKChjIC0gZCAqIHIpICogbW9kKHIgKyBkKSk7IC8vIDRcbiAgbGV0IHsgaXNWYWxpZDogTnNfRF9pc19zcSwgdmFsdWU6IHMgfSA9IHV2UmF0aW8oTnMsIEQpOyAvLyA1XG4gIGxldCBzXyA9IG1vZChzICogcjApOyAvLyA2XG4gIGlmICghaXNOZWdhdGl2ZUxFKHNfLCBQKSkgc18gPSBtb2QoLXNfKTtcbiAgaWYgKCFOc19EX2lzX3NxKSBzID0gc187IC8vIDdcbiAgaWYgKCFOc19EX2lzX3NxKSBjID0gcjsgLy8gOFxuICBjb25zdCBOdCA9IG1vZChjICogKHIgLSBfMW4pICogRF9NSU5VU19PTkVfU1EgLSBEKTsgLy8gOVxuICBjb25zdCBzMiA9IHMgKiBzO1xuICBjb25zdCBXMCA9IG1vZCgocyArIHMpICogRCk7IC8vIDEwXG4gIGNvbnN0IFcxID0gbW9kKE50ICogU1FSVF9BRF9NSU5VU19PTkUpOyAvLyAxMVxuICBjb25zdCBXMiA9IG1vZChfMW4gLSBzMik7IC8vIDEyXG4gIGNvbnN0IFczID0gbW9kKF8xbiArIHMyKTsgLy8gMTNcbiAgcmV0dXJuIG5ldyBlZDI1NTE5LlBvaW50KG1vZChXMCAqIFczKSwgbW9kKFcyICogVzEpLCBtb2QoVzEgKiBXMyksIG1vZChXMCAqIFcyKSk7XG59XG5cbmZ1bmN0aW9uIHJpc3RyZXR0bzI1NV9tYXAoYnl0ZXM6IFVpbnQ4QXJyYXkpOiBfUmlzdHJldHRvUG9pbnQge1xuICBhYnl0ZXMoYnl0ZXMsIDY0KTtcbiAgY29uc3QgcjEgPSBieXRlczI1NVRvTnVtYmVyTEUoYnl0ZXMuc3ViYXJyYXkoMCwgMzIpKTtcbiAgY29uc3QgUjEgPSBjYWxjRWxsaWdhdG9yUmlzdHJldHRvTWFwKHIxKTtcbiAgY29uc3QgcjIgPSBieXRlczI1NVRvTnVtYmVyTEUoYnl0ZXMuc3ViYXJyYXkoMzIsIDY0KSk7XG4gIGNvbnN0IFIyID0gY2FsY0VsbGlnYXRvclJpc3RyZXR0b01hcChyMik7XG4gIHJldHVybiBuZXcgX1Jpc3RyZXR0b1BvaW50KFIxLmFkZChSMikpO1xufVxuXG4vKipcbiAqIFdyYXBwZXIgb3ZlciBFZHdhcmRzIFBvaW50IGZvciByaXN0cmV0dG8yNTUuXG4gKlxuICogRWFjaCBlZDI1NTE5L0V4dGVuZGVkUG9pbnQgaGFzIDggZGlmZmVyZW50IGVxdWl2YWxlbnQgcG9pbnRzLiBUaGlzIGNhbiBiZVxuICogYSBzb3VyY2Ugb2YgYnVncyBmb3IgcHJvdG9jb2xzIGxpa2UgcmluZyBzaWduYXR1cmVzLiBSaXN0cmV0dG8gd2FzIGNyZWF0ZWQgdG8gc29sdmUgdGhpcy5cbiAqIFJpc3RyZXR0byBwb2ludCBvcGVyYXRlcyBpbiBYOlk6WjpUIGV4dGVuZGVkIGNvb3JkaW5hdGVzIGxpa2UgRXh0ZW5kZWRQb2ludCxcbiAqIGJ1dCBpdCBzaG91bGQgd29yayBpbiBpdHMgb3duIG5hbWVzcGFjZTogZG8gbm90IGNvbWJpbmUgdGhvc2UgdHdvLlxuICogU2VlIFtSRkM5NDk2XShodHRwczovL3d3dy5yZmMtZWRpdG9yLm9yZy9yZmMvcmZjOTQ5NikuXG4gKi9cbmNsYXNzIF9SaXN0cmV0dG9Qb2ludCBleHRlbmRzIFByaW1lRWR3YXJkc1BvaW50PF9SaXN0cmV0dG9Qb2ludD4ge1xuICAvLyBEbyBOT1QgY2hhbmdlIHN5bnRheDogdGhlIGZvbGxvd2luZyBneW1uYXN0aWNzIGlzIGRvbmUsXG4gIC8vIGJlY2F1c2UgdHlwZXNjcmlwdCBzdHJpcHMgY29tbWVudHMsIHdoaWNoIG1ha2VzIGJ1bmRsZXJzIGRpc2FibGUgdHJlZS1zaGFraW5nLlxuICAvLyBwcmV0dGllci1pZ25vcmVcbiAgc3RhdGljIEJBU0U6IF9SaXN0cmV0dG9Qb2ludCA9XG4gICAgLyogQF9fUFVSRV9fICovICgoKSA9PiBuZXcgX1Jpc3RyZXR0b1BvaW50KGVkMjU1MTkuUG9pbnQuQkFTRSkpKCk7XG4gIC8vIHByZXR0aWVyLWlnbm9yZVxuICBzdGF0aWMgWkVSTzogX1Jpc3RyZXR0b1BvaW50ID1cbiAgICAvKiBAX19QVVJFX18gKi8gKCgpID0+IG5ldyBfUmlzdHJldHRvUG9pbnQoZWQyNTUxOS5Qb2ludC5aRVJPKSkoKTtcbiAgLy8gcHJldHRpZXItaWdub3JlXG4gIHN0YXRpYyBGcDogSUZpZWxkPGJpZ2ludD4gPVxuICAgIC8qIEBfX1BVUkVfXyAqLyAoKCkgPT4gRnApKCk7XG4gIC8vIHByZXR0aWVyLWlnbm9yZVxuICBzdGF0aWMgRm46IElGaWVsZDxiaWdpbnQ+ID1cbiAgICAvKiBAX19QVVJFX18gKi8gKCgpID0+IEZuKSgpO1xuXG4gIGNvbnN0cnVjdG9yKGVwOiBFeHRlbmRlZFBvaW50KSB7XG4gICAgc3VwZXIoZXApO1xuICB9XG5cbiAgc3RhdGljIGZyb21BZmZpbmUoYXA6IEFmZmluZVBvaW50PGJpZ2ludD4pOiBfUmlzdHJldHRvUG9pbnQge1xuICAgIHJldHVybiBuZXcgX1Jpc3RyZXR0b1BvaW50KGVkMjU1MTkuUG9pbnQuZnJvbUFmZmluZShhcCkpO1xuICB9XG5cbiAgcHJvdGVjdGVkIGFzc2VydFNhbWUob3RoZXI6IF9SaXN0cmV0dG9Qb2ludCk6IHZvaWQge1xuICAgIGlmICghKG90aGVyIGluc3RhbmNlb2YgX1Jpc3RyZXR0b1BvaW50KSkgdGhyb3cgbmV3IEVycm9yKCdSaXN0cmV0dG9Qb2ludCBleHBlY3RlZCcpO1xuICB9XG5cbiAgcHJvdGVjdGVkIGluaXQoZXA6IEVkd2FyZHNQb2ludCk6IF9SaXN0cmV0dG9Qb2ludCB7XG4gICAgcmV0dXJuIG5ldyBfUmlzdHJldHRvUG9pbnQoZXApO1xuICB9XG5cbiAgLyoqIEBkZXByZWNhdGVkIHVzZSBgaW1wb3J0IHsgcmlzdHJldHRvMjU1X2hhc2hlciB9IGZyb20gJ0Bub2JsZS9jdXJ2ZXMvZWQyNTUxOS5qcyc7YCAqL1xuICBzdGF0aWMgaGFzaFRvQ3VydmUoaGV4OiBIZXgpOiBfUmlzdHJldHRvUG9pbnQge1xuICAgIHJldHVybiByaXN0cmV0dG8yNTVfbWFwKGVuc3VyZUJ5dGVzKCdyaXN0cmV0dG9IYXNoJywgaGV4LCA2NCkpO1xuICB9XG5cbiAgc3RhdGljIGZyb21CeXRlcyhieXRlczogVWludDhBcnJheSk6IF9SaXN0cmV0dG9Qb2ludCB7XG4gICAgYWJ5dGVzKGJ5dGVzLCAzMik7XG4gICAgY29uc3QgeyBhLCBkIH0gPSBlZDI1NTE5X0NVUlZFO1xuICAgIGNvbnN0IFAgPSBlZDI1NTE5X0NVUlZFX3A7XG4gICAgY29uc3QgbW9kID0gKG46IGJpZ2ludCkgPT4gRnAuY3JlYXRlKG4pO1xuICAgIGNvbnN0IHMgPSBieXRlczI1NVRvTnVtYmVyTEUoYnl0ZXMpO1xuICAgIC8vIDEuIENoZWNrIHRoYXQgc19ieXRlcyBpcyB0aGUgY2Fub25pY2FsIGVuY29kaW5nIG9mIGEgZmllbGQgZWxlbWVudCwgb3IgZWxzZSBhYm9ydC5cbiAgICAvLyAzLiBDaGVjayB0aGF0IHMgaXMgbm9uLW5lZ2F0aXZlLCBvciBlbHNlIGFib3J0XG4gICAgaWYgKCFlcXVhbEJ5dGVzKEZwLnRvQnl0ZXMocyksIGJ5dGVzKSB8fCBpc05lZ2F0aXZlTEUocywgUCkpXG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ2ludmFsaWQgcmlzdHJldHRvMjU1IGVuY29kaW5nIDEnKTtcbiAgICBjb25zdCBzMiA9IG1vZChzICogcyk7XG4gICAgY29uc3QgdTEgPSBtb2QoXzFuICsgYSAqIHMyKTsgLy8gNCAoYSBpcyAtMSlcbiAgICBjb25zdCB1MiA9IG1vZChfMW4gLSBhICogczIpOyAvLyA1XG4gICAgY29uc3QgdTFfMiA9IG1vZCh1MSAqIHUxKTtcbiAgICBjb25zdCB1Ml8yID0gbW9kKHUyICogdTIpO1xuICAgIGNvbnN0IHYgPSBtb2QoYSAqIGQgKiB1MV8yIC0gdTJfMik7IC8vIDZcbiAgICBjb25zdCB7IGlzVmFsaWQsIHZhbHVlOiBJIH0gPSBpbnZlcnRTcXJ0KG1vZCh2ICogdTJfMikpOyAvLyA3XG4gICAgY29uc3QgRHggPSBtb2QoSSAqIHUyKTsgLy8gOFxuICAgIGNvbnN0IER5ID0gbW9kKEkgKiBEeCAqIHYpOyAvLyA5XG4gICAgbGV0IHggPSBtb2QoKHMgKyBzKSAqIER4KTsgLy8gMTBcbiAgICBpZiAoaXNOZWdhdGl2ZUxFKHgsIFApKSB4ID0gbW9kKC14KTsgLy8gMTBcbiAgICBjb25zdCB5ID0gbW9kKHUxICogRHkpOyAvLyAxMVxuICAgIGNvbnN0IHQgPSBtb2QoeCAqIHkpOyAvLyAxMlxuICAgIGlmICghaXNWYWxpZCB8fCBpc05lZ2F0aXZlTEUodCwgUCkgfHwgeSA9PT0gXzBuKVxuICAgICAgdGhyb3cgbmV3IEVycm9yKCdpbnZhbGlkIHJpc3RyZXR0bzI1NSBlbmNvZGluZyAyJyk7XG4gICAgcmV0dXJuIG5ldyBfUmlzdHJldHRvUG9pbnQobmV3IGVkMjU1MTkuUG9pbnQoeCwgeSwgXzFuLCB0KSk7XG4gIH1cblxuICAvKipcbiAgICogQ29udmVydHMgcmlzdHJldHRvLWVuY29kZWQgc3RyaW5nIHRvIHJpc3RyZXR0byBwb2ludC5cbiAgICogRGVzY3JpYmVkIGluIFtSRkM5NDk2XShodHRwczovL3d3dy5yZmMtZWRpdG9yLm9yZy9yZmMvcmZjOTQ5NiNuYW1lLWRlY29kZSkuXG4gICAqIEBwYXJhbSBoZXggUmlzdHJldHRvLWVuY29kZWQgMzIgYnl0ZXMuIE5vdCBldmVyeSAzMi1ieXRlIHN0cmluZyBpcyB2YWxpZCByaXN0cmV0dG8gZW5jb2RpbmdcbiAgICovXG4gIHN0YXRpYyBmcm9tSGV4KGhleDogSGV4KTogX1Jpc3RyZXR0b1BvaW50IHtcbiAgICByZXR1cm4gX1Jpc3RyZXR0b1BvaW50LmZyb21CeXRlcyhlbnN1cmVCeXRlcygncmlzdHJldHRvSGV4JywgaGV4LCAzMikpO1xuICB9XG5cbiAgc3RhdGljIG1zbShwb2ludHM6IF9SaXN0cmV0dG9Qb2ludFtdLCBzY2FsYXJzOiBiaWdpbnRbXSk6IF9SaXN0cmV0dG9Qb2ludCB7XG4gICAgcmV0dXJuIHBpcHBlbmdlcihfUmlzdHJldHRvUG9pbnQsIGVkMjU1MTkuUG9pbnQuRm4sIHBvaW50cywgc2NhbGFycyk7XG4gIH1cblxuICAvKipcbiAgICogRW5jb2RlcyByaXN0cmV0dG8gcG9pbnQgdG8gVWludDhBcnJheS5cbiAgICogRGVzY3JpYmVkIGluIFtSRkM5NDk2XShodHRwczovL3d3dy5yZmMtZWRpdG9yLm9yZy9yZmMvcmZjOTQ5NiNuYW1lLWVuY29kZSkuXG4gICAqL1xuICB0b0J5dGVzKCk6IFVpbnQ4QXJyYXkge1xuICAgIGxldCB7IFgsIFksIFosIFQgfSA9IHRoaXMuZXA7XG4gICAgY29uc3QgUCA9IGVkMjU1MTlfQ1VSVkVfcDtcbiAgICBjb25zdCBtb2QgPSAobjogYmlnaW50KSA9PiBGcC5jcmVhdGUobik7XG4gICAgY29uc3QgdTEgPSBtb2QobW9kKFogKyBZKSAqIG1vZChaIC0gWSkpOyAvLyAxXG4gICAgY29uc3QgdTIgPSBtb2QoWCAqIFkpOyAvLyAyXG4gICAgLy8gU3F1YXJlIHJvb3QgYWx3YXlzIGV4aXN0c1xuICAgIGNvbnN0IHUyc3EgPSBtb2QodTIgKiB1Mik7XG4gICAgY29uc3QgeyB2YWx1ZTogaW52c3FydCB9ID0gaW52ZXJ0U3FydChtb2QodTEgKiB1MnNxKSk7IC8vIDNcbiAgICBjb25zdCBEMSA9IG1vZChpbnZzcXJ0ICogdTEpOyAvLyA0XG4gICAgY29uc3QgRDIgPSBtb2QoaW52c3FydCAqIHUyKTsgLy8gNVxuICAgIGNvbnN0IHpJbnYgPSBtb2QoRDEgKiBEMiAqIFQpOyAvLyA2XG4gICAgbGV0IEQ6IGJpZ2ludDsgLy8gN1xuICAgIGlmIChpc05lZ2F0aXZlTEUoVCAqIHpJbnYsIFApKSB7XG4gICAgICBsZXQgX3ggPSBtb2QoWSAqIFNRUlRfTTEpO1xuICAgICAgbGV0IF95ID0gbW9kKFggKiBTUVJUX00xKTtcbiAgICAgIFggPSBfeDtcbiAgICAgIFkgPSBfeTtcbiAgICAgIEQgPSBtb2QoRDEgKiBJTlZTUVJUX0FfTUlOVVNfRCk7XG4gICAgfSBlbHNlIHtcbiAgICAgIEQgPSBEMjsgLy8gOFxuICAgIH1cbiAgICBpZiAoaXNOZWdhdGl2ZUxFKFggKiB6SW52LCBQKSkgWSA9IG1vZCgtWSk7IC8vIDlcbiAgICBsZXQgcyA9IG1vZCgoWiAtIFkpICogRCk7IC8vIDEwIChjaGVjayBmb290ZXIncyBub3RlLCBubyBzcXJ0KC1hKSlcbiAgICBpZiAoaXNOZWdhdGl2ZUxFKHMsIFApKSBzID0gbW9kKC1zKTtcbiAgICByZXR1cm4gRnAudG9CeXRlcyhzKTsgLy8gMTFcbiAgfVxuXG4gIC8qKlxuICAgKiBDb21wYXJlcyB0d28gUmlzdHJldHRvIHBvaW50cy5cbiAgICogRGVzY3JpYmVkIGluIFtSRkM5NDk2XShodHRwczovL3d3dy5yZmMtZWRpdG9yLm9yZy9yZmMvcmZjOTQ5NiNuYW1lLWVxdWFscykuXG4gICAqL1xuICBlcXVhbHMob3RoZXI6IF9SaXN0cmV0dG9Qb2ludCk6IGJvb2xlYW4ge1xuICAgIHRoaXMuYXNzZXJ0U2FtZShvdGhlcik7XG4gICAgY29uc3QgeyBYOiBYMSwgWTogWTEgfSA9IHRoaXMuZXA7XG4gICAgY29uc3QgeyBYOiBYMiwgWTogWTIgfSA9IG90aGVyLmVwO1xuICAgIGNvbnN0IG1vZCA9IChuOiBiaWdpbnQpID0+IEZwLmNyZWF0ZShuKTtcbiAgICAvLyAoeDEgKiB5MiA9PSB5MSAqIHgyKSB8ICh5MSAqIHkyID09IHgxICogeDIpXG4gICAgY29uc3Qgb25lID0gbW9kKFgxICogWTIpID09PSBtb2QoWTEgKiBYMik7XG4gICAgY29uc3QgdHdvID0gbW9kKFkxICogWTIpID09PSBtb2QoWDEgKiBYMik7XG4gICAgcmV0dXJuIG9uZSB8fCB0d287XG4gIH1cblxuICBpczAoKTogYm9vbGVhbiB7XG4gICAgcmV0dXJuIHRoaXMuZXF1YWxzKF9SaXN0cmV0dG9Qb2ludC5aRVJPKTtcbiAgfVxufVxuXG5leHBvcnQgY29uc3QgcmlzdHJldHRvMjU1OiB7XG4gIFBvaW50OiB0eXBlb2YgX1Jpc3RyZXR0b1BvaW50O1xufSA9IHsgUG9pbnQ6IF9SaXN0cmV0dG9Qb2ludCB9O1xuXG4vKiogSGFzaGluZyB0byByaXN0cmV0dG8yNTUgcG9pbnRzIC8gZmllbGQuIFJGQyA5MzgwIG1ldGhvZHMuICovXG5leHBvcnQgY29uc3QgcmlzdHJldHRvMjU1X2hhc2hlcjogSDJDSGFzaGVyQmFzZTxiaWdpbnQ+ID0ge1xuICBoYXNoVG9DdXJ2ZShtc2c6IFVpbnQ4QXJyYXksIG9wdGlvbnM/OiBodGZCYXNpY09wdHMpOiBfUmlzdHJldHRvUG9pbnQge1xuICAgIGNvbnN0IERTVCA9IG9wdGlvbnM/LkRTVCB8fCAncmlzdHJldHRvMjU1X1hNRDpTSEEtNTEyX1IyNTVNQVBfUk9fJztcbiAgICBjb25zdCB4bWQgPSBleHBhbmRfbWVzc2FnZV94bWQobXNnLCBEU1QsIDY0LCBzaGE1MTIpO1xuICAgIHJldHVybiByaXN0cmV0dG8yNTVfbWFwKHhtZCk7XG4gIH0sXG4gIGhhc2hUb1NjYWxhcihtc2c6IFVpbnQ4QXJyYXksIG9wdGlvbnM6IGh0ZkJhc2ljT3B0cyA9IHsgRFNUOiBfRFNUX3NjYWxhciB9KSB7XG4gICAgY29uc3QgeG1kID0gZXhwYW5kX21lc3NhZ2VfeG1kKG1zZywgb3B0aW9ucy5EU1QsIDY0LCBzaGE1MTIpO1xuICAgIHJldHVybiBGbi5jcmVhdGUoYnl0ZXNUb051bWJlckxFKHhtZCkpO1xuICB9LFxufTtcblxuLy8gZXhwb3J0IGNvbnN0IHJpc3RyZXR0bzI1NV9vcHJmOiBPUFJGID0gY3JlYXRlT1JQRih7XG4vLyAgIG5hbWU6ICdyaXN0cmV0dG8yNTUtU0hBNTEyJyxcbi8vICAgUG9pbnQ6IFJpc3RyZXR0b1BvaW50LFxuLy8gICBoYXNoOiBzaGE1MTIsXG4vLyAgIGhhc2hUb0dyb3VwOiByaXN0cmV0dG8yNTVfaGFzaGVyLmhhc2hUb0N1cnZlLFxuLy8gICBoYXNoVG9TY2FsYXI6IHJpc3RyZXR0bzI1NV9oYXNoZXIuaGFzaFRvU2NhbGFyLFxuLy8gfSk7XG5cbi8qKlxuICogV2VpcmQgLyBib2d1cyBwb2ludHMsIHVzZWZ1bCBmb3IgZGVidWdnaW5nLlxuICogQWxsIDggZWQyNTUxOSBwb2ludHMgb2YgOC10b3JzaW9uIHN1Ymdyb3VwIGNhbiBiZSBnZW5lcmF0ZWQgZnJvbSB0aGUgcG9pbnRcbiAqIFQgPSBgMjZlODk1OGZjMmIyMjdiMDQ1YzNmNDg5ZjJlZjk4ZjBkNWRmYWMwNWQzYzYzMzM5YjEzODAyODg2ZDUzZmMwNWAuXG4gKiBcdTI3RThUXHUyN0U5ID0geyBPLCBULCAyVCwgM1QsIDRULCA1VCwgNlQsIDdUIH1cbiAqL1xuZXhwb3J0IGNvbnN0IEVEMjU1MTlfVE9SU0lPTl9TVUJHUk9VUDogc3RyaW5nW10gPSBbXG4gICcwMTAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwJyxcbiAgJ2M3MTc2YTcwM2Q0ZGQ4NGZiYTNjMGI3NjBkMTA2NzBmMmEyMDUzZmEyYzM5Y2NjNjRlYzdmZDc3OTJhYzAzN2EnLFxuICAnMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA4MCcsXG4gICcyNmU4OTU4ZmMyYjIyN2IwNDVjM2Y0ODlmMmVmOThmMGQ1ZGZhYzA1ZDNjNjMzMzliMTM4MDI4ODZkNTNmYzA1JyxcbiAgJ2VjZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmN2YnLFxuICAnMjZlODk1OGZjMmIyMjdiMDQ1YzNmNDg5ZjJlZjk4ZjBkNWRmYWMwNWQzYzYzMzM5YjEzODAyODg2ZDUzZmM4NScsXG4gICcwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwJyxcbiAgJ2M3MTc2YTcwM2Q0ZGQ4NGZiYTNjMGI3NjBkMTA2NzBmMmEyMDUzZmEyYzM5Y2NjNjRlYzdmZDc3OTJhYzAzZmEnLFxuXTtcblxuLyoqIEBkZXByZWNhdGVkIHVzZSBgZWQyNTUxOS51dGlscy50b01vbnRnb21lcnlgICovXG5leHBvcnQgZnVuY3Rpb24gZWR3YXJkc1RvTW9udGdvbWVyeVB1YihlZHdhcmRzUHViOiBIZXgpOiBVaW50OEFycmF5IHtcbiAgcmV0dXJuIGVkMjU1MTkudXRpbHMudG9Nb250Z29tZXJ5KGVuc3VyZUJ5dGVzKCdwdWInLCBlZHdhcmRzUHViKSk7XG59XG4vKiogQGRlcHJlY2F0ZWQgdXNlIGBlZDI1NTE5LnV0aWxzLnRvTW9udGdvbWVyeWAgKi9cbmV4cG9ydCBjb25zdCBlZHdhcmRzVG9Nb250Z29tZXJ5OiB0eXBlb2YgZWR3YXJkc1RvTW9udGdvbWVyeVB1YiA9IGVkd2FyZHNUb01vbnRnb21lcnlQdWI7XG5cbi8qKiBAZGVwcmVjYXRlZCB1c2UgYGVkMjU1MTkudXRpbHMudG9Nb250Z29tZXJ5U2VjcmV0YCAqL1xuZXhwb3J0IGZ1bmN0aW9uIGVkd2FyZHNUb01vbnRnb21lcnlQcml2KGVkd2FyZHNQcml2OiBVaW50OEFycmF5KTogVWludDhBcnJheSB7XG4gIHJldHVybiBlZDI1NTE5LnV0aWxzLnRvTW9udGdvbWVyeVNlY3JldChlbnN1cmVCeXRlcygncHViJywgZWR3YXJkc1ByaXYpKTtcbn1cblxuLyoqIEBkZXByZWNhdGVkIHVzZSBgcmlzdHJldHRvMjU1LlBvaW50YCAqL1xuZXhwb3J0IGNvbnN0IFJpc3RyZXR0b1BvaW50OiB0eXBlb2YgX1Jpc3RyZXR0b1BvaW50ID0gX1Jpc3RyZXR0b1BvaW50O1xuLyoqIEBkZXByZWNhdGVkIHVzZSBgaW1wb3J0IHsgZWQyNTUxOV9oYXNoZXIgfSBmcm9tICdAbm9ibGUvY3VydmVzL2VkMjU1MTkuanMnO2AgKi9cbmV4cG9ydCBjb25zdCBoYXNoVG9DdXJ2ZTogSDJDTWV0aG9kPGJpZ2ludD4gPSAvKiBAX19QVVJFX18gKi8gKCgpID0+IGVkMjU1MTlfaGFzaGVyLmhhc2hUb0N1cnZlKSgpO1xuLyoqIEBkZXByZWNhdGVkIHVzZSBgaW1wb3J0IHsgZWQyNTUxOV9oYXNoZXIgfSBmcm9tICdAbm9ibGUvY3VydmVzL2VkMjU1MTkuanMnO2AgKi9cbmV4cG9ydCBjb25zdCBlbmNvZGVUb0N1cnZlOiBIMkNNZXRob2Q8YmlnaW50PiA9IC8qIEBfX1BVUkVfXyAqLyAoKCkgPT5cbiAgZWQyNTUxOV9oYXNoZXIuZW5jb2RlVG9DdXJ2ZSkoKTtcbnR5cGUgUmlzdEhhc2hlciA9IChtc2c6IFVpbnQ4QXJyYXksIG9wdGlvbnM6IGh0ZkJhc2ljT3B0cykgPT4gX1Jpc3RyZXR0b1BvaW50O1xuLyoqIEBkZXByZWNhdGVkIHVzZSBgaW1wb3J0IHsgcmlzdHJldHRvMjU1X2hhc2hlciB9IGZyb20gJ0Bub2JsZS9jdXJ2ZXMvZWQyNTUxOS5qcyc7YCAqL1xuZXhwb3J0IGNvbnN0IGhhc2hUb1Jpc3RyZXR0bzI1NTogUmlzdEhhc2hlciA9IC8qIEBfX1BVUkVfXyAqLyAoKCkgPT5cbiAgcmlzdHJldHRvMjU1X2hhc2hlci5oYXNoVG9DdXJ2ZSBhcyBSaXN0SGFzaGVyKSgpO1xuLyoqIEBkZXByZWNhdGVkIHVzZSBgaW1wb3J0IHsgcmlzdHJldHRvMjU1X2hhc2hlciB9IGZyb20gJ0Bub2JsZS9jdXJ2ZXMvZWQyNTUxOS5qcyc7YCAqL1xuZXhwb3J0IGNvbnN0IGhhc2hfdG9fcmlzdHJldHRvMjU1OiBSaXN0SGFzaGVyID0gLyogQF9fUFVSRV9fICovICgoKSA9PlxuICByaXN0cmV0dG8yNTVfaGFzaGVyLmhhc2hUb0N1cnZlIGFzIFJpc3RIYXNoZXIpKCk7XG4iLCAiLy8gWDI1NTE5IGtleSBkZXJpdmF0aW9uIHVzaW5nIEBub2JsZS9jdXJ2ZXNcblxuaW1wb3J0IHsgeDI1NTE5IH0gZnJvbSAnQG5vYmxlL2N1cnZlcy9lZDI1NTE5JztcbmltcG9ydCB0eXBlIHsgRGVyaXZlZEtleXMgfSBmcm9tICcuL3R5cGVzLmpzJztcblxuLyoqXG4gKiBEZXJpdmUgYW4gWDI1NTE5IGtleXBhaXIgZnJvbSBhIDMyLWJ5dGUgUFJGIG91dHB1dC5cbiAqIFRoZSBQUkYgb3V0cHV0IGlzIHVzZWQgZGlyZWN0bHkgYXMgdGhlIHByaXZhdGUga2V5LlxuICpcbiAqIElNUE9SVEFOVDogVGhlIHJldHVybmVkIHByaXZhdGVLZXkgbXVzdCBiZSB6ZXJvLWZpbGxlZCBhZnRlciB1c2UuXG4gKlxuICogQHBhcmFtIHByZk91dHB1dCAzMi1ieXRlIGRldGVybWluaXN0aWMgUFJGIG91dHB1dFxuICogQHJldHVybnMgRGVyaXZlZEtleXMgY29udGFpbmluZyBwcml2YXRlS2V5IGFuZCBwdWJsaWNLZXlcbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGRlcml2ZUtleXBhaXJGcm9tUHJmKHByZk91dHB1dDogVWludDhBcnJheSk6IERlcml2ZWRLZXlzIHtcbiAgICBpZiAocHJmT3V0cHV0Lmxlbmd0aCAhPT0gMzIpIHtcbiAgICAgICAgdGhyb3cgbmV3IEVycm9yKGBQUkYgb3V0cHV0IG11c3QgYmUgMzIgYnl0ZXMsIGdvdCAke3ByZk91dHB1dC5sZW5ndGh9YCk7XG4gICAgfVxuXG4gICAgLy8gVXNlIFBSRiBvdXRwdXQgZGlyZWN0bHkgYXMgWDI1NTE5IHByaXZhdGUga2V5XG4gICAgLy8gWDI1NTE5IHdpbGwgYXBwbHkgY2xhbXBpbmcgaW50ZXJuYWxseVxuICAgIGNvbnN0IHByaXZhdGVLZXkgPSBuZXcgVWludDhBcnJheShwcmZPdXRwdXQpO1xuICAgIGNvbnN0IHB1YmxpY0tleSA9IHgyNTUxOS5nZXRQdWJsaWNLZXkocHJpdmF0ZUtleSk7XG5cbiAgICByZXR1cm4ge1xuICAgICAgICBwcml2YXRlS2V5LFxuICAgICAgICBwdWJsaWNLZXlcbiAgICB9O1xufVxuXG4vKipcbiAqIENvbXB1dGUgRUNESCBzaGFyZWQgc2VjcmV0IHVzaW5nIFgyNTUxOS5cbiAqXG4gKiBAcGFyYW0gcHJpdmF0ZUtleSBPdXIgMzItYnl0ZSBwcml2YXRlIGtleVxuICogQHBhcmFtIHB1YmxpY0tleSBUaGVpciAzMi1ieXRlIHB1YmxpYyBrZXlcbiAqIEByZXR1cm5zIDMyLWJ5dGUgc2hhcmVkIHNlY3JldFxuICovXG5leHBvcnQgZnVuY3Rpb24gY29tcHV0ZVNoYXJlZFNlY3JldChcbiAgICBwcml2YXRlS2V5OiBVaW50OEFycmF5LFxuICAgIHB1YmxpY0tleTogVWludDhBcnJheVxuKTogVWludDhBcnJheSB7XG4gICAgaWYgKHByaXZhdGVLZXkubGVuZ3RoICE9PSAzMikge1xuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoYFByaXZhdGUga2V5IG11c3QgYmUgMzIgYnl0ZXMsIGdvdCAke3ByaXZhdGVLZXkubGVuZ3RofWApO1xuICAgIH1cbiAgICBpZiAocHVibGljS2V5Lmxlbmd0aCAhPT0gMzIpIHtcbiAgICAgICAgdGhyb3cgbmV3IEVycm9yKGBQdWJsaWMga2V5IG11c3QgYmUgMzIgYnl0ZXMsIGdvdCAke3B1YmxpY0tleS5sZW5ndGh9YCk7XG4gICAgfVxuXG4gICAgcmV0dXJuIHgyNTUxOS5nZXRTaGFyZWRTZWNyZXQocHJpdmF0ZUtleSwgcHVibGljS2V5KTtcbn1cblxuLyoqXG4gKiBHZW5lcmF0ZSBhIHJhbmRvbSBlcGhlbWVyYWwgWDI1NTE5IGtleXBhaXIgZm9yIEVDSUVTIGVuY3J5cHRpb24uXG4gKlxuICogQHJldHVybnMgRGVyaXZlZEtleXMgd2l0aCByYW5kb20gZXBoZW1lcmFsIGtleXNcbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGdlbmVyYXRlRXBoZW1lcmFsS2V5cGFpcigpOiBEZXJpdmVkS2V5cyB7XG4gICAgY29uc3QgcHJpdmF0ZUtleSA9IHgyNTUxOS51dGlscy5yYW5kb21Qcml2YXRlS2V5KCk7XG4gICAgY29uc3QgcHVibGljS2V5ID0geDI1NTE5LmdldFB1YmxpY0tleShwcml2YXRlS2V5KTtcblxuICAgIHJldHVybiB7XG4gICAgICAgIHByaXZhdGVLZXksXG4gICAgICAgIHB1YmxpY0tleVxuICAgIH07XG59XG4iLCAiLyoqXG4gKiBVdGlsaXRpZXMgZm9yIGhleCwgYnl0ZXMsIENTUFJORy5cbiAqIEBtb2R1bGVcbiAqL1xuLyohIG5vYmxlLWNpcGhlcnMgLSBNSVQgTGljZW5zZSAoYykgMjAyMyBQYXVsIE1pbGxlciAocGF1bG1pbGxyLmNvbSkgKi9cblxuLyoqIENoZWNrcyBpZiBzb21ldGhpbmcgaXMgVWludDhBcnJheS4gQmUgY2FyZWZ1bDogbm9kZWpzIEJ1ZmZlciB3aWxsIHJldHVybiB0cnVlLiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGlzQnl0ZXMoYTogdW5rbm93bik6IGEgaXMgVWludDhBcnJheSB7XG4gIHJldHVybiBhIGluc3RhbmNlb2YgVWludDhBcnJheSB8fCAoQXJyYXlCdWZmZXIuaXNWaWV3KGEpICYmIGEuY29uc3RydWN0b3IubmFtZSA9PT0gJ1VpbnQ4QXJyYXknKTtcbn1cblxuLyoqIEFzc2VydHMgc29tZXRoaW5nIGlzIGJvb2xlYW4uICovXG5leHBvcnQgZnVuY3Rpb24gYWJvb2woYjogYm9vbGVhbik6IHZvaWQge1xuICBpZiAodHlwZW9mIGIgIT09ICdib29sZWFuJykgdGhyb3cgbmV3IEVycm9yKGBib29sZWFuIGV4cGVjdGVkLCBub3QgJHtifWApO1xufVxuXG4vKiogQXNzZXJ0cyBzb21ldGhpbmcgaXMgcG9zaXRpdmUgaW50ZWdlci4gKi9cbmV4cG9ydCBmdW5jdGlvbiBhbnVtYmVyKG46IG51bWJlcik6IHZvaWQge1xuICBpZiAoIU51bWJlci5pc1NhZmVJbnRlZ2VyKG4pIHx8IG4gPCAwKSB0aHJvdyBuZXcgRXJyb3IoJ3Bvc2l0aXZlIGludGVnZXIgZXhwZWN0ZWQsIGdvdCAnICsgbik7XG59XG5cbi8qKiBBc3NlcnRzIHNvbWV0aGluZyBpcyBVaW50OEFycmF5LiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGFieXRlcyhiOiBVaW50OEFycmF5IHwgdW5kZWZpbmVkLCAuLi5sZW5ndGhzOiBudW1iZXJbXSk6IHZvaWQge1xuICBpZiAoIWlzQnl0ZXMoYikpIHRocm93IG5ldyBFcnJvcignVWludDhBcnJheSBleHBlY3RlZCcpO1xuICBpZiAobGVuZ3Rocy5sZW5ndGggPiAwICYmICFsZW5ndGhzLmluY2x1ZGVzKGIubGVuZ3RoKSlcbiAgICB0aHJvdyBuZXcgRXJyb3IoJ1VpbnQ4QXJyYXkgZXhwZWN0ZWQgb2YgbGVuZ3RoICcgKyBsZW5ndGhzICsgJywgZ290IGxlbmd0aD0nICsgYi5sZW5ndGgpO1xufVxuXG4vKipcbiAqIEFzc2VydHMgc29tZXRoaW5nIGlzIGhhc2hcbiAqIFRPRE86IHJlbW92ZVxuICogQGRlcHJlY2F0ZWRcbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGFoYXNoKGg6IElIYXNoKTogdm9pZCB7XG4gIGlmICh0eXBlb2YgaCAhPT0gJ2Z1bmN0aW9uJyB8fCB0eXBlb2YgaC5jcmVhdGUgIT09ICdmdW5jdGlvbicpXG4gICAgdGhyb3cgbmV3IEVycm9yKCdIYXNoIHNob3VsZCBiZSB3cmFwcGVkIGJ5IHV0aWxzLmNyZWF0ZUhhc2hlcicpO1xuICBhbnVtYmVyKGgub3V0cHV0TGVuKTtcbiAgYW51bWJlcihoLmJsb2NrTGVuKTtcbn1cblxuLyoqIEFzc2VydHMgYSBoYXNoIGluc3RhbmNlIGhhcyBub3QgYmVlbiBkZXN0cm95ZWQgLyBmaW5pc2hlZCAqL1xuZXhwb3J0IGZ1bmN0aW9uIGFleGlzdHMoaW5zdGFuY2U6IGFueSwgY2hlY2tGaW5pc2hlZCA9IHRydWUpOiB2b2lkIHtcbiAgaWYgKGluc3RhbmNlLmRlc3Ryb3llZCkgdGhyb3cgbmV3IEVycm9yKCdIYXNoIGluc3RhbmNlIGhhcyBiZWVuIGRlc3Ryb3llZCcpO1xuICBpZiAoY2hlY2tGaW5pc2hlZCAmJiBpbnN0YW5jZS5maW5pc2hlZCkgdGhyb3cgbmV3IEVycm9yKCdIYXNoI2RpZ2VzdCgpIGhhcyBhbHJlYWR5IGJlZW4gY2FsbGVkJyk7XG59XG5cbi8qKiBBc3NlcnRzIG91dHB1dCBpcyBwcm9wZXJseS1zaXplZCBieXRlIGFycmF5ICovXG5leHBvcnQgZnVuY3Rpb24gYW91dHB1dChvdXQ6IGFueSwgaW5zdGFuY2U6IGFueSk6IHZvaWQge1xuICBhYnl0ZXMob3V0KTtcbiAgY29uc3QgbWluID0gaW5zdGFuY2Uub3V0cHV0TGVuO1xuICBpZiAob3V0Lmxlbmd0aCA8IG1pbikge1xuICAgIHRocm93IG5ldyBFcnJvcignZGlnZXN0SW50bygpIGV4cGVjdHMgb3V0cHV0IGJ1ZmZlciBvZiBsZW5ndGggYXQgbGVhc3QgJyArIG1pbik7XG4gIH1cbn1cblxuZXhwb3J0IHR5cGUgSUhhc2ggPSB7XG4gIChkYXRhOiBzdHJpbmcgfCBVaW50OEFycmF5KTogVWludDhBcnJheTtcbiAgYmxvY2tMZW46IG51bWJlcjtcbiAgb3V0cHV0TGVuOiBudW1iZXI7XG4gIGNyZWF0ZTogYW55O1xufTtcblxuLyoqIEdlbmVyaWMgdHlwZSBlbmNvbXBhc3NpbmcgOC8xNi8zMi1ieXRlIGFycmF5cyAtIGJ1dCBub3QgNjQtYnl0ZS4gKi9cbi8vIHByZXR0aWVyLWlnbm9yZVxuZXhwb3J0IHR5cGUgVHlwZWRBcnJheSA9IEludDhBcnJheSB8IFVpbnQ4Q2xhbXBlZEFycmF5IHwgVWludDhBcnJheSB8XG4gIFVpbnQxNkFycmF5IHwgSW50MTZBcnJheSB8IFVpbnQzMkFycmF5IHwgSW50MzJBcnJheTtcblxuLyoqIENhc3QgdTggLyB1MTYgLyB1MzIgdG8gdTguICovXG5leHBvcnQgZnVuY3Rpb24gdTgoYXJyOiBUeXBlZEFycmF5KTogVWludDhBcnJheSB7XG4gIHJldHVybiBuZXcgVWludDhBcnJheShhcnIuYnVmZmVyLCBhcnIuYnl0ZU9mZnNldCwgYXJyLmJ5dGVMZW5ndGgpO1xufVxuXG4vKiogQ2FzdCB1OCAvIHUxNiAvIHUzMiB0byB1MzIuICovXG5leHBvcnQgZnVuY3Rpb24gdTMyKGFycjogVHlwZWRBcnJheSk6IFVpbnQzMkFycmF5IHtcbiAgcmV0dXJuIG5ldyBVaW50MzJBcnJheShhcnIuYnVmZmVyLCBhcnIuYnl0ZU9mZnNldCwgTWF0aC5mbG9vcihhcnIuYnl0ZUxlbmd0aCAvIDQpKTtcbn1cblxuLyoqIFplcm9pemUgYSBieXRlIGFycmF5LiBXYXJuaW5nOiBKUyBwcm92aWRlcyBubyBndWFyYW50ZWVzLiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGNsZWFuKC4uLmFycmF5czogVHlwZWRBcnJheVtdKTogdm9pZCB7XG4gIGZvciAobGV0IGkgPSAwOyBpIDwgYXJyYXlzLmxlbmd0aDsgaSsrKSB7XG4gICAgYXJyYXlzW2ldLmZpbGwoMCk7XG4gIH1cbn1cblxuLyoqIENyZWF0ZSBEYXRhVmlldyBvZiBhbiBhcnJheSBmb3IgZWFzeSBieXRlLWxldmVsIG1hbmlwdWxhdGlvbi4gKi9cbmV4cG9ydCBmdW5jdGlvbiBjcmVhdGVWaWV3KGFycjogVHlwZWRBcnJheSk6IERhdGFWaWV3IHtcbiAgcmV0dXJuIG5ldyBEYXRhVmlldyhhcnIuYnVmZmVyLCBhcnIuYnl0ZU9mZnNldCwgYXJyLmJ5dGVMZW5ndGgpO1xufVxuXG4vKiogSXMgY3VycmVudCBwbGF0Zm9ybSBsaXR0bGUtZW5kaWFuPyBNb3N0IGFyZS4gQmlnLUVuZGlhbiBwbGF0Zm9ybTogSUJNICovXG5leHBvcnQgY29uc3QgaXNMRTogYm9vbGVhbiA9IC8qIEBfX1BVUkVfXyAqLyAoKCkgPT5cbiAgbmV3IFVpbnQ4QXJyYXkobmV3IFVpbnQzMkFycmF5KFsweDExMjIzMzQ0XSkuYnVmZmVyKVswXSA9PT0gMHg0NCkoKTtcblxuLy8gQnVpbHQtaW4gaGV4IGNvbnZlcnNpb24gaHR0cHM6Ly9jYW5pdXNlLmNvbS9tZG4tamF2YXNjcmlwdF9idWlsdGluc191aW50OGFycmF5X2Zyb21oZXhcbmNvbnN0IGhhc0hleEJ1aWx0aW46IGJvb2xlYW4gPSAvKiBAX19QVVJFX18gKi8gKCgpID0+XG4gIC8vIEB0cy1pZ25vcmVcbiAgdHlwZW9mIFVpbnQ4QXJyYXkuZnJvbShbXSkudG9IZXggPT09ICdmdW5jdGlvbicgJiYgdHlwZW9mIFVpbnQ4QXJyYXkuZnJvbUhleCA9PT0gJ2Z1bmN0aW9uJykoKTtcblxuLy8gQXJyYXkgd2hlcmUgaW5kZXggMHhmMCAoMjQwKSBpcyBtYXBwZWQgdG8gc3RyaW5nICdmMCdcbmNvbnN0IGhleGVzID0gLyogQF9fUFVSRV9fICovIEFycmF5LmZyb20oeyBsZW5ndGg6IDI1NiB9LCAoXywgaSkgPT5cbiAgaS50b1N0cmluZygxNikucGFkU3RhcnQoMiwgJzAnKVxuKTtcblxuLyoqXG4gKiBDb252ZXJ0IGJ5dGUgYXJyYXkgdG8gaGV4IHN0cmluZy4gVXNlcyBidWlsdC1pbiBmdW5jdGlvbiwgd2hlbiBhdmFpbGFibGUuXG4gKiBAZXhhbXBsZSBieXRlc1RvSGV4KFVpbnQ4QXJyYXkuZnJvbShbMHhjYSwgMHhmZSwgMHgwMSwgMHgyM10pKSAvLyAnY2FmZTAxMjMnXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBieXRlc1RvSGV4KGJ5dGVzOiBVaW50OEFycmF5KTogc3RyaW5nIHtcbiAgYWJ5dGVzKGJ5dGVzKTtcbiAgLy8gQHRzLWlnbm9yZVxuICBpZiAoaGFzSGV4QnVpbHRpbikgcmV0dXJuIGJ5dGVzLnRvSGV4KCk7XG4gIC8vIHByZS1jYWNoaW5nIGltcHJvdmVzIHRoZSBzcGVlZCA2eFxuICBsZXQgaGV4ID0gJyc7XG4gIGZvciAobGV0IGkgPSAwOyBpIDwgYnl0ZXMubGVuZ3RoOyBpKyspIHtcbiAgICBoZXggKz0gaGV4ZXNbYnl0ZXNbaV1dO1xuICB9XG4gIHJldHVybiBoZXg7XG59XG5cbi8vIFdlIHVzZSBvcHRpbWl6ZWQgdGVjaG5pcXVlIHRvIGNvbnZlcnQgaGV4IHN0cmluZyB0byBieXRlIGFycmF5XG5jb25zdCBhc2NpaXMgPSB7IF8wOiA0OCwgXzk6IDU3LCBBOiA2NSwgRjogNzAsIGE6IDk3LCBmOiAxMDIgfSBhcyBjb25zdDtcbmZ1bmN0aW9uIGFzY2lpVG9CYXNlMTYoY2g6IG51bWJlcik6IG51bWJlciB8IHVuZGVmaW5lZCB7XG4gIGlmIChjaCA+PSBhc2NpaXMuXzAgJiYgY2ggPD0gYXNjaWlzLl85KSByZXR1cm4gY2ggLSBhc2NpaXMuXzA7IC8vICcyJyA9PiA1MC00OFxuICBpZiAoY2ggPj0gYXNjaWlzLkEgJiYgY2ggPD0gYXNjaWlzLkYpIHJldHVybiBjaCAtIChhc2NpaXMuQSAtIDEwKTsgLy8gJ0InID0+IDY2LSg2NS0xMClcbiAgaWYgKGNoID49IGFzY2lpcy5hICYmIGNoIDw9IGFzY2lpcy5mKSByZXR1cm4gY2ggLSAoYXNjaWlzLmEgLSAxMCk7IC8vICdiJyA9PiA5OC0oOTctMTApXG4gIHJldHVybjtcbn1cblxuLyoqXG4gKiBDb252ZXJ0IGhleCBzdHJpbmcgdG8gYnl0ZSBhcnJheS4gVXNlcyBidWlsdC1pbiBmdW5jdGlvbiwgd2hlbiBhdmFpbGFibGUuXG4gKiBAZXhhbXBsZSBoZXhUb0J5dGVzKCdjYWZlMDEyMycpIC8vIFVpbnQ4QXJyYXkuZnJvbShbMHhjYSwgMHhmZSwgMHgwMSwgMHgyM10pXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBoZXhUb0J5dGVzKGhleDogc3RyaW5nKTogVWludDhBcnJheSB7XG4gIGlmICh0eXBlb2YgaGV4ICE9PSAnc3RyaW5nJykgdGhyb3cgbmV3IEVycm9yKCdoZXggc3RyaW5nIGV4cGVjdGVkLCBnb3QgJyArIHR5cGVvZiBoZXgpO1xuICAvLyBAdHMtaWdub3JlXG4gIGlmIChoYXNIZXhCdWlsdGluKSByZXR1cm4gVWludDhBcnJheS5mcm9tSGV4KGhleCk7XG4gIGNvbnN0IGhsID0gaGV4Lmxlbmd0aDtcbiAgY29uc3QgYWwgPSBobCAvIDI7XG4gIGlmIChobCAlIDIpIHRocm93IG5ldyBFcnJvcignaGV4IHN0cmluZyBleHBlY3RlZCwgZ290IHVucGFkZGVkIGhleCBvZiBsZW5ndGggJyArIGhsKTtcbiAgY29uc3QgYXJyYXkgPSBuZXcgVWludDhBcnJheShhbCk7XG4gIGZvciAobGV0IGFpID0gMCwgaGkgPSAwOyBhaSA8IGFsOyBhaSsrLCBoaSArPSAyKSB7XG4gICAgY29uc3QgbjEgPSBhc2NpaVRvQmFzZTE2KGhleC5jaGFyQ29kZUF0KGhpKSk7XG4gICAgY29uc3QgbjIgPSBhc2NpaVRvQmFzZTE2KGhleC5jaGFyQ29kZUF0KGhpICsgMSkpO1xuICAgIGlmIChuMSA9PT0gdW5kZWZpbmVkIHx8IG4yID09PSB1bmRlZmluZWQpIHtcbiAgICAgIGNvbnN0IGNoYXIgPSBoZXhbaGldICsgaGV4W2hpICsgMV07XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ2hleCBzdHJpbmcgZXhwZWN0ZWQsIGdvdCBub24taGV4IGNoYXJhY3RlciBcIicgKyBjaGFyICsgJ1wiIGF0IGluZGV4ICcgKyBoaSk7XG4gICAgfVxuICAgIGFycmF5W2FpXSA9IG4xICogMTYgKyBuMjsgLy8gbXVsdGlwbHkgZmlyc3Qgb2N0ZXQsIGUuZy4gJ2EzJyA9PiAxMCoxNiszID0+IDE2MCArIDMgPT4gMTYzXG4gIH1cbiAgcmV0dXJuIGFycmF5O1xufVxuXG4vLyBVc2VkIGluIG1pY3JvXG5leHBvcnQgZnVuY3Rpb24gaGV4VG9OdW1iZXIoaGV4OiBzdHJpbmcpOiBiaWdpbnQge1xuICBpZiAodHlwZW9mIGhleCAhPT0gJ3N0cmluZycpIHRocm93IG5ldyBFcnJvcignaGV4IHN0cmluZyBleHBlY3RlZCwgZ290ICcgKyB0eXBlb2YgaGV4KTtcbiAgcmV0dXJuIEJpZ0ludChoZXggPT09ICcnID8gJzAnIDogJzB4JyArIGhleCk7IC8vIEJpZyBFbmRpYW5cbn1cblxuLy8gVXNlZCBpbiBmZjFcbi8vIEJFOiBCaWcgRW5kaWFuLCBMRTogTGl0dGxlIEVuZGlhblxuZXhwb3J0IGZ1bmN0aW9uIGJ5dGVzVG9OdW1iZXJCRShieXRlczogVWludDhBcnJheSk6IGJpZ2ludCB7XG4gIHJldHVybiBoZXhUb051bWJlcihieXRlc1RvSGV4KGJ5dGVzKSk7XG59XG5cbi8vIFVzZWQgaW4gbWljcm8sIGZmMVxuZXhwb3J0IGZ1bmN0aW9uIG51bWJlclRvQnl0ZXNCRShuOiBudW1iZXIgfCBiaWdpbnQsIGxlbjogbnVtYmVyKTogVWludDhBcnJheSB7XG4gIHJldHVybiBoZXhUb0J5dGVzKG4udG9TdHJpbmcoMTYpLnBhZFN0YXJ0KGxlbiAqIDIsICcwJykpO1xufVxuXG4vLyBUT0RPOiByZW1vdmVcbi8vIFRoZXJlIGlzIG5vIHNldEltbWVkaWF0ZSBpbiBicm93c2VyIGFuZCBzZXRUaW1lb3V0IGlzIHNsb3cuXG4vLyBjYWxsIG9mIGFzeW5jIGZuIHdpbGwgcmV0dXJuIFByb21pc2UsIHdoaWNoIHdpbGwgYmUgZnVsbGZpbGVkIG9ubHkgb25cbi8vIG5leHQgc2NoZWR1bGVyIHF1ZXVlIHByb2Nlc3Npbmcgc3RlcCBhbmQgdGhpcyBpcyBleGFjdGx5IHdoYXQgd2UgbmVlZC5cbmV4cG9ydCBjb25zdCBuZXh0VGljayA9IGFzeW5jICgpOiBQcm9taXNlPHZvaWQ+ID0+IHt9O1xuXG4vLyBHbG9iYWwgc3ltYm9scywgYnV0IHRzIGRvZXNuJ3Qgc2VlIHRoZW06IGh0dHBzOi8vZ2l0aHViLmNvbS9taWNyb3NvZnQvVHlwZVNjcmlwdC9pc3N1ZXMvMzE1MzVcbmRlY2xhcmUgY29uc3QgVGV4dEVuY29kZXI6IGFueTtcbmRlY2xhcmUgY29uc3QgVGV4dERlY29kZXI6IGFueTtcblxuLyoqXG4gKiBDb252ZXJ0cyBzdHJpbmcgdG8gYnl0ZXMgdXNpbmcgVVRGOCBlbmNvZGluZy5cbiAqIEBleGFtcGxlIHV0ZjhUb0J5dGVzKCdhYmMnKSAvLyBuZXcgVWludDhBcnJheShbOTcsIDk4LCA5OV0pXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiB1dGY4VG9CeXRlcyhzdHI6IHN0cmluZyk6IFVpbnQ4QXJyYXkge1xuICBpZiAodHlwZW9mIHN0ciAhPT0gJ3N0cmluZycpIHRocm93IG5ldyBFcnJvcignc3RyaW5nIGV4cGVjdGVkJyk7XG4gIHJldHVybiBuZXcgVWludDhBcnJheShuZXcgVGV4dEVuY29kZXIoKS5lbmNvZGUoc3RyKSk7IC8vIGh0dHBzOi8vYnVnemlsLmxhLzE2ODE4MDlcbn1cblxuLyoqXG4gKiBDb252ZXJ0cyBieXRlcyB0byBzdHJpbmcgdXNpbmcgVVRGOCBlbmNvZGluZy5cbiAqIEBleGFtcGxlIGJ5dGVzVG9VdGY4KG5ldyBVaW50OEFycmF5KFs5NywgOTgsIDk5XSkpIC8vICdhYmMnXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBieXRlc1RvVXRmOChieXRlczogVWludDhBcnJheSk6IHN0cmluZyB7XG4gIHJldHVybiBuZXcgVGV4dERlY29kZXIoKS5kZWNvZGUoYnl0ZXMpO1xufVxuXG4vLyBUT0RPOiByZW1vdmVcbmV4cG9ydCB0eXBlIElucHV0ID0gVWludDhBcnJheSB8IHN0cmluZztcbi8qKlxuICogTm9ybWFsaXplcyAobm9uLWhleCkgc3RyaW5nIG9yIFVpbnQ4QXJyYXkgdG8gVWludDhBcnJheS5cbiAqIFdhcm5pbmc6IHdoZW4gVWludDhBcnJheSBpcyBwYXNzZWQsIGl0IHdvdWxkIE5PVCBnZXQgY29waWVkLlxuICogS2VlcCBpbiBtaW5kIGZvciBmdXR1cmUgbXV0YWJsZSBvcGVyYXRpb25zLlxuICovXG5leHBvcnQgZnVuY3Rpb24gdG9CeXRlcyhkYXRhOiBzdHJpbmcgfCBVaW50OEFycmF5KTogVWludDhBcnJheSB7XG4gIGlmICh0eXBlb2YgZGF0YSA9PT0gJ3N0cmluZycpIGRhdGEgPSB1dGY4VG9CeXRlcyhkYXRhKTtcbiAgZWxzZSBpZiAoaXNCeXRlcyhkYXRhKSkgZGF0YSA9IGNvcHlCeXRlcyhkYXRhKTtcbiAgZWxzZSB0aHJvdyBuZXcgRXJyb3IoJ1VpbnQ4QXJyYXkgZXhwZWN0ZWQsIGdvdCAnICsgdHlwZW9mIGRhdGEpO1xuICByZXR1cm4gZGF0YTtcbn1cblxuLyoqXG4gKiBDaGVja3MgaWYgdHdvIFU4QSB1c2Ugc2FtZSB1bmRlcmx5aW5nIGJ1ZmZlciBhbmQgb3ZlcmxhcHMuXG4gKiBUaGlzIGlzIGludmFsaWQgYW5kIGNhbiBjb3JydXB0IGRhdGEuXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBvdmVybGFwQnl0ZXMoYTogVWludDhBcnJheSwgYjogVWludDhBcnJheSk6IGJvb2xlYW4ge1xuICByZXR1cm4gKFxuICAgIGEuYnVmZmVyID09PSBiLmJ1ZmZlciAmJiAvLyBiZXN0IHdlIGNhbiBkbywgbWF5IGZhaWwgd2l0aCBhbiBvYnNjdXJlIFByb3h5XG4gICAgYS5ieXRlT2Zmc2V0IDwgYi5ieXRlT2Zmc2V0ICsgYi5ieXRlTGVuZ3RoICYmIC8vIGEgc3RhcnRzIGJlZm9yZSBiIGVuZFxuICAgIGIuYnl0ZU9mZnNldCA8IGEuYnl0ZU9mZnNldCArIGEuYnl0ZUxlbmd0aCAvLyBiIHN0YXJ0cyBiZWZvcmUgYSBlbmRcbiAgKTtcbn1cblxuLyoqXG4gKiBJZiBpbnB1dCBhbmQgb3V0cHV0IG92ZXJsYXAgYW5kIGlucHV0IHN0YXJ0cyBiZWZvcmUgb3V0cHV0LCB3ZSB3aWxsIG92ZXJ3cml0ZSBlbmQgb2YgaW5wdXQgYmVmb3JlXG4gKiB3ZSBzdGFydCBwcm9jZXNzaW5nIGl0LCBzbyB0aGlzIGlzIG5vdCBzdXBwb3J0ZWQgZm9yIG1vc3QgY2lwaGVycyAoZXhjZXB0IGNoYWNoYS9zYWxzZSwgd2hpY2ggZGVzaWduZWQgd2l0aCB0aGlzKVxuICovXG5leHBvcnQgZnVuY3Rpb24gY29tcGxleE92ZXJsYXBCeXRlcyhpbnB1dDogVWludDhBcnJheSwgb3V0cHV0OiBVaW50OEFycmF5KTogdm9pZCB7XG4gIC8vIFRoaXMgaXMgdmVyeSBjdXJzZWQuIEl0IHdvcmtzIHNvbWVob3csIGJ1dCBJJ20gY29tcGxldGVseSB1bnN1cmUsXG4gIC8vIHJlYXNvbmluZyBhYm91dCBvdmVybGFwcGluZyBhbGlnbmVkIHdpbmRvd3MgaXMgdmVyeSBoYXJkLlxuICBpZiAob3ZlcmxhcEJ5dGVzKGlucHV0LCBvdXRwdXQpICYmIGlucHV0LmJ5dGVPZmZzZXQgPCBvdXRwdXQuYnl0ZU9mZnNldClcbiAgICB0aHJvdyBuZXcgRXJyb3IoJ2NvbXBsZXggb3ZlcmxhcCBvZiBpbnB1dCBhbmQgb3V0cHV0IGlzIG5vdCBzdXBwb3J0ZWQnKTtcbn1cblxuLyoqXG4gKiBDb3BpZXMgc2V2ZXJhbCBVaW50OEFycmF5cyBpbnRvIG9uZS5cbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGNvbmNhdEJ5dGVzKC4uLmFycmF5czogVWludDhBcnJheVtdKTogVWludDhBcnJheSB7XG4gIGxldCBzdW0gPSAwO1xuICBmb3IgKGxldCBpID0gMDsgaSA8IGFycmF5cy5sZW5ndGg7IGkrKykge1xuICAgIGNvbnN0IGEgPSBhcnJheXNbaV07XG4gICAgYWJ5dGVzKGEpO1xuICAgIHN1bSArPSBhLmxlbmd0aDtcbiAgfVxuICBjb25zdCByZXMgPSBuZXcgVWludDhBcnJheShzdW0pO1xuICBmb3IgKGxldCBpID0gMCwgcGFkID0gMDsgaSA8IGFycmF5cy5sZW5ndGg7IGkrKykge1xuICAgIGNvbnN0IGEgPSBhcnJheXNbaV07XG4gICAgcmVzLnNldChhLCBwYWQpO1xuICAgIHBhZCArPSBhLmxlbmd0aDtcbiAgfVxuICByZXR1cm4gcmVzO1xufVxuXG4vLyBVc2VkIGluIEFSWCBvbmx5XG50eXBlIEVtcHR5T2JqID0ge307XG5leHBvcnQgZnVuY3Rpb24gY2hlY2tPcHRzPFQxIGV4dGVuZHMgRW1wdHlPYmosIFQyIGV4dGVuZHMgRW1wdHlPYmo+KFxuICBkZWZhdWx0czogVDEsXG4gIG9wdHM6IFQyXG4pOiBUMSAmIFQyIHtcbiAgaWYgKG9wdHMgPT0gbnVsbCB8fCB0eXBlb2Ygb3B0cyAhPT0gJ29iamVjdCcpIHRocm93IG5ldyBFcnJvcignb3B0aW9ucyBtdXN0IGJlIGRlZmluZWQnKTtcbiAgY29uc3QgbWVyZ2VkID0gT2JqZWN0LmFzc2lnbihkZWZhdWx0cywgb3B0cyk7XG4gIHJldHVybiBtZXJnZWQgYXMgVDEgJiBUMjtcbn1cblxuLyoqIENvbXBhcmVzIDIgdWludDhhcnJheS1zIGluIGtpbmRhIGNvbnN0YW50IHRpbWUuICovXG5leHBvcnQgZnVuY3Rpb24gZXF1YWxCeXRlcyhhOiBVaW50OEFycmF5LCBiOiBVaW50OEFycmF5KTogYm9vbGVhbiB7XG4gIGlmIChhLmxlbmd0aCAhPT0gYi5sZW5ndGgpIHJldHVybiBmYWxzZTtcbiAgbGV0IGRpZmYgPSAwO1xuICBmb3IgKGxldCBpID0gMDsgaSA8IGEubGVuZ3RoOyBpKyspIGRpZmYgfD0gYVtpXSBeIGJbaV07XG4gIHJldHVybiBkaWZmID09PSAwO1xufVxuXG4vLyBUT0RPOiByZW1vdmVcbi8qKiBGb3IgcnVudGltZSBjaGVjayBpZiBjbGFzcyBpbXBsZW1lbnRzIGludGVyZmFjZS4gKi9cbmV4cG9ydCBhYnN0cmFjdCBjbGFzcyBIYXNoPFQgZXh0ZW5kcyBIYXNoPFQ+PiB7XG4gIGFic3RyYWN0IGJsb2NrTGVuOiBudW1iZXI7IC8vIEJ5dGVzIHBlciBibG9ja1xuICBhYnN0cmFjdCBvdXRwdXRMZW46IG51bWJlcjsgLy8gQnl0ZXMgaW4gb3V0cHV0XG4gIGFic3RyYWN0IHVwZGF0ZShidWY6IHN0cmluZyB8IFVpbnQ4QXJyYXkpOiB0aGlzO1xuICAvLyBXcml0ZXMgZGlnZXN0IGludG8gYnVmXG4gIGFic3RyYWN0IGRpZ2VzdEludG8oYnVmOiBVaW50OEFycmF5KTogdm9pZDtcbiAgYWJzdHJhY3QgZGlnZXN0KCk6IFVpbnQ4QXJyYXk7XG4gIC8qKlxuICAgKiBSZXNldHMgaW50ZXJuYWwgc3RhdGUuIE1ha2VzIEhhc2ggaW5zdGFuY2UgdW51c2FibGUuXG4gICAqIFJlc2V0IGlzIGltcG9zc2libGUgZm9yIGtleWVkIGhhc2hlcyBpZiBrZXkgaXMgY29uc3VtZWQgaW50byBzdGF0ZS4gSWYgZGlnZXN0IGlzIG5vdCBjb25zdW1lZFxuICAgKiBieSB1c2VyLCB0aGV5IHdpbGwgbmVlZCB0byBtYW51YWxseSBjYWxsIGBkZXN0cm95KClgIHdoZW4gemVyb2luZyBpcyBuZWNlc3NhcnkuXG4gICAqL1xuICBhYnN0cmFjdCBkZXN0cm95KCk6IHZvaWQ7XG59XG5cbi8vIFRoaXMgd2lsbCBhbGxvdyB0byByZS11c2Ugd2l0aCBjb21wb3NhYmxlIHRoaW5ncyBsaWtlIHBhY2tlZCAmIGJhc2UgZW5jb2RlcnNcbi8vIEFsc28sIHdlIHByb2JhYmx5IGNhbiBtYWtlIHRhZ3MgY29tcG9zYWJsZVxuXG4vKiogU3luYyBjaXBoZXI6IHRha2VzIGJ5dGUgYXJyYXkgYW5kIHJldHVybnMgYnl0ZSBhcnJheS4gKi9cbmV4cG9ydCB0eXBlIENpcGhlciA9IHtcbiAgZW5jcnlwdChwbGFpbnRleHQ6IFVpbnQ4QXJyYXkpOiBVaW50OEFycmF5O1xuICBkZWNyeXB0KGNpcGhlcnRleHQ6IFVpbnQ4QXJyYXkpOiBVaW50OEFycmF5O1xufTtcblxuLyoqIEFzeW5jIGNpcGhlciBlLmcuIGZyb20gYnVpbHQtaW4gV2ViQ3J5cHRvLiAqL1xuZXhwb3J0IHR5cGUgQXN5bmNDaXBoZXIgPSB7XG4gIGVuY3J5cHQocGxhaW50ZXh0OiBVaW50OEFycmF5KTogUHJvbWlzZTxVaW50OEFycmF5PjtcbiAgZGVjcnlwdChjaXBoZXJ0ZXh0OiBVaW50OEFycmF5KTogUHJvbWlzZTxVaW50OEFycmF5Pjtcbn07XG5cbi8qKiBDaXBoZXIgd2l0aCBgb3V0cHV0YCBhcmd1bWVudCB3aGljaCBjYW4gb3B0aW1pemUgYnkgZG9pbmcgMSBsZXNzIGFsbG9jYXRpb24uICovXG5leHBvcnQgdHlwZSBDaXBoZXJXaXRoT3V0cHV0ID0gQ2lwaGVyICYge1xuICBlbmNyeXB0KHBsYWludGV4dDogVWludDhBcnJheSwgb3V0cHV0PzogVWludDhBcnJheSk6IFVpbnQ4QXJyYXk7XG4gIGRlY3J5cHQoY2lwaGVydGV4dDogVWludDhBcnJheSwgb3V0cHV0PzogVWludDhBcnJheSk6IFVpbnQ4QXJyYXk7XG59O1xuXG4vKipcbiAqIFBhcmFtcyBhcmUgb3V0c2lkZSBvZiByZXR1cm4gdHlwZSwgc28gaXQgaXMgYWNjZXNzaWJsZSBiZWZvcmUgY2FsbGluZyBjb25zdHJ1Y3Rvci5cbiAqIElmIGZ1bmN0aW9uIHN1cHBvcnQgbXVsdGlwbGUgbm9uY2VMZW5ndGgncywgd2UgcmV0dXJuIHRoZSBiZXN0IG9uZS5cbiAqL1xuZXhwb3J0IHR5cGUgQ2lwaGVyUGFyYW1zID0ge1xuICBibG9ja1NpemU6IG51bWJlcjtcbiAgbm9uY2VMZW5ndGg/OiBudW1iZXI7XG4gIHRhZ0xlbmd0aD86IG51bWJlcjtcbiAgdmFyU2l6ZU5vbmNlPzogYm9vbGVhbjtcbn07XG4vKiogQVJYIGNpcGhlciwgbGlrZSBzYWxzYSBvciBjaGFjaGEuICovXG5leHBvcnQgdHlwZSBBUlhDaXBoZXIgPSAoKFxuICBrZXk6IFVpbnQ4QXJyYXksXG4gIG5vbmNlOiBVaW50OEFycmF5LFxuICBBQUQ/OiBVaW50OEFycmF5XG4pID0+IENpcGhlcldpdGhPdXRwdXQpICYge1xuICBibG9ja1NpemU6IG51bWJlcjtcbiAgbm9uY2VMZW5ndGg6IG51bWJlcjtcbiAgdGFnTGVuZ3RoOiBudW1iZXI7XG59O1xuZXhwb3J0IHR5cGUgQ2lwaGVyQ29uczxUIGV4dGVuZHMgYW55W10+ID0gKGtleTogVWludDhBcnJheSwgLi4uYXJnczogVCkgPT4gQ2lwaGVyO1xuLyoqXG4gKiBXcmFwcyBhIGNpcGhlcjogdmFsaWRhdGVzIGFyZ3MsIGVuc3VyZXMgZW5jcnlwdCgpIGNhbiBvbmx5IGJlIGNhbGxlZCBvbmNlLlxuICogQF9fTk9fU0lERV9FRkZFQ1RTX19cbiAqL1xuZXhwb3J0IGNvbnN0IHdyYXBDaXBoZXIgPSA8QyBleHRlbmRzIENpcGhlckNvbnM8YW55PiwgUCBleHRlbmRzIENpcGhlclBhcmFtcz4oXG4gIHBhcmFtczogUCxcbiAgY29uc3RydWN0b3I6IENcbik6IEMgJiBQID0+IHtcbiAgZnVuY3Rpb24gd3JhcHBlZENpcGhlcihrZXk6IFVpbnQ4QXJyYXksIC4uLmFyZ3M6IGFueVtdKTogQ2lwaGVyV2l0aE91dHB1dCB7XG4gICAgLy8gVmFsaWRhdGUga2V5XG4gICAgYWJ5dGVzKGtleSk7XG5cbiAgICAvLyBCaWctRW5kaWFuIGhhcmR3YXJlIGlzIHJhcmUuIEp1c3QgaW4gY2FzZSBzb21lb25lIHN0aWxsIGRlY2lkZXMgdG8gcnVuIGNpcGhlcnM6XG4gICAgaWYgKCFpc0xFKSB0aHJvdyBuZXcgRXJyb3IoJ05vbiBsaXR0bGUtZW5kaWFuIGhhcmR3YXJlIGlzIG5vdCB5ZXQgc3VwcG9ydGVkJyk7XG5cbiAgICAvLyBWYWxpZGF0ZSBub25jZSBpZiBub25jZUxlbmd0aCBpcyBwcmVzZW50XG4gICAgaWYgKHBhcmFtcy5ub25jZUxlbmd0aCAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICBjb25zdCBub25jZSA9IGFyZ3NbMF07XG4gICAgICBpZiAoIW5vbmNlKSB0aHJvdyBuZXcgRXJyb3IoJ25vbmNlIC8gaXYgcmVxdWlyZWQnKTtcbiAgICAgIGlmIChwYXJhbXMudmFyU2l6ZU5vbmNlKSBhYnl0ZXMobm9uY2UpO1xuICAgICAgZWxzZSBhYnl0ZXMobm9uY2UsIHBhcmFtcy5ub25jZUxlbmd0aCk7XG4gICAgfVxuXG4gICAgLy8gVmFsaWRhdGUgQUFEIGlmIHRhZ0xlbmd0aCBwcmVzZW50XG4gICAgY29uc3QgdGFnbCA9IHBhcmFtcy50YWdMZW5ndGg7XG4gICAgaWYgKHRhZ2wgJiYgYXJnc1sxXSAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICBhYnl0ZXMoYXJnc1sxXSk7XG4gICAgfVxuXG4gICAgY29uc3QgY2lwaGVyID0gY29uc3RydWN0b3Ioa2V5LCAuLi5hcmdzKTtcbiAgICBjb25zdCBjaGVja091dHB1dCA9IChmbkxlbmd0aDogbnVtYmVyLCBvdXRwdXQ/OiBVaW50OEFycmF5KSA9PiB7XG4gICAgICBpZiAob3V0cHV0ICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgaWYgKGZuTGVuZ3RoICE9PSAyKSB0aHJvdyBuZXcgRXJyb3IoJ2NpcGhlciBvdXRwdXQgbm90IHN1cHBvcnRlZCcpO1xuICAgICAgICBhYnl0ZXMob3V0cHV0KTtcbiAgICAgIH1cbiAgICB9O1xuICAgIC8vIENyZWF0ZSB3cmFwcGVkIGNpcGhlciB3aXRoIHZhbGlkYXRpb24gYW5kIHNpbmdsZS11c2UgZW5jcnlwdGlvblxuICAgIGxldCBjYWxsZWQgPSBmYWxzZTtcbiAgICBjb25zdCB3ckNpcGhlciA9IHtcbiAgICAgIGVuY3J5cHQoZGF0YTogVWludDhBcnJheSwgb3V0cHV0PzogVWludDhBcnJheSkge1xuICAgICAgICBpZiAoY2FsbGVkKSB0aHJvdyBuZXcgRXJyb3IoJ2Nhbm5vdCBlbmNyeXB0KCkgdHdpY2Ugd2l0aCBzYW1lIGtleSArIG5vbmNlJyk7XG4gICAgICAgIGNhbGxlZCA9IHRydWU7XG4gICAgICAgIGFieXRlcyhkYXRhKTtcbiAgICAgICAgY2hlY2tPdXRwdXQoY2lwaGVyLmVuY3J5cHQubGVuZ3RoLCBvdXRwdXQpO1xuICAgICAgICByZXR1cm4gKGNpcGhlciBhcyBDaXBoZXJXaXRoT3V0cHV0KS5lbmNyeXB0KGRhdGEsIG91dHB1dCk7XG4gICAgICB9LFxuICAgICAgZGVjcnlwdChkYXRhOiBVaW50OEFycmF5LCBvdXRwdXQ/OiBVaW50OEFycmF5KSB7XG4gICAgICAgIGFieXRlcyhkYXRhKTtcbiAgICAgICAgaWYgKHRhZ2wgJiYgZGF0YS5sZW5ndGggPCB0YWdsKVxuICAgICAgICAgIHRocm93IG5ldyBFcnJvcignaW52YWxpZCBjaXBoZXJ0ZXh0IGxlbmd0aDogc21hbGxlciB0aGFuIHRhZ0xlbmd0aD0nICsgdGFnbCk7XG4gICAgICAgIGNoZWNrT3V0cHV0KGNpcGhlci5kZWNyeXB0Lmxlbmd0aCwgb3V0cHV0KTtcbiAgICAgICAgcmV0dXJuIChjaXBoZXIgYXMgQ2lwaGVyV2l0aE91dHB1dCkuZGVjcnlwdChkYXRhLCBvdXRwdXQpO1xuICAgICAgfSxcbiAgICB9O1xuXG4gICAgcmV0dXJuIHdyQ2lwaGVyO1xuICB9XG5cbiAgT2JqZWN0LmFzc2lnbih3cmFwcGVkQ2lwaGVyLCBwYXJhbXMpO1xuICByZXR1cm4gd3JhcHBlZENpcGhlciBhcyBDICYgUDtcbn07XG5cbi8qKiBSZXByZXNlbnRzIHNhbHNhIC8gY2hhY2hhIHN0cmVhbS4gKi9cbmV4cG9ydCB0eXBlIFhvclN0cmVhbSA9IChcbiAga2V5OiBVaW50OEFycmF5LFxuICBub25jZTogVWludDhBcnJheSxcbiAgZGF0YTogVWludDhBcnJheSxcbiAgb3V0cHV0PzogVWludDhBcnJheSxcbiAgY291bnRlcj86IG51bWJlclxuKSA9PiBVaW50OEFycmF5O1xuXG4vKipcbiAqIEJ5IGRlZmF1bHQsIHJldHVybnMgdThhIG9mIGxlbmd0aC5cbiAqIFdoZW4gb3V0IGlzIGF2YWlsYWJsZSwgaXQgY2hlY2tzIGl0IGZvciB2YWxpZGl0eSBhbmQgdXNlcyBpdC5cbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGdldE91dHB1dChcbiAgZXhwZWN0ZWRMZW5ndGg6IG51bWJlcixcbiAgb3V0PzogVWludDhBcnJheSxcbiAgb25seUFsaWduZWQgPSB0cnVlXG4pOiBVaW50OEFycmF5IHtcbiAgaWYgKG91dCA9PT0gdW5kZWZpbmVkKSByZXR1cm4gbmV3IFVpbnQ4QXJyYXkoZXhwZWN0ZWRMZW5ndGgpO1xuICBpZiAob3V0Lmxlbmd0aCAhPT0gZXhwZWN0ZWRMZW5ndGgpXG4gICAgdGhyb3cgbmV3IEVycm9yKCdpbnZhbGlkIG91dHB1dCBsZW5ndGgsIGV4cGVjdGVkICcgKyBleHBlY3RlZExlbmd0aCArICcsIGdvdDogJyArIG91dC5sZW5ndGgpO1xuICBpZiAob25seUFsaWduZWQgJiYgIWlzQWxpZ25lZDMyKG91dCkpIHRocm93IG5ldyBFcnJvcignaW52YWxpZCBvdXRwdXQsIG11c3QgYmUgYWxpZ25lZCcpO1xuICByZXR1cm4gb3V0O1xufVxuXG4vKiogUG9seWZpbGwgZm9yIFNhZmFyaSAxNC4gKi9cbmV4cG9ydCBmdW5jdGlvbiBzZXRCaWdVaW50NjQoXG4gIHZpZXc6IERhdGFWaWV3LFxuICBieXRlT2Zmc2V0OiBudW1iZXIsXG4gIHZhbHVlOiBiaWdpbnQsXG4gIGlzTEU6IGJvb2xlYW5cbik6IHZvaWQge1xuICBpZiAodHlwZW9mIHZpZXcuc2V0QmlnVWludDY0ID09PSAnZnVuY3Rpb24nKSByZXR1cm4gdmlldy5zZXRCaWdVaW50NjQoYnl0ZU9mZnNldCwgdmFsdWUsIGlzTEUpO1xuICBjb25zdCBfMzJuID0gQmlnSW50KDMyKTtcbiAgY29uc3QgX3UzMl9tYXggPSBCaWdJbnQoMHhmZmZmZmZmZik7XG4gIGNvbnN0IHdoID0gTnVtYmVyKCh2YWx1ZSA+PiBfMzJuKSAmIF91MzJfbWF4KTtcbiAgY29uc3Qgd2wgPSBOdW1iZXIodmFsdWUgJiBfdTMyX21heCk7XG4gIGNvbnN0IGggPSBpc0xFID8gNCA6IDA7XG4gIGNvbnN0IGwgPSBpc0xFID8gMCA6IDQ7XG4gIHZpZXcuc2V0VWludDMyKGJ5dGVPZmZzZXQgKyBoLCB3aCwgaXNMRSk7XG4gIHZpZXcuc2V0VWludDMyKGJ5dGVPZmZzZXQgKyBsLCB3bCwgaXNMRSk7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiB1NjRMZW5ndGhzKGRhdGFMZW5ndGg6IG51bWJlciwgYWFkTGVuZ3RoOiBudW1iZXIsIGlzTEU6IGJvb2xlYW4pOiBVaW50OEFycmF5IHtcbiAgYWJvb2woaXNMRSk7XG4gIGNvbnN0IG51bSA9IG5ldyBVaW50OEFycmF5KDE2KTtcbiAgY29uc3QgdmlldyA9IGNyZWF0ZVZpZXcobnVtKTtcbiAgc2V0QmlnVWludDY0KHZpZXcsIDAsIEJpZ0ludChhYWRMZW5ndGgpLCBpc0xFKTtcbiAgc2V0QmlnVWludDY0KHZpZXcsIDgsIEJpZ0ludChkYXRhTGVuZ3RoKSwgaXNMRSk7XG4gIHJldHVybiBudW07XG59XG5cbi8vIElzIGJ5dGUgYXJyYXkgYWxpZ25lZCB0byA0IGJ5dGUgb2Zmc2V0ICh1MzIpP1xuZXhwb3J0IGZ1bmN0aW9uIGlzQWxpZ25lZDMyKGJ5dGVzOiBVaW50OEFycmF5KTogYm9vbGVhbiB7XG4gIHJldHVybiBieXRlcy5ieXRlT2Zmc2V0ICUgNCA9PT0gMDtcbn1cblxuLy8gY29weSBieXRlcyB0byBuZXcgdThhIChhbGlnbmVkKS4gQmVjYXVzZSBCdWZmZXIuc2xpY2UgaXMgYnJva2VuLlxuZXhwb3J0IGZ1bmN0aW9uIGNvcHlCeXRlcyhieXRlczogVWludDhBcnJheSk6IFVpbnQ4QXJyYXkge1xuICByZXR1cm4gVWludDhBcnJheS5mcm9tKGJ5dGVzKTtcbn1cbiIsICIvKipcbiAqIEJhc2ljIHV0aWxzIGZvciBBUlggKGFkZC1yb3RhdGUteG9yKSBzYWxzYSBhbmQgY2hhY2hhIGNpcGhlcnMuXG5cblJGQzg0MzkgcmVxdWlyZXMgbXVsdGktc3RlcCBjaXBoZXIgc3RyZWFtLCB3aGVyZVxuYXV0aEtleSBzdGFydHMgd2l0aCBjb3VudGVyOiAwLCBhY3R1YWwgbXNnIHdpdGggY291bnRlcjogMS5cblxuRm9yIHRoaXMsIHdlIG5lZWQgYSB3YXkgdG8gcmUtdXNlIG5vbmNlIC8gY291bnRlcjpcblxuICAgIGNvbnN0IGNvdW50ZXIgPSBuZXcgVWludDhBcnJheSg0KTtcbiAgICBjaGFjaGEoLi4uLCBjb3VudGVyLCAuLi4pOyAvLyBjb3VudGVyIGlzIG5vdyAxXG4gICAgY2hhY2hhKC4uLiwgY291bnRlciwgLi4uKTsgLy8gY291bnRlciBpcyBub3cgMlxuXG5UaGlzIGlzIGNvbXBsaWNhdGVkOlxuXG4tIDMyLWJpdCBjb3VudGVycyBhcmUgZW5vdWdoLCBubyBuZWVkIGZvciA2NC1iaXQ6IG1heCBBcnJheUJ1ZmZlciBzaXplIGluIEpTIGlzIDRHQlxuLSBPcmlnaW5hbCBwYXBlcnMgZG9uJ3QgYWxsb3cgbXV0YXRpbmcgY291bnRlcnNcbi0gQ291bnRlciBvdmVyZmxvdyBpcyB1bmRlZmluZWQgW14xXVxuLSBJZGVhIEE6IGFsbG93IHByb3ZpZGluZyAobm9uY2UgfCBjb3VudGVyKSBpbnN0ZWFkIG9mIGp1c3Qgbm9uY2UsIHJlLXVzZSBpdFxuLSBDYXZlYXQ6IENhbm5vdCBiZSByZS11c2VkIHRocm91Z2ggYWxsIGNhc2VzOlxuLSAqIGNoYWNoYSBoYXMgKGNvdW50ZXIgfCBub25jZSlcbi0gKiB4Y2hhY2hhIGhhcyAobm9uY2UxNiB8IGNvdW50ZXIgfCBub25jZTE2KVxuLSBJZGVhIEI6IHNlcGFyYXRlIG5vbmNlIC8gY291bnRlciBhbmQgcHJvdmlkZSBzZXBhcmF0ZSBBUEkgZm9yIGNvdW50ZXIgcmUtdXNlXG4tIENhdmVhdDogdGhlcmUgYXJlIGRpZmZlcmVudCBjb3VudGVyIHNpemVzIGRlcGVuZGluZyBvbiBhbiBhbGdvcml0aG0uXG4tIHNhbHNhICYgY2hhY2hhIGFsc28gZGlmZmVyIGluIHN0cnVjdHVyZXMgb2Yga2V5ICYgc2lnbWE6XG4gIHNhbHNhMjA6ICAgICAgc1swXSB8IGsoNCkgfCBzWzFdIHwgbm9uY2UoMikgfCBjdHIoMikgfCBzWzJdIHwgayg0KSB8IHNbM11cbiAgY2hhY2hhOiAgICAgICBzKDQpIHwgayg4KSB8IGN0cigxKSB8IG5vbmNlKDMpXG4gIGNoYWNoYTIwb3JpZzogcyg0KSB8IGsoOCkgfCBjdHIoMikgfCBub25jZSgyKVxuLSBJZGVhIEM6IGhlbHBlciBtZXRob2Qgc3VjaCBhcyBgc2V0U2Fsc2FTdGF0ZShrZXksIG5vbmNlLCBzaWdtYSwgZGF0YSlgXG4tIENhdmVhdDogd2UgY2FuJ3QgcmUtdXNlIGNvdW50ZXIgYXJyYXlcblxueGNoYWNoYSBbXjJdIHVzZXMgdGhlIHN1YmtleSBhbmQgcmVtYWluaW5nIDggYnl0ZSBub25jZSB3aXRoIENoYUNoYTIwIGFzIG5vcm1hbFxuKHByZWZpeGVkIGJ5IDQgTlVMIGJ5dGVzLCBzaW5jZSBbUkZDODQzOV0gc3BlY2lmaWVzIGEgMTItYnl0ZSBub25jZSkuXG5cblteMV06IGh0dHBzOi8vbWFpbGFyY2hpdmUuaWV0Zi5vcmcvYXJjaC9tc2cvY2ZyZy9nc09uVEp6Y2JnRzZPcUQ4U2MwR081YVJfdFUvXG5bXjJdOiBodHRwczovL2RhdGF0cmFja2VyLmlldGYub3JnL2RvYy9odG1sL2RyYWZ0LWlydGYtY2ZyZy14Y2hhY2hhI2FwcGVuZGl4LUEuMlxuXG4gKiBAbW9kdWxlXG4gKi9cbi8vIHByZXR0aWVyLWlnbm9yZVxuaW1wb3J0IHtcbiAgdHlwZSBYb3JTdHJlYW0sIGFib29sLCBhYnl0ZXMsIGFudW1iZXIsIGNoZWNrT3B0cywgY2xlYW4sIGNvcHlCeXRlcywgdTMyXG59IGZyb20gJy4vdXRpbHMudHMnO1xuXG4vLyBXZSBjYW4ndCBtYWtlIHRvcC1sZXZlbCB2YXIgZGVwZW5kIG9uIHV0aWxzLnV0ZjhUb0J5dGVzXG4vLyBiZWNhdXNlIGl0J3Mgbm90IHByZXNlbnQgaW4gYWxsIGVudnMuIENyZWF0aW5nIGEgc2ltaWxhciBmbiBoZXJlXG5jb25zdCBfdXRmOFRvQnl0ZXMgPSAoc3RyOiBzdHJpbmcpID0+IFVpbnQ4QXJyYXkuZnJvbShzdHIuc3BsaXQoJycpLm1hcCgoYykgPT4gYy5jaGFyQ29kZUF0KDApKSk7XG5jb25zdCBzaWdtYTE2ID0gX3V0ZjhUb0J5dGVzKCdleHBhbmQgMTYtYnl0ZSBrJyk7XG5jb25zdCBzaWdtYTMyID0gX3V0ZjhUb0J5dGVzKCdleHBhbmQgMzItYnl0ZSBrJyk7XG5jb25zdCBzaWdtYTE2XzMyID0gdTMyKHNpZ21hMTYpO1xuY29uc3Qgc2lnbWEzMl8zMiA9IHUzMihzaWdtYTMyKTtcblxuZXhwb3J0IGZ1bmN0aW9uIHJvdGwoYTogbnVtYmVyLCBiOiBudW1iZXIpOiBudW1iZXIge1xuICByZXR1cm4gKGEgPDwgYikgfCAoYSA+Pj4gKDMyIC0gYikpO1xufVxuXG4vKiogQ2lwaGVycyBtdXN0IHVzZSB1MzIgZm9yIGVmZmljaWVuY3kuICovXG5leHBvcnQgdHlwZSBDaXBoZXJDb3JlRm4gPSAoXG4gIHNpZ21hOiBVaW50MzJBcnJheSxcbiAga2V5OiBVaW50MzJBcnJheSxcbiAgbm9uY2U6IFVpbnQzMkFycmF5LFxuICBvdXRwdXQ6IFVpbnQzMkFycmF5LFxuICBjb3VudGVyOiBudW1iZXIsXG4gIHJvdW5kcz86IG51bWJlclxuKSA9PiB2b2lkO1xuXG4vKiogTWV0aG9kIHdoaWNoIGV4dGVuZHMga2V5ICsgc2hvcnQgbm9uY2UgaW50byBsYXJnZXIgbm9uY2UgLyBkaWZmIGtleS4gKi9cbmV4cG9ydCB0eXBlIEV4dGVuZE5vbmNlRm4gPSAoXG4gIHNpZ21hOiBVaW50MzJBcnJheSxcbiAga2V5OiBVaW50MzJBcnJheSxcbiAgaW5wdXQ6IFVpbnQzMkFycmF5LFxuICBvdXRwdXQ6IFVpbnQzMkFycmF5XG4pID0+IHZvaWQ7XG5cbi8qKiBBUlggY2lwaGVyIG9wdGlvbnMuXG4gKiAqIGBhbGxvd1Nob3J0S2V5c2AgZm9yIDE2LWJ5dGUga2V5c1xuICogKiBgY291bnRlckxlbmd0aGAgaW4gYnl0ZXNcbiAqICogYGNvdW50ZXJSaWdodGA6IHJpZ2h0OiBgbm9uY2V8Y291bnRlcmA7IGxlZnQ6IGBjb3VudGVyfG5vbmNlYFxuICogKi9cbmV4cG9ydCB0eXBlIENpcGhlck9wdHMgPSB7XG4gIGFsbG93U2hvcnRLZXlzPzogYm9vbGVhbjsgLy8gT3JpZ2luYWwgc2Fsc2EgLyBjaGFjaGEgYWxsb3cgMTYtYnl0ZSBrZXlzXG4gIGV4dGVuZE5vbmNlRm4/OiBFeHRlbmROb25jZUZuO1xuICBjb3VudGVyTGVuZ3RoPzogbnVtYmVyO1xuICBjb3VudGVyUmlnaHQ/OiBib29sZWFuO1xuICByb3VuZHM/OiBudW1iZXI7XG59O1xuXG4vLyBJcyBieXRlIGFycmF5IGFsaWduZWQgdG8gNCBieXRlIG9mZnNldCAodTMyKT9cbmZ1bmN0aW9uIGlzQWxpZ25lZDMyKGI6IFVpbnQ4QXJyYXkpIHtcbiAgcmV0dXJuIGIuYnl0ZU9mZnNldCAlIDQgPT09IDA7XG59XG5cbi8vIFNhbHNhIGFuZCBDaGFjaGEgYmxvY2sgbGVuZ3RoIGlzIGFsd2F5cyA1MTItYml0XG5jb25zdCBCTE9DS19MRU4gPSA2NDtcbmNvbnN0IEJMT0NLX0xFTjMyID0gMTY7XG5cbi8vIG5ldyBVaW50MzJBcnJheShbMioqMzJdKSAgIC8vID0+IFVpbnQzMkFycmF5KDEpIFsgMCBdXG4vLyBuZXcgVWludDMyQXJyYXkoWzIqKjMyLTFdKSAvLyA9PiBVaW50MzJBcnJheSgxKSBbIDQyOTQ5NjcyOTUgXVxuY29uc3QgTUFYX0NPVU5URVIgPSAyICoqIDMyIC0gMTtcblxuY29uc3QgVTMyX0VNUFRZID0gbmV3IFVpbnQzMkFycmF5KCk7XG5mdW5jdGlvbiBydW5DaXBoZXIoXG4gIGNvcmU6IENpcGhlckNvcmVGbixcbiAgc2lnbWE6IFVpbnQzMkFycmF5LFxuICBrZXk6IFVpbnQzMkFycmF5LFxuICBub25jZTogVWludDMyQXJyYXksXG4gIGRhdGE6IFVpbnQ4QXJyYXksXG4gIG91dHB1dDogVWludDhBcnJheSxcbiAgY291bnRlcjogbnVtYmVyLFxuICByb3VuZHM6IG51bWJlclxuKTogdm9pZCB7XG4gIGNvbnN0IGxlbiA9IGRhdGEubGVuZ3RoO1xuICBjb25zdCBibG9jayA9IG5ldyBVaW50OEFycmF5KEJMT0NLX0xFTik7XG4gIGNvbnN0IGIzMiA9IHUzMihibG9jayk7XG4gIC8vIE1ha2Ugc3VyZSB0aGF0IGJ1ZmZlcnMgYWxpZ25lZCB0byA0IGJ5dGVzXG4gIGNvbnN0IGlzQWxpZ25lZCA9IGlzQWxpZ25lZDMyKGRhdGEpICYmIGlzQWxpZ25lZDMyKG91dHB1dCk7XG4gIGNvbnN0IGQzMiA9IGlzQWxpZ25lZCA/IHUzMihkYXRhKSA6IFUzMl9FTVBUWTtcbiAgY29uc3QgbzMyID0gaXNBbGlnbmVkID8gdTMyKG91dHB1dCkgOiBVMzJfRU1QVFk7XG4gIGZvciAobGV0IHBvcyA9IDA7IHBvcyA8IGxlbjsgY291bnRlcisrKSB7XG4gICAgY29yZShzaWdtYSwga2V5LCBub25jZSwgYjMyLCBjb3VudGVyLCByb3VuZHMpO1xuICAgIGlmIChjb3VudGVyID49IE1BWF9DT1VOVEVSKSB0aHJvdyBuZXcgRXJyb3IoJ2FyeDogY291bnRlciBvdmVyZmxvdycpO1xuICAgIGNvbnN0IHRha2UgPSBNYXRoLm1pbihCTE9DS19MRU4sIGxlbiAtIHBvcyk7XG4gICAgLy8gYWxpZ25lZCB0byA0IGJ5dGVzXG4gICAgaWYgKGlzQWxpZ25lZCAmJiB0YWtlID09PSBCTE9DS19MRU4pIHtcbiAgICAgIGNvbnN0IHBvczMyID0gcG9zIC8gNDtcbiAgICAgIGlmIChwb3MgJSA0ICE9PSAwKSB0aHJvdyBuZXcgRXJyb3IoJ2FyeDogaW52YWxpZCBibG9jayBwb3NpdGlvbicpO1xuICAgICAgZm9yIChsZXQgaiA9IDAsIHBvc2o6IG51bWJlcjsgaiA8IEJMT0NLX0xFTjMyOyBqKyspIHtcbiAgICAgICAgcG9zaiA9IHBvczMyICsgajtcbiAgICAgICAgbzMyW3Bvc2pdID0gZDMyW3Bvc2pdIF4gYjMyW2pdO1xuICAgICAgfVxuICAgICAgcG9zICs9IEJMT0NLX0xFTjtcbiAgICAgIGNvbnRpbnVlO1xuICAgIH1cbiAgICBmb3IgKGxldCBqID0gMCwgcG9zajsgaiA8IHRha2U7IGorKykge1xuICAgICAgcG9zaiA9IHBvcyArIGo7XG4gICAgICBvdXRwdXRbcG9zal0gPSBkYXRhW3Bvc2pdIF4gYmxvY2tbal07XG4gICAgfVxuICAgIHBvcyArPSB0YWtlO1xuICB9XG59XG5cbi8qKiBDcmVhdGVzIEFSWC1saWtlIChDaGFDaGEsIFNhbHNhKSBjaXBoZXIgc3RyZWFtIGZyb20gY29yZSBmdW5jdGlvbi4gKi9cbmV4cG9ydCBmdW5jdGlvbiBjcmVhdGVDaXBoZXIoY29yZTogQ2lwaGVyQ29yZUZuLCBvcHRzOiBDaXBoZXJPcHRzKTogWG9yU3RyZWFtIHtcbiAgY29uc3QgeyBhbGxvd1Nob3J0S2V5cywgZXh0ZW5kTm9uY2VGbiwgY291bnRlckxlbmd0aCwgY291bnRlclJpZ2h0LCByb3VuZHMgfSA9IGNoZWNrT3B0cyhcbiAgICB7IGFsbG93U2hvcnRLZXlzOiBmYWxzZSwgY291bnRlckxlbmd0aDogOCwgY291bnRlclJpZ2h0OiBmYWxzZSwgcm91bmRzOiAyMCB9LFxuICAgIG9wdHNcbiAgKTtcbiAgaWYgKHR5cGVvZiBjb3JlICE9PSAnZnVuY3Rpb24nKSB0aHJvdyBuZXcgRXJyb3IoJ2NvcmUgbXVzdCBiZSBhIGZ1bmN0aW9uJyk7XG4gIGFudW1iZXIoY291bnRlckxlbmd0aCk7XG4gIGFudW1iZXIocm91bmRzKTtcbiAgYWJvb2woY291bnRlclJpZ2h0KTtcbiAgYWJvb2woYWxsb3dTaG9ydEtleXMpO1xuICByZXR1cm4gKFxuICAgIGtleTogVWludDhBcnJheSxcbiAgICBub25jZTogVWludDhBcnJheSxcbiAgICBkYXRhOiBVaW50OEFycmF5LFxuICAgIG91dHB1dD86IFVpbnQ4QXJyYXksXG4gICAgY291bnRlciA9IDBcbiAgKTogVWludDhBcnJheSA9PiB7XG4gICAgYWJ5dGVzKGtleSk7XG4gICAgYWJ5dGVzKG5vbmNlKTtcbiAgICBhYnl0ZXMoZGF0YSk7XG4gICAgY29uc3QgbGVuID0gZGF0YS5sZW5ndGg7XG4gICAgaWYgKG91dHB1dCA9PT0gdW5kZWZpbmVkKSBvdXRwdXQgPSBuZXcgVWludDhBcnJheShsZW4pO1xuICAgIGFieXRlcyhvdXRwdXQpO1xuICAgIGFudW1iZXIoY291bnRlcik7XG4gICAgaWYgKGNvdW50ZXIgPCAwIHx8IGNvdW50ZXIgPj0gTUFYX0NPVU5URVIpIHRocm93IG5ldyBFcnJvcignYXJ4OiBjb3VudGVyIG92ZXJmbG93Jyk7XG4gICAgaWYgKG91dHB1dC5sZW5ndGggPCBsZW4pXG4gICAgICB0aHJvdyBuZXcgRXJyb3IoYGFyeDogb3V0cHV0ICgke291dHB1dC5sZW5ndGh9KSBpcyBzaG9ydGVyIHRoYW4gZGF0YSAoJHtsZW59KWApO1xuICAgIGNvbnN0IHRvQ2xlYW4gPSBbXTtcblxuICAgIC8vIEtleSAmIHNpZ21hXG4gICAgLy8ga2V5PTE2IC0+IHNpZ21hMTYsIGs9a2V5fGtleVxuICAgIC8vIGtleT0zMiAtPiBzaWdtYTMyLCBrPWtleVxuICAgIGxldCBsID0ga2V5Lmxlbmd0aDtcbiAgICBsZXQgazogVWludDhBcnJheTtcbiAgICBsZXQgc2lnbWE6IFVpbnQzMkFycmF5O1xuICAgIGlmIChsID09PSAzMikge1xuICAgICAgdG9DbGVhbi5wdXNoKChrID0gY29weUJ5dGVzKGtleSkpKTtcbiAgICAgIHNpZ21hID0gc2lnbWEzMl8zMjtcbiAgICB9IGVsc2UgaWYgKGwgPT09IDE2ICYmIGFsbG93U2hvcnRLZXlzKSB7XG4gICAgICBrID0gbmV3IFVpbnQ4QXJyYXkoMzIpO1xuICAgICAgay5zZXQoa2V5KTtcbiAgICAgIGsuc2V0KGtleSwgMTYpO1xuICAgICAgc2lnbWEgPSBzaWdtYTE2XzMyO1xuICAgICAgdG9DbGVhbi5wdXNoKGspO1xuICAgIH0gZWxzZSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoYGFyeDogaW52YWxpZCAzMi1ieXRlIGtleSwgZ290IGxlbmd0aD0ke2x9YCk7XG4gICAgfVxuXG4gICAgLy8gTm9uY2VcbiAgICAvLyBzYWxzYTIwOiAgICAgIDggICAoOC1ieXRlIGNvdW50ZXIpXG4gICAgLy8gY2hhY2hhMjBvcmlnOiA4ICAgKDgtYnl0ZSBjb3VudGVyKVxuICAgIC8vIGNoYWNoYTIwOiAgICAgMTIgICg0LWJ5dGUgY291bnRlcilcbiAgICAvLyB4c2Fsc2EyMDogICAgIDI0ICAoMTYgLT4gaHNhbHNhLCAgOCAtPiBvbGQgbm9uY2UpXG4gICAgLy8geGNoYWNoYTIwOiAgICAyNCAgKDE2IC0+IGhjaGFjaGEsIDggLT4gb2xkIG5vbmNlKVxuICAgIC8vIEFsaWduIG5vbmNlIHRvIDQgYnl0ZXNcbiAgICBpZiAoIWlzQWxpZ25lZDMyKG5vbmNlKSkgdG9DbGVhbi5wdXNoKChub25jZSA9IGNvcHlCeXRlcyhub25jZSkpKTtcblxuICAgIGNvbnN0IGszMiA9IHUzMihrKTtcbiAgICAvLyBoc2Fsc2EgJiBoY2hhY2hhOiBoYW5kbGUgZXh0ZW5kZWQgbm9uY2VcbiAgICBpZiAoZXh0ZW5kTm9uY2VGbikge1xuICAgICAgaWYgKG5vbmNlLmxlbmd0aCAhPT0gMjQpIHRocm93IG5ldyBFcnJvcihgYXJ4OiBleHRlbmRlZCBub25jZSBtdXN0IGJlIDI0IGJ5dGVzYCk7XG4gICAgICBleHRlbmROb25jZUZuKHNpZ21hLCBrMzIsIHUzMihub25jZS5zdWJhcnJheSgwLCAxNikpLCBrMzIpO1xuICAgICAgbm9uY2UgPSBub25jZS5zdWJhcnJheSgxNik7XG4gICAgfVxuXG4gICAgLy8gSGFuZGxlIG5vbmNlIGNvdW50ZXJcbiAgICBjb25zdCBub25jZU5jTGVuID0gMTYgLSBjb3VudGVyTGVuZ3RoO1xuICAgIGlmIChub25jZU5jTGVuICE9PSBub25jZS5sZW5ndGgpXG4gICAgICB0aHJvdyBuZXcgRXJyb3IoYGFyeDogbm9uY2UgbXVzdCBiZSAke25vbmNlTmNMZW59IG9yIDE2IGJ5dGVzYCk7XG5cbiAgICAvLyBQYWQgY291bnRlciB3aGVuIG5vbmNlIGlzIDY0IGJpdFxuICAgIGlmIChub25jZU5jTGVuICE9PSAxMikge1xuICAgICAgY29uc3QgbmMgPSBuZXcgVWludDhBcnJheSgxMik7XG4gICAgICBuYy5zZXQobm9uY2UsIGNvdW50ZXJSaWdodCA/IDAgOiAxMiAtIG5vbmNlLmxlbmd0aCk7XG4gICAgICBub25jZSA9IG5jO1xuICAgICAgdG9DbGVhbi5wdXNoKG5vbmNlKTtcbiAgICB9XG4gICAgY29uc3QgbjMyID0gdTMyKG5vbmNlKTtcbiAgICBydW5DaXBoZXIoY29yZSwgc2lnbWEsIGszMiwgbjMyLCBkYXRhLCBvdXRwdXQsIGNvdW50ZXIsIHJvdW5kcyk7XG4gICAgY2xlYW4oLi4udG9DbGVhbik7XG4gICAgcmV0dXJuIG91dHB1dDtcbiAgfTtcbn1cbiIsICIvKipcbiAqIFBvbHkxMzA1IChbUERGXShodHRwczovL2NyLnlwLnRvL21hYy9wb2x5MTMwNS0yMDA1MDMyOS5wZGYpLFxuICogW3dpa2ldKGh0dHBzOi8vZW4ud2lraXBlZGlhLm9yZy93aWtpL1BvbHkxMzA1KSlcbiAqIGlzIGEgZmFzdCBhbmQgcGFyYWxsZWwgc2VjcmV0LWtleSBtZXNzYWdlLWF1dGhlbnRpY2F0aW9uIGNvZGUgc3VpdGFibGUgZm9yXG4gKiBhIHdpZGUgdmFyaWV0eSBvZiBhcHBsaWNhdGlvbnMuIEl0IHdhcyBzdGFuZGFyZGl6ZWQgaW5cbiAqIFtSRkMgODQzOV0oaHR0cHM6Ly9kYXRhdHJhY2tlci5pZXRmLm9yZy9kb2MvaHRtbC9yZmM4NDM5KSBhbmQgaXMgbm93IHVzZWQgaW4gVExTIDEuMy5cbiAqXG4gKiBQb2x5bm9taWFsIE1BQ3MgYXJlIG5vdCBwZXJmZWN0IGZvciBldmVyeSBzaXR1YXRpb246XG4gKiB0aGV5IGxhY2sgUmFuZG9tIEtleSBSb2J1c3RuZXNzOiB0aGUgTUFDIGNhbiBiZSBmb3JnZWQsIGFuZCBjYW4ndCBiZSB1c2VkIGluIFBBS0Ugc2NoZW1lcy5cbiAqIFNlZSBbaW52aXNpYmxlIHNhbGFtYW5kZXJzIGF0dGFja10oaHR0cHM6Ly9rZXltYXRlcmlhbC5uZXQvMjAyMC8wOS8wNy9pbnZpc2libGUtc2FsYW1hbmRlcnMtaW4tYWVzLWdjbS1zaXYvKS5cbiAqIFRvIGNvbWJhdCBpbnZpc2libGUgc2FsYW1hbmRlcnMsIGBoYXNoKGtleSlgIGNhbiBiZSBpbmNsdWRlZCBpbiBjaXBoZXJ0ZXh0LFxuICogaG93ZXZlciwgdGhpcyB3b3VsZCB2aW9sYXRlIGNpcGhlcnRleHQgaW5kaXN0aW5ndWlzaGFiaWxpdHk6XG4gKiBhbiBhdHRhY2tlciB3b3VsZCBrbm93IHdoaWNoIGtleSB3YXMgdXNlZCAtIHNvIGBIS0RGKGtleSwgaSlgXG4gKiBjb3VsZCBiZSB1c2VkIGluc3RlYWQuXG4gKlxuICogQ2hlY2sgb3V0IFtvcmlnaW5hbCB3ZWJzaXRlXShodHRwczovL2NyLnlwLnRvL21hYy5odG1sKS5cbiAqIEBtb2R1bGVcbiAqL1xuaW1wb3J0IHsgSGFzaCwgdHlwZSBJbnB1dCwgYWJ5dGVzLCBhZXhpc3RzLCBhb3V0cHV0LCBjbGVhbiwgdG9CeXRlcyB9IGZyb20gJy4vdXRpbHMudHMnO1xuXG4vLyBCYXNlZCBvbiBQdWJsaWMgRG9tYWluIHBvbHkxMzA1LWRvbm5hIGh0dHBzOi8vZ2l0aHViLmNvbS9mbG9vZHliZXJyeS9wb2x5MTMwNS1kb25uYVxuY29uc3QgdTh0bzE2ID0gKGE6IFVpbnQ4QXJyYXksIGk6IG51bWJlcikgPT4gKGFbaSsrXSAmIDB4ZmYpIHwgKChhW2krK10gJiAweGZmKSA8PCA4KTtcbmNsYXNzIFBvbHkxMzA1IGltcGxlbWVudHMgSGFzaDxQb2x5MTMwNT4ge1xuICByZWFkb25seSBibG9ja0xlbiA9IDE2O1xuICByZWFkb25seSBvdXRwdXRMZW4gPSAxNjtcbiAgcHJpdmF0ZSBidWZmZXIgPSBuZXcgVWludDhBcnJheSgxNik7XG4gIHByaXZhdGUgciA9IG5ldyBVaW50MTZBcnJheSgxMCk7XG4gIHByaXZhdGUgaCA9IG5ldyBVaW50MTZBcnJheSgxMCk7XG4gIHByaXZhdGUgcGFkID0gbmV3IFVpbnQxNkFycmF5KDgpO1xuICBwcml2YXRlIHBvcyA9IDA7XG4gIHByb3RlY3RlZCBmaW5pc2hlZCA9IGZhbHNlO1xuXG4gIGNvbnN0cnVjdG9yKGtleTogSW5wdXQpIHtcbiAgICBrZXkgPSB0b0J5dGVzKGtleSk7XG4gICAgYWJ5dGVzKGtleSwgMzIpO1xuICAgIGNvbnN0IHQwID0gdTh0bzE2KGtleSwgMCk7XG4gICAgY29uc3QgdDEgPSB1OHRvMTYoa2V5LCAyKTtcbiAgICBjb25zdCB0MiA9IHU4dG8xNihrZXksIDQpO1xuICAgIGNvbnN0IHQzID0gdTh0bzE2KGtleSwgNik7XG4gICAgY29uc3QgdDQgPSB1OHRvMTYoa2V5LCA4KTtcbiAgICBjb25zdCB0NSA9IHU4dG8xNihrZXksIDEwKTtcbiAgICBjb25zdCB0NiA9IHU4dG8xNihrZXksIDEyKTtcbiAgICBjb25zdCB0NyA9IHU4dG8xNihrZXksIDE0KTtcblxuICAgIC8vIGh0dHBzOi8vZ2l0aHViLmNvbS9mbG9vZHliZXJyeS9wb2x5MTMwNS1kb25uYS9ibG9iL2U2YWQ2ZTA5MWQzMGQ3ZjRlYzJkNGY5NzhiZTFmY2ZjYmNlNzI3ODEvcG9seTEzMDUtZG9ubmEtMTYuaCNMNDdcbiAgICB0aGlzLnJbMF0gPSB0MCAmIDB4MWZmZjtcbiAgICB0aGlzLnJbMV0gPSAoKHQwID4+PiAxMykgfCAodDEgPDwgMykpICYgMHgxZmZmO1xuICAgIHRoaXMuclsyXSA9ICgodDEgPj4+IDEwKSB8ICh0MiA8PCA2KSkgJiAweDFmMDM7XG4gICAgdGhpcy5yWzNdID0gKCh0MiA+Pj4gNykgfCAodDMgPDwgOSkpICYgMHgxZmZmO1xuICAgIHRoaXMucls0XSA9ICgodDMgPj4+IDQpIHwgKHQ0IDw8IDEyKSkgJiAweDAwZmY7XG4gICAgdGhpcy5yWzVdID0gKHQ0ID4+PiAxKSAmIDB4MWZmZTtcbiAgICB0aGlzLnJbNl0gPSAoKHQ0ID4+PiAxNCkgfCAodDUgPDwgMikpICYgMHgxZmZmO1xuICAgIHRoaXMucls3XSA9ICgodDUgPj4+IDExKSB8ICh0NiA8PCA1KSkgJiAweDFmODE7XG4gICAgdGhpcy5yWzhdID0gKCh0NiA+Pj4gOCkgfCAodDcgPDwgOCkpICYgMHgxZmZmO1xuICAgIHRoaXMucls5XSA9ICh0NyA+Pj4gNSkgJiAweDAwN2Y7XG4gICAgZm9yIChsZXQgaSA9IDA7IGkgPCA4OyBpKyspIHRoaXMucGFkW2ldID0gdTh0bzE2KGtleSwgMTYgKyAyICogaSk7XG4gIH1cblxuICBwcml2YXRlIHByb2Nlc3MoZGF0YTogVWludDhBcnJheSwgb2Zmc2V0OiBudW1iZXIsIGlzTGFzdCA9IGZhbHNlKSB7XG4gICAgY29uc3QgaGliaXQgPSBpc0xhc3QgPyAwIDogMSA8PCAxMTtcbiAgICBjb25zdCB7IGgsIHIgfSA9IHRoaXM7XG4gICAgY29uc3QgcjAgPSByWzBdO1xuICAgIGNvbnN0IHIxID0gclsxXTtcbiAgICBjb25zdCByMiA9IHJbMl07XG4gICAgY29uc3QgcjMgPSByWzNdO1xuICAgIGNvbnN0IHI0ID0gcls0XTtcbiAgICBjb25zdCByNSA9IHJbNV07XG4gICAgY29uc3QgcjYgPSByWzZdO1xuICAgIGNvbnN0IHI3ID0gcls3XTtcbiAgICBjb25zdCByOCA9IHJbOF07XG4gICAgY29uc3QgcjkgPSByWzldO1xuXG4gICAgY29uc3QgdDAgPSB1OHRvMTYoZGF0YSwgb2Zmc2V0ICsgMCk7XG4gICAgY29uc3QgdDEgPSB1OHRvMTYoZGF0YSwgb2Zmc2V0ICsgMik7XG4gICAgY29uc3QgdDIgPSB1OHRvMTYoZGF0YSwgb2Zmc2V0ICsgNCk7XG4gICAgY29uc3QgdDMgPSB1OHRvMTYoZGF0YSwgb2Zmc2V0ICsgNik7XG4gICAgY29uc3QgdDQgPSB1OHRvMTYoZGF0YSwgb2Zmc2V0ICsgOCk7XG4gICAgY29uc3QgdDUgPSB1OHRvMTYoZGF0YSwgb2Zmc2V0ICsgMTApO1xuICAgIGNvbnN0IHQ2ID0gdTh0bzE2KGRhdGEsIG9mZnNldCArIDEyKTtcbiAgICBjb25zdCB0NyA9IHU4dG8xNihkYXRhLCBvZmZzZXQgKyAxNCk7XG5cbiAgICBsZXQgaDAgPSBoWzBdICsgKHQwICYgMHgxZmZmKTtcbiAgICBsZXQgaDEgPSBoWzFdICsgKCgodDAgPj4+IDEzKSB8ICh0MSA8PCAzKSkgJiAweDFmZmYpO1xuICAgIGxldCBoMiA9IGhbMl0gKyAoKCh0MSA+Pj4gMTApIHwgKHQyIDw8IDYpKSAmIDB4MWZmZik7XG4gICAgbGV0IGgzID0gaFszXSArICgoKHQyID4+PiA3KSB8ICh0MyA8PCA5KSkgJiAweDFmZmYpO1xuICAgIGxldCBoNCA9IGhbNF0gKyAoKCh0MyA+Pj4gNCkgfCAodDQgPDwgMTIpKSAmIDB4MWZmZik7XG4gICAgbGV0IGg1ID0gaFs1XSArICgodDQgPj4+IDEpICYgMHgxZmZmKTtcbiAgICBsZXQgaDYgPSBoWzZdICsgKCgodDQgPj4+IDE0KSB8ICh0NSA8PCAyKSkgJiAweDFmZmYpO1xuICAgIGxldCBoNyA9IGhbN10gKyAoKCh0NSA+Pj4gMTEpIHwgKHQ2IDw8IDUpKSAmIDB4MWZmZik7XG4gICAgbGV0IGg4ID0gaFs4XSArICgoKHQ2ID4+PiA4KSB8ICh0NyA8PCA4KSkgJiAweDFmZmYpO1xuICAgIGxldCBoOSA9IGhbOV0gKyAoKHQ3ID4+PiA1KSB8IGhpYml0KTtcblxuICAgIGxldCBjID0gMDtcblxuICAgIGxldCBkMCA9IGMgKyBoMCAqIHIwICsgaDEgKiAoNSAqIHI5KSArIGgyICogKDUgKiByOCkgKyBoMyAqICg1ICogcjcpICsgaDQgKiAoNSAqIHI2KTtcbiAgICBjID0gZDAgPj4+IDEzO1xuICAgIGQwICY9IDB4MWZmZjtcbiAgICBkMCArPSBoNSAqICg1ICogcjUpICsgaDYgKiAoNSAqIHI0KSArIGg3ICogKDUgKiByMykgKyBoOCAqICg1ICogcjIpICsgaDkgKiAoNSAqIHIxKTtcbiAgICBjICs9IGQwID4+PiAxMztcbiAgICBkMCAmPSAweDFmZmY7XG5cbiAgICBsZXQgZDEgPSBjICsgaDAgKiByMSArIGgxICogcjAgKyBoMiAqICg1ICogcjkpICsgaDMgKiAoNSAqIHI4KSArIGg0ICogKDUgKiByNyk7XG4gICAgYyA9IGQxID4+PiAxMztcbiAgICBkMSAmPSAweDFmZmY7XG4gICAgZDEgKz0gaDUgKiAoNSAqIHI2KSArIGg2ICogKDUgKiByNSkgKyBoNyAqICg1ICogcjQpICsgaDggKiAoNSAqIHIzKSArIGg5ICogKDUgKiByMik7XG4gICAgYyArPSBkMSA+Pj4gMTM7XG4gICAgZDEgJj0gMHgxZmZmO1xuXG4gICAgbGV0IGQyID0gYyArIGgwICogcjIgKyBoMSAqIHIxICsgaDIgKiByMCArIGgzICogKDUgKiByOSkgKyBoNCAqICg1ICogcjgpO1xuICAgIGMgPSBkMiA+Pj4gMTM7XG4gICAgZDIgJj0gMHgxZmZmO1xuICAgIGQyICs9IGg1ICogKDUgKiByNykgKyBoNiAqICg1ICogcjYpICsgaDcgKiAoNSAqIHI1KSArIGg4ICogKDUgKiByNCkgKyBoOSAqICg1ICogcjMpO1xuICAgIGMgKz0gZDIgPj4+IDEzO1xuICAgIGQyICY9IDB4MWZmZjtcblxuICAgIGxldCBkMyA9IGMgKyBoMCAqIHIzICsgaDEgKiByMiArIGgyICogcjEgKyBoMyAqIHIwICsgaDQgKiAoNSAqIHI5KTtcbiAgICBjID0gZDMgPj4+IDEzO1xuICAgIGQzICY9IDB4MWZmZjtcbiAgICBkMyArPSBoNSAqICg1ICogcjgpICsgaDYgKiAoNSAqIHI3KSArIGg3ICogKDUgKiByNikgKyBoOCAqICg1ICogcjUpICsgaDkgKiAoNSAqIHI0KTtcbiAgICBjICs9IGQzID4+PiAxMztcbiAgICBkMyAmPSAweDFmZmY7XG5cbiAgICBsZXQgZDQgPSBjICsgaDAgKiByNCArIGgxICogcjMgKyBoMiAqIHIyICsgaDMgKiByMSArIGg0ICogcjA7XG4gICAgYyA9IGQ0ID4+PiAxMztcbiAgICBkNCAmPSAweDFmZmY7XG4gICAgZDQgKz0gaDUgKiAoNSAqIHI5KSArIGg2ICogKDUgKiByOCkgKyBoNyAqICg1ICogcjcpICsgaDggKiAoNSAqIHI2KSArIGg5ICogKDUgKiByNSk7XG4gICAgYyArPSBkNCA+Pj4gMTM7XG4gICAgZDQgJj0gMHgxZmZmO1xuXG4gICAgbGV0IGQ1ID0gYyArIGgwICogcjUgKyBoMSAqIHI0ICsgaDIgKiByMyArIGgzICogcjIgKyBoNCAqIHIxO1xuICAgIGMgPSBkNSA+Pj4gMTM7XG4gICAgZDUgJj0gMHgxZmZmO1xuICAgIGQ1ICs9IGg1ICogcjAgKyBoNiAqICg1ICogcjkpICsgaDcgKiAoNSAqIHI4KSArIGg4ICogKDUgKiByNykgKyBoOSAqICg1ICogcjYpO1xuICAgIGMgKz0gZDUgPj4+IDEzO1xuICAgIGQ1ICY9IDB4MWZmZjtcblxuICAgIGxldCBkNiA9IGMgKyBoMCAqIHI2ICsgaDEgKiByNSArIGgyICogcjQgKyBoMyAqIHIzICsgaDQgKiByMjtcbiAgICBjID0gZDYgPj4+IDEzO1xuICAgIGQ2ICY9IDB4MWZmZjtcbiAgICBkNiArPSBoNSAqIHIxICsgaDYgKiByMCArIGg3ICogKDUgKiByOSkgKyBoOCAqICg1ICogcjgpICsgaDkgKiAoNSAqIHI3KTtcbiAgICBjICs9IGQ2ID4+PiAxMztcbiAgICBkNiAmPSAweDFmZmY7XG5cbiAgICBsZXQgZDcgPSBjICsgaDAgKiByNyArIGgxICogcjYgKyBoMiAqIHI1ICsgaDMgKiByNCArIGg0ICogcjM7XG4gICAgYyA9IGQ3ID4+PiAxMztcbiAgICBkNyAmPSAweDFmZmY7XG4gICAgZDcgKz0gaDUgKiByMiArIGg2ICogcjEgKyBoNyAqIHIwICsgaDggKiAoNSAqIHI5KSArIGg5ICogKDUgKiByOCk7XG4gICAgYyArPSBkNyA+Pj4gMTM7XG4gICAgZDcgJj0gMHgxZmZmO1xuXG4gICAgbGV0IGQ4ID0gYyArIGgwICogcjggKyBoMSAqIHI3ICsgaDIgKiByNiArIGgzICogcjUgKyBoNCAqIHI0O1xuICAgIGMgPSBkOCA+Pj4gMTM7XG4gICAgZDggJj0gMHgxZmZmO1xuICAgIGQ4ICs9IGg1ICogcjMgKyBoNiAqIHIyICsgaDcgKiByMSArIGg4ICogcjAgKyBoOSAqICg1ICogcjkpO1xuICAgIGMgKz0gZDggPj4+IDEzO1xuICAgIGQ4ICY9IDB4MWZmZjtcblxuICAgIGxldCBkOSA9IGMgKyBoMCAqIHI5ICsgaDEgKiByOCArIGgyICogcjcgKyBoMyAqIHI2ICsgaDQgKiByNTtcbiAgICBjID0gZDkgPj4+IDEzO1xuICAgIGQ5ICY9IDB4MWZmZjtcbiAgICBkOSArPSBoNSAqIHI0ICsgaDYgKiByMyArIGg3ICogcjIgKyBoOCAqIHIxICsgaDkgKiByMDtcbiAgICBjICs9IGQ5ID4+PiAxMztcbiAgICBkOSAmPSAweDFmZmY7XG5cbiAgICBjID0gKChjIDw8IDIpICsgYykgfCAwO1xuICAgIGMgPSAoYyArIGQwKSB8IDA7XG4gICAgZDAgPSBjICYgMHgxZmZmO1xuICAgIGMgPSBjID4+PiAxMztcbiAgICBkMSArPSBjO1xuXG4gICAgaFswXSA9IGQwO1xuICAgIGhbMV0gPSBkMTtcbiAgICBoWzJdID0gZDI7XG4gICAgaFszXSA9IGQzO1xuICAgIGhbNF0gPSBkNDtcbiAgICBoWzVdID0gZDU7XG4gICAgaFs2XSA9IGQ2O1xuICAgIGhbN10gPSBkNztcbiAgICBoWzhdID0gZDg7XG4gICAgaFs5XSA9IGQ5O1xuICB9XG5cbiAgcHJpdmF0ZSBmaW5hbGl6ZSgpIHtcbiAgICBjb25zdCB7IGgsIHBhZCB9ID0gdGhpcztcbiAgICBjb25zdCBnID0gbmV3IFVpbnQxNkFycmF5KDEwKTtcbiAgICBsZXQgYyA9IGhbMV0gPj4+IDEzO1xuICAgIGhbMV0gJj0gMHgxZmZmO1xuICAgIGZvciAobGV0IGkgPSAyOyBpIDwgMTA7IGkrKykge1xuICAgICAgaFtpXSArPSBjO1xuICAgICAgYyA9IGhbaV0gPj4+IDEzO1xuICAgICAgaFtpXSAmPSAweDFmZmY7XG4gICAgfVxuICAgIGhbMF0gKz0gYyAqIDU7XG4gICAgYyA9IGhbMF0gPj4+IDEzO1xuICAgIGhbMF0gJj0gMHgxZmZmO1xuICAgIGhbMV0gKz0gYztcbiAgICBjID0gaFsxXSA+Pj4gMTM7XG4gICAgaFsxXSAmPSAweDFmZmY7XG4gICAgaFsyXSArPSBjO1xuXG4gICAgZ1swXSA9IGhbMF0gKyA1O1xuICAgIGMgPSBnWzBdID4+PiAxMztcbiAgICBnWzBdICY9IDB4MWZmZjtcbiAgICBmb3IgKGxldCBpID0gMTsgaSA8IDEwOyBpKyspIHtcbiAgICAgIGdbaV0gPSBoW2ldICsgYztcbiAgICAgIGMgPSBnW2ldID4+PiAxMztcbiAgICAgIGdbaV0gJj0gMHgxZmZmO1xuICAgIH1cbiAgICBnWzldIC09IDEgPDwgMTM7XG5cbiAgICBsZXQgbWFzayA9IChjIF4gMSkgLSAxO1xuICAgIGZvciAobGV0IGkgPSAwOyBpIDwgMTA7IGkrKykgZ1tpXSAmPSBtYXNrO1xuICAgIG1hc2sgPSB+bWFzaztcbiAgICBmb3IgKGxldCBpID0gMDsgaSA8IDEwOyBpKyspIGhbaV0gPSAoaFtpXSAmIG1hc2spIHwgZ1tpXTtcbiAgICBoWzBdID0gKGhbMF0gfCAoaFsxXSA8PCAxMykpICYgMHhmZmZmO1xuICAgIGhbMV0gPSAoKGhbMV0gPj4+IDMpIHwgKGhbMl0gPDwgMTApKSAmIDB4ZmZmZjtcbiAgICBoWzJdID0gKChoWzJdID4+PiA2KSB8IChoWzNdIDw8IDcpKSAmIDB4ZmZmZjtcbiAgICBoWzNdID0gKChoWzNdID4+PiA5KSB8IChoWzRdIDw8IDQpKSAmIDB4ZmZmZjtcbiAgICBoWzRdID0gKChoWzRdID4+PiAxMikgfCAoaFs1XSA8PCAxKSB8IChoWzZdIDw8IDE0KSkgJiAweGZmZmY7XG4gICAgaFs1XSA9ICgoaFs2XSA+Pj4gMikgfCAoaFs3XSA8PCAxMSkpICYgMHhmZmZmO1xuICAgIGhbNl0gPSAoKGhbN10gPj4+IDUpIHwgKGhbOF0gPDwgOCkpICYgMHhmZmZmO1xuICAgIGhbN10gPSAoKGhbOF0gPj4+IDgpIHwgKGhbOV0gPDwgNSkpICYgMHhmZmZmO1xuXG4gICAgbGV0IGYgPSBoWzBdICsgcGFkWzBdO1xuICAgIGhbMF0gPSBmICYgMHhmZmZmO1xuICAgIGZvciAobGV0IGkgPSAxOyBpIDwgODsgaSsrKSB7XG4gICAgICBmID0gKCgoaFtpXSArIHBhZFtpXSkgfCAwKSArIChmID4+PiAxNikpIHwgMDtcbiAgICAgIGhbaV0gPSBmICYgMHhmZmZmO1xuICAgIH1cbiAgICBjbGVhbihnKTtcbiAgfVxuICB1cGRhdGUoZGF0YTogSW5wdXQpOiB0aGlzIHtcbiAgICBhZXhpc3RzKHRoaXMpO1xuICAgIGRhdGEgPSB0b0J5dGVzKGRhdGEpO1xuICAgIGFieXRlcyhkYXRhKTtcbiAgICBjb25zdCB7IGJ1ZmZlciwgYmxvY2tMZW4gfSA9IHRoaXM7XG4gICAgY29uc3QgbGVuID0gZGF0YS5sZW5ndGg7XG5cbiAgICBmb3IgKGxldCBwb3MgPSAwOyBwb3MgPCBsZW47ICkge1xuICAgICAgY29uc3QgdGFrZSA9IE1hdGgubWluKGJsb2NrTGVuIC0gdGhpcy5wb3MsIGxlbiAtIHBvcyk7XG4gICAgICAvLyBGYXN0IHBhdGg6IHdlIGhhdmUgYXQgbGVhc3Qgb25lIGJsb2NrIGluIGlucHV0XG4gICAgICBpZiAodGFrZSA9PT0gYmxvY2tMZW4pIHtcbiAgICAgICAgZm9yICg7IGJsb2NrTGVuIDw9IGxlbiAtIHBvczsgcG9zICs9IGJsb2NrTGVuKSB0aGlzLnByb2Nlc3MoZGF0YSwgcG9zKTtcbiAgICAgICAgY29udGludWU7XG4gICAgICB9XG4gICAgICBidWZmZXIuc2V0KGRhdGEuc3ViYXJyYXkocG9zLCBwb3MgKyB0YWtlKSwgdGhpcy5wb3MpO1xuICAgICAgdGhpcy5wb3MgKz0gdGFrZTtcbiAgICAgIHBvcyArPSB0YWtlO1xuICAgICAgaWYgKHRoaXMucG9zID09PSBibG9ja0xlbikge1xuICAgICAgICB0aGlzLnByb2Nlc3MoYnVmZmVyLCAwLCBmYWxzZSk7XG4gICAgICAgIHRoaXMucG9zID0gMDtcbiAgICAgIH1cbiAgICB9XG4gICAgcmV0dXJuIHRoaXM7XG4gIH1cbiAgZGVzdHJveSgpIHtcbiAgICBjbGVhbih0aGlzLmgsIHRoaXMuciwgdGhpcy5idWZmZXIsIHRoaXMucGFkKTtcbiAgfVxuICBkaWdlc3RJbnRvKG91dDogVWludDhBcnJheSkge1xuICAgIGFleGlzdHModGhpcyk7XG4gICAgYW91dHB1dChvdXQsIHRoaXMpO1xuICAgIHRoaXMuZmluaXNoZWQgPSB0cnVlO1xuICAgIGNvbnN0IHsgYnVmZmVyLCBoIH0gPSB0aGlzO1xuICAgIGxldCB7IHBvcyB9ID0gdGhpcztcbiAgICBpZiAocG9zKSB7XG4gICAgICBidWZmZXJbcG9zKytdID0gMTtcbiAgICAgIGZvciAoOyBwb3MgPCAxNjsgcG9zKyspIGJ1ZmZlcltwb3NdID0gMDtcbiAgICAgIHRoaXMucHJvY2VzcyhidWZmZXIsIDAsIHRydWUpO1xuICAgIH1cbiAgICB0aGlzLmZpbmFsaXplKCk7XG4gICAgbGV0IG9wb3MgPSAwO1xuICAgIGZvciAobGV0IGkgPSAwOyBpIDwgODsgaSsrKSB7XG4gICAgICBvdXRbb3BvcysrXSA9IGhbaV0gPj4+IDA7XG4gICAgICBvdXRbb3BvcysrXSA9IGhbaV0gPj4+IDg7XG4gICAgfVxuICAgIHJldHVybiBvdXQ7XG4gIH1cbiAgZGlnZXN0KCk6IFVpbnQ4QXJyYXkge1xuICAgIGNvbnN0IHsgYnVmZmVyLCBvdXRwdXRMZW4gfSA9IHRoaXM7XG4gICAgdGhpcy5kaWdlc3RJbnRvKGJ1ZmZlcik7XG4gICAgY29uc3QgcmVzID0gYnVmZmVyLnNsaWNlKDAsIG91dHB1dExlbik7XG4gICAgdGhpcy5kZXN0cm95KCk7XG4gICAgcmV0dXJuIHJlcztcbiAgfVxufVxuXG5leHBvcnQgdHlwZSBDSGFzaCA9IFJldHVyblR5cGU8dHlwZW9mIHdyYXBDb25zdHJ1Y3RvcldpdGhLZXk+O1xuZXhwb3J0IGZ1bmN0aW9uIHdyYXBDb25zdHJ1Y3RvcldpdGhLZXk8SCBleHRlbmRzIEhhc2g8SD4+KFxuICBoYXNoQ29uczogKGtleTogSW5wdXQpID0+IEhhc2g8SD5cbik6IHtcbiAgKG1zZzogSW5wdXQsIGtleTogSW5wdXQpOiBVaW50OEFycmF5O1xuICBvdXRwdXRMZW46IG51bWJlcjtcbiAgYmxvY2tMZW46IG51bWJlcjtcbiAgY3JlYXRlKGtleTogSW5wdXQpOiBIYXNoPEg+O1xufSB7XG4gIGNvbnN0IGhhc2hDID0gKG1zZzogSW5wdXQsIGtleTogSW5wdXQpOiBVaW50OEFycmF5ID0+IGhhc2hDb25zKGtleSkudXBkYXRlKHRvQnl0ZXMobXNnKSkuZGlnZXN0KCk7XG4gIGNvbnN0IHRtcCA9IGhhc2hDb25zKG5ldyBVaW50OEFycmF5KDMyKSk7XG4gIGhhc2hDLm91dHB1dExlbiA9IHRtcC5vdXRwdXRMZW47XG4gIGhhc2hDLmJsb2NrTGVuID0gdG1wLmJsb2NrTGVuO1xuICBoYXNoQy5jcmVhdGUgPSAoa2V5OiBJbnB1dCkgPT4gaGFzaENvbnMoa2V5KTtcbiAgcmV0dXJuIGhhc2hDO1xufVxuXG4vKiogUG9seTEzMDUgTUFDIGZyb20gUkZDIDg0MzkuICovXG5leHBvcnQgY29uc3QgcG9seTEzMDU6IENIYXNoID0gd3JhcENvbnN0cnVjdG9yV2l0aEtleSgoa2V5KSA9PiBuZXcgUG9seTEzMDUoa2V5KSk7XG4iLCAiLyoqXG4gKiBbQ2hhQ2hhMjBdKGh0dHBzOi8vY3IueXAudG8vY2hhY2hhLmh0bWwpIHN0cmVhbSBjaXBoZXIsIHJlbGVhc2VkXG4gKiBpbiAyMDA4LiBEZXZlbG9wZWQgYWZ0ZXIgU2Fsc2EyMCwgQ2hhQ2hhIGFpbXMgdG8gaW5jcmVhc2UgZGlmZnVzaW9uIHBlciByb3VuZC5cbiAqIEl0IHdhcyBzdGFuZGFyZGl6ZWQgaW4gW1JGQyA4NDM5XShodHRwczovL2RhdGF0cmFja2VyLmlldGYub3JnL2RvYy9odG1sL3JmYzg0MzkpIGFuZFxuICogaXMgbm93IHVzZWQgaW4gVExTIDEuMy5cbiAqXG4gKiBbWENoYUNoYTIwXShodHRwczovL2RhdGF0cmFja2VyLmlldGYub3JnL2RvYy9odG1sL2RyYWZ0LWlydGYtY2ZyZy14Y2hhY2hhKVxuICogZXh0ZW5kZWQtbm9uY2UgdmFyaWFudCBpcyBhbHNvIHByb3ZpZGVkLiBTaW1pbGFyIHRvIFhTYWxzYSwgaXQncyBzYWZlIHRvIHVzZSB3aXRoXG4gKiByYW5kb21seS1nZW5lcmF0ZWQgbm9uY2VzLlxuICpcbiAqIENoZWNrIG91dCBbUERGXShodHRwOi8vY3IueXAudG8vY2hhY2hhL2NoYWNoYS0yMDA4MDEyOC5wZGYpIGFuZFxuICogW3dpa2ldKGh0dHBzOi8vZW4ud2lraXBlZGlhLm9yZy93aWtpL1NhbHNhMjApLlxuICogQG1vZHVsZVxuICovXG5pbXBvcnQgeyBjcmVhdGVDaXBoZXIsIHJvdGwgfSBmcm9tICcuL19hcngudHMnO1xuaW1wb3J0IHsgcG9seTEzMDUgfSBmcm9tICcuL19wb2x5MTMwNS50cyc7XG5pbXBvcnQge1xuICB0eXBlIEFSWENpcGhlcixcbiAgdHlwZSBDaXBoZXJXaXRoT3V0cHV0LFxuICB0eXBlIFhvclN0cmVhbSxcbiAgY2xlYW4sXG4gIGVxdWFsQnl0ZXMsXG4gIGdldE91dHB1dCxcbiAgdTY0TGVuZ3RocyxcbiAgd3JhcENpcGhlcixcbn0gZnJvbSAnLi91dGlscy50cyc7XG5cbi8qKlxuICogQ2hhQ2hhIGNvcmUgZnVuY3Rpb24uXG4gKi9cbi8vIHByZXR0aWVyLWlnbm9yZVxuZnVuY3Rpb24gY2hhY2hhQ29yZShcbiAgczogVWludDMyQXJyYXksIGs6IFVpbnQzMkFycmF5LCBuOiBVaW50MzJBcnJheSwgb3V0OiBVaW50MzJBcnJheSwgY250OiBudW1iZXIsIHJvdW5kcyA9IDIwXG4pOiB2b2lkIHtcbiAgbGV0IHkwMCA9IHNbMF0sIHkwMSA9IHNbMV0sIHkwMiA9IHNbMl0sIHkwMyA9IHNbM10sIC8vIFwiZXhwYVwiICAgXCJuZCAzXCIgIFwiMi1ieVwiICBcInRlIGtcIlxuICAgIHkwNCA9IGtbMF0sIHkwNSA9IGtbMV0sIHkwNiA9IGtbMl0sIHkwNyA9IGtbM10sICAgLy8gS2V5ICAgICAgS2V5ICAgICBLZXkgICAgIEtleVxuICAgIHkwOCA9IGtbNF0sIHkwOSA9IGtbNV0sIHkxMCA9IGtbNl0sIHkxMSA9IGtbN10sICAgLy8gS2V5ICAgICAgS2V5ICAgICBLZXkgICAgIEtleVxuICAgIHkxMiA9IGNudCwgeTEzID0gblswXSwgeTE0ID0gblsxXSwgeTE1ID0gblsyXTsgICAgLy8gQ291bnRlciAgQ291bnRlclx0Tm9uY2UgICBOb25jZVxuICAvLyBTYXZlIHN0YXRlIHRvIHRlbXBvcmFyeSB2YXJpYWJsZXNcbiAgbGV0IHgwMCA9IHkwMCwgeDAxID0geTAxLCB4MDIgPSB5MDIsIHgwMyA9IHkwMyxcbiAgICAgIHgwNCA9IHkwNCwgeDA1ID0geTA1LCB4MDYgPSB5MDYsIHgwNyA9IHkwNyxcbiAgICAgIHgwOCA9IHkwOCwgeDA5ID0geTA5LCB4MTAgPSB5MTAsIHgxMSA9IHkxMSxcbiAgICAgIHgxMiA9IHkxMiwgeDEzID0geTEzLCB4MTQgPSB5MTQsIHgxNSA9IHkxNTtcbiAgZm9yIChsZXQgciA9IDA7IHIgPCByb3VuZHM7IHIgKz0gMikge1xuICAgIHgwMCA9ICh4MDAgKyB4MDQpIHwgMDsgeDEyID0gcm90bCh4MTIgXiB4MDAsIDE2KTtcbiAgICB4MDggPSAoeDA4ICsgeDEyKSB8IDA7IHgwNCA9IHJvdGwoeDA0IF4geDA4LCAxMik7XG4gICAgeDAwID0gKHgwMCArIHgwNCkgfCAwOyB4MTIgPSByb3RsKHgxMiBeIHgwMCwgOCk7XG4gICAgeDA4ID0gKHgwOCArIHgxMikgfCAwOyB4MDQgPSByb3RsKHgwNCBeIHgwOCwgNyk7XG5cbiAgICB4MDEgPSAoeDAxICsgeDA1KSB8IDA7IHgxMyA9IHJvdGwoeDEzIF4geDAxLCAxNik7XG4gICAgeDA5ID0gKHgwOSArIHgxMykgfCAwOyB4MDUgPSByb3RsKHgwNSBeIHgwOSwgMTIpO1xuICAgIHgwMSA9ICh4MDEgKyB4MDUpIHwgMDsgeDEzID0gcm90bCh4MTMgXiB4MDEsIDgpO1xuICAgIHgwOSA9ICh4MDkgKyB4MTMpIHwgMDsgeDA1ID0gcm90bCh4MDUgXiB4MDksIDcpO1xuXG4gICAgeDAyID0gKHgwMiArIHgwNikgfCAwOyB4MTQgPSByb3RsKHgxNCBeIHgwMiwgMTYpO1xuICAgIHgxMCA9ICh4MTAgKyB4MTQpIHwgMDsgeDA2ID0gcm90bCh4MDYgXiB4MTAsIDEyKTtcbiAgICB4MDIgPSAoeDAyICsgeDA2KSB8IDA7IHgxNCA9IHJvdGwoeDE0IF4geDAyLCA4KTtcbiAgICB4MTAgPSAoeDEwICsgeDE0KSB8IDA7IHgwNiA9IHJvdGwoeDA2IF4geDEwLCA3KTtcblxuICAgIHgwMyA9ICh4MDMgKyB4MDcpIHwgMDsgeDE1ID0gcm90bCh4MTUgXiB4MDMsIDE2KTtcbiAgICB4MTEgPSAoeDExICsgeDE1KSB8IDA7IHgwNyA9IHJvdGwoeDA3IF4geDExLCAxMik7XG4gICAgeDAzID0gKHgwMyArIHgwNykgfCAwOyB4MTUgPSByb3RsKHgxNSBeIHgwMywgOClcbiAgICB4MTEgPSAoeDExICsgeDE1KSB8IDA7IHgwNyA9IHJvdGwoeDA3IF4geDExLCA3KTtcblxuICAgIHgwMCA9ICh4MDAgKyB4MDUpIHwgMDsgeDE1ID0gcm90bCh4MTUgXiB4MDAsIDE2KTtcbiAgICB4MTAgPSAoeDEwICsgeDE1KSB8IDA7IHgwNSA9IHJvdGwoeDA1IF4geDEwLCAxMik7XG4gICAgeDAwID0gKHgwMCArIHgwNSkgfCAwOyB4MTUgPSByb3RsKHgxNSBeIHgwMCwgOCk7XG4gICAgeDEwID0gKHgxMCArIHgxNSkgfCAwOyB4MDUgPSByb3RsKHgwNSBeIHgxMCwgNyk7XG5cbiAgICB4MDEgPSAoeDAxICsgeDA2KSB8IDA7IHgxMiA9IHJvdGwoeDEyIF4geDAxLCAxNik7XG4gICAgeDExID0gKHgxMSArIHgxMikgfCAwOyB4MDYgPSByb3RsKHgwNiBeIHgxMSwgMTIpO1xuICAgIHgwMSA9ICh4MDEgKyB4MDYpIHwgMDsgeDEyID0gcm90bCh4MTIgXiB4MDEsIDgpO1xuICAgIHgxMSA9ICh4MTEgKyB4MTIpIHwgMDsgeDA2ID0gcm90bCh4MDYgXiB4MTEsIDcpO1xuXG4gICAgeDAyID0gKHgwMiArIHgwNykgfCAwOyB4MTMgPSByb3RsKHgxMyBeIHgwMiwgMTYpO1xuICAgIHgwOCA9ICh4MDggKyB4MTMpIHwgMDsgeDA3ID0gcm90bCh4MDcgXiB4MDgsIDEyKTtcbiAgICB4MDIgPSAoeDAyICsgeDA3KSB8IDA7IHgxMyA9IHJvdGwoeDEzIF4geDAyLCA4KTtcbiAgICB4MDggPSAoeDA4ICsgeDEzKSB8IDA7IHgwNyA9IHJvdGwoeDA3IF4geDA4LCA3KTtcblxuICAgIHgwMyA9ICh4MDMgKyB4MDQpIHwgMDsgeDE0ID0gcm90bCh4MTQgXiB4MDMsIDE2KVxuICAgIHgwOSA9ICh4MDkgKyB4MTQpIHwgMDsgeDA0ID0gcm90bCh4MDQgXiB4MDksIDEyKTtcbiAgICB4MDMgPSAoeDAzICsgeDA0KSB8IDA7IHgxNCA9IHJvdGwoeDE0IF4geDAzLCA4KTtcbiAgICB4MDkgPSAoeDA5ICsgeDE0KSB8IDA7IHgwNCA9IHJvdGwoeDA0IF4geDA5LCA3KTtcbiAgfVxuICAvLyBXcml0ZSBvdXRwdXRcbiAgbGV0IG9pID0gMDtcbiAgb3V0W29pKytdID0gKHkwMCArIHgwMCkgfCAwOyBvdXRbb2krK10gPSAoeTAxICsgeDAxKSB8IDA7XG4gIG91dFtvaSsrXSA9ICh5MDIgKyB4MDIpIHwgMDsgb3V0W29pKytdID0gKHkwMyArIHgwMykgfCAwO1xuICBvdXRbb2krK10gPSAoeTA0ICsgeDA0KSB8IDA7IG91dFtvaSsrXSA9ICh5MDUgKyB4MDUpIHwgMDtcbiAgb3V0W29pKytdID0gKHkwNiArIHgwNikgfCAwOyBvdXRbb2krK10gPSAoeTA3ICsgeDA3KSB8IDA7XG4gIG91dFtvaSsrXSA9ICh5MDggKyB4MDgpIHwgMDsgb3V0W29pKytdID0gKHkwOSArIHgwOSkgfCAwO1xuICBvdXRbb2krK10gPSAoeTEwICsgeDEwKSB8IDA7IG91dFtvaSsrXSA9ICh5MTEgKyB4MTEpIHwgMDtcbiAgb3V0W29pKytdID0gKHkxMiArIHgxMikgfCAwOyBvdXRbb2krK10gPSAoeTEzICsgeDEzKSB8IDA7XG4gIG91dFtvaSsrXSA9ICh5MTQgKyB4MTQpIHwgMDsgb3V0W29pKytdID0gKHkxNSArIHgxNSkgfCAwO1xufVxuLyoqXG4gKiBoY2hhY2hhIGhlbHBlciBtZXRob2QsIHVzZWQgcHJpbWFyaWx5IGluIHhjaGFjaGEsIHRvIGhhc2hcbiAqIGtleSBhbmQgbm9uY2UgaW50byBrZXknIGFuZCBub25jZScuXG4gKiBTYW1lIGFzIGNoYWNoYUNvcmUsIGJ1dCB0aGVyZSBkb2Vzbid0IHNlZW0gdG8gYmUgYSB3YXkgdG8gbW92ZSB0aGUgYmxvY2tcbiAqIG91dCB3aXRob3V0IDI1JSBwZXJmb3JtYW5jZSBoaXQuXG4gKi9cbi8vIHByZXR0aWVyLWlnbm9yZVxuZXhwb3J0IGZ1bmN0aW9uIGhjaGFjaGEoXG4gIHM6IFVpbnQzMkFycmF5LCBrOiBVaW50MzJBcnJheSwgaTogVWludDMyQXJyYXksIG8zMjogVWludDMyQXJyYXlcbik6IHZvaWQge1xuICBsZXQgeDAwID0gc1swXSwgeDAxID0gc1sxXSwgeDAyID0gc1syXSwgeDAzID0gc1szXSxcbiAgICAgIHgwNCA9IGtbMF0sIHgwNSA9IGtbMV0sIHgwNiA9IGtbMl0sIHgwNyA9IGtbM10sXG4gICAgICB4MDggPSBrWzRdLCB4MDkgPSBrWzVdLCB4MTAgPSBrWzZdLCB4MTEgPSBrWzddLFxuICAgICAgeDEyID0gaVswXSwgeDEzID0gaVsxXSwgeDE0ID0gaVsyXSwgeDE1ID0gaVszXTtcbiAgZm9yIChsZXQgciA9IDA7IHIgPCAyMDsgciArPSAyKSB7XG4gICAgeDAwID0gKHgwMCArIHgwNCkgfCAwOyB4MTIgPSByb3RsKHgxMiBeIHgwMCwgMTYpO1xuICAgIHgwOCA9ICh4MDggKyB4MTIpIHwgMDsgeDA0ID0gcm90bCh4MDQgXiB4MDgsIDEyKTtcbiAgICB4MDAgPSAoeDAwICsgeDA0KSB8IDA7IHgxMiA9IHJvdGwoeDEyIF4geDAwLCA4KTtcbiAgICB4MDggPSAoeDA4ICsgeDEyKSB8IDA7IHgwNCA9IHJvdGwoeDA0IF4geDA4LCA3KTtcblxuICAgIHgwMSA9ICh4MDEgKyB4MDUpIHwgMDsgeDEzID0gcm90bCh4MTMgXiB4MDEsIDE2KTtcbiAgICB4MDkgPSAoeDA5ICsgeDEzKSB8IDA7IHgwNSA9IHJvdGwoeDA1IF4geDA5LCAxMik7XG4gICAgeDAxID0gKHgwMSArIHgwNSkgfCAwOyB4MTMgPSByb3RsKHgxMyBeIHgwMSwgOCk7XG4gICAgeDA5ID0gKHgwOSArIHgxMykgfCAwOyB4MDUgPSByb3RsKHgwNSBeIHgwOSwgNyk7XG5cbiAgICB4MDIgPSAoeDAyICsgeDA2KSB8IDA7IHgxNCA9IHJvdGwoeDE0IF4geDAyLCAxNik7XG4gICAgeDEwID0gKHgxMCArIHgxNCkgfCAwOyB4MDYgPSByb3RsKHgwNiBeIHgxMCwgMTIpO1xuICAgIHgwMiA9ICh4MDIgKyB4MDYpIHwgMDsgeDE0ID0gcm90bCh4MTQgXiB4MDIsIDgpO1xuICAgIHgxMCA9ICh4MTAgKyB4MTQpIHwgMDsgeDA2ID0gcm90bCh4MDYgXiB4MTAsIDcpO1xuXG4gICAgeDAzID0gKHgwMyArIHgwNykgfCAwOyB4MTUgPSByb3RsKHgxNSBeIHgwMywgMTYpO1xuICAgIHgxMSA9ICh4MTEgKyB4MTUpIHwgMDsgeDA3ID0gcm90bCh4MDcgXiB4MTEsIDEyKTtcbiAgICB4MDMgPSAoeDAzICsgeDA3KSB8IDA7IHgxNSA9IHJvdGwoeDE1IF4geDAzLCA4KVxuICAgIHgxMSA9ICh4MTEgKyB4MTUpIHwgMDsgeDA3ID0gcm90bCh4MDcgXiB4MTEsIDcpO1xuXG4gICAgeDAwID0gKHgwMCArIHgwNSkgfCAwOyB4MTUgPSByb3RsKHgxNSBeIHgwMCwgMTYpO1xuICAgIHgxMCA9ICh4MTAgKyB4MTUpIHwgMDsgeDA1ID0gcm90bCh4MDUgXiB4MTAsIDEyKTtcbiAgICB4MDAgPSAoeDAwICsgeDA1KSB8IDA7IHgxNSA9IHJvdGwoeDE1IF4geDAwLCA4KTtcbiAgICB4MTAgPSAoeDEwICsgeDE1KSB8IDA7IHgwNSA9IHJvdGwoeDA1IF4geDEwLCA3KTtcblxuICAgIHgwMSA9ICh4MDEgKyB4MDYpIHwgMDsgeDEyID0gcm90bCh4MTIgXiB4MDEsIDE2KTtcbiAgICB4MTEgPSAoeDExICsgeDEyKSB8IDA7IHgwNiA9IHJvdGwoeDA2IF4geDExLCAxMik7XG4gICAgeDAxID0gKHgwMSArIHgwNikgfCAwOyB4MTIgPSByb3RsKHgxMiBeIHgwMSwgOCk7XG4gICAgeDExID0gKHgxMSArIHgxMikgfCAwOyB4MDYgPSByb3RsKHgwNiBeIHgxMSwgNyk7XG5cbiAgICB4MDIgPSAoeDAyICsgeDA3KSB8IDA7IHgxMyA9IHJvdGwoeDEzIF4geDAyLCAxNik7XG4gICAgeDA4ID0gKHgwOCArIHgxMykgfCAwOyB4MDcgPSByb3RsKHgwNyBeIHgwOCwgMTIpO1xuICAgIHgwMiA9ICh4MDIgKyB4MDcpIHwgMDsgeDEzID0gcm90bCh4MTMgXiB4MDIsIDgpO1xuICAgIHgwOCA9ICh4MDggKyB4MTMpIHwgMDsgeDA3ID0gcm90bCh4MDcgXiB4MDgsIDcpO1xuXG4gICAgeDAzID0gKHgwMyArIHgwNCkgfCAwOyB4MTQgPSByb3RsKHgxNCBeIHgwMywgMTYpXG4gICAgeDA5ID0gKHgwOSArIHgxNCkgfCAwOyB4MDQgPSByb3RsKHgwNCBeIHgwOSwgMTIpO1xuICAgIHgwMyA9ICh4MDMgKyB4MDQpIHwgMDsgeDE0ID0gcm90bCh4MTQgXiB4MDMsIDgpO1xuICAgIHgwOSA9ICh4MDkgKyB4MTQpIHwgMDsgeDA0ID0gcm90bCh4MDQgXiB4MDksIDcpO1xuICB9XG4gIGxldCBvaSA9IDA7XG4gIG8zMltvaSsrXSA9IHgwMDsgbzMyW29pKytdID0geDAxO1xuICBvMzJbb2krK10gPSB4MDI7IG8zMltvaSsrXSA9IHgwMztcbiAgbzMyW29pKytdID0geDEyOyBvMzJbb2krK10gPSB4MTM7XG4gIG8zMltvaSsrXSA9IHgxNDsgbzMyW29pKytdID0geDE1O1xufVxuLyoqXG4gKiBPcmlnaW5hbCwgbm9uLVJGQyBjaGFjaGEyMCBmcm9tIERKQi4gOC1ieXRlIG5vbmNlLCA4LWJ5dGUgY291bnRlci5cbiAqL1xuZXhwb3J0IGNvbnN0IGNoYWNoYTIwb3JpZzogWG9yU3RyZWFtID0gLyogQF9fUFVSRV9fICovIGNyZWF0ZUNpcGhlcihjaGFjaGFDb3JlLCB7XG4gIGNvdW50ZXJSaWdodDogZmFsc2UsXG4gIGNvdW50ZXJMZW5ndGg6IDgsXG4gIGFsbG93U2hvcnRLZXlzOiB0cnVlLFxufSk7XG4vKipcbiAqIENoYUNoYSBzdHJlYW0gY2lwaGVyLiBDb25mb3JtcyB0byBSRkMgODQzOSAoSUVURiwgVExTKS4gMTItYnl0ZSBub25jZSwgNC1ieXRlIGNvdW50ZXIuXG4gKiBXaXRoIDEyLWJ5dGUgbm9uY2UsIGl0J3Mgbm90IHNhZmUgdG8gdXNlIGZpbGwgaXQgd2l0aCByYW5kb20gKENTUFJORyksIGR1ZSB0byBjb2xsaXNpb24gY2hhbmNlLlxuICovXG5leHBvcnQgY29uc3QgY2hhY2hhMjA6IFhvclN0cmVhbSA9IC8qIEBfX1BVUkVfXyAqLyBjcmVhdGVDaXBoZXIoY2hhY2hhQ29yZSwge1xuICBjb3VudGVyUmlnaHQ6IGZhbHNlLFxuICBjb3VudGVyTGVuZ3RoOiA0LFxuICBhbGxvd1Nob3J0S2V5czogZmFsc2UsXG59KTtcblxuLyoqXG4gKiBYQ2hhQ2hhIGVYdGVuZGVkLW5vbmNlIENoYUNoYS4gMjQtYnl0ZSBub25jZS5cbiAqIFdpdGggMjQtYnl0ZSBub25jZSwgaXQncyBzYWZlIHRvIHVzZSBmaWxsIGl0IHdpdGggcmFuZG9tIChDU1BSTkcpLlxuICogaHR0cHM6Ly9kYXRhdHJhY2tlci5pZXRmLm9yZy9kb2MvaHRtbC9kcmFmdC1pcnRmLWNmcmcteGNoYWNoYVxuICovXG5leHBvcnQgY29uc3QgeGNoYWNoYTIwOiBYb3JTdHJlYW0gPSAvKiBAX19QVVJFX18gKi8gY3JlYXRlQ2lwaGVyKGNoYWNoYUNvcmUsIHtcbiAgY291bnRlclJpZ2h0OiBmYWxzZSxcbiAgY291bnRlckxlbmd0aDogOCxcbiAgZXh0ZW5kTm9uY2VGbjogaGNoYWNoYSxcbiAgYWxsb3dTaG9ydEtleXM6IGZhbHNlLFxufSk7XG5cbi8qKlxuICogUmVkdWNlZCA4LXJvdW5kIGNoYWNoYSwgZGVzY3JpYmVkIGluIG9yaWdpbmFsIHBhcGVyLlxuICovXG5leHBvcnQgY29uc3QgY2hhY2hhODogWG9yU3RyZWFtID0gLyogQF9fUFVSRV9fICovIGNyZWF0ZUNpcGhlcihjaGFjaGFDb3JlLCB7XG4gIGNvdW50ZXJSaWdodDogZmFsc2UsXG4gIGNvdW50ZXJMZW5ndGg6IDQsXG4gIHJvdW5kczogOCxcbn0pO1xuXG4vKipcbiAqIFJlZHVjZWQgMTItcm91bmQgY2hhY2hhLCBkZXNjcmliZWQgaW4gb3JpZ2luYWwgcGFwZXIuXG4gKi9cbmV4cG9ydCBjb25zdCBjaGFjaGExMjogWG9yU3RyZWFtID0gLyogQF9fUFVSRV9fICovIGNyZWF0ZUNpcGhlcihjaGFjaGFDb3JlLCB7XG4gIGNvdW50ZXJSaWdodDogZmFsc2UsXG4gIGNvdW50ZXJMZW5ndGg6IDQsXG4gIHJvdW5kczogMTIsXG59KTtcblxuY29uc3QgWkVST1MxNiA9IC8qIEBfX1BVUkVfXyAqLyBuZXcgVWludDhBcnJheSgxNik7XG4vLyBQYWQgdG8gZGlnZXN0IHNpemUgd2l0aCB6ZXJvc1xuY29uc3QgdXBkYXRlUGFkZGVkID0gKGg6IFJldHVyblR5cGU8dHlwZW9mIHBvbHkxMzA1LmNyZWF0ZT4sIG1zZzogVWludDhBcnJheSkgPT4ge1xuICBoLnVwZGF0ZShtc2cpO1xuICBjb25zdCBsZWZ0ID0gbXNnLmxlbmd0aCAlIDE2O1xuICBpZiAobGVmdCkgaC51cGRhdGUoWkVST1MxNi5zdWJhcnJheShsZWZ0KSk7XG59O1xuXG5jb25zdCBaRVJPUzMyID0gLyogQF9fUFVSRV9fICovIG5ldyBVaW50OEFycmF5KDMyKTtcbmZ1bmN0aW9uIGNvbXB1dGVUYWcoXG4gIGZuOiBYb3JTdHJlYW0sXG4gIGtleTogVWludDhBcnJheSxcbiAgbm9uY2U6IFVpbnQ4QXJyYXksXG4gIGRhdGE6IFVpbnQ4QXJyYXksXG4gIEFBRD86IFVpbnQ4QXJyYXlcbik6IFVpbnQ4QXJyYXkge1xuICBjb25zdCBhdXRoS2V5ID0gZm4oa2V5LCBub25jZSwgWkVST1MzMik7XG4gIGNvbnN0IGggPSBwb2x5MTMwNS5jcmVhdGUoYXV0aEtleSk7XG4gIGlmIChBQUQpIHVwZGF0ZVBhZGRlZChoLCBBQUQpO1xuICB1cGRhdGVQYWRkZWQoaCwgZGF0YSk7XG4gIGNvbnN0IG51bSA9IHU2NExlbmd0aHMoZGF0YS5sZW5ndGgsIEFBRCA/IEFBRC5sZW5ndGggOiAwLCB0cnVlKTtcbiAgaC51cGRhdGUobnVtKTtcbiAgY29uc3QgcmVzID0gaC5kaWdlc3QoKTtcbiAgY2xlYW4oYXV0aEtleSwgbnVtKTtcbiAgcmV0dXJuIHJlcztcbn1cblxuLyoqXG4gKiBBRUFEIGFsZ29yaXRobSBmcm9tIFJGQyA4NDM5LlxuICogU2Fsc2EyMCBhbmQgY2hhY2hhIChSRkMgODQzOSkgdXNlIHBvbHkxMzA1IGRpZmZlcmVudGx5LlxuICogV2UgY291bGQgaGF2ZSBjb21wb3NlZCB0aGVtIHNpbWlsYXIgdG86XG4gKiBodHRwczovL2dpdGh1Yi5jb20vcGF1bG1pbGxyL3NjdXJlLWJhc2UvYmxvYi9iMjY2YzczZGRlOTc3YjFkZDdlZjQwZWY3YTIzY2MxNWFhYjUyNmIzL2luZGV4LnRzI0wyNTBcbiAqIEJ1dCBpdCdzIGhhcmQgYmVjYXVzZSBvZiBhdXRoS2V5OlxuICogSW4gc2Fsc2EyMCwgYXV0aEtleSBjaGFuZ2VzIHBvc2l0aW9uIGluIHNhbHNhIHN0cmVhbS5cbiAqIEluIGNoYWNoYSwgYXV0aEtleSBjYW4ndCBiZSBjb21wdXRlZCBpbnNpZGUgY29tcHV0ZVRhZywgaXQgbW9kaWZpZXMgdGhlIGNvdW50ZXIuXG4gKi9cbmV4cG9ydCBjb25zdCBfcG9seTEzMDVfYWVhZCA9XG4gICh4b3JTdHJlYW06IFhvclN0cmVhbSkgPT5cbiAgKGtleTogVWludDhBcnJheSwgbm9uY2U6IFVpbnQ4QXJyYXksIEFBRD86IFVpbnQ4QXJyYXkpOiBDaXBoZXJXaXRoT3V0cHV0ID0+IHtcbiAgICBjb25zdCB0YWdMZW5ndGggPSAxNjtcbiAgICByZXR1cm4ge1xuICAgICAgZW5jcnlwdChwbGFpbnRleHQ6IFVpbnQ4QXJyYXksIG91dHB1dD86IFVpbnQ4QXJyYXkpIHtcbiAgICAgICAgY29uc3QgcGxlbmd0aCA9IHBsYWludGV4dC5sZW5ndGg7XG4gICAgICAgIG91dHB1dCA9IGdldE91dHB1dChwbGVuZ3RoICsgdGFnTGVuZ3RoLCBvdXRwdXQsIGZhbHNlKTtcbiAgICAgICAgb3V0cHV0LnNldChwbGFpbnRleHQpO1xuICAgICAgICBjb25zdCBvUGxhaW4gPSBvdXRwdXQuc3ViYXJyYXkoMCwgLXRhZ0xlbmd0aCk7XG4gICAgICAgIHhvclN0cmVhbShrZXksIG5vbmNlLCBvUGxhaW4sIG9QbGFpbiwgMSk7XG4gICAgICAgIGNvbnN0IHRhZyA9IGNvbXB1dGVUYWcoeG9yU3RyZWFtLCBrZXksIG5vbmNlLCBvUGxhaW4sIEFBRCk7XG4gICAgICAgIG91dHB1dC5zZXQodGFnLCBwbGVuZ3RoKTsgLy8gYXBwZW5kIHRhZ1xuICAgICAgICBjbGVhbih0YWcpO1xuICAgICAgICByZXR1cm4gb3V0cHV0O1xuICAgICAgfSxcbiAgICAgIGRlY3J5cHQoY2lwaGVydGV4dDogVWludDhBcnJheSwgb3V0cHV0PzogVWludDhBcnJheSkge1xuICAgICAgICBvdXRwdXQgPSBnZXRPdXRwdXQoY2lwaGVydGV4dC5sZW5ndGggLSB0YWdMZW5ndGgsIG91dHB1dCwgZmFsc2UpO1xuICAgICAgICBjb25zdCBkYXRhID0gY2lwaGVydGV4dC5zdWJhcnJheSgwLCAtdGFnTGVuZ3RoKTtcbiAgICAgICAgY29uc3QgcGFzc2VkVGFnID0gY2lwaGVydGV4dC5zdWJhcnJheSgtdGFnTGVuZ3RoKTtcbiAgICAgICAgY29uc3QgdGFnID0gY29tcHV0ZVRhZyh4b3JTdHJlYW0sIGtleSwgbm9uY2UsIGRhdGEsIEFBRCk7XG4gICAgICAgIGlmICghZXF1YWxCeXRlcyhwYXNzZWRUYWcsIHRhZykpIHRocm93IG5ldyBFcnJvcignaW52YWxpZCB0YWcnKTtcbiAgICAgICAgb3V0cHV0LnNldChjaXBoZXJ0ZXh0LnN1YmFycmF5KDAsIC10YWdMZW5ndGgpKTtcbiAgICAgICAgeG9yU3RyZWFtKGtleSwgbm9uY2UsIG91dHB1dCwgb3V0cHV0LCAxKTsgLy8gc3RhcnQgc3RyZWFtIHdpdGggaT0xXG4gICAgICAgIGNsZWFuKHRhZyk7XG4gICAgICAgIHJldHVybiBvdXRwdXQ7XG4gICAgICB9LFxuICAgIH07XG4gIH07XG5cbi8qKlxuICogQ2hhQ2hhMjAtUG9seTEzMDUgZnJvbSBSRkMgODQzOS5cbiAqXG4gKiBVbnNhZmUgdG8gdXNlIHJhbmRvbSBub25jZXMgdW5kZXIgdGhlIHNhbWUga2V5LCBkdWUgdG8gY29sbGlzaW9uIGNoYW5jZS5cbiAqIFByZWZlciBYQ2hhQ2hhIGluc3RlYWQuXG4gKi9cbmV4cG9ydCBjb25zdCBjaGFjaGEyMHBvbHkxMzA1OiBBUlhDaXBoZXIgPSAvKiBAX19QVVJFX18gKi8gd3JhcENpcGhlcihcbiAgeyBibG9ja1NpemU6IDY0LCBub25jZUxlbmd0aDogMTIsIHRhZ0xlbmd0aDogMTYgfSxcbiAgX3BvbHkxMzA1X2FlYWQoY2hhY2hhMjApXG4pO1xuLyoqXG4gKiBYQ2hhQ2hhMjAtUG9seTEzMDUgZXh0ZW5kZWQtbm9uY2UgY2hhY2hhLlxuICpcbiAqIENhbiBiZSBzYWZlbHkgdXNlZCB3aXRoIHJhbmRvbSBub25jZXMgKENTUFJORykuXG4gKiBTZWUgW0lSVEYgZHJhZnRdKGh0dHBzOi8vZGF0YXRyYWNrZXIuaWV0Zi5vcmcvZG9jL2h0bWwvZHJhZnQtaXJ0Zi1jZnJnLXhjaGFjaGEpLlxuICovXG5leHBvcnQgY29uc3QgeGNoYWNoYTIwcG9seTEzMDU6IEFSWENpcGhlciA9IC8qIEBfX1BVUkVfXyAqLyB3cmFwQ2lwaGVyKFxuICB7IGJsb2NrU2l6ZTogNjQsIG5vbmNlTGVuZ3RoOiAyNCwgdGFnTGVuZ3RoOiAxNiB9LFxuICBfcG9seTEzMDVfYWVhZCh4Y2hhY2hhMjApXG4pO1xuIiwgIi8qKlxuICogSW50ZXJuYWwgd2ViY3J5cHRvIGFsaWFzLlxuICogV2UgdXNlIFdlYkNyeXB0byBha2EgZ2xvYmFsVGhpcy5jcnlwdG8sIHdoaWNoIGV4aXN0cyBpbiBicm93c2VycyBhbmQgbm9kZS5qcyAxNisuXG4gKiBTZWUgdXRpbHMudHMgZm9yIGRldGFpbHMuXG4gKiBAbW9kdWxlXG4gKi9cbmRlY2xhcmUgY29uc3QgZ2xvYmFsVGhpczogUmVjb3JkPHN0cmluZywgYW55PiB8IHVuZGVmaW5lZDtcbmV4cG9ydCBjb25zdCBjcnlwdG86IGFueSA9XG4gIHR5cGVvZiBnbG9iYWxUaGlzID09PSAnb2JqZWN0JyAmJiAnY3J5cHRvJyBpbiBnbG9iYWxUaGlzID8gZ2xvYmFsVGhpcy5jcnlwdG8gOiB1bmRlZmluZWQ7XG4iLCAiLyoqXG4gKiBXZWJDcnlwdG8tYmFzZWQgQUVTIGdjbS9jdHIvY2JjLCBgbWFuYWdlZE5vbmNlYCBhbmQgYHJhbmRvbUJ5dGVzYC5cbiAqIFdlIHVzZSBXZWJDcnlwdG8gYWthIGdsb2JhbFRoaXMuY3J5cHRvLCB3aGljaCBleGlzdHMgaW4gYnJvd3NlcnMgYW5kIG5vZGUuanMgMTYrLlxuICogbm9kZS5qcyB2ZXJzaW9ucyBlYXJsaWVyIHRoYW4gdjE5IGRvbid0IGRlY2xhcmUgaXQgaW4gZ2xvYmFsIHNjb3BlLlxuICogRm9yIG5vZGUuanMsIHBhY2thZ2UuanMgb24jZXhwb3J0cyBmaWVsZCBtYXBwaW5nIHJld3JpdGVzIGltcG9ydFxuICogZnJvbSBgY3J5cHRvYCB0byBgY3J5cHRvTm9kZWAsIHdoaWNoIGltcG9ydHMgbmF0aXZlIG1vZHVsZS5cbiAqIE1ha2VzIHRoZSB1dGlscyB1bi1pbXBvcnRhYmxlIGluIGJyb3dzZXJzIHdpdGhvdXQgYSBidW5kbGVyLlxuICogT25jZSBub2RlLmpzIDE4IGlzIGRlcHJlY2F0ZWQsIHdlIGNhbiBqdXN0IGRyb3AgdGhlIGltcG9ydC5cbiAqIEBtb2R1bGVcbiAqL1xuLy8gVXNlIGZ1bGwgcGF0aCBzbyB0aGF0IE5vZGUuanMgY2FuIHJld3JpdGUgaXQgdG8gYGNyeXB0b05vZGUuanNgLlxuaW1wb3J0IHsgY3J5cHRvIH0gZnJvbSAnQG5vYmxlL2NpcGhlcnMvY3J5cHRvJztcbmltcG9ydCB7IGFieXRlcywgYW51bWJlciwgdHlwZSBBc3luY0NpcGhlciwgdHlwZSBDaXBoZXIsIGNvbmNhdEJ5dGVzIH0gZnJvbSAnLi91dGlscy50cyc7XG5cbi8qKlxuICogU2VjdXJlIFBSTkcuIFVzZXMgYGNyeXB0by5nZXRSYW5kb21WYWx1ZXNgLCB3aGljaCBkZWZlcnMgdG8gT1MuXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiByYW5kb21CeXRlcyhieXRlc0xlbmd0aCA9IDMyKTogVWludDhBcnJheSB7XG4gIGlmIChjcnlwdG8gJiYgdHlwZW9mIGNyeXB0by5nZXRSYW5kb21WYWx1ZXMgPT09ICdmdW5jdGlvbicpIHtcbiAgICByZXR1cm4gY3J5cHRvLmdldFJhbmRvbVZhbHVlcyhuZXcgVWludDhBcnJheShieXRlc0xlbmd0aCkpO1xuICB9XG4gIC8vIExlZ2FjeSBOb2RlLmpzIGNvbXBhdGliaWxpdHlcbiAgaWYgKGNyeXB0byAmJiB0eXBlb2YgY3J5cHRvLnJhbmRvbUJ5dGVzID09PSAnZnVuY3Rpb24nKSB7XG4gICAgcmV0dXJuIFVpbnQ4QXJyYXkuZnJvbShjcnlwdG8ucmFuZG9tQnl0ZXMoYnl0ZXNMZW5ndGgpKTtcbiAgfVxuICB0aHJvdyBuZXcgRXJyb3IoJ2NyeXB0by5nZXRSYW5kb21WYWx1ZXMgbXVzdCBiZSBkZWZpbmVkJyk7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBnZXRXZWJjcnlwdG9TdWJ0bGUoKTogYW55IHtcbiAgaWYgKGNyeXB0byAmJiB0eXBlb2YgY3J5cHRvLnN1YnRsZSA9PT0gJ29iamVjdCcgJiYgY3J5cHRvLnN1YnRsZSAhPSBudWxsKSByZXR1cm4gY3J5cHRvLnN1YnRsZTtcbiAgdGhyb3cgbmV3IEVycm9yKCdjcnlwdG8uc3VidGxlIG11c3QgYmUgZGVmaW5lZCcpO1xufVxuXG50eXBlIFJlbW92ZU5vbmNlSW5uZXI8VCBleHRlbmRzIGFueVtdLCBSZXQ+ID0gKCguLi5hcmdzOiBUKSA9PiBSZXQpIGV4dGVuZHMgKFxuICBhcmcwOiBhbnksXG4gIGFyZzE6IGFueSxcbiAgLi4ucmVzdDogaW5mZXIgUlxuKSA9PiBhbnlcbiAgPyAoa2V5OiBVaW50OEFycmF5LCAuLi5hcmdzOiBSKSA9PiBSZXRcbiAgOiBuZXZlcjtcblxudHlwZSBSZW1vdmVOb25jZTxUIGV4dGVuZHMgKC4uLmFyZ3M6IGFueSkgPT4gYW55PiA9IFJlbW92ZU5vbmNlSW5uZXI8UGFyYW1ldGVyczxUPiwgUmV0dXJuVHlwZTxUPj47XG50eXBlIENpcGhlcldpdGhOb25jZSA9ICgoa2V5OiBVaW50OEFycmF5LCBub25jZTogVWludDhBcnJheSwgLi4uYXJnczogYW55W10pID0+IENpcGhlcikgJiB7XG4gIG5vbmNlTGVuZ3RoOiBudW1iZXI7XG59O1xuXG4vKipcbiAqIFVzZXMgQ1NQUkcgZm9yIG5vbmNlLCBub25jZSBpbmplY3RlZCBpbiBjaXBoZXJ0ZXh0LlxuICogQGV4YW1wbGVcbiAqIGNvbnN0IGdjbSA9IG1hbmFnZWROb25jZShhZXMuZ2NtKTtcbiAqIGNvbnN0IGNpcGhyID0gZ2NtKGtleSkuZW5jcnlwdChkYXRhKTtcbiAqIGNvbnN0IHBsYWluID0gZ2NtKGtleSkuZGVjcnlwdChjaXBoKTtcbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIG1hbmFnZWROb25jZTxUIGV4dGVuZHMgQ2lwaGVyV2l0aE5vbmNlPihmbjogVCk6IFJlbW92ZU5vbmNlPFQ+IHtcbiAgY29uc3QgeyBub25jZUxlbmd0aCB9ID0gZm47XG4gIGFudW1iZXIobm9uY2VMZW5ndGgpO1xuICByZXR1cm4gKChrZXk6IFVpbnQ4QXJyYXksIC4uLmFyZ3M6IGFueVtdKTogYW55ID0+ICh7XG4gICAgZW5jcnlwdChwbGFpbnRleHQ6IFVpbnQ4QXJyYXksIC4uLmFyZ3NFbmM6IGFueVtdKSB7XG4gICAgICBjb25zdCBub25jZSA9IHJhbmRvbUJ5dGVzKG5vbmNlTGVuZ3RoKTtcbiAgICAgIGNvbnN0IGNpcGhlcnRleHQgPSAoZm4oa2V5LCBub25jZSwgLi4uYXJncykuZW5jcnlwdCBhcyBhbnkpKHBsYWludGV4dCwgLi4uYXJnc0VuYyk7XG4gICAgICBjb25zdCBvdXQgPSBjb25jYXRCeXRlcyhub25jZSwgY2lwaGVydGV4dCk7XG4gICAgICBjaXBoZXJ0ZXh0LmZpbGwoMCk7XG4gICAgICByZXR1cm4gb3V0O1xuICAgIH0sXG4gICAgZGVjcnlwdChjaXBoZXJ0ZXh0OiBVaW50OEFycmF5LCAuLi5hcmdzRGVjOiBhbnlbXSkge1xuICAgICAgY29uc3Qgbm9uY2UgPSBjaXBoZXJ0ZXh0LnN1YmFycmF5KDAsIG5vbmNlTGVuZ3RoKTtcbiAgICAgIGNvbnN0IGRhdGEgPSBjaXBoZXJ0ZXh0LnN1YmFycmF5KG5vbmNlTGVuZ3RoKTtcbiAgICAgIHJldHVybiAoZm4oa2V5LCBub25jZSwgLi4uYXJncykuZGVjcnlwdCBhcyBhbnkpKGRhdGEsIC4uLmFyZ3NEZWMpO1xuICAgIH0sXG4gIH0pKSBhcyBSZW1vdmVOb25jZTxUPjtcbn1cblxuLy8gT3ZlcnJpZGFibGVcbi8vIEBUT0RPXG5leHBvcnQgY29uc3QgdXRpbHM6IHtcbiAgZW5jcnlwdDogKGtleTogVWludDhBcnJheSwgLi4uYWxsOiBhbnlbXSkgPT4gUHJvbWlzZTxVaW50OEFycmF5PjtcbiAgZGVjcnlwdDogKGtleTogVWludDhBcnJheSwgLi4uYWxsOiBhbnlbXSkgPT4gUHJvbWlzZTxVaW50OEFycmF5Pjtcbn0gPSB7XG4gIGFzeW5jIGVuY3J5cHQoXG4gICAga2V5OiBVaW50OEFycmF5LFxuICAgIGtleVBhcmFtczogYW55LFxuICAgIGNyeXB0UGFyYW1zOiBhbnksXG4gICAgcGxhaW50ZXh0OiBVaW50OEFycmF5XG4gICk6IFByb21pc2U8VWludDhBcnJheT4ge1xuICAgIGNvbnN0IGNyID0gZ2V0V2ViY3J5cHRvU3VidGxlKCk7XG4gICAgY29uc3QgaUtleSA9IGF3YWl0IGNyLmltcG9ydEtleSgncmF3Jywga2V5LCBrZXlQYXJhbXMsIHRydWUsIFsnZW5jcnlwdCddKTtcbiAgICBjb25zdCBjaXBoZXJ0ZXh0ID0gYXdhaXQgY3IuZW5jcnlwdChjcnlwdFBhcmFtcywgaUtleSwgcGxhaW50ZXh0KTtcbiAgICByZXR1cm4gbmV3IFVpbnQ4QXJyYXkoY2lwaGVydGV4dCk7XG4gIH0sXG4gIGFzeW5jIGRlY3J5cHQoXG4gICAga2V5OiBVaW50OEFycmF5LFxuICAgIGtleVBhcmFtczogYW55LFxuICAgIGNyeXB0UGFyYW1zOiBhbnksXG4gICAgY2lwaGVydGV4dDogVWludDhBcnJheVxuICApOiBQcm9taXNlPFVpbnQ4QXJyYXk+IHtcbiAgICBjb25zdCBjciA9IGdldFdlYmNyeXB0b1N1YnRsZSgpO1xuICAgIGNvbnN0IGlLZXkgPSBhd2FpdCBjci5pbXBvcnRLZXkoJ3JhdycsIGtleSwga2V5UGFyYW1zLCB0cnVlLCBbJ2RlY3J5cHQnXSk7XG4gICAgY29uc3QgcGxhaW50ZXh0ID0gYXdhaXQgY3IuZGVjcnlwdChjcnlwdFBhcmFtcywgaUtleSwgY2lwaGVydGV4dCk7XG4gICAgcmV0dXJuIG5ldyBVaW50OEFycmF5KHBsYWludGV4dCk7XG4gIH0sXG59O1xuXG5jb25zdCBtb2RlID0ge1xuICBDQkM6ICdBRVMtQ0JDJyxcbiAgQ1RSOiAnQUVTLUNUUicsXG4gIEdDTTogJ0FFUy1HQ00nLFxufSBhcyBjb25zdDtcbnR5cGUgQmxvY2tNb2RlID0gKHR5cGVvZiBtb2RlKVtrZXlvZiB0eXBlb2YgbW9kZV07XG5cbmZ1bmN0aW9uIGdldENyeXB0UGFyYW1zKGFsZ286IEJsb2NrTW9kZSwgbm9uY2U6IFVpbnQ4QXJyYXksIEFBRD86IFVpbnQ4QXJyYXkpIHtcbiAgaWYgKGFsZ28gPT09IG1vZGUuQ0JDKSByZXR1cm4geyBuYW1lOiBtb2RlLkNCQywgaXY6IG5vbmNlIH07XG4gIGlmIChhbGdvID09PSBtb2RlLkNUUikgcmV0dXJuIHsgbmFtZTogbW9kZS5DVFIsIGNvdW50ZXI6IG5vbmNlLCBsZW5ndGg6IDY0IH07XG4gIGlmIChhbGdvID09PSBtb2RlLkdDTSkge1xuICAgIGlmIChBQUQpIHJldHVybiB7IG5hbWU6IG1vZGUuR0NNLCBpdjogbm9uY2UsIGFkZGl0aW9uYWxEYXRhOiBBQUQgfTtcbiAgICBlbHNlIHJldHVybiB7IG5hbWU6IG1vZGUuR0NNLCBpdjogbm9uY2UgfTtcbiAgfVxuXG4gIHRocm93IG5ldyBFcnJvcigndW5rbm93biBhZXMgYmxvY2sgbW9kZScpO1xufVxuXG5mdW5jdGlvbiBnZW5lcmF0ZShhbGdvOiBCbG9ja01vZGUpIHtcbiAgcmV0dXJuIChrZXk6IFVpbnQ4QXJyYXksIG5vbmNlOiBVaW50OEFycmF5LCBBQUQ/OiBVaW50OEFycmF5KTogQXN5bmNDaXBoZXIgPT4ge1xuICAgIGFieXRlcyhrZXkpO1xuICAgIGFieXRlcyhub25jZSk7XG4gICAgY29uc3Qga2V5UGFyYW1zID0geyBuYW1lOiBhbGdvLCBsZW5ndGg6IGtleS5sZW5ndGggKiA4IH07XG4gICAgY29uc3QgY3J5cHRQYXJhbXMgPSBnZXRDcnlwdFBhcmFtcyhhbGdvLCBub25jZSwgQUFEKTtcbiAgICBsZXQgY29uc3VtZWQgPSBmYWxzZTtcbiAgICByZXR1cm4ge1xuICAgICAgLy8ga2V5TGVuZ3RoLFxuICAgICAgZW5jcnlwdChwbGFpbnRleHQ6IFVpbnQ4QXJyYXkpIHtcbiAgICAgICAgYWJ5dGVzKHBsYWludGV4dCk7XG4gICAgICAgIGlmIChjb25zdW1lZCkgdGhyb3cgbmV3IEVycm9yKCdDYW5ub3QgZW5jcnlwdCgpIHR3aWNlIHdpdGggc2FtZSBrZXkgLyBub25jZScpO1xuICAgICAgICBjb25zdW1lZCA9IHRydWU7XG4gICAgICAgIHJldHVybiB1dGlscy5lbmNyeXB0KGtleSwga2V5UGFyYW1zLCBjcnlwdFBhcmFtcywgcGxhaW50ZXh0KTtcbiAgICAgIH0sXG4gICAgICBkZWNyeXB0KGNpcGhlcnRleHQ6IFVpbnQ4QXJyYXkpIHtcbiAgICAgICAgYWJ5dGVzKGNpcGhlcnRleHQpO1xuICAgICAgICByZXR1cm4gdXRpbHMuZGVjcnlwdChrZXksIGtleVBhcmFtcywgY3J5cHRQYXJhbXMsIGNpcGhlcnRleHQpO1xuICAgICAgfSxcbiAgICB9O1xuICB9O1xufVxuXG4vKiogQUVTLUNCQywgbmF0aXZlIHdlYmNyeXB0byB2ZXJzaW9uICovXG5leHBvcnQgY29uc3QgY2JjOiAoa2V5OiBVaW50OEFycmF5LCBpdjogVWludDhBcnJheSkgPT4gQXN5bmNDaXBoZXIgPSAvKiBAX19QVVJFX18gKi8gKCgpID0+XG4gIGdlbmVyYXRlKG1vZGUuQ0JDKSkoKTtcbi8qKiBBRVMtQ1RSLCBuYXRpdmUgd2ViY3J5cHRvIHZlcnNpb24gKi9cbmV4cG9ydCBjb25zdCBjdHI6IChrZXk6IFVpbnQ4QXJyYXksIG5vbmNlOiBVaW50OEFycmF5KSA9PiBBc3luY0NpcGhlciA9IC8qIEBfX1BVUkVfXyAqLyAoKCkgPT5cbiAgZ2VuZXJhdGUobW9kZS5DVFIpKSgpO1xuLyoqIEFFUy1HQ00sIG5hdGl2ZSB3ZWJjcnlwdG8gdmVyc2lvbiAqL1xuZXhwb3J0IGNvbnN0IGdjbTogKGtleTogVWludDhBcnJheSwgbm9uY2U6IFVpbnQ4QXJyYXksIEFBRD86IFVpbnQ4QXJyYXkpID0+IEFzeW5jQ2lwaGVyID1cbiAgLyogQF9fUFVSRV9fICovICgoKSA9PiBnZW5lcmF0ZShtb2RlLkdDTSkpKCk7XG5cbi8vIC8vIFR5cGUgdGVzdHNcbi8vIGltcG9ydCB7IHNpdiwgZ2NtLCBjdHIsIGVjYiwgY2JjIH0gZnJvbSAnLi4vYWVzLnRzJztcbi8vIGltcG9ydCB7IHhzYWxzYTIwcG9seTEzMDUgfSBmcm9tICcuLi9zYWxzYS50cyc7XG4vLyBpbXBvcnQgeyBjaGFjaGEyMHBvbHkxMzA1LCB4Y2hhY2hhMjBwb2x5MTMwNSB9IGZyb20gJy4uL2NoYWNoYS50cyc7XG5cbi8vIGNvbnN0IHdzaXYgPSBtYW5hZ2VkTm9uY2Uoc2l2KTtcbi8vIGNvbnN0IHdnY20gPSBtYW5hZ2VkTm9uY2UoZ2NtKTtcbi8vIGNvbnN0IHdjdHIgPSBtYW5hZ2VkTm9uY2UoY3RyKTtcbi8vIGNvbnN0IHdjYmMgPSBtYW5hZ2VkTm9uY2UoY2JjKTtcbi8vIGNvbnN0IHdzYWxzYXBvbHkgPSBtYW5hZ2VkTm9uY2UoeHNhbHNhMjBwb2x5MTMwNSk7XG4vLyBjb25zdCB3Y2hhY2hhID0gbWFuYWdlZE5vbmNlKGNoYWNoYTIwcG9seTEzMDUpO1xuLy8gY29uc3Qgd3hjaGFjaGEgPSBtYW5hZ2VkTm9uY2UoeGNoYWNoYTIwcG9seTEzMDUpO1xuXG4vLyAvLyBzaG91bGQgZmFpbFxuLy8gY29uc3Qgd2NiYzIgPSBtYW5hZ2VkTm9uY2UobWFuYWdlZE5vbmNlKGNiYykpO1xuLy8gY29uc3Qgd2N0ciA9IG1hbmFnZWROb25jZShjdHIpO1xuIiwgIi8vIFN5bW1ldHJpYyBlbmNyeXB0aW9uIHVzaW5nIENoYUNoYTIwLVBvbHkxMzA1XG5cbmltcG9ydCB7IGNoYWNoYTIwcG9seTEzMDUgfSBmcm9tICdAbm9ibGUvY2lwaGVycy9jaGFjaGEnO1xuaW1wb3J0IHsgcmFuZG9tQnl0ZXMgfSBmcm9tICdAbm9ibGUvY2lwaGVycy93ZWJjcnlwdG8nO1xuaW1wb3J0IHR5cGUgeyBTeW1tZXRyaWNFbmNyeXB0ZWRNZXNzYWdlIH0gZnJvbSAnLi90eXBlcy5qcyc7XG5pbXBvcnQgeyB0b0Jhc2U2NCwgZnJvbUJhc2U2NCwgemVyb0ZpbGwgfSBmcm9tICcuL3V0aWxzLmpzJztcblxuY29uc3QgTk9OQ0VfTEVOR1RIID0gMTI7IC8vIENoYUNoYTIwLVBvbHkxMzA1IHVzZXMgMTItYnl0ZSBub25jZVxuXG4vKipcbiAqIEVuY3J5cHQgYSBtZXNzYWdlIHVzaW5nIENoYUNoYTIwLVBvbHkxMzA1IHN5bW1ldHJpYyBlbmNyeXB0aW9uLlxuICogVGhlIGtleSBpcyByZWNlaXZlZCBmcm9tIEMjIChXQVNNIG1lbW9yeSkgYW5kIHplcm9lZCBhZnRlciB1c2UuXG4gKlxuICogQHBhcmFtIG1lc3NhZ2UgVGhlIHBsYWludGV4dCBtZXNzYWdlIHRvIGVuY3J5cHRcbiAqIEBwYXJhbSBrZXlCYXNlNjQgVGhlIDMyLWJ5dGUgc3ltbWV0cmljIGtleSAoQmFzZTY0IGVuY29kZWQgZnJvbSBDIylcbiAqIEByZXR1cm5zIFN5bW1ldHJpY0VuY3J5cHRlZE1lc3NhZ2Ugd2l0aCBjaXBoZXJ0ZXh0IGFuZCBub25jZVxuICovXG5leHBvcnQgZnVuY3Rpb24gc3ltbWV0cmljRW5jcnlwdChcbiAgICBtZXNzYWdlOiBzdHJpbmcsXG4gICAga2V5QmFzZTY0OiBzdHJpbmdcbik6IFN5bW1ldHJpY0VuY3J5cHRlZE1lc3NhZ2Uge1xuICAgIGNvbnN0IGtleSA9IGZyb21CYXNlNjQoa2V5QmFzZTY0KTtcblxuICAgIHRyeSB7XG4gICAgICAgIGlmIChrZXkubGVuZ3RoICE9PSAzMikge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKGBTeW1tZXRyaWMga2V5IG11c3QgYmUgMzIgYnl0ZXMsIGdvdCAke2tleS5sZW5ndGh9YCk7XG4gICAgICAgIH1cblxuICAgICAgICAvLyBHZW5lcmF0ZSByYW5kb20gbm9uY2VcbiAgICAgICAgY29uc3Qgbm9uY2UgPSByYW5kb21CeXRlcyhOT05DRV9MRU5HVEgpO1xuXG4gICAgICAgIC8vIEVuY29kZSBtZXNzYWdlIHRvIGJ5dGVzXG4gICAgICAgIGNvbnN0IGVuY29kZXIgPSBuZXcgVGV4dEVuY29kZXIoKTtcbiAgICAgICAgY29uc3QgcGxhaW50ZXh0ID0gZW5jb2Rlci5lbmNvZGUobWVzc2FnZSk7XG5cbiAgICAgICAgLy8gRW5jcnlwdCB3aXRoIENoYUNoYTIwLVBvbHkxMzA1XG4gICAgICAgIGNvbnN0IGNpcGhlciA9IGNoYWNoYTIwcG9seTEzMDUoa2V5LCBub25jZSk7XG4gICAgICAgIGNvbnN0IGNpcGhlcnRleHQgPSBjaXBoZXIuZW5jcnlwdChwbGFpbnRleHQpO1xuXG4gICAgICAgIHJldHVybiB7XG4gICAgICAgICAgICBjaXBoZXJ0ZXh0OiB0b0Jhc2U2NChjaXBoZXJ0ZXh0KSxcbiAgICAgICAgICAgIG5vbmNlOiB0b0Jhc2U2NChub25jZSlcbiAgICAgICAgfTtcbiAgICB9IGZpbmFsbHkge1xuICAgICAgICAvLyBBbHdheXMgemVybyB0aGUga2V5IGFmdGVyIHVzZVxuICAgICAgICB6ZXJvRmlsbChrZXkpO1xuICAgIH1cbn1cblxuLyoqXG4gKiBEZWNyeXB0IGEgbWVzc2FnZSB1c2luZyBDaGFDaGEyMC1Qb2x5MTMwNSBzeW1tZXRyaWMgZW5jcnlwdGlvbi5cbiAqIFRoZSBrZXkgaXMgcmVjZWl2ZWQgZnJvbSBDIyAoV0FTTSBtZW1vcnkpIGFuZCB6ZXJvZWQgYWZ0ZXIgdXNlLlxuICpcbiAqIEBwYXJhbSBlbmNyeXB0ZWQgVGhlIGVuY3J5cHRlZCBtZXNzYWdlIHdpdGggY2lwaGVydGV4dCBhbmQgbm9uY2VcbiAqIEBwYXJhbSBrZXlCYXNlNjQgVGhlIDMyLWJ5dGUgc3ltbWV0cmljIGtleSAoQmFzZTY0IGVuY29kZWQgZnJvbSBDIylcbiAqIEByZXR1cm5zIFRoZSBkZWNyeXB0ZWQgcGxhaW50ZXh0IG1lc3NhZ2VcbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIHN5bW1ldHJpY0RlY3J5cHQoXG4gICAgZW5jcnlwdGVkOiBTeW1tZXRyaWNFbmNyeXB0ZWRNZXNzYWdlLFxuICAgIGtleUJhc2U2NDogc3RyaW5nXG4pOiBzdHJpbmcge1xuICAgIGNvbnN0IGtleSA9IGZyb21CYXNlNjQoa2V5QmFzZTY0KTtcblxuICAgIHRyeSB7XG4gICAgICAgIGlmIChrZXkubGVuZ3RoICE9PSAzMikge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKGBTeW1tZXRyaWMga2V5IG11c3QgYmUgMzIgYnl0ZXMsIGdvdCAke2tleS5sZW5ndGh9YCk7XG4gICAgICAgIH1cblxuICAgICAgICBjb25zdCBjaXBoZXJ0ZXh0ID0gZnJvbUJhc2U2NChlbmNyeXB0ZWQuY2lwaGVydGV4dCk7XG4gICAgICAgIGNvbnN0IG5vbmNlID0gZnJvbUJhc2U2NChlbmNyeXB0ZWQubm9uY2UpO1xuXG4gICAgICAgIGlmIChub25jZS5sZW5ndGggIT09IE5PTkNFX0xFTkdUSCkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKGBOb25jZSBtdXN0IGJlICR7Tk9OQ0VfTEVOR1RIfSBieXRlcywgZ290ICR7bm9uY2UubGVuZ3RofWApO1xuICAgICAgICB9XG5cbiAgICAgICAgLy8gRGVjcnlwdCB3aXRoIENoYUNoYTIwLVBvbHkxMzA1XG4gICAgICAgIGNvbnN0IGNpcGhlciA9IGNoYWNoYTIwcG9seTEzMDUoa2V5LCBub25jZSk7XG4gICAgICAgIGNvbnN0IHBsYWludGV4dCA9IGNpcGhlci5kZWNyeXB0KGNpcGhlcnRleHQpO1xuXG4gICAgICAgIC8vIERlY29kZSBieXRlcyB0byBzdHJpbmdcbiAgICAgICAgY29uc3QgZGVjb2RlciA9IG5ldyBUZXh0RGVjb2RlcigpO1xuICAgICAgICByZXR1cm4gZGVjb2Rlci5kZWNvZGUocGxhaW50ZXh0KTtcbiAgICB9IGZpbmFsbHkge1xuICAgICAgICAvLyBBbHdheXMgemVybyB0aGUga2V5IGFmdGVyIHVzZVxuICAgICAgICB6ZXJvRmlsbChrZXkpO1xuICAgIH1cbn1cbiIsICIvKipcbiAqIEhNQUM6IFJGQzIxMDQgbWVzc2FnZSBhdXRoZW50aWNhdGlvbiBjb2RlLlxuICogQG1vZHVsZVxuICovXG5pbXBvcnQgeyBhYnl0ZXMsIGFleGlzdHMsIGFoYXNoLCBjbGVhbiwgSGFzaCwgdG9CeXRlcywgdHlwZSBDSGFzaCwgdHlwZSBJbnB1dCB9IGZyb20gJy4vdXRpbHMudHMnO1xuXG5leHBvcnQgY2xhc3MgSE1BQzxUIGV4dGVuZHMgSGFzaDxUPj4gZXh0ZW5kcyBIYXNoPEhNQUM8VD4+IHtcbiAgb0hhc2g6IFQ7XG4gIGlIYXNoOiBUO1xuICBibG9ja0xlbjogbnVtYmVyO1xuICBvdXRwdXRMZW46IG51bWJlcjtcbiAgcHJpdmF0ZSBmaW5pc2hlZCA9IGZhbHNlO1xuICBwcml2YXRlIGRlc3Ryb3llZCA9IGZhbHNlO1xuXG4gIGNvbnN0cnVjdG9yKGhhc2g6IENIYXNoLCBfa2V5OiBJbnB1dCkge1xuICAgIHN1cGVyKCk7XG4gICAgYWhhc2goaGFzaCk7XG4gICAgY29uc3Qga2V5ID0gdG9CeXRlcyhfa2V5KTtcbiAgICB0aGlzLmlIYXNoID0gaGFzaC5jcmVhdGUoKSBhcyBUO1xuICAgIGlmICh0eXBlb2YgdGhpcy5pSGFzaC51cGRhdGUgIT09ICdmdW5jdGlvbicpXG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ0V4cGVjdGVkIGluc3RhbmNlIG9mIGNsYXNzIHdoaWNoIGV4dGVuZHMgdXRpbHMuSGFzaCcpO1xuICAgIHRoaXMuYmxvY2tMZW4gPSB0aGlzLmlIYXNoLmJsb2NrTGVuO1xuICAgIHRoaXMub3V0cHV0TGVuID0gdGhpcy5pSGFzaC5vdXRwdXRMZW47XG4gICAgY29uc3QgYmxvY2tMZW4gPSB0aGlzLmJsb2NrTGVuO1xuICAgIGNvbnN0IHBhZCA9IG5ldyBVaW50OEFycmF5KGJsb2NrTGVuKTtcbiAgICAvLyBibG9ja0xlbiBjYW4gYmUgYmlnZ2VyIHRoYW4gb3V0cHV0TGVuXG4gICAgcGFkLnNldChrZXkubGVuZ3RoID4gYmxvY2tMZW4gPyBoYXNoLmNyZWF0ZSgpLnVwZGF0ZShrZXkpLmRpZ2VzdCgpIDoga2V5KTtcbiAgICBmb3IgKGxldCBpID0gMDsgaSA8IHBhZC5sZW5ndGg7IGkrKykgcGFkW2ldIF49IDB4MzY7XG4gICAgdGhpcy5pSGFzaC51cGRhdGUocGFkKTtcbiAgICAvLyBCeSBkb2luZyB1cGRhdGUgKHByb2Nlc3Npbmcgb2YgZmlyc3QgYmxvY2spIG9mIG91dGVyIGhhc2ggaGVyZSB3ZSBjYW4gcmUtdXNlIGl0IGJldHdlZW4gbXVsdGlwbGUgY2FsbHMgdmlhIGNsb25lXG4gICAgdGhpcy5vSGFzaCA9IGhhc2guY3JlYXRlKCkgYXMgVDtcbiAgICAvLyBVbmRvIGludGVybmFsIFhPUiAmJiBhcHBseSBvdXRlciBYT1JcbiAgICBmb3IgKGxldCBpID0gMDsgaSA8IHBhZC5sZW5ndGg7IGkrKykgcGFkW2ldIF49IDB4MzYgXiAweDVjO1xuICAgIHRoaXMub0hhc2gudXBkYXRlKHBhZCk7XG4gICAgY2xlYW4ocGFkKTtcbiAgfVxuICB1cGRhdGUoYnVmOiBJbnB1dCk6IHRoaXMge1xuICAgIGFleGlzdHModGhpcyk7XG4gICAgdGhpcy5pSGFzaC51cGRhdGUoYnVmKTtcbiAgICByZXR1cm4gdGhpcztcbiAgfVxuICBkaWdlc3RJbnRvKG91dDogVWludDhBcnJheSk6IHZvaWQge1xuICAgIGFleGlzdHModGhpcyk7XG4gICAgYWJ5dGVzKG91dCwgdGhpcy5vdXRwdXRMZW4pO1xuICAgIHRoaXMuZmluaXNoZWQgPSB0cnVlO1xuICAgIHRoaXMuaUhhc2guZGlnZXN0SW50byhvdXQpO1xuICAgIHRoaXMub0hhc2gudXBkYXRlKG91dCk7XG4gICAgdGhpcy5vSGFzaC5kaWdlc3RJbnRvKG91dCk7XG4gICAgdGhpcy5kZXN0cm95KCk7XG4gIH1cbiAgZGlnZXN0KCk6IFVpbnQ4QXJyYXkge1xuICAgIGNvbnN0IG91dCA9IG5ldyBVaW50OEFycmF5KHRoaXMub0hhc2gub3V0cHV0TGVuKTtcbiAgICB0aGlzLmRpZ2VzdEludG8ob3V0KTtcbiAgICByZXR1cm4gb3V0O1xuICB9XG4gIF9jbG9uZUludG8odG8/OiBITUFDPFQ+KTogSE1BQzxUPiB7XG4gICAgLy8gQ3JlYXRlIG5ldyBpbnN0YW5jZSB3aXRob3V0IGNhbGxpbmcgY29uc3RydWN0b3Igc2luY2Uga2V5IGFscmVhZHkgaW4gc3RhdGUgYW5kIHdlIGRvbid0IGtub3cgaXQuXG4gICAgdG8gfHw9IE9iamVjdC5jcmVhdGUoT2JqZWN0LmdldFByb3RvdHlwZU9mKHRoaXMpLCB7fSk7XG4gICAgY29uc3QgeyBvSGFzaCwgaUhhc2gsIGZpbmlzaGVkLCBkZXN0cm95ZWQsIGJsb2NrTGVuLCBvdXRwdXRMZW4gfSA9IHRoaXM7XG4gICAgdG8gPSB0byBhcyB0aGlzO1xuICAgIHRvLmZpbmlzaGVkID0gZmluaXNoZWQ7XG4gICAgdG8uZGVzdHJveWVkID0gZGVzdHJveWVkO1xuICAgIHRvLmJsb2NrTGVuID0gYmxvY2tMZW47XG4gICAgdG8ub3V0cHV0TGVuID0gb3V0cHV0TGVuO1xuICAgIHRvLm9IYXNoID0gb0hhc2guX2Nsb25lSW50byh0by5vSGFzaCk7XG4gICAgdG8uaUhhc2ggPSBpSGFzaC5fY2xvbmVJbnRvKHRvLmlIYXNoKTtcbiAgICByZXR1cm4gdG87XG4gIH1cbiAgY2xvbmUoKTogSE1BQzxUPiB7XG4gICAgcmV0dXJuIHRoaXMuX2Nsb25lSW50bygpO1xuICB9XG4gIGRlc3Ryb3koKTogdm9pZCB7XG4gICAgdGhpcy5kZXN0cm95ZWQgPSB0cnVlO1xuICAgIHRoaXMub0hhc2guZGVzdHJveSgpO1xuICAgIHRoaXMuaUhhc2guZGVzdHJveSgpO1xuICB9XG59XG5cbi8qKlxuICogSE1BQzogUkZDMjEwNCBtZXNzYWdlIGF1dGhlbnRpY2F0aW9uIGNvZGUuXG4gKiBAcGFyYW0gaGFzaCAtIGZ1bmN0aW9uIHRoYXQgd291bGQgYmUgdXNlZCBlLmcuIHNoYTI1NlxuICogQHBhcmFtIGtleSAtIG1lc3NhZ2Uga2V5XG4gKiBAcGFyYW0gbWVzc2FnZSAtIG1lc3NhZ2UgZGF0YVxuICogQGV4YW1wbGVcbiAqIGltcG9ydCB7IGhtYWMgfSBmcm9tICdAbm9ibGUvaGFzaGVzL2htYWMnO1xuICogaW1wb3J0IHsgc2hhMjU2IH0gZnJvbSAnQG5vYmxlL2hhc2hlcy9zaGEyJztcbiAqIGNvbnN0IG1hYzEgPSBobWFjKHNoYTI1NiwgJ2tleScsICdtZXNzYWdlJyk7XG4gKi9cbmV4cG9ydCBjb25zdCBobWFjOiB7XG4gIChoYXNoOiBDSGFzaCwga2V5OiBJbnB1dCwgbWVzc2FnZTogSW5wdXQpOiBVaW50OEFycmF5O1xuICBjcmVhdGUoaGFzaDogQ0hhc2gsIGtleTogSW5wdXQpOiBITUFDPGFueT47XG59ID0gKGhhc2g6IENIYXNoLCBrZXk6IElucHV0LCBtZXNzYWdlOiBJbnB1dCk6IFVpbnQ4QXJyYXkgPT5cbiAgbmV3IEhNQUM8YW55PihoYXNoLCBrZXkpLnVwZGF0ZShtZXNzYWdlKS5kaWdlc3QoKTtcbmhtYWMuY3JlYXRlID0gKGhhc2g6IENIYXNoLCBrZXk6IElucHV0KSA9PiBuZXcgSE1BQzxhbnk+KGhhc2gsIGtleSk7XG4iLCAiLyoqXG4gKiBIS0RGIChSRkMgNTg2OSk6IGV4dHJhY3QgKyBleHBhbmQgaW4gb25lIHN0ZXAuXG4gKiBTZWUgaHR0cHM6Ly9zb2F0b2suYmxvZy8yMDIxLzExLzE3L3VuZGVyc3RhbmRpbmctaGtkZi8uXG4gKiBAbW9kdWxlXG4gKi9cbmltcG9ydCB7IGhtYWMgfSBmcm9tICcuL2htYWMudHMnO1xuaW1wb3J0IHsgYWhhc2gsIGFudW1iZXIsIHR5cGUgQ0hhc2gsIGNsZWFuLCB0eXBlIElucHV0LCB0b0J5dGVzIH0gZnJvbSAnLi91dGlscy50cyc7XG5cbi8qKlxuICogSEtERi1leHRyYWN0IGZyb20gc3BlYy4gTGVzcyBpbXBvcnRhbnQgcGFydC4gYEhLREYtRXh0cmFjdChJS00sIHNhbHQpIC0+IFBSS2BcbiAqIEFyZ3VtZW50cyBwb3NpdGlvbiBkaWZmZXJzIGZyb20gc3BlYyAoSUtNIGlzIGZpcnN0IG9uZSwgc2luY2UgaXQgaXMgbm90IG9wdGlvbmFsKVxuICogQHBhcmFtIGhhc2ggLSBoYXNoIGZ1bmN0aW9uIHRoYXQgd291bGQgYmUgdXNlZCAoZS5nLiBzaGEyNTYpXG4gKiBAcGFyYW0gaWttIC0gaW5wdXQga2V5aW5nIG1hdGVyaWFsLCB0aGUgaW5pdGlhbCBrZXlcbiAqIEBwYXJhbSBzYWx0IC0gb3B0aW9uYWwgc2FsdCB2YWx1ZSAoYSBub24tc2VjcmV0IHJhbmRvbSB2YWx1ZSlcbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGV4dHJhY3QoaGFzaDogQ0hhc2gsIGlrbTogSW5wdXQsIHNhbHQ/OiBJbnB1dCk6IFVpbnQ4QXJyYXkge1xuICBhaGFzaChoYXNoKTtcbiAgLy8gTk9URTogc29tZSBsaWJyYXJpZXMgdHJlYXQgemVyby1sZW5ndGggYXJyYXkgYXMgJ25vdCBwcm92aWRlZCc7XG4gIC8vIHdlIGRvbid0LCBzaW5jZSB3ZSBoYXZlIHVuZGVmaW5lZCBhcyAnbm90IHByb3ZpZGVkJ1xuICAvLyBodHRwczovL2dpdGh1Yi5jb20vUnVzdENyeXB0by9LREZzL2lzc3Vlcy8xNVxuICBpZiAoc2FsdCA9PT0gdW5kZWZpbmVkKSBzYWx0ID0gbmV3IFVpbnQ4QXJyYXkoaGFzaC5vdXRwdXRMZW4pO1xuICByZXR1cm4gaG1hYyhoYXNoLCB0b0J5dGVzKHNhbHQpLCB0b0J5dGVzKGlrbSkpO1xufVxuXG5jb25zdCBIS0RGX0NPVU5URVIgPSAvKiBAX19QVVJFX18gKi8gVWludDhBcnJheS5mcm9tKFswXSk7XG5jb25zdCBFTVBUWV9CVUZGRVIgPSAvKiBAX19QVVJFX18gKi8gVWludDhBcnJheS5vZigpO1xuXG4vKipcbiAqIEhLREYtZXhwYW5kIGZyb20gdGhlIHNwZWMuIFRoZSBtb3N0IGltcG9ydGFudCBwYXJ0LiBgSEtERi1FeHBhbmQoUFJLLCBpbmZvLCBMKSAtPiBPS01gXG4gKiBAcGFyYW0gaGFzaCAtIGhhc2ggZnVuY3Rpb24gdGhhdCB3b3VsZCBiZSB1c2VkIChlLmcuIHNoYTI1NilcbiAqIEBwYXJhbSBwcmsgLSBhIHBzZXVkb3JhbmRvbSBrZXkgb2YgYXQgbGVhc3QgSGFzaExlbiBvY3RldHMgKHVzdWFsbHksIHRoZSBvdXRwdXQgZnJvbSB0aGUgZXh0cmFjdCBzdGVwKVxuICogQHBhcmFtIGluZm8gLSBvcHRpb25hbCBjb250ZXh0IGFuZCBhcHBsaWNhdGlvbiBzcGVjaWZpYyBpbmZvcm1hdGlvbiAoY2FuIGJlIGEgemVyby1sZW5ndGggc3RyaW5nKVxuICogQHBhcmFtIGxlbmd0aCAtIGxlbmd0aCBvZiBvdXRwdXQga2V5aW5nIG1hdGVyaWFsIGluIGJ5dGVzXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBleHBhbmQoaGFzaDogQ0hhc2gsIHByazogSW5wdXQsIGluZm8/OiBJbnB1dCwgbGVuZ3RoOiBudW1iZXIgPSAzMik6IFVpbnQ4QXJyYXkge1xuICBhaGFzaChoYXNoKTtcbiAgYW51bWJlcihsZW5ndGgpO1xuICBjb25zdCBvbGVuID0gaGFzaC5vdXRwdXRMZW47XG4gIGlmIChsZW5ndGggPiAyNTUgKiBvbGVuKSB0aHJvdyBuZXcgRXJyb3IoJ0xlbmd0aCBzaG91bGQgYmUgPD0gMjU1Kkhhc2hMZW4nKTtcbiAgY29uc3QgYmxvY2tzID0gTWF0aC5jZWlsKGxlbmd0aCAvIG9sZW4pO1xuICBpZiAoaW5mbyA9PT0gdW5kZWZpbmVkKSBpbmZvID0gRU1QVFlfQlVGRkVSO1xuICAvLyBmaXJzdCBMKGVuZ3RoKSBvY3RldHMgb2YgVFxuICBjb25zdCBva20gPSBuZXcgVWludDhBcnJheShibG9ja3MgKiBvbGVuKTtcbiAgLy8gUmUtdXNlIEhNQUMgaW5zdGFuY2UgYmV0d2VlbiBibG9ja3NcbiAgY29uc3QgSE1BQyA9IGhtYWMuY3JlYXRlKGhhc2gsIHByayk7XG4gIGNvbnN0IEhNQUNUbXAgPSBITUFDLl9jbG9uZUludG8oKTtcbiAgY29uc3QgVCA9IG5ldyBVaW50OEFycmF5KEhNQUMub3V0cHV0TGVuKTtcbiAgZm9yIChsZXQgY291bnRlciA9IDA7IGNvdW50ZXIgPCBibG9ja3M7IGNvdW50ZXIrKykge1xuICAgIEhLREZfQ09VTlRFUlswXSA9IGNvdW50ZXIgKyAxO1xuICAgIC8vIFQoMCkgPSBlbXB0eSBzdHJpbmcgKHplcm8gbGVuZ3RoKVxuICAgIC8vIFQoTikgPSBITUFDLUhhc2goUFJLLCBUKE4tMSkgfCBpbmZvIHwgTilcbiAgICBITUFDVG1wLnVwZGF0ZShjb3VudGVyID09PSAwID8gRU1QVFlfQlVGRkVSIDogVClcbiAgICAgIC51cGRhdGUoaW5mbylcbiAgICAgIC51cGRhdGUoSEtERl9DT1VOVEVSKVxuICAgICAgLmRpZ2VzdEludG8oVCk7XG4gICAgb2ttLnNldChULCBvbGVuICogY291bnRlcik7XG4gICAgSE1BQy5fY2xvbmVJbnRvKEhNQUNUbXApO1xuICB9XG4gIEhNQUMuZGVzdHJveSgpO1xuICBITUFDVG1wLmRlc3Ryb3koKTtcbiAgY2xlYW4oVCwgSEtERl9DT1VOVEVSKTtcbiAgcmV0dXJuIG9rbS5zbGljZSgwLCBsZW5ndGgpO1xufVxuXG4vKipcbiAqIEhLREYgKFJGQyA1ODY5KTogZGVyaXZlIGtleXMgZnJvbSBhbiBpbml0aWFsIGlucHV0LlxuICogQ29tYmluZXMgaGtkZl9leHRyYWN0ICsgaGtkZl9leHBhbmQgaW4gb25lIHN0ZXBcbiAqIEBwYXJhbSBoYXNoIC0gaGFzaCBmdW5jdGlvbiB0aGF0IHdvdWxkIGJlIHVzZWQgKGUuZy4gc2hhMjU2KVxuICogQHBhcmFtIGlrbSAtIGlucHV0IGtleWluZyBtYXRlcmlhbCwgdGhlIGluaXRpYWwga2V5XG4gKiBAcGFyYW0gc2FsdCAtIG9wdGlvbmFsIHNhbHQgdmFsdWUgKGEgbm9uLXNlY3JldCByYW5kb20gdmFsdWUpXG4gKiBAcGFyYW0gaW5mbyAtIG9wdGlvbmFsIGNvbnRleHQgYW5kIGFwcGxpY2F0aW9uIHNwZWNpZmljIGluZm9ybWF0aW9uIChjYW4gYmUgYSB6ZXJvLWxlbmd0aCBzdHJpbmcpXG4gKiBAcGFyYW0gbGVuZ3RoIC0gbGVuZ3RoIG9mIG91dHB1dCBrZXlpbmcgbWF0ZXJpYWwgaW4gYnl0ZXNcbiAqIEBleGFtcGxlXG4gKiBpbXBvcnQgeyBoa2RmIH0gZnJvbSAnQG5vYmxlL2hhc2hlcy9oa2RmJztcbiAqIGltcG9ydCB7IHNoYTI1NiB9IGZyb20gJ0Bub2JsZS9oYXNoZXMvc2hhMic7XG4gKiBpbXBvcnQgeyByYW5kb21CeXRlcyB9IGZyb20gJ0Bub2JsZS9oYXNoZXMvdXRpbHMnO1xuICogY29uc3QgaW5wdXRLZXkgPSByYW5kb21CeXRlcygzMik7XG4gKiBjb25zdCBzYWx0ID0gcmFuZG9tQnl0ZXMoMzIpO1xuICogY29uc3QgaW5mbyA9ICdhcHBsaWNhdGlvbi1rZXknO1xuICogY29uc3QgaGsxID0gaGtkZihzaGEyNTYsIGlucHV0S2V5LCBzYWx0LCBpbmZvLCAzMik7XG4gKi9cbmV4cG9ydCBjb25zdCBoa2RmID0gKFxuICBoYXNoOiBDSGFzaCxcbiAgaWttOiBJbnB1dCxcbiAgc2FsdDogSW5wdXQgfCB1bmRlZmluZWQsXG4gIGluZm86IElucHV0IHwgdW5kZWZpbmVkLFxuICBsZW5ndGg6IG51bWJlclxuKTogVWludDhBcnJheSA9PiBleHBhbmQoaGFzaCwgZXh0cmFjdChoYXNoLCBpa20sIHNhbHQpLCBpbmZvLCBsZW5ndGgpO1xuIiwgIi8vIEVDSUVTIGFzeW1tZXRyaWMgZW5jcnlwdGlvbiB1c2luZyBYMjU1MTkgKyBDaGFDaGEyMC1Qb2x5MTMwNVxuXG5pbXBvcnQgeyBjaGFjaGEyMHBvbHkxMzA1IH0gZnJvbSAnQG5vYmxlL2NpcGhlcnMvY2hhY2hhJztcbmltcG9ydCB7IHJhbmRvbUJ5dGVzIH0gZnJvbSAnQG5vYmxlL2NpcGhlcnMvd2ViY3J5cHRvJztcbmltcG9ydCB7IGhrZGYgfSBmcm9tICdAbm9ibGUvaGFzaGVzL2hrZGYnO1xuaW1wb3J0IHsgc2hhMjU2IH0gZnJvbSAnQG5vYmxlL2hhc2hlcy9zaGEyNTYnO1xuaW1wb3J0IHR5cGUgeyBFbmNyeXB0ZWRNZXNzYWdlIH0gZnJvbSAnLi90eXBlcy5qcyc7XG5pbXBvcnQgeyB0b0Jhc2U2NCwgZnJvbUJhc2U2NCwgemVyb0ZpbGwgfSBmcm9tICcuL3V0aWxzLmpzJztcbmltcG9ydCB7IGdlbmVyYXRlRXBoZW1lcmFsS2V5cGFpciwgY29tcHV0ZVNoYXJlZFNlY3JldCB9IGZyb20gJy4va2V5cGFpci5qcyc7XG5cbmNvbnN0IE5PTkNFX0xFTkdUSCA9IDEyO1xuY29uc3QgSEtERl9JTkZPID0gbmV3IFRleHRFbmNvZGVyKCkuZW5jb2RlKCdCbGF6b3JQUkYtRUNJRVMtdjEnKTtcblxuLyoqXG4gKiBEZXJpdmUgYW4gZW5jcnlwdGlvbiBrZXkgZnJvbSBzaGFyZWQgc2VjcmV0IHVzaW5nIEhLREYuXG4gKlxuICogQHBhcmFtIHNoYXJlZFNlY3JldCBUaGUgRUNESCBzaGFyZWQgc2VjcmV0XG4gKiBAcGFyYW0gZXBoZW1lcmFsUHVibGljS2V5IFRoZSBlcGhlbWVyYWwgcHVibGljIGtleSAodXNlZCBhcyBzYWx0KVxuICogQHJldHVybnMgMzItYnl0ZSBlbmNyeXB0aW9uIGtleVxuICovXG5mdW5jdGlvbiBkZXJpdmVFbmNyeXB0aW9uS2V5KFxuICAgIHNoYXJlZFNlY3JldDogVWludDhBcnJheSxcbiAgICBlcGhlbWVyYWxQdWJsaWNLZXk6IFVpbnQ4QXJyYXlcbik6IFVpbnQ4QXJyYXkge1xuICAgIHJldHVybiBoa2RmKFxuICAgICAgICBzaGEyNTYsXG4gICAgICAgIHNoYXJlZFNlY3JldCxcbiAgICAgICAgZXBoZW1lcmFsUHVibGljS2V5LCAvLyBVc2UgZXBoZW1lcmFsIHB1YmxpYyBrZXkgYXMgc2FsdFxuICAgICAgICBIS0RGX0lORk8sXG4gICAgICAgIDMyXG4gICAgKTtcbn1cblxuLyoqXG4gKiBFbmNyeXB0IGEgbWVzc2FnZSB1c2luZyBFQ0lFUyBwYXR0ZXJuOlxuICogMS4gR2VuZXJhdGUgZXBoZW1lcmFsIFgyNTUxOSBrZXlwYWlyXG4gKiAyLiBDb21wdXRlIEVDREggc2hhcmVkIHNlY3JldCB3aXRoIHJlY2lwaWVudCdzIHB1YmxpYyBrZXlcbiAqIDMuIERlcml2ZSBlbmNyeXB0aW9uIGtleSB1c2luZyBIS0RGXG4gKiA0LiBFbmNyeXB0IG1lc3NhZ2Ugd2l0aCBDaGFDaGEyMC1Qb2x5MTMwNVxuICpcbiAqIFRoaXMgZnVuY3Rpb24gZG9lcyBOT1QgcmVxdWlyZSB0aGUgcmVjaXBpZW50J3MgcHJpdmF0ZSBrZXkuXG4gKiBBbnlvbmUgY2FuIGVuY3J5cHQgdG8gYSBwdWJsaWMga2V5LlxuICpcbiAqIEBwYXJhbSBtZXNzYWdlIFRoZSBwbGFpbnRleHQgbWVzc2FnZSB0byBlbmNyeXB0XG4gKiBAcGFyYW0gcmVjaXBpZW50UHVibGljS2V5QmFzZTY0IFRoZSByZWNpcGllbnQncyBYMjU1MTkgcHVibGljIGtleSAoQmFzZTY0KVxuICogQHJldHVybnMgRW5jcnlwdGVkTWVzc2FnZSB3aXRoIGVwaGVtZXJhbCBwdWJsaWMga2V5LCBjaXBoZXJ0ZXh0LCBhbmQgbm9uY2VcbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGFzeW1tZXRyaWNFbmNyeXB0KFxuICAgIG1lc3NhZ2U6IHN0cmluZyxcbiAgICByZWNpcGllbnRQdWJsaWNLZXlCYXNlNjQ6IHN0cmluZ1xuKTogRW5jcnlwdGVkTWVzc2FnZSB7XG4gICAgY29uc3QgcmVjaXBpZW50UHVibGljS2V5ID0gZnJvbUJhc2U2NChyZWNpcGllbnRQdWJsaWNLZXlCYXNlNjQpO1xuXG4gICAgaWYgKHJlY2lwaWVudFB1YmxpY0tleS5sZW5ndGggIT09IDMyKSB7XG4gICAgICAgIHRocm93IG5ldyBFcnJvcihgUmVjaXBpZW50IHB1YmxpYyBrZXkgbXVzdCBiZSAzMiBieXRlcywgZ290ICR7cmVjaXBpZW50UHVibGljS2V5Lmxlbmd0aH1gKTtcbiAgICB9XG5cbiAgICAvLyBHZW5lcmF0ZSBlcGhlbWVyYWwga2V5cGFpciBmb3IgZm9yd2FyZCBzZWNyZWN5XG4gICAgY29uc3QgZXBoZW1lcmFsID0gZ2VuZXJhdGVFcGhlbWVyYWxLZXlwYWlyKCk7XG4gICAgbGV0IHNoYXJlZFNlY3JldDogVWludDhBcnJheSB8IG51bGwgPSBudWxsO1xuICAgIGxldCBlbmNyeXB0aW9uS2V5OiBVaW50OEFycmF5IHwgbnVsbCA9IG51bGw7XG5cbiAgICB0cnkge1xuICAgICAgICAvLyBDb21wdXRlIEVDREggc2hhcmVkIHNlY3JldFxuICAgICAgICBzaGFyZWRTZWNyZXQgPSBjb21wdXRlU2hhcmVkU2VjcmV0KGVwaGVtZXJhbC5wcml2YXRlS2V5LCByZWNpcGllbnRQdWJsaWNLZXkpO1xuXG4gICAgICAgIC8vIERlcml2ZSBlbmNyeXB0aW9uIGtleVxuICAgICAgICBlbmNyeXB0aW9uS2V5ID0gZGVyaXZlRW5jcnlwdGlvbktleShzaGFyZWRTZWNyZXQsIGVwaGVtZXJhbC5wdWJsaWNLZXkpO1xuXG4gICAgICAgIC8vIEdlbmVyYXRlIHJhbmRvbSBub25jZVxuICAgICAgICBjb25zdCBub25jZSA9IHJhbmRvbUJ5dGVzKE5PTkNFX0xFTkdUSCk7XG5cbiAgICAgICAgLy8gRW5jb2RlIG1lc3NhZ2UgdG8gYnl0ZXNcbiAgICAgICAgY29uc3QgZW5jb2RlciA9IG5ldyBUZXh0RW5jb2RlcigpO1xuICAgICAgICBjb25zdCBwbGFpbnRleHQgPSBlbmNvZGVyLmVuY29kZShtZXNzYWdlKTtcblxuICAgICAgICAvLyBFbmNyeXB0IHdpdGggQ2hhQ2hhMjAtUG9seTEzMDVcbiAgICAgICAgY29uc3QgY2lwaGVyID0gY2hhY2hhMjBwb2x5MTMwNShlbmNyeXB0aW9uS2V5LCBub25jZSk7XG4gICAgICAgIGNvbnN0IGNpcGhlcnRleHQgPSBjaXBoZXIuZW5jcnlwdChwbGFpbnRleHQpO1xuXG4gICAgICAgIHJldHVybiB7XG4gICAgICAgICAgICBlcGhlbWVyYWxQdWJsaWNLZXk6IHRvQmFzZTY0KGVwaGVtZXJhbC5wdWJsaWNLZXkpLFxuICAgICAgICAgICAgY2lwaGVydGV4dDogdG9CYXNlNjQoY2lwaGVydGV4dCksXG4gICAgICAgICAgICBub25jZTogdG9CYXNlNjQobm9uY2UpXG4gICAgICAgIH07XG4gICAgfSBmaW5hbGx5IHtcbiAgICAgICAgLy8gWmVybyBhbGwgc2Vuc2l0aXZlIGRhdGFcbiAgICAgICAgemVyb0ZpbGwoZXBoZW1lcmFsLnByaXZhdGVLZXkpO1xuICAgICAgICBpZiAoc2hhcmVkU2VjcmV0KSB7XG4gICAgICAgICAgICB6ZXJvRmlsbChzaGFyZWRTZWNyZXQpO1xuICAgICAgICB9XG4gICAgICAgIGlmIChlbmNyeXB0aW9uS2V5KSB7XG4gICAgICAgICAgICB6ZXJvRmlsbChlbmNyeXB0aW9uS2V5KTtcbiAgICAgICAgfVxuICAgIH1cbn1cblxuLyoqXG4gKiBEZWNyeXB0IGEgbWVzc2FnZSB1c2luZyBFQ0lFUyBwYXR0ZXJuOlxuICogMS4gQ29tcHV0ZSBFQ0RIIHNoYXJlZCBzZWNyZXQgd2l0aCBlcGhlbWVyYWwgcHVibGljIGtleSBhbmQgb3VyIHByaXZhdGUga2V5XG4gKiAyLiBEZXJpdmUgZW5jcnlwdGlvbiBrZXkgdXNpbmcgSEtERlxuICogMy4gRGVjcnlwdCBtZXNzYWdlIHdpdGggQ2hhQ2hhMjAtUG9seTEzMDVcbiAqXG4gKiBUaGUgcHJpdmF0ZSBrZXkgaXMgcmVjZWl2ZWQgZnJvbSBDIyAoV0FTTSBtZW1vcnkpIGFuZCB6ZXJvZWQgYWZ0ZXIgdXNlLlxuICpcbiAqIEBwYXJhbSBlbmNyeXB0ZWQgVGhlIGVuY3J5cHRlZCBtZXNzYWdlXG4gKiBAcGFyYW0gcHJpdmF0ZUtleUJhc2U2NCBPdXIgWDI1NTE5IHByaXZhdGUga2V5IChCYXNlNjQgZW5jb2RlZCBmcm9tIEMjKVxuICogQHJldHVybnMgVGhlIGRlY3J5cHRlZCBwbGFpbnRleHQgbWVzc2FnZVxuICovXG5leHBvcnQgZnVuY3Rpb24gYXN5bW1ldHJpY0RlY3J5cHQoXG4gICAgZW5jcnlwdGVkOiBFbmNyeXB0ZWRNZXNzYWdlLFxuICAgIHByaXZhdGVLZXlCYXNlNjQ6IHN0cmluZ1xuKTogc3RyaW5nIHtcbiAgICBjb25zdCBwcml2YXRlS2V5ID0gZnJvbUJhc2U2NChwcml2YXRlS2V5QmFzZTY0KTtcblxuICAgIGlmIChwcml2YXRlS2V5Lmxlbmd0aCAhPT0gMzIpIHtcbiAgICAgICAgdGhyb3cgbmV3IEVycm9yKGBQcml2YXRlIGtleSBtdXN0IGJlIDMyIGJ5dGVzLCBnb3QgJHtwcml2YXRlS2V5Lmxlbmd0aH1gKTtcbiAgICB9XG5cbiAgICBjb25zdCBlcGhlbWVyYWxQdWJsaWNLZXkgPSBmcm9tQmFzZTY0KGVuY3J5cHRlZC5lcGhlbWVyYWxQdWJsaWNLZXkpO1xuICAgIGNvbnN0IGNpcGhlcnRleHQgPSBmcm9tQmFzZTY0KGVuY3J5cHRlZC5jaXBoZXJ0ZXh0KTtcbiAgICBjb25zdCBub25jZSA9IGZyb21CYXNlNjQoZW5jcnlwdGVkLm5vbmNlKTtcblxuICAgIGlmIChlcGhlbWVyYWxQdWJsaWNLZXkubGVuZ3RoICE9PSAzMikge1xuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoYEVwaGVtZXJhbCBwdWJsaWMga2V5IG11c3QgYmUgMzIgYnl0ZXMsIGdvdCAke2VwaGVtZXJhbFB1YmxpY0tleS5sZW5ndGh9YCk7XG4gICAgfVxuXG4gICAgaWYgKG5vbmNlLmxlbmd0aCAhPT0gTk9OQ0VfTEVOR1RIKSB7XG4gICAgICAgIHRocm93IG5ldyBFcnJvcihgTm9uY2UgbXVzdCBiZSAke05PTkNFX0xFTkdUSH0gYnl0ZXMsIGdvdCAke25vbmNlLmxlbmd0aH1gKTtcbiAgICB9XG5cbiAgICBsZXQgc2hhcmVkU2VjcmV0OiBVaW50OEFycmF5IHwgbnVsbCA9IG51bGw7XG4gICAgbGV0IGVuY3J5cHRpb25LZXk6IFVpbnQ4QXJyYXkgfCBudWxsID0gbnVsbDtcblxuICAgIHRyeSB7XG4gICAgICAgIC8vIENvbXB1dGUgRUNESCBzaGFyZWQgc2VjcmV0XG4gICAgICAgIHNoYXJlZFNlY3JldCA9IGNvbXB1dGVTaGFyZWRTZWNyZXQocHJpdmF0ZUtleSwgZXBoZW1lcmFsUHVibGljS2V5KTtcblxuICAgICAgICAvLyBEZXJpdmUgZW5jcnlwdGlvbiBrZXkgKHNhbWUgZGVyaXZhdGlvbiBhcyBlbmNyeXB0aW9uKVxuICAgICAgICBlbmNyeXB0aW9uS2V5ID0gZGVyaXZlRW5jcnlwdGlvbktleShzaGFyZWRTZWNyZXQsIGVwaGVtZXJhbFB1YmxpY0tleSk7XG5cbiAgICAgICAgLy8gRGVjcnlwdCB3aXRoIENoYUNoYTIwLVBvbHkxMzA1XG4gICAgICAgIGNvbnN0IGNpcGhlciA9IGNoYWNoYTIwcG9seTEzMDUoZW5jcnlwdGlvbktleSwgbm9uY2UpO1xuICAgICAgICBjb25zdCBwbGFpbnRleHQgPSBjaXBoZXIuZGVjcnlwdChjaXBoZXJ0ZXh0KTtcblxuICAgICAgICAvLyBEZWNvZGUgYnl0ZXMgdG8gc3RyaW5nXG4gICAgICAgIGNvbnN0IGRlY29kZXIgPSBuZXcgVGV4dERlY29kZXIoKTtcbiAgICAgICAgcmV0dXJuIGRlY29kZXIuZGVjb2RlKHBsYWludGV4dCk7XG4gICAgfSBmaW5hbGx5IHtcbiAgICAgICAgLy8gWmVybyBhbGwgc2Vuc2l0aXZlIGRhdGFcbiAgICAgICAgemVyb0ZpbGwocHJpdmF0ZUtleSk7XG4gICAgICAgIGlmIChzaGFyZWRTZWNyZXQpIHtcbiAgICAgICAgICAgIHplcm9GaWxsKHNoYXJlZFNlY3JldCk7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKGVuY3J5cHRpb25LZXkpIHtcbiAgICAgICAgICAgIHplcm9GaWxsKGVuY3J5cHRpb25LZXkpO1xuICAgICAgICB9XG4gICAgfVxufVxuIiwgIi8vIE1haW4gZW50cnkgcG9pbnQgLSBleHBvcnRzIGFsbCBmdW5jdGlvbnMgZm9yIEMjIEpTSW1wb3J0XG4vLyBUaGlzIG1vZHVsZSBpcyBTVEFURUxFU1MgLSBubyBrZXkgY2FjaGluZyBpbiBKYXZhU2NyaXB0XG5cbmltcG9ydCB7XG4gICAgUHJmRXJyb3JDb2RlLFxuICAgIHR5cGUgUHJmQ3JlZGVudGlhbCxcbiAgICB0eXBlIFByZk9wdGlvbnMsXG4gICAgdHlwZSBQcmZSZXN1bHQsXG4gICAgdHlwZSBFbmNyeXB0ZWRNZXNzYWdlLFxuICAgIHR5cGUgU3ltbWV0cmljRW5jcnlwdGVkTWVzc2FnZVxufSBmcm9tICcuL3R5cGVzLmpzJztcbmltcG9ydCB7IGNoZWNrUHJmU3VwcG9ydCwgcmVnaXN0ZXJDcmVkZW50aWFsV2l0aFByZiB9IGZyb20gJy4vd2ViYXV0aG4uanMnO1xuaW1wb3J0IHsgZXZhbHVhdGVQcmYsIGV2YWx1YXRlUHJmRGlzY292ZXJhYmxlIH0gZnJvbSAnLi9wcmYuanMnO1xuaW1wb3J0IHsgZGVyaXZlS2V5cGFpckZyb21QcmYgfSBmcm9tICcuL2tleXBhaXIuanMnO1xuaW1wb3J0IHsgc3ltbWV0cmljRW5jcnlwdCwgc3ltbWV0cmljRGVjcnlwdCB9IGZyb20gJy4vc3ltbWV0cmljLmpzJztcbmltcG9ydCB7IGFzeW1tZXRyaWNFbmNyeXB0LCBhc3ltbWV0cmljRGVjcnlwdCB9IGZyb20gJy4vYXN5bW1ldHJpYy5qcyc7XG5pbXBvcnQgeyB0b0Jhc2U2NCwgZnJvbUJhc2U2NCwgemVyb0ZpbGwgfSBmcm9tICcuL3V0aWxzLmpzJztcblxuLy8gPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PVxuLy8gV2ViQXV0aG4gLyBQUkYgRnVuY3Rpb25zXG4vLyA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09XG5cbi8qKlxuICogQ2hlY2sgaWYgUFJGIGV4dGVuc2lvbiBpcyBzdXBwb3J0ZWQuXG4gKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBpc1ByZlN1cHBvcnRlZCgpOiBQcm9taXNlPGJvb2xlYW4+IHtcbiAgICByZXR1cm4gY2hlY2tQcmZTdXBwb3J0KCk7XG59XG5cbi8qKlxuICogUmVnaXN0ZXIgYSBuZXcgY3JlZGVudGlhbCB3aXRoIFBSRiBzdXBwb3J0LlxuICogUmV0dXJucyBKU09OLXNlcmlhbGl6ZWQgUHJmUmVzdWx0PFByZkNyZWRlbnRpYWw+LlxuICovXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gcmVnaXN0ZXIoXG4gICAgZGlzcGxheU5hbWU6IHN0cmluZyB8IG51bGwsXG4gICAgb3B0aW9uc0pzb246IHN0cmluZ1xuKTogUHJvbWlzZTxzdHJpbmc+IHtcbiAgICBjb25zdCBvcHRpb25zOiBQcmZPcHRpb25zID0gSlNPTi5wYXJzZShvcHRpb25zSnNvbik7XG4gICAgY29uc3QgcmVzdWx0ID0gYXdhaXQgcmVnaXN0ZXJDcmVkZW50aWFsV2l0aFByZihkaXNwbGF5TmFtZSwgb3B0aW9ucyk7XG4gICAgcmV0dXJuIEpTT04uc3RyaW5naWZ5KHJlc3VsdCk7XG59XG5cbi8qKlxuICogRGVyaXZlIGtleXMgZnJvbSBQUkYgd2l0aCBhIHNwZWNpZmljIGNyZWRlbnRpYWwuXG4gKiBSZXR1cm5zIEpTT04gd2l0aCBwdWJsaWNLZXlCYXNlNjQgKHByaXZhdGUga2V5IGlzIGNhY2hlZCBpbiBDIykuXG4gKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBkZXJpdmVLZXlzKFxuICAgIGNyZWRlbnRpYWxJZEJhc2U2NDogc3RyaW5nLFxuICAgIHNhbHQ6IHN0cmluZyxcbiAgICBvcHRpb25zSnNvbjogc3RyaW5nXG4pOiBQcm9taXNlPHN0cmluZz4ge1xuICAgIGNvbnN0IG9wdGlvbnM6IFByZk9wdGlvbnMgPSBKU09OLnBhcnNlKG9wdGlvbnNKc29uKTtcblxuICAgIC8vIEV2YWx1YXRlIFBSRiB0byBnZXQgZGV0ZXJtaW5pc3RpYyBvdXRwdXRcbiAgICBjb25zdCBwcmZSZXN1bHQgPSBhd2FpdCBldmFsdWF0ZVByZihjcmVkZW50aWFsSWRCYXNlNjQsIHNhbHQsIG9wdGlvbnMpO1xuXG4gICAgaWYgKCFwcmZSZXN1bHQuc3VjY2VzcyB8fCAhcHJmUmVzdWx0LnZhbHVlKSB7XG4gICAgICAgIHJldHVybiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgICBzdWNjZXNzOiBmYWxzZSxcbiAgICAgICAgICAgIGVycm9yQ29kZTogcHJmUmVzdWx0LmVycm9yQ29kZSxcbiAgICAgICAgICAgIGNhbmNlbGxlZDogcHJmUmVzdWx0LmNhbmNlbGxlZFxuICAgICAgICB9KTtcbiAgICB9XG5cbiAgICAvLyBEZXJpdmUga2V5cGFpciBmcm9tIFBSRiBvdXRwdXRcbiAgICBjb25zdCBwcmZPdXRwdXQgPSBmcm9tQmFzZTY0KHByZlJlc3VsdC52YWx1ZSk7XG4gICAgY29uc3Qga2V5cGFpciA9IGRlcml2ZUtleXBhaXJGcm9tUHJmKHByZk91dHB1dCk7XG5cbiAgICAvLyBDb252ZXJ0IGtleXMgdG8gQmFzZTY0XG4gICAgY29uc3QgcHJpdmF0ZUtleUJhc2U2NCA9IHRvQmFzZTY0KGtleXBhaXIucHJpdmF0ZUtleSk7XG4gICAgY29uc3QgcHVibGljS2V5QmFzZTY0ID0gdG9CYXNlNjQoa2V5cGFpci5wdWJsaWNLZXkpO1xuXG4gICAgLy8gWmVybyBzZW5zaXRpdmUgZGF0YSBpbiBKUyBtZW1vcnlcbiAgICB6ZXJvRmlsbChwcmZPdXRwdXQpO1xuICAgIHplcm9GaWxsKGtleXBhaXIucHJpdmF0ZUtleSk7XG5cbiAgICAvLyBSZXR1cm4gYm90aCBrZXlzIHRvIEMjIC0gQyMgd2lsbCBjYWNoZSBpbiBXQVNNIG1lbW9yeVxuICAgIHJldHVybiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHN1Y2Nlc3M6IHRydWUsXG4gICAgICAgIHZhbHVlOiB7XG4gICAgICAgICAgICBwcml2YXRlS2V5QmFzZTY0LFxuICAgICAgICAgICAgcHVibGljS2V5QmFzZTY0XG4gICAgICAgIH1cbiAgICB9KTtcbn1cblxuLyoqXG4gKiBEZXJpdmUga2V5cyB1c2luZyBkaXNjb3ZlcmFibGUgY3JlZGVudGlhbCAodXNlciBzZWxlY3RzKS5cbiAqIFJldHVybnMgSlNPTiB3aXRoIGNyZWRlbnRpYWxJZCBhbmQga2V5cy5cbiAqL1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGRlcml2ZUtleXNEaXNjb3ZlcmFibGUoXG4gICAgc2FsdDogc3RyaW5nLFxuICAgIG9wdGlvbnNKc29uOiBzdHJpbmdcbik6IFByb21pc2U8c3RyaW5nPiB7XG4gICAgY29uc3Qgb3B0aW9uczogUHJmT3B0aW9ucyA9IEpTT04ucGFyc2Uob3B0aW9uc0pzb24pO1xuXG4gICAgLy8gRXZhbHVhdGUgUFJGIHdpdGggZGlzY292ZXJhYmxlIGNyZWRlbnRpYWxcbiAgICBjb25zdCBwcmZSZXN1bHQgPSBhd2FpdCBldmFsdWF0ZVByZkRpc2NvdmVyYWJsZShzYWx0LCBvcHRpb25zKTtcblxuICAgIGlmICghcHJmUmVzdWx0LnN1Y2Nlc3MgfHwgIXByZlJlc3VsdC52YWx1ZSkge1xuICAgICAgICByZXR1cm4gSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgICAgc3VjY2VzczogZmFsc2UsXG4gICAgICAgICAgICBlcnJvckNvZGU6IHByZlJlc3VsdC5lcnJvckNvZGUsXG4gICAgICAgICAgICBjYW5jZWxsZWQ6IHByZlJlc3VsdC5jYW5jZWxsZWRcbiAgICAgICAgfSk7XG4gICAgfVxuXG4gICAgLy8gRGVyaXZlIGtleXBhaXIgZnJvbSBQUkYgb3V0cHV0XG4gICAgY29uc3QgcHJmT3V0cHV0ID0gZnJvbUJhc2U2NChwcmZSZXN1bHQudmFsdWUucHJmT3V0cHV0KTtcbiAgICBjb25zdCBrZXlwYWlyID0gZGVyaXZlS2V5cGFpckZyb21QcmYocHJmT3V0cHV0KTtcblxuICAgIC8vIENvbnZlcnQga2V5cyB0byBCYXNlNjRcbiAgICBjb25zdCBwcml2YXRlS2V5QmFzZTY0ID0gdG9CYXNlNjQoa2V5cGFpci5wcml2YXRlS2V5KTtcbiAgICBjb25zdCBwdWJsaWNLZXlCYXNlNjQgPSB0b0Jhc2U2NChrZXlwYWlyLnB1YmxpY0tleSk7XG5cbiAgICAvLyBaZXJvIHNlbnNpdGl2ZSBkYXRhIGluIEpTIG1lbW9yeVxuICAgIHplcm9GaWxsKHByZk91dHB1dCk7XG4gICAgemVyb0ZpbGwoa2V5cGFpci5wcml2YXRlS2V5KTtcblxuICAgIC8vIFJldHVybiBjcmVkZW50aWFsIElEIGFuZCBib3RoIGtleXMgdG8gQyNcbiAgICByZXR1cm4gSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICBzdWNjZXNzOiB0cnVlLFxuICAgICAgICB2YWx1ZToge1xuICAgICAgICAgICAgY3JlZGVudGlhbElkOiBwcmZSZXN1bHQudmFsdWUuY3JlZGVudGlhbElkLFxuICAgICAgICAgICAgcHJpdmF0ZUtleUJhc2U2NCxcbiAgICAgICAgICAgIHB1YmxpY0tleUJhc2U2NFxuICAgICAgICB9XG4gICAgfSk7XG59XG5cbi8vID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT1cbi8vIFN5bW1ldHJpYyBFbmNyeXB0aW9uIEZ1bmN0aW9uc1xuLy8gPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PVxuXG4vKipcbiAqIEVuY3J5cHQgYSBtZXNzYWdlIHdpdGggc3ltbWV0cmljIGtleS5cbiAqIEtleSBpcyBwYXNzZWQgZnJvbSBDIyBXQVNNIG1lbW9yeSBhbmQgemVyb2VkIGFmdGVyIHVzZS5cbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGVuY3J5cHRTeW1tZXRyaWMoXG4gICAgbWVzc2FnZTogc3RyaW5nLFxuICAgIGtleUJhc2U2NDogc3RyaW5nXG4pOiBzdHJpbmcge1xuICAgIGNvbnN0IGVuY3J5cHRlZCA9IHN5bW1ldHJpY0VuY3J5cHQobWVzc2FnZSwga2V5QmFzZTY0KTtcbiAgICByZXR1cm4gSlNPTi5zdHJpbmdpZnkoZW5jcnlwdGVkKTtcbn1cblxuLyoqXG4gKiBEZWNyeXB0IGEgbWVzc2FnZSB3aXRoIHN5bW1ldHJpYyBrZXkuXG4gKiBLZXkgaXMgcGFzc2VkIGZyb20gQyMgV0FTTSBtZW1vcnkgYW5kIHplcm9lZCBhZnRlciB1c2UuXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBkZWNyeXB0U3ltbWV0cmljKFxuICAgIGVuY3J5cHRlZEpzb246IHN0cmluZyxcbiAgICBrZXlCYXNlNjQ6IHN0cmluZ1xuKTogc3RyaW5nIHtcbiAgICBjb25zdCBlbmNyeXB0ZWQ6IFN5bW1ldHJpY0VuY3J5cHRlZE1lc3NhZ2UgPSBKU09OLnBhcnNlKGVuY3J5cHRlZEpzb24pO1xuICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IHBsYWludGV4dCA9IHN5bW1ldHJpY0RlY3J5cHQoZW5jcnlwdGVkLCBrZXlCYXNlNjQpO1xuICAgICAgICByZXR1cm4gSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgICAgc3VjY2VzczogdHJ1ZSxcbiAgICAgICAgICAgIHZhbHVlOiBwbGFpbnRleHRcbiAgICAgICAgfSk7XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgICAgY29uc3QgcmF3TWVzc2FnZSA9IGVycm9yIGluc3RhbmNlb2YgRXJyb3IgPyBlcnJvci5tZXNzYWdlIDogJyc7XG4gICAgICAgIGNvbnN0IGVycm9yQ29kZSA9IHJhd01lc3NhZ2UudG9Mb3dlckNhc2UoKS5pbmNsdWRlcygndGFnJylcbiAgICAgICAgICAgID8gUHJmRXJyb3JDb2RlLkF1dGhlbnRpY2F0aW9uVGFnTWlzbWF0Y2hcbiAgICAgICAgICAgIDogUHJmRXJyb3JDb2RlLkRlY3J5cHRpb25GYWlsZWQ7XG4gICAgICAgIHJldHVybiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgICBzdWNjZXNzOiBmYWxzZSxcbiAgICAgICAgICAgIGVycm9yQ29kZVxuICAgICAgICB9KTtcbiAgICB9XG59XG5cbi8vID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT1cbi8vIEFzeW1tZXRyaWMgKEVDSUVTKSBFbmNyeXB0aW9uIEZ1bmN0aW9uc1xuLy8gPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PVxuXG4vKipcbiAqIEVuY3J5cHQgYSBtZXNzYWdlIHdpdGggcmVjaXBpZW50J3MgcHVibGljIGtleS5cbiAqIE5vIHByaXZhdGUga2V5IG5lZWRlZCAtIGFueW9uZSBjYW4gZW5jcnlwdCB0byBhIHB1YmxpYyBrZXkuXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBlbmNyeXB0QXN5bW1ldHJpYyhcbiAgICBwbGFpbnRleHQ6IHN0cmluZyxcbiAgICByZWNpcGllbnRQdWJsaWNLZXlCYXNlNjQ6IHN0cmluZ1xuKTogc3RyaW5nIHtcbiAgICB0cnkge1xuICAgICAgICBjb25zdCBlbmNyeXB0ZWQgPSBhc3ltbWV0cmljRW5jcnlwdChwbGFpbnRleHQsIHJlY2lwaWVudFB1YmxpY0tleUJhc2U2NCk7XG4gICAgICAgIHJldHVybiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgICBzdWNjZXNzOiB0cnVlLFxuICAgICAgICAgICAgdmFsdWU6IGVuY3J5cHRlZFxuICAgICAgICB9KTtcbiAgICB9IGNhdGNoIHtcbiAgICAgICAgcmV0dXJuIEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgICAgIHN1Y2Nlc3M6IGZhbHNlLFxuICAgICAgICAgICAgZXJyb3JDb2RlOiBQcmZFcnJvckNvZGUuRW5jcnlwdGlvbkZhaWxlZFxuICAgICAgICB9KTtcbiAgICB9XG59XG5cbi8qKlxuICogRGVjcnlwdCBhIG1lc3NhZ2Ugd2l0aCBvdXIgcHJpdmF0ZSBrZXkuXG4gKiBQcml2YXRlIGtleSBpcyBwYXNzZWQgZnJvbSBDIyBXQVNNIG1lbW9yeSBhbmQgemVyb2VkIGFmdGVyIHVzZS5cbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGRlY3J5cHRBc3ltbWV0cmljKFxuICAgIGVuY3J5cHRlZEpzb246IHN0cmluZyxcbiAgICBwcml2YXRlS2V5QmFzZTY0OiBzdHJpbmdcbik6IHN0cmluZyB7XG4gICAgY29uc3QgZW5jcnlwdGVkOiBFbmNyeXB0ZWRNZXNzYWdlID0gSlNPTi5wYXJzZShlbmNyeXB0ZWRKc29uKTtcbiAgICB0cnkge1xuICAgICAgICBjb25zdCBwbGFpbnRleHQgPSBhc3ltbWV0cmljRGVjcnlwdChlbmNyeXB0ZWQsIHByaXZhdGVLZXlCYXNlNjQpO1xuICAgICAgICByZXR1cm4gSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgICAgc3VjY2VzczogdHJ1ZSxcbiAgICAgICAgICAgIHZhbHVlOiBwbGFpbnRleHRcbiAgICAgICAgfSk7XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgICAgY29uc3QgcmF3TWVzc2FnZSA9IGVycm9yIGluc3RhbmNlb2YgRXJyb3IgPyBlcnJvci5tZXNzYWdlIDogJyc7XG4gICAgICAgIGNvbnN0IGVycm9yQ29kZSA9IHJhd01lc3NhZ2UudG9Mb3dlckNhc2UoKS5pbmNsdWRlcygndGFnJylcbiAgICAgICAgICAgID8gUHJmRXJyb3JDb2RlLkF1dGhlbnRpY2F0aW9uVGFnTWlzbWF0Y2hcbiAgICAgICAgICAgIDogUHJmRXJyb3JDb2RlLkRlY3J5cHRpb25GYWlsZWQ7XG4gICAgICAgIHJldHVybiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgICBzdWNjZXNzOiBmYWxzZSxcbiAgICAgICAgICAgIGVycm9yQ29kZVxuICAgICAgICB9KTtcbiAgICB9XG59XG5cbi8vID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT1cbi8vIEV4cG9ydCB0byBnbG9iYWwgc2NvcGUgZm9yIEMjIEpTSW1wb3J0XG4vLyA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09XG5cbmNvbnN0IGJsYXpvclByZiA9IHtcbiAgICBpc1ByZlN1cHBvcnRlZCxcbiAgICByZWdpc3RlcixcbiAgICBkZXJpdmVLZXlzLFxuICAgIGRlcml2ZUtleXNEaXNjb3ZlcmFibGUsXG4gICAgZW5jcnlwdFN5bW1ldHJpYyxcbiAgICBkZWNyeXB0U3ltbWV0cmljLFxuICAgIGVuY3J5cHRBc3ltbWV0cmljLFxuICAgIGRlY3J5cHRBc3ltbWV0cmljXG59O1xuXG4vLyBNYWtlIGF2YWlsYWJsZSBnbG9iYWxseSBmb3IgSlNJbXBvcnRcbihnbG9iYWxUaGlzIGFzIFJlY29yZDxzdHJpbmcsIHVua25vd24+KS5ibGF6b3JQcmYgPSBibGF6b3JQcmY7XG5cbmV4cG9ydCBkZWZhdWx0IGJsYXpvclByZjtcbiJdLAogICJtYXBwaW5ncyI6ICI7QUFNTyxTQUFTLFNBQVMsUUFBMEI7QUFDL0MsU0FBTyxLQUFLLENBQUM7QUFDakI7QUFzQk8sU0FBUyxTQUFTLE1BQTBCO0FBQy9DLFNBQU8sS0FBSyxPQUFPLGFBQWEsR0FBRyxJQUFJLENBQUM7QUFDNUM7QUFLTyxTQUFTLFdBQVcsUUFBNEI7QUFDbkQsUUFBTSxTQUFTLEtBQUssTUFBTTtBQUMxQixRQUFNLFFBQVEsSUFBSSxXQUFXLE9BQU8sTUFBTTtBQUMxQyxXQUFTLElBQUksR0FBRyxJQUFJLE9BQU8sUUFBUSxLQUFLO0FBQ3BDLFVBQU0sQ0FBQyxJQUFJLE9BQU8sV0FBVyxDQUFDO0FBQUEsRUFDbEM7QUFDQSxTQUFPO0FBQ1g7QUFLTyxTQUFTLG9CQUFvQixRQUE2QjtBQUM3RCxTQUFPLFNBQVMsSUFBSSxXQUFXLE1BQU0sQ0FBQztBQUMxQztBQUtPLFNBQVMsb0JBQW9CLFFBQTZCO0FBQzdELFNBQU8sV0FBVyxNQUFNLEVBQUU7QUFDOUI7OztBQ2hEQSxlQUFzQixrQkFBb0M7QUFFdEQsTUFBSSxDQUFDLE9BQU8scUJBQXFCO0FBQzdCLFdBQU87QUFBQSxFQUNYO0FBR0EsTUFBSSxPQUFPLG9CQUFvQixrREFBa0QsWUFBWTtBQUN6RixVQUFNLFlBQVksTUFBTSxvQkFBb0IsOENBQThDO0FBQzFGLFFBQUksQ0FBQyxXQUFXO0FBQ1osYUFBTztBQUFBLElBQ1g7QUFBQSxFQUNKO0FBSUEsU0FBTztBQUNYO0FBU0EsZUFBc0IsMEJBQ2xCLGFBQ0EsU0FDaUM7QUFDakMsTUFBSTtBQUVBLFVBQU0sU0FBUyxPQUFPLGdCQUFnQixJQUFJLFdBQVcsRUFBRSxDQUFDO0FBR3hELFVBQU0sdUJBQXVCLGVBQWUsUUFBUTtBQUdwRCxVQUFNLDBCQUNGLFFBQVEsNEJBQTRC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QUFLO0FBQ1YsV0FBSyxLQUFLO0FBQ1YsV0FBSyxLQUFLO0FBQ1YsV0FBSyxLQUFLO0FBQ1YsT0FBQyxFQUFFLEdBQUcsSUFBSSxHQUFHLEdBQUUsSUFBUyxJQUFJLEtBQUssR0FBRyxLQUFLLEdBQUcsTUFBTSxHQUFHLE1BQU0sQ0FBQztBQUM1RCxXQUFLLEtBQUs7QUFDVixXQUFLLEtBQUs7QUFDVixXQUFLLEtBQUs7QUFDVixXQUFLLEtBQUs7QUFDVixXQUFLLEtBQUs7QUFDVixXQUFLLEtBQUs7QUFDVixZQUFNLE1BQVUsTUFBTSxLQUFLLFNBQVMsSUFBSTtBQUN4QyxXQUFTLE1BQU0sS0FBSyxLQUFLLFNBQVMsSUFBSTtBQUN0QyxXQUFLLE1BQU07SUFDYjtBQUVBLEtBQUMsRUFBRSxHQUFHLElBQUksR0FBRyxHQUFFLElBQVMsSUFBSSxLQUFLLEtBQUssR0FBRyxLQUFLLEtBQUssR0FBRyxLQUFLLEdBQUcsS0FBSyxDQUFDO0FBQ3BFLEtBQUMsRUFBRSxHQUFHLElBQUksR0FBRyxHQUFFLElBQVMsSUFBSSxLQUFLLEtBQUssR0FBRyxLQUFLLEtBQUssR0FBRyxLQUFLLEdBQUcsS0FBSyxDQUFDO0FBQ3BFLEtBQUMsRUFBRSxHQUFHLElBQUksR0FBRyxHQUFFLElBQVMsSUFBSSxLQUFLLEtBQUssR0FBRyxLQUFLLEtBQUssR0FBRyxLQUFLLEdBQUcsS0FBSyxDQUFDO0FBQ3BFLEtBQUMsRUFBRSxHQUFHLElBQUksR0FBRyxHQUFFLElBQVMsSUFBSSxLQUFLLEtBQUssR0FBRyxLQUFLLEtBQUssR0FBRyxLQUFLLEdBQUcsS0FBSyxDQUFDO0FBQ3BFLEtBQUMsRUFBRSxHQUFHLElBQUksR0FBRyxHQUFFLElBQVMsSUFBSSxLQUFLLEtBQUssR0FBRyxLQUFLLEtBQUssR0FBRyxLQUFLLEdBQUcsS0FBSyxDQUFDO0FBQ3BFLEtBQUMsRUFBRSxHQUFHLElBQUksR0FBRyxHQUFFLElBQVMsSUFBSSxLQUFLLEtBQUssR0FBRyxLQUFLLEtBQUssR0FBRyxLQUFLLEdBQUcsS0FBSyxDQUFDO0FBQ3BFLEtB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SUFBSSxZQUFZLEVBQUU7QUFDNUIsUUFBSSxJQUFJLEVBQUUsQ0FBQyxNQUFNO0FBQ2pCLE1BQUUsQ0FBQyxLQUFLO0FBQ1IsYUFBUyxJQUFJLEdBQUcsSUFBSSxJQUFJLEtBQUs7QUFDM0IsUUFBRSxDQUFDLEtBQUs7QUFDUixVQUFJLEVBQUUsQ0FBQyxNQUFNO0FBQ2IsUUFBRSxDQUFDLEtBQUs7SUFDVjtBQUNBLE1BQUUsQ0FBQyxLQUFLLElBQUk7QUFDWixRQUFJLEVBQUUsQ0FBQyxNQUFNO0FBQ2IsTUFBRSxDQUFDLEtBQUs7QUFDUixNQUFFLENBQUMsS0FBSztBQUNSLFFBQUksRUFBRSxDQUFDLE1BQU07QUFDYixNQUFFLENBQUMsS0FBSztBQUNSLE1BQUUsQ0FBQyxLQUFLO0FBRVIsTUFBRSxDQUFDLElBQUksRUFBRSxDQUFDLElBQUk7QUFDZCxRQUFJLEVBQUUsQ0FBQyxNQUFNO0FBQ2IsTUFBRSxDQUFDLEtBQUs7QUFDUixhQUFTLElBQUksR0FBRyxJQUFJLElBQUksS0FBSztBQUMzQixRQUFFLENBQUMsSUFBSSxFQUFFLENBQUMsSUFBSTtBQUNkLFVBQUksRUFBRSxDQUFDLE1BQU07QUFDYixRQUFFLENBQUMsS0FBSztJQUNWO0FBQ0EsTUFBRSxDQUFDLEtBQUssS0FBSztBQUViLFFBQUksUUFBUSxJQUFJLEtBQUs7QUFDckIsYUFBUyxJQUFJLEdBQUcsSUFBSSxJQUFJO0FBQUssUUFBRSxDQUFDLEtBQUs7QUFDckMsV0FBTyxDQUFDO0FBQ1IsYUFBUyxJQUFJLEdBQUcsSUFBSSxJQUFJO0FBQUssUUFBRSxDQUFDLElBQUssRUFBRSxDQUFDLElBQUksT0FBUSxFQUFFLENBQUM7QUFDdkQsTUFBRSxDQUFDLEtBQUssRUFBRSxDQUFDLElBQUssRUFBRSxDQUFDLEtBQUssTUFBTztBQUMvQixNQUFFLENBQUMsS0FBTSxFQUFFLENBQUMsTUFBTSxJQUFNLEVBQUUsQ0FBQyxLQUFLLE1BQU87QUFDdkMsTUFBRSxDQUFDLEtBQU0sRUFBRSxDQUFDLE1BQU0sSUFBTSxFQUFFLENBQUMsS0FBSyxL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S0FBSyxDQUFDO0FBRTlDLFVBQU8sTUFBTSxNQUFPO0FBQUcsVUFBTSxLQUFLLE1BQU0sS0FBSyxFQUFFO0FBQy9DLFVBQU8sTUFBTSxNQUFPO0FBQUcsVUFBTSxLQUFLLE1BQU0sS0FBSyxFQUFFO0FBQy9DLFVBQU8sTUFBTSxNQUFPO0FBQUcsVUFBTSxLQUFLLE1BQU0sS0FBSyxDQUFDO0FBQzlDLFVBQU8sTUFBTSxNQUFPO0FBQUcsVUFBTSxLQUFLLE1BQU0sS0FBSyxDQUFDO0FBRTlDLFVBQU8sTUFBTSxNQUFPO0FBQUcsVUFBTSxLQUFLLE1BQU0sS0FBSyxFQUFFO0FBQy9DLFVBQU8sTUFBTSxNQUFPO0FBQUcsVUFBTSxLQUFLLE1BQU0sS0FBSyxFQUFFO0FBQy9DLFVBQU8sTUFBTSxNQUFPO0FBQUcsVUFBTSxLQUFLLE1BQU0sS0FBSyxDQUFDO0FBQzlDLFVBQU8sTUFBTSxNQUFPO0FBQUcsVUFBTSxLQUFLLE1BQU0sS0FBSyxDQUFDO0FBRTlDLFVBQU8sTUFBTSxNQUFPO0FBQUcsVUFBTSxLQUFLLE1BQU0sS0FBSyxFQUFFO0FBQy9DLFVBQU8sTUFBTSxNQUFPO0FBQUcsVUFBTSxLQUFLLE1BQU0sS0FBSyxFQUFFO0FBQy9DLFVBQU8sTUFBTSxNQUFPO0FBQUcsVUFBTSxLQUFLLE1BQU0sS0FBSyxDQUFDO0FBQzlDLFVBQU8sTUFBTSxNQUFPO0FBQUcsVUFBTSxLQUFLLE1BQU0sS0FBSyxDQUFDO0FBRTlDLFVBQU8sTUFBTSxNQUFPO0FBQUcsVUFBTSxLQUFLLE1BQU0sS0FBSyxFQUFFO0FBQy9DLFVBQU8sTUFBTSxNQUFPO0FBQUcsVUFBTSxLQUFLLE1BQU0sS0FBSyxFQUFFO0FBQy9DLFVBQU8sTUFBTSxNQUFPO0FBQUcsVUFBTSxLQUFLLE1BQU0sS0FBSyxDQUFDO0FBQzlDLFVBQU8sTUFBTSxNQUFPO0FBQUcsVUFBTSxLQUFLLE1BQU0sS0FBSyxDQUFDO0FBRTlDLFVBQU8sTUFBTSxNQUFPO0FBQUcsVUFBTSxLQUFLLE1BQU0sS0FBSyxFQUFFO0FBQy9DLFVBQU8sTUFBTSxNQUFPO0FBQUcsVUFBTSxLQUFLLE1BQU0sS0FBSyxFQUFFO0FBQy9DLFVBQU8sTUFBTSxNQUFPO0FBQUcsVUFBTSxLQUFLLE1BQU0sS0FBSyxDQUFDO0FBQzlDLFVBQU8sTUFBTSxNQUFPO0FBQUcsVUFBTSxLQUFLLE1BQU0sS0FBSyxDQUFDO0FBRTlDLFVBQU8sTUFBTSxNQUFPO0FBQUcsVUFBTSxLQUFLLE1BQU0sS0FBSyxFQUFFO0FBQy9DLFVBQU8sTUFBTSxNQUFPO0FBQUcsVUFBTSxLQUFLLE1BQU0sS0FBSyxFQUFFO0FBQy9DLFVBQU8sTUFBTSxNQUFPO0FBQUcsVUFBTSxLQUFLLE1BQU0sS0FBSyxDQUFDO0FBQzlDLFVBQU8sTUFBTSxNQUFPO0FBQUcsVUFBTSxLQUFLLE1BQU0sS0FBSyxDQUFDO0FBRTlDLFVBQU8sTUFBTSxNQUFPO0FBQUcsVUFBTSxLQUFLLE1BQU0sS0FBSyxFQUFFO0FBQy9DLFVBQU8sTUFBTSxNQUFPO0FBQUcsVUFBTSxLQUFLLE1BQU0sS0FBSyxFQUFFO0FBQy9DLFVBQU8sTUFBTSxNQUFPO0FBQUcsVUFBTSxLQUFLLE1BQU0sS0FBSyxDQUFDO0FBQzlDLFVBQU8sTUFBTSxNQUFPO0FBQUcsVUFBTSxLQUFLLE1BQU0sS0FBSyxDQUFDO0VBQ2hEO0FBRUEsTUFBSSxLQUFLO0FBQ1QsTUFBSSxJQUFJLElBQUssTUFBTSxNQUFPO0FBQUcsTUFBSSxJQUFJLElBQUssTUFBTSxNQUFPO0FBQ3ZELE1BQUksSUFBSSxJQUFLLE1BQU0sTUFBTztBQUFHLE1BQUksSUFBSSxJQUFLLE1BQU0sTUFBTztBQUN2RCxNQUFJLElBQUksSUFBSyxNQUFNLE1BQU87QUFBRyxNQUFJLElBQUksSUFBSyxNQUFNLE1BQU87QUFDdkQsTUFBSSxJQUFJLElBQUssTUFBTSxNQUFPO0FBQUcsTUFBSSxJQUFJLElBQUssTUFBTSxNQUFPO0FBQ3ZELE1BQUksSUFBSSxJQUFLLE1BQU0sTUFBTztBQUFHLE1BQUksSUFBSSxJQUFLLE1BQU0sTUFBTztBQUN2RCxNQUFJLElBQUksSUFBSyxNQUFNLE1BQU87QUFBRyxNQUFJLElBQUksSUFBSyxNQUFNLE1BQU87QUFDdkQsTUFBSSxJQUFJLElBQUssTUFBTSxNQUFPO0FBQUcsTUFBSSxJQUFJLElBQUssTUFBTSxNQUFPO0FBQ3ZELE1BQUksSUFBSSxJQUFLLE1BQU0sTUFBTztBQUFHLE1BQUksSUFBSSxJQUFLLE1BQU0sTUFBTztBQUN6RDtBQVFNLFNBQVUsUUFDZCxHQUFnQixHQUFnQixHQUFnQixLQUFnQjtBQUVoRSxNQUFJLE1BQU0sRUFBRSxDQUFDLEdBQUcsTUFBTSxFQUFFLENBQUMsR0FBRyxNQUFNLEVBQUUsQ0FBQyxHQUFHLE1BQU0sRUFBRSxDQUFDLEdBQzdDLE1BQU0sRUFBRSxDQUFDLEdBQUcsTUFBTSxFQUFFLENBQUMsR0FBRyxNQUFNLEVBQUUsQ0FBQyxHQUFHLE1BQU0sRUFBRSxDQUFDLEdBQzdDLE1BQU0sRUFBRSxDQUFDLEdBQUcsTUFBTSxFQUFFLENBQUMsR0FBRyxNQUFNLEVBQUUsQ0FBQyxHQUFHLE1BQU0sRUFBRSxDQUFDLEdBQzdDLE1BQU0sRUFBRSxDQUFDLEdBQUcsTUFBTSxFQUFFLENBQUMsR0FBRyxNQUFNLEVBQUUsQ0FBQyxHQUFHLE1BQU0sRUFBRSxDQUFDO0FBQ2pELFdBQVMsSUFBSSxHQUFHLElBQUksSUFBSSxLQUFLLEdBQUc7QUFDOUIsVUFBTyxNQUFNLE1BQU87QUFBRyxVQUFNLEtBQUssTUFBTSxLQUFLLEVBQUU7QUFDL0MsVUFBTyxNQUFNLE1BQU87QUFBRyxVQUFNLEtBQUssTUFBTSxLQUFLLEVBQUU7QUFDL0MsVUFBTyxNQUFNLE1BQU87QUFBRyxVQUFNLEtBQUssTUFBTSxLQUFLLENBQUM7QUFDOUMsVUFBTyxNQUFNLE1BQU87QUFBRyxVQUFNLEtBQUssTUFBTSxLQUFLLENBQUM7QUFFOUMsVUFBTyxNQUFNLE1BQU87QUFBRyxVQUFNLEtBQUssTUFBTSxLQUFLLEVBQUU7QUFDL0MsVUFBTyxNQUFNLE1BQU87QUFBRyxVQUFNLEtBQUssTUFBTSxLQUFLLEVBQUU7QUFDL0MsVUFBTyxNQUFNLE1BQU87QUFBRyxVQUFNLEtBQUssTUFBTSxLQUFLLENBQUM7QUFDOUMsVUFBTyxNQUFNLE1BQU87QUFBRyxVQUFNLEtBQUssTUFBTSxLQUFLLENBQUM7QUFFOUMsVUFBTyxNQUFNLE1BQU87QUFBRyxVQUFNLEtBQUssTUFBTSxLQUFLLEVBQUU7QUFDL0MsVUFBTyxNQUFNLE1BQU87QUFBRyxVQUFNLEtBQUssTUFBTSxLQUFLLEVBQUU7QUFDL0MsVUFBTyxNQUFNLE1BQU87QUFBRyxVQUFNLEtBQUssTUFBTSxLQUFLLENBQUM7QUFDOUMsVUFBTyxNQUFNLE1BQU87QUFBRyxVQUFNLEtBQUssTUFBTSxLQUFLLENBQUM7QUFFOUMsVUFBTyxNQUFNLE1BQU87QUFBRyxVQUFNLEtBQUssTUFBTSxLQUFLLEVBQUU7QUFDL0MsVUFBTyxNQUFNLE1BQU87QUFBRyxVQUFNLEtBQUssTUFBTSxLQUFLLEVBQUU7QUFDL0MsVUFBTyxNQUFNLE1BQU87QUFBRyxVQUFNLEtBQUssTUFBTSxLQUFLLENBQUM7QUFDOUMsVUFBTyxNQUFNLE1BQU87QUFBRyxVQUFNLEtBQUssTUFBTSxLQUFLLENBQUM7QUFFOUMsVUFBTyxNQUFNLE1BQU87QUFBRyxVQUFNLEtBQUssTUFBTSxLQUFLLEVBQUU7QUFDL0MsVUFBTyxNQUFNLE1BQU87QUFBRyxVQUFNLEtBQUssTUFBTSxLQUFLLEVBQUU7QUFDL0MsVUFBTyxNQUFNLE1BQU87QUFBRyxVQUFNLEtBQUssTUFBTSxLQUFLLENBQUM7QUFDOUMsVUFBTyxNQUFNLE1BQU87QUFBRyxVQUFNLEtBQUssTUFBTSxLQUFLLENBQUM7QUFFOUMsVUFBTyxNQUFNLE1BQU87QUFBRyxVQUFNLEtBQUssTUFBTSxLQUFLLEVBQUU7QUFDL0MsVUFBTyxNQUFNLE1BQU87QUFBRyxVQUFNLEtBQUssTUFBTSxLQUFLLEVBQUU7QUFDL0MsVUFBTyxNQUFNLE1BQU87QUFBRyxVQUFNLEtBQUssTUFBTSxLQUFLLENBQUM7QUFDOUMsVUFBTyxNQUFNLE1BQU87QUFBRyxVQUFNLEtBQUssTUFBTSxLQUFLLENBQUM7QUFFOUMsVUFBTyxNQUFN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Q04sTUFBSTtBQUNBLFVBQU0sWUFBWSxrQkFBa0IsV0FBVyx3QkFBd0I7QUFDdkUsV0FBTyxLQUFLLFVBQVU7QUFBQSxNQUNsQixTQUFTO0FBQUEsTUFDVCxPQUFPO0FBQUEsSUFDWCxDQUFDO0FBQUEsRUFDTCxRQUFRO0FBQ0osV0FBTyxLQUFLLFVBQVU7QUFBQSxNQUNsQixTQUFTO0FBQUEsTUFDVDtBQUFBLElBQ0osQ0FBQztBQUFBLEVBQ0w7QUFDSjtBQU1PLFNBQVMsa0JBQ1osZUFDQSxrQkFDTTtBQUNOLFFBQU0sWUFBOEIsS0FBSyxNQUFNLGFBQWE7QUFDNUQsTUFBSTtBQUNBLFVBQU0sWUFBWSxrQkFBa0IsV0FBVyxnQkFBZ0I7QUFDL0QsV0FBTyxLQUFLLFVBQVU7QUFBQSxNQUNsQixTQUFTO0FBQUEsTUFDVCxPQUFPO0FBQUEsSUFDWCxDQUFDO0FBQUEsRUFDTCxTQUFTLE9BQU87QUFDWixVQUFNLGFBQWEsaUJBQWlCLFFBQVEsTUFBTSxVQUFVO0FBQzVELFVBQU0sWUFBWSxXQUFXLFlBQVksRUFBRSxTQUFTLEtBQUs7QUFHekQsV0FBTyxLQUFLLFVBQVU7QUFBQSxNQUNsQixTQUFTO0FBQUEsTUFDVDtBQUFBLElBQ0osQ0FBQztBQUFBLEVBQ0w7QUFDSjtBQU1BLElBQU0sWUFBWTtBQUFBLEVBQ2Q7QUFBQSxFQUNBO0FBQUEsRUFDQTtBQUFBLEVBQ0E7QUFBQSxFQUNBO0FBQUEsRUFDQTtBQUFBLEVBQ0E7QUFBQSxFQUNBO0FBQ0o7QUFHQyxXQUF1QyxZQUFZO0FBRXBELElBQU8sZ0JBQVE7IiwKICAibmFtZXMiOiBbImNyeXB0byIsICJjcnlwdG8iLCAiaXNMRSIsICJfMzJuIiwgInNoYTI1NiIsICJzaGEyNTYiLCAiXzBuIiwgIl8xbiIsICJfMG4iLCAiXzFuIiwgIkZwIiwgIkZwIiwgIl8xbiIsICJpc0xFIiwgIl8wbiIsICJfMW4iLCAiXzBuIiwgIl8xbiIsICJ3aW5kb3ciLCAid2JpdHMiLCAiaXNMRSIsICJfMG4iLCAiRnAiLCAiRm4iLCAiXzBuIiwgIl8xbiIsICJfMm4iLCAiXzhuIiwgIkZwIiwgIkZuIiwgInV2UmF0aW8iLCAicCIsICJyYW5kb21CeXRlcyIsICJhZGp1c3RTY2FsYXJCeXRlcyIsICJlZGRzYSIsICJfMG4iLCAiXzFuIiwgIl8ybiIsICJhZGp1c3RTY2FsYXJCeXRlcyIsICJfMG4iLCAiXzFuIiwgIl8ybiIsICJfM24iLCAiXzVuIiwgIl84biIsICJfM24iLCAiXzFuIiwgIm1vZCIsICJfMG4iLCAiaXNCeXRlcyIsICJhbnVtYmVyIiwgImFieXRlcyIsICJhZXhpc3RzIiwgImFvdXRwdXQiLCAiYWJ5dGVzIiwgImNsZWFuIiwgImNyZWF0ZVZpZXciLCAidXRmOFRvQnl0ZXMiLCAidG9CeXRlcyIsICJ1dGY4VG9CeXRlcyIsICJpc0J5dGVzIiwgImNvcHlCeXRlcyIsICJlcXVhbEJ5dGVzIiwgImFieXRlcyIsICJzZXRCaWdVaW50NjQiLCAiaXNMRSIsICJfMzJuIiwgImNyZWF0ZVZpZXciLCAiY29weUJ5dGVzIiwgImlzQWxpZ25lZDMyIiwgImFudW1iZXIiLCAiYWJ5dGVzIiwgImNvcHlCeXRlcyIsICJjbGVhbiIsICJ0b0J5dGVzIiwgImFieXRlcyIsICJjbGVhbiIsICJhZXhpc3RzIiwgImFvdXRwdXQiLCAiY2xlYW4iLCAiZXF1YWxCeXRlcyIsICJjcnlwdG8iLCAicmFuZG9tQnl0ZXMiLCAiY3J5cHRvIiwgInJhbmRvbUJ5dGVzIiwgIkhNQUMiLCAiTk9OQ0VfTEVOR1RIIiwgInNoYTI1NiIsICJyYW5kb21CeXRlcyJdCn0K
