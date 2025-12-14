// src/baseprf.ts
var keyCache = /* @__PURE__ */ new Map();
var onKeyExpiredCallback = null;
function setKeyExpiredCallback(callback) {
  onKeyExpiredCallback = callback;
}
function clearCacheEntry(salt) {
  const entry = keyCache.get(salt);
  if (entry?.expirationTimer) {
    clearTimeout(entry.expirationTimer);
  }
  keyCache.delete(salt);
}
function scheduleExpiration(salt, ttlMs) {
  const timer = setTimeout(() => {
    clearCacheEntry(salt);
    onKeyExpiredCallback?.(salt);
  }, ttlMs);
  const entry = keyCache.get(salt);
  if (entry) {
    entry.expirationTimer = timer;
    entry.expiresAt = Date.now() + ttlMs;
  }
}
async function register(displayName) {
  try {
    const rpId = window.location.hostname;
    const rpName = document.title || rpId;
    const userId = crypto.getRandomValues(new Uint8Array(32));
    const credential = await navigator.credentials.create({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rp: { id: rpId, name: rpName },
        user: {
          id: userId,
          name: displayName || `user-${Date.now()}`,
          displayName: displayName || "BlazorPRFBase User"
        },
        pubKeyCredParams: [
          { type: "public-key", alg: -7 },
          // ES256
          { type: "public-key", alg: -257 }
          // RS256
        ],
        authenticatorSelection: {
          residentKey: "preferred",
          userVerification: "preferred"
        },
        extensions: {
          prf: {}
        }
      }
    });
    if (!credential) {
      return JSON.stringify({ success: false, error: "Registration cancelled" });
    }
    const extensions = credential.getClientExtensionResults();
    if (!extensions.prf?.enabled) {
      return JSON.stringify({ success: false, error: "PRF extension not supported by authenticator" });
    }
    return JSON.stringify({
      success: true,
      credentialId: bytesToBase64(new Uint8Array(credential.rawId))
    });
  } catch (e) {
    return JSON.stringify({ success: false, error: e.message });
  }
}
async function authenticate(credentialIdBase64, saltBase64, ttlMs) {
  try {
    const credentialId = base64ToBytes(credentialIdBase64);
    const salt = base64ToBytes(saltBase64);
    const credential = await navigator.credentials.get({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rpId: window.location.hostname,
        allowCredentials: [{
          type: "public-key",
          id: credentialId
        }],
        userVerification: "preferred",
        extensions: {
          prf: {
            eval: {
              first: salt
            }
          }
        }
      }
    });
    if (!credential) {
      return JSON.stringify({ success: false, error: "Authentication cancelled" });
    }
    return await deriveAndCacheKeys(credential, saltBase64, ttlMs);
  } catch (e) {
    return JSON.stringify({ success: false, error: e.message });
  }
}
async function authenticateDiscoverable(saltBase64, ttlMs) {
  try {
    const salt = base64ToBytes(saltBase64);
    const credential = await navigator.credentials.get({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rpId: window.location.hostname,
        userVerification: "preferred",
        extensions: {
          prf: {
            eval: {
              first: salt
            }
          }
        }
      }
    });
    if (!credential) {
      return JSON.stringify({ success: false, error: "Authentication cancelled" });
    }
    return await deriveAndCacheKeys(credential, saltBase64, ttlMs);
  } catch (e) {
    return JSON.stringify({ success: false, error: e.message });
  }
}
async function deriveAndCacheKeys(credential, saltBase64, ttlMs) {
  const extensions = credential.getClientExtensionResults();
  const prfOutput = extensions.prf?.results?.first;
  if (!prfOutput) {
    return JSON.stringify({ success: false, error: "PRF output not available" });
  }
  const prfBytes = new Uint8Array(prfOutput);
  const credentialIdBase64 = bytesToBase64(new Uint8Array(credential.rawId));
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    prfBytes,
    "HKDF",
    false,
    ["deriveBits", "deriveKey"]
  );
  const encryptionKey = await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new TextEncoder().encode("BlazorPRFBase-encryption"),
      info: new TextEncoder().encode("aes-gcm-key")
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    // NOT extractable
    ["encrypt", "decrypt"]
  );
  const signingKeyBits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new TextEncoder().encode("BlazorPRFBase-signing"),
      info: new TextEncoder().encode("ed25519-seed")
    },
    keyMaterial,
    256
  );
  const signingKeyBytes = new Uint8Array(signingKeyBits);
  const pkcs8Key = wrapSeedInPkcs8(signingKeyBytes);
  const signingKey = await crypto.subtle.importKey(
    "pkcs8",
    pkcs8Key,
    { name: "Ed25519" },
    false,
    // NOT extractable
    ["sign"]
  );
  const tempSigningKey = await crypto.subtle.importKey(
    "pkcs8",
    pkcs8Key,
    { name: "Ed25519" },
    true,
    // extractable to get public key
    ["sign"]
  );
  const jwk = await crypto.subtle.exportKey("jwk", tempSigningKey);
  const publicKeyBase64 = base64UrlToBase64(jwk.x);
  signingKeyBytes.fill(0);
  pkcs8Key.fill(0);
  clearCacheEntry(saltBase64);
  keyCache.set(saltBase64, {
    encryptionKey,
    signingKey,
    publicKeyBase64,
    credentialIdBase64,
    expiresAt: null,
    expirationTimer: null
  });
  if (ttlMs !== null && ttlMs > 0) {
    scheduleExpiration(saltBase64, ttlMs);
  }
  return JSON.stringify({
    success: true,
    credentialId: credentialIdBase64,
    publicKey: publicKeyBase64
  });
}
function hasCachedKeys(saltBase64) {
  const entry = keyCache.get(saltBase64);
  if (!entry) {
    return false;
  }
  if (entry.expiresAt !== null && Date.now() > entry.expiresAt) {
    clearCacheEntry(saltBase64);
    return false;
  }
  return true;
}
function getCachedPublicInfo(saltBase64) {
  const entry = keyCache.get(saltBase64);
  if (!entry) {
    return JSON.stringify({ success: false, error: "No cached keys" });
  }
  if (entry.expiresAt !== null && Date.now() > entry.expiresAt) {
    clearCacheEntry(saltBase64);
    return JSON.stringify({ success: false, error: "Keys expired" });
  }
  return JSON.stringify({
    success: true,
    credentialId: entry.credentialIdBase64,
    publicKey: entry.publicKeyBase64
  });
}
function clearCachedKeys(saltBase64) {
  clearCacheEntry(saltBase64);
}
function clearAllCachedKeys() {
  for (const salt of keyCache.keys()) {
    clearCacheEntry(salt);
  }
}
async function encryptAesGcm(plaintextBase64, saltBase64) {
  try {
    const entry = keyCache.get(saltBase64);
    if (!entry) {
      return JSON.stringify({ success: false, error: "No cached encryption key - authenticate first" });
    }
    if (entry.expiresAt !== null && Date.now() > entry.expiresAt) {
      clearCacheEntry(saltBase64);
      return JSON.stringify({ success: false, error: "Keys expired - re-authenticate" });
    }
    const plaintext = base64ToBytes(plaintextBase64);
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce },
      entry.encryptionKey,
      plaintext
    );
    return JSON.stringify({
      success: true,
      ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
      nonce: bytesToBase64(nonce)
    });
  } catch (e) {
    return JSON.stringify({ success: false, error: e.message });
  }
}
async function decryptAesGcm(ciphertextBase64, nonceBase64, saltBase64) {
  try {
    const entry = keyCache.get(saltBase64);
    if (!entry) {
      return JSON.stringify({ success: false, error: "No cached encryption key - authenticate first" });
    }
    if (entry.expiresAt !== null && Date.now() > entry.expiresAt) {
      clearCacheEntry(saltBase64);
      return JSON.stringify({ success: false, error: "Keys expired - re-authenticate" });
    }
    const ciphertext = base64ToBytes(ciphertextBase64);
    const nonce = base64ToBytes(nonceBase64);
    if (nonce.length !== 12) {
      return JSON.stringify({ success: false, error: "Invalid nonce length - must be 12 bytes" });
    }
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce },
      entry.encryptionKey,
      ciphertext
    );
    return JSON.stringify({
      success: true,
      plaintext: bytesToBase64(new Uint8Array(plaintext))
    });
  } catch {
    return JSON.stringify({ success: false, error: "Decryption failed - authentication tag mismatch or wrong key" });
  }
}
async function ed25519Sign(messageBase64, saltBase64) {
  try {
    const entry = keyCache.get(saltBase64);
    if (!entry) {
      return JSON.stringify({ success: false, error: "No cached signing key - authenticate first" });
    }
    if (entry.expiresAt !== null && Date.now() > entry.expiresAt) {
      clearCacheEntry(saltBase64);
      return JSON.stringify({ success: false, error: "Keys expired - re-authenticate" });
    }
    const message = base64ToBytes(messageBase64);
    const signature = await crypto.subtle.sign(
      { name: "Ed25519" },
      entry.signingKey,
      message
    );
    return JSON.stringify({
      success: true,
      signature: bytesToBase64(new Uint8Array(signature))
    });
  } catch (e) {
    return JSON.stringify({ success: false, error: e.message });
  }
}
async function ed25519Verify(messageBase64, signatureBase64, publicKeyBase64) {
  try {
    const message = base64ToBytes(messageBase64);
    const signature = base64ToBytes(signatureBase64);
    const publicKeyBytes = base64ToBytes(publicKeyBase64);
    const publicKey = await crypto.subtle.importKey(
      "raw",
      publicKeyBytes,
      { name: "Ed25519" },
      false,
      ["verify"]
    );
    return await crypto.subtle.verify(
      { name: "Ed25519" },
      publicKey,
      signature,
      message
    );
  } catch {
    return false;
  }
}
function isPrfSupported() {
  return typeof PublicKeyCredential !== "undefined" && typeof navigator.credentials !== "undefined";
}
async function isConditionalMediationAvailable() {
  if (typeof PublicKeyCredential === "undefined") {
    return false;
  }
  if (typeof PublicKeyCredential.isConditionalMediationAvailable !== "function") {
    return false;
  }
  return await PublicKeyCredential.isConditionalMediationAvailable();
}
function wrapSeedInPkcs8(seed) {
  const pkcs8Header = new Uint8Array([
    48,
    46,
    2,
    1,
    0,
    48,
    5,
    6,
    3,
    43,
    101,
    112,
    4,
    34,
    4,
    32
  ]);
  const pkcs8Key = new Uint8Array(pkcs8Header.length + seed.length);
  pkcs8Key.set(pkcs8Header);
  pkcs8Key.set(seed, pkcs8Header.length);
  return pkcs8Key;
}
function bytesToBase64(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}
function base64ToBytes(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
function base64UrlToBase64(base64url) {
  return base64url.replace(/-/g, "+").replace(/_/g, "/").padEnd(base64url.length + (4 - base64url.length % 4) % 4, "=");
}
var BlazorPRFBase = {
  isPrfSupported,
  isConditionalMediationAvailable,
  register,
  authenticate,
  authenticateDiscoverable,
  hasCachedKeys,
  getCachedPublicInfo,
  clearCachedKeys,
  clearAllCachedKeys,
  encryptAesGcm,
  decryptAesGcm,
  ed25519Sign,
  ed25519Verify,
  setKeyExpiredCallback
};
export {
  BlazorPRFBase,
  authenticate,
  authenticateDiscoverable,
  clearAllCachedKeys,
  clearCachedKeys,
  decryptAesGcm,
  ed25519Sign,
  ed25519Verify,
  encryptAesGcm,
  getCachedPublicInfo,
  hasCachedKeys,
  isConditionalMediationAvailable,
  isPrfSupported,
  register,
  setKeyExpiredCallback
};
//# sourceMappingURL=blazorprfbase-wasm.js.map
