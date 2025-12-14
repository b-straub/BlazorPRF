/**
 * BlazorPRFBase - Combined WebAuthn PRF + WebCrypto
 *
 * All cryptographic operations using browser-native SubtleCrypto API.
 * Private keys NEVER leave JavaScript - stored as non-extractable CryptoKey objects.
 */

// ============================================================
// KEY CACHE - Keeps CryptoKey objects in JS memory
// ============================================================

interface CachedKeys {
    encryptionKey: CryptoKey;   // AES-GCM, non-extractable
    signingKey: CryptoKey;      // Ed25519, non-extractable
    publicKeyBase64: string;    // Ed25519 public key - safe to share
    credentialIdBase64: string; // Credential ID used
    expiresAt: number | null;   // Unix timestamp or null for no expiry
    expirationTimer: number | null;
}

const keyCache = new Map<string, CachedKeys>();

// Event callback for key expiration (called from JS, C# can subscribe)
let onKeyExpiredCallback: ((salt: string) => void) | null = null;

export function setKeyExpiredCallback(callback: (salt: string) => void): void {
    onKeyExpiredCallback = callback;
}

function clearCacheEntry(salt: string): void {
    const entry = keyCache.get(salt);
    if (entry?.expirationTimer) {
        clearTimeout(entry.expirationTimer);
    }
    keyCache.delete(salt);
}

function scheduleExpiration(salt: string, ttlMs: number): void {
    const timer = setTimeout(() => {
        clearCacheEntry(salt);
        onKeyExpiredCallback?.(salt);
    }, ttlMs) as unknown as number;

    const entry = keyCache.get(salt);
    if (entry) {
        entry.expirationTimer = timer;
        entry.expiresAt = Date.now() + ttlMs;
    }
}

// ============================================================
// WEBAUTHN PRF REGISTRATION
// ============================================================

/**
 * Register a new passkey with PRF extension support.
 * @returns JSON with credentialId (Base64) or error
 */
export async function register(displayName: string | null): Promise<string> {
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
                    { type: "public-key", alg: -7 },   // ES256
                    { type: "public-key", alg: -257 }  // RS256
                ],
                authenticatorSelection: {
                    residentKey: "preferred",
                    userVerification: "preferred"
                },
                extensions: {
                    prf: {}
                } as AuthenticationExtensionsClientInputs
            }
        }) as PublicKeyCredential | null;

        if (!credential) {
            return JSON.stringify({ success: false, error: "Registration cancelled" });
        }

        const extensions = credential.getClientExtensionResults() as { prf?: { enabled?: boolean } };

        if (!extensions.prf?.enabled) {
            return JSON.stringify({ success: false, error: "PRF extension not supported by authenticator" });
        }

        return JSON.stringify({
            success: true,
            credentialId: bytesToBase64(new Uint8Array(credential.rawId))
        });
    } catch (e) {
        return JSON.stringify({ success: false, error: (e as Error).message });
    }
}

// ============================================================
// WEBAUTHN PRF AUTHENTICATION + KEY DERIVATION & CACHING
// ============================================================

/**
 * Authenticate with a specific credential, derive keys, and cache them.
 * @param credentialIdBase64 The credential ID from registration
 * @param saltBase64 Salt for key derivation (also used as cache key)
 * @param ttlMs Optional TTL in milliseconds (null = no expiration)
 * @returns JSON with public key only (private keys stay in JS)
 */
export async function authenticate(
    credentialIdBase64: string,
    saltBase64: string,
    ttlMs: number | null
): Promise<string> {
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
                } as AuthenticationExtensionsClientInputs
            }
        }) as PublicKeyCredential | null;

        if (!credential) {
            return JSON.stringify({ success: false, error: "Authentication cancelled" });
        }

        return await deriveAndCacheKeys(credential, saltBase64, ttlMs);
    } catch (e) {
        return JSON.stringify({ success: false, error: (e as Error).message });
    }
}

/**
 * Authenticate with discoverable credential (user selects).
 * @param saltBase64 Salt for key derivation (also used as cache key)
 * @param ttlMs Optional TTL in milliseconds (null = no expiration)
 * @returns JSON with credential ID and public key only
 */
export async function authenticateDiscoverable(
    saltBase64: string,
    ttlMs: number | null
): Promise<string> {
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
                } as AuthenticationExtensionsClientInputs
            }
        }) as PublicKeyCredential | null;

        if (!credential) {
            return JSON.stringify({ success: false, error: "Authentication cancelled" });
        }

        return await deriveAndCacheKeys(credential, saltBase64, ttlMs);
    } catch (e) {
        return JSON.stringify({ success: false, error: (e as Error).message });
    }
}

/**
 * Derive keys from PRF output and store as non-extractable CryptoKey objects.
 */
async function deriveAndCacheKeys(
    credential: PublicKeyCredential,
    saltBase64: string,
    ttlMs: number | null
): Promise<string> {
    const extensions = credential.getClientExtensionResults() as {
        prf?: { results?: { first?: ArrayBuffer } }
    };

    const prfOutput = extensions.prf?.results?.first;
    if (!prfOutput) {
        return JSON.stringify({ success: false, error: "PRF output not available" });
    }

    const prfBytes = new Uint8Array(prfOutput);
    const credentialIdBase64 = bytesToBase64(new Uint8Array(credential.rawId));

    // Import PRF output as HKDF key material
    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        prfBytes,
        "HKDF",
        false,
        ["deriveBits", "deriveKey"]
    );

    // Derive AES-256-GCM key directly as non-extractable CryptoKey
    const encryptionKey = await crypto.subtle.deriveKey(
        {
            name: "HKDF",
            hash: "SHA-256",
            salt: new TextEncoder().encode("BlazorPRFBase-encryption"),
            info: new TextEncoder().encode("aes-gcm-key")
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,  // NOT extractable
        ["encrypt", "decrypt"]
    );

    // Derive Ed25519 seed bits for signing key
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

    // Import as Ed25519 private key (non-extractable)
    const signingKeyBytes = new Uint8Array(signingKeyBits);
    const pkcs8Key = wrapSeedInPkcs8(signingKeyBytes);
    const signingKey = await crypto.subtle.importKey(
        "pkcs8",
        pkcs8Key,
        { name: "Ed25519" },
        false,  // NOT extractable
        ["sign"]
    );

    // Get public key (we need extractable temporarily just to get public key)
    const tempSigningKey = await crypto.subtle.importKey(
        "pkcs8",
        pkcs8Key,
        { name: "Ed25519" },
        true,  // extractable to get public key
        ["sign"]
    );
    const jwk = await crypto.subtle.exportKey("jwk", tempSigningKey);
    const publicKeyBase64 = base64UrlToBase64(jwk.x!);

    // Clear sensitive key material from memory
    signingKeyBytes.fill(0);
    pkcs8Key.fill(0);

    // Clear any existing entry for this salt
    clearCacheEntry(saltBase64);

    // Cache the keys
    keyCache.set(saltBase64, {
        encryptionKey,
        signingKey,
        publicKeyBase64,
        credentialIdBase64,
        expiresAt: null,
        expirationTimer: null
    });

    // Schedule expiration if TTL provided
    if (ttlMs !== null && ttlMs > 0) {
        scheduleExpiration(saltBase64, ttlMs);
    }

    // Return only public information - private keys stay in JS
    return JSON.stringify({
        success: true,
        credentialId: credentialIdBase64,
        publicKey: publicKeyBase64
    });
}

// ============================================================
// CACHE MANAGEMENT
// ============================================================

/**
 * Check if keys are cached for the given salt.
 */
export function hasCachedKeys(saltBase64: string): boolean {
    const entry = keyCache.get(saltBase64);
    if (!entry) {
        return false;
    }
    // Check expiration
    if (entry.expiresAt !== null && Date.now() > entry.expiresAt) {
        clearCacheEntry(saltBase64);
        return false;
    }
    return true;
}

/**
 * Get cached public key and credential ID (no private key exposure).
 */
export function getCachedPublicInfo(saltBase64: string): string {
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

/**
 * Clear cached keys for the given salt.
 */
export function clearCachedKeys(saltBase64: string): void {
    clearCacheEntry(saltBase64);
}

/**
 * Clear all cached keys.
 */
export function clearAllCachedKeys(): void {
    for (const salt of keyCache.keys()) {
        clearCacheEntry(salt);
    }
}

// ============================================================
// AES-256-GCM SYMMETRIC ENCRYPTION (using cached keys)
// ============================================================

/**
 * Encrypt plaintext using cached AES-GCM key.
 * @param plaintextBase64 Base64-encoded plaintext
 * @param saltBase64 Salt identifying the cached key
 * @returns JSON with ciphertext and nonce (both Base64)
 */
export async function encryptAesGcm(plaintextBase64: string, saltBase64: string): Promise<string> {
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
        return JSON.stringify({ success: false, error: (e as Error).message });
    }
}

/**
 * Decrypt ciphertext using cached AES-GCM key.
 * @param ciphertextBase64 Base64-encoded ciphertext (includes auth tag)
 * @param nonceBase64 Base64-encoded 12-byte nonce
 * @param saltBase64 Salt identifying the cached key
 * @returns JSON with plaintext or error
 */
export async function decryptAesGcm(
    ciphertextBase64: string,
    nonceBase64: string,
    saltBase64: string
): Promise<string> {
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

        // Validate nonce length (must be 12 bytes for AES-GCM)
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

// ============================================================
// ED25519 DIGITAL SIGNATURES (using cached keys)
// ============================================================

/**
 * Sign a message using cached Ed25519 key.
 * @param messageBase64 Base64-encoded message
 * @param saltBase64 Salt identifying the cached key
 * @returns JSON with signature or error
 */
export async function ed25519Sign(messageBase64: string, saltBase64: string): Promise<string> {
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
        return JSON.stringify({ success: false, error: (e as Error).message });
    }
}

/**
 * Verify an Ed25519 signature.
 * @param messageBase64 Base64-encoded message
 * @param signatureBase64 Base64-encoded 64-byte signature
 * @param publicKeyBase64 Base64-encoded 32-byte public key
 * @returns true if valid, false otherwise
 */
export async function ed25519Verify(
    messageBase64: string,
    signatureBase64: string,
    publicKeyBase64: string
): Promise<boolean> {
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

// ============================================================
// UTILITY FUNCTIONS
// ============================================================

/**
 * Check if PRF extension is likely supported.
 */
export function isPrfSupported(): boolean {
    return typeof PublicKeyCredential !== "undefined" &&
        typeof navigator.credentials !== "undefined";
}

/**
 * Check if conditional mediation (passkey autofill) is available.
 * Returns true if the browser supports passkey autofill UI.
 */
export async function isConditionalMediationAvailable(): Promise<boolean> {
    if (typeof PublicKeyCredential === "undefined") {
        return false;
    }
    if (typeof PublicKeyCredential.isConditionalMediationAvailable !== "function") {
        return false;
    }
    return await PublicKeyCredential.isConditionalMediationAvailable();
}

/**
 * Wrap Ed25519 seed in PKCS8 format.
 */
function wrapSeedInPkcs8(seed: Uint8Array): Uint8Array {
    const pkcs8Header = new Uint8Array([
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
        0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20
    ]);
    const pkcs8Key = new Uint8Array(pkcs8Header.length + seed.length);
    pkcs8Key.set(pkcs8Header);
    pkcs8Key.set(seed, pkcs8Header.length);
    return pkcs8Key;
}

function bytesToBase64(bytes: Uint8Array): string {
    let binary = "";
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

function base64ToBytes(base64: string): Uint8Array {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

function base64UrlToBase64(base64url: string): string {
    return base64url
        .replace(/-/g, "+")
        .replace(/_/g, "/")
        .padEnd(base64url.length + (4 - base64url.length % 4) % 4, "=");
}

// Export for .NET JSImport
export const BlazorPRFBase = {
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
