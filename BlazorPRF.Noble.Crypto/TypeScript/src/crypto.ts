/**
 * BlazorPRF Noble.js + SubtleCrypto Hybrid Crypto Provider
 *
 * Uses:
 * - Noble.js: X25519 (ECIES), Ed25519 (signing), ChaCha20-Poly1305
 * - SubtleCrypto: AES-GCM (hardware accelerated), HKDF, random bytes
 */

import { x25519 } from '@noble/curves/ed25519';
import { ed25519 } from '@noble/curves/ed25519';
import { xchacha20poly1305 } from '@noble/ciphers/chacha';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { randomBytes } from '@noble/ciphers/webcrypto';

// ============================================================
// CONSTANTS
// ============================================================

const NONCE_LENGTH_CHACHA = 24;  // XChaCha20-Poly1305 uses 24-byte nonce
const NONCE_LENGTH_AES = 12;     // AES-GCM uses 12-byte nonce
const KEY_LENGTH = 32;           // 256-bit keys

// ============================================================
// KEY CACHE (Keys stored in JS, C# only references by keyId)
// ============================================================

/**
 * Cached key set containing all derived keys for a keyId.
 * Keys stay in JS memory - they never travel back to C#.
 */
interface CachedKeySet {
    x25519Private: Uint8Array;
    x25519Public: Uint8Array;
    ed25519Private: Uint8Array;
    ed25519Public: Uint8Array;
    symmetricKey: Uint8Array;
    aesEncryptKey: CryptoKey | null;  // For AES-GCM hardware acceleration
    aesDecryptKey: CryptoKey | null;
    expiresAt: number | null;
    expirationTimer: number | null;
}

const keyCache = new Map<string, CachedKeySet>();

/**
 * Store and derive all keys from PRF seed, caching in JS.
 * This is called once after WebAuthn authentication.
 * Keys stay in JS - C# only uses keyId for subsequent operations.
 */
export async function storeKeys(keyId: string, prfSeedBase64: string, ttlMs: number | null): Promise<string> {
    try {
        const seed = base64ToBytes(prfSeedBase64);

        // Derive all keypairs using HKDF
        const x25519Private = hkdf(sha256, seed, undefined, 'x25519-key', 32);
        const x25519Public = x25519.getPublicKey(x25519Private);
        const ed25519Private = hkdf(sha256, seed, undefined, 'ed25519-key', 32);
        const ed25519Public = ed25519.getPublicKey(ed25519Private);
        const symmetricKey = hkdf(sha256, seed, undefined, 'symmetric-key', 32);

        // Import AES key for SubtleCrypto (hardware accelerated)
        const aesEncryptKey = await crypto.subtle.importKey(
            'raw', symmetricKey, { name: 'AES-GCM' }, false, ['encrypt']
        );
        const aesDecryptKey = await crypto.subtle.importKey(
            'raw', symmetricKey, { name: 'AES-GCM' }, false, ['decrypt']
        );

        // Clear the seed immediately
        clearBytes(seed);

        // Remove existing entry if present
        removeKeys(keyId);

        const expiresAt = ttlMs !== null ? Date.now() + ttlMs : null;
        let expirationTimer: number | null = null;

        if (ttlMs !== null) {
            expirationTimer = window.setTimeout(() => {
                removeKeys(keyId);
            }, ttlMs);
        }

        keyCache.set(keyId, {
            x25519Private,
            x25519Public,
            ed25519Private,
            ed25519Public,
            symmetricKey,
            aesEncryptKey,
            aesDecryptKey,
            expiresAt,
            expirationTimer
        });

        return JSON.stringify({
            success: true,
            x25519PublicKeyBase64: bytesToBase64(x25519Public),
            ed25519PublicKeyBase64: bytesToBase64(ed25519Public)
        });
    } catch (e) {
        return JSON.stringify({
            success: false,
            error: `Key storage failed: ${e instanceof Error ? e.message : 'Unknown error'}`
        });
    }
}

/**
 * Get public keys for a cached key set.
 */
export function getPublicKeys(keyId: string): string {
    const keys = keyCache.get(keyId);
    if (!keys || isExpired(keys)) {
        return JSON.stringify({
            success: false,
            error: 'Key not found or expired'
        });
    }

    return JSON.stringify({
        success: true,
        x25519PublicKeyBase64: bytesToBase64(keys.x25519Public),
        ed25519PublicKeyBase64: bytesToBase64(keys.ed25519Public)
    });
}

/**
 * Check if a key exists and is not expired.
 */
export function hasKey(keyId: string): boolean {
    const keys = keyCache.get(keyId);
    return keys !== undefined && !isExpired(keys);
}

/**
 * Remove and securely clear a cached key set.
 */
export function removeKeys(keyId: string): void {
    const keys = keyCache.get(keyId);
    if (keys) {
        // Clear timer if active
        if (keys.expirationTimer !== null) {
            clearTimeout(keys.expirationTimer);
        }

        // Securely clear all key material
        clearBytes(keys.x25519Private);
        clearBytes(keys.x25519Public);
        clearBytes(keys.ed25519Private);
        clearBytes(keys.ed25519Public);
        clearBytes(keys.symmetricKey);

        keyCache.delete(keyId);
    }
}

/**
 * Remove all cached keys.
 */
export function clearAllKeys(): void {
    for (const keyId of keyCache.keys()) {
        removeKeys(keyId);
    }
}

/**
 * Check if a key set is expired.
 */
function isExpired(keys: CachedKeySet): boolean {
    return keys.expiresAt !== null && Date.now() >= keys.expiresAt;
}

/**
 * Get cached keys, returns null if not found or expired.
 */
function getCachedKeys(keyId: string): CachedKeySet | null {
    const keys = keyCache.get(keyId);
    if (!keys || isExpired(keys)) {
        if (keys) {
            removeKeys(keyId);
        }
        return null;
    }
    return keys;
}

// ============================================================
// CACHED KEY OPERATIONS (use keyId, keys stay in JS)
// ============================================================

/**
 * Sign with Ed25519 using cached key.
 */
export function signWithCachedKey(keyId: string, messageBase64: string): string {
    try {
        const keys = getCachedKeys(keyId);
        if (!keys) {
            return JSON.stringify({ success: false, error: 'Key not found or expired' });
        }

        const message = base64ToBytes(messageBase64);
        const signature = ed25519.sign(message, keys.ed25519Private);

        return JSON.stringify({
            success: true,
            signatureBase64: bytesToBase64(signature)
        });
    } catch (e) {
        return JSON.stringify({
            success: false,
            error: 'Signing failed'
        });
    }
}

/**
 * Encrypt symmetric with ChaCha20-Poly1305 using cached key.
 */
export function encryptSymmetricCachedChaCha(keyId: string, plaintextBase64: string): string {
    try {
        const keys = getCachedKeys(keyId);
        if (!keys) {
            return JSON.stringify({ success: false, error: 'Key not found or expired' });
        }

        const plaintext = base64ToBytes(plaintextBase64);
        const nonce = randomBytes(NONCE_LENGTH_CHACHA);
        const cipher = xchacha20poly1305(keys.symmetricKey, nonce);
        const ciphertext = cipher.encrypt(plaintext);

        return JSON.stringify({
            success: true,
            ciphertextBase64: bytesToBase64(ciphertext),
            nonceBase64: bytesToBase64(nonce)
        });
    } catch (e) {
        return JSON.stringify({
            success: false,
            error: 'Encryption failed'
        });
    }
}

/**
 * Decrypt symmetric with ChaCha20-Poly1305 using cached key.
 */
export function decryptSymmetricCachedChaCha(keyId: string, ciphertextBase64: string, nonceBase64: string): string {
    try {
        const keys = getCachedKeys(keyId);
        if (!keys) {
            return JSON.stringify({ success: false, error: 'Key not found or expired' });
        }

        const ciphertext = base64ToBytes(ciphertextBase64);
        const nonce = base64ToBytes(nonceBase64);

        if (nonce.length !== NONCE_LENGTH_CHACHA) {
            return JSON.stringify({ success: false, error: 'Invalid nonce length' });
        }

        const cipher = xchacha20poly1305(keys.symmetricKey, nonce);
        const plaintext = cipher.decrypt(ciphertext);

        return JSON.stringify({
            success: true,
            plaintextBase64: bytesToBase64(plaintext)
        });
    } catch (e) {
        return JSON.stringify({
            success: false,
            error: 'Decryption failed'
        });
    }
}

/**
 * Encrypt symmetric with AES-GCM using cached CryptoKey (hardware accelerated).
 */
export async function encryptSymmetricCachedAesGcm(keyId: string, plaintextBase64: string): Promise<string> {
    try {
        const keys = getCachedKeys(keyId);
        if (!keys || !keys.aesEncryptKey) {
            return JSON.stringify({ success: false, error: 'Key not found or expired' });
        }

        const plaintext = base64ToBytes(plaintextBase64);
        const nonce = randomBytes(NONCE_LENGTH_AES);

        const ciphertext = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: nonce },
            keys.aesEncryptKey,
            plaintext
        );

        return JSON.stringify({
            success: true,
            ciphertextBase64: bytesToBase64(new Uint8Array(ciphertext)),
            nonceBase64: bytesToBase64(nonce)
        });
    } catch (e) {
        return JSON.stringify({
            success: false,
            error: 'AES-GCM encryption failed'
        });
    }
}

/**
 * Decrypt symmetric with AES-GCM using cached CryptoKey (hardware accelerated).
 */
export async function decryptSymmetricCachedAesGcm(keyId: string, ciphertextBase64: string, nonceBase64: string): Promise<string> {
    try {
        const keys = getCachedKeys(keyId);
        if (!keys || !keys.aesDecryptKey) {
            return JSON.stringify({ success: false, error: 'Key not found or expired' });
        }

        const ciphertext = base64ToBytes(ciphertextBase64);
        const nonce = base64ToBytes(nonceBase64);

        if (nonce.length !== NONCE_LENGTH_AES) {
            return JSON.stringify({ success: false, error: 'Invalid nonce length' });
        }

        const plaintext = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: nonce },
            keys.aesDecryptKey,
            ciphertext
        );

        return JSON.stringify({
            success: true,
            plaintextBase64: bytesToBase64(new Uint8Array(plaintext))
        });
    } catch (e) {
        return JSON.stringify({
            success: false,
            error: 'AES-GCM decryption failed'
        });
    }
}

/**
 * Decrypt asymmetric (ECIES) with ChaCha20-Poly1305 using cached X25519 private key.
 */
export function decryptAsymmetricCachedChaCha(
    keyId: string,
    ephemeralPublicKeyBase64: string,
    ciphertextBase64: string,
    nonceBase64: string
): string {
    try {
        const keys = getCachedKeys(keyId);
        if (!keys) {
            return JSON.stringify({ success: false, error: 'Key not found or expired' });
        }

        const ephemeralPublicKey = base64ToBytes(ephemeralPublicKeyBase64);
        const ciphertext = base64ToBytes(ciphertextBase64);
        const nonce = base64ToBytes(nonceBase64);

        if (nonce.length !== NONCE_LENGTH_CHACHA) {
            return JSON.stringify({ success: false, error: 'Invalid nonce length' });
        }

        // X25519 key agreement using cached private key
        const sharedSecret = x25519.getSharedSecret(keys.x25519Private, ephemeralPublicKey);
        const encryptionKey = hkdf(sha256, sharedSecret, undefined, 'ecies-xchacha20poly1305', 32);

        const cipher = xchacha20poly1305(encryptionKey, nonce);
        const plaintext = cipher.decrypt(ciphertext);

        clearBytes(sharedSecret);
        clearBytes(encryptionKey);

        return JSON.stringify({
            success: true,
            plaintextBase64: bytesToBase64(plaintext)
        });
    } catch (e) {
        return JSON.stringify({
            success: false,
            error: 'Asymmetric decryption failed'
        });
    }
}

/**
 * Decrypt asymmetric (ECIES) with AES-GCM using cached X25519 private key.
 */
export async function decryptAsymmetricCachedAesGcm(
    keyId: string,
    ephemeralPublicKeyBase64: string,
    ciphertextBase64: string,
    nonceBase64: string
): Promise<string> {
    try {
        const keys = getCachedKeys(keyId);
        if (!keys) {
            return JSON.stringify({ success: false, error: 'Key not found or expired' });
        }

        const ephemeralPublicKey = base64ToBytes(ephemeralPublicKeyBase64);
        const ciphertext = base64ToBytes(ciphertextBase64);
        const nonce = base64ToBytes(nonceBase64);

        if (nonce.length !== NONCE_LENGTH_AES) {
            return JSON.stringify({ success: false, error: 'Invalid nonce length' });
        }

        // X25519 key agreement using cached private key
        const sharedSecret = x25519.getSharedSecret(keys.x25519Private, ephemeralPublicKey);
        const encryptionKeyBytes = hkdf(sha256, sharedSecret, undefined, 'ecies-aes-gcm', 32);

        const encryptionKey = await crypto.subtle.importKey(
            'raw', encryptionKeyBytes, { name: 'AES-GCM' }, false, ['decrypt']
        );

        const plaintext = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: nonce },
            encryptionKey,
            ciphertext
        );

        clearBytes(sharedSecret);
        clearBytes(encryptionKeyBytes);

        return JSON.stringify({
            success: true,
            plaintextBase64: bytesToBase64(new Uint8Array(plaintext))
        });
    } catch (e) {
        return JSON.stringify({
            success: false,
            error: 'Asymmetric decryption failed'
        });
    }
}

// ============================================================
// UTILITY FUNCTIONS
// ============================================================

function base64ToBytes(base64: string): Uint8Array {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

function bytesToBase64(bytes: Uint8Array): string {
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

function clearBytes(bytes: Uint8Array): void {
    bytes.fill(0);
}

// ============================================================
// X25519 KEY EXCHANGE (Noble.js)
// ============================================================

/**
 * Generate X25519 keypair
 */
export function generateX25519KeyPair(): string {
    const privateKey = randomBytes(32);
    const publicKey = x25519.getPublicKey(privateKey);

    const result = JSON.stringify({
        success: true,
        privateKeyBase64: bytesToBase64(privateKey),
        publicKeyBase64: bytesToBase64(publicKey)
    });

    clearBytes(privateKey);
    return result;
}

/**
 * Derive X25519 public key from private key
 */
export function getX25519PublicKey(privateKeyBase64: string): string {
    try {
        const privateKey = base64ToBytes(privateKeyBase64);
        const publicKey = x25519.getPublicKey(privateKey);
        clearBytes(privateKey);
        return bytesToBase64(publicKey);
    } catch (e) {
        return '';
    }
}

/**
 * Perform X25519 key agreement (ECDH)
 */
function x25519SharedSecret(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
    return x25519.getSharedSecret(privateKey, publicKey);
}

// ============================================================
// ED25519 SIGNING (Noble.js)
// ============================================================

/**
 * Generate Ed25519 keypair
 */
export function generateEd25519KeyPair(): string {
    const privateKey = randomBytes(32);
    const publicKey = ed25519.getPublicKey(privateKey);

    const result = JSON.stringify({
        success: true,
        privateKeyBase64: bytesToBase64(privateKey),
        publicKeyBase64: bytesToBase64(publicKey)
    });

    clearBytes(privateKey);
    return result;
}

/**
 * Derive Ed25519 public key from private key
 */
export function getEd25519PublicKey(privateKeyBase64: string): string {
    try {
        const privateKey = base64ToBytes(privateKeyBase64);
        const publicKey = ed25519.getPublicKey(privateKey);
        clearBytes(privateKey);
        return bytesToBase64(publicKey);
    } catch (e) {
        return '';
    }
}

/**
 * Sign a message with Ed25519
 */
export function ed25519Sign(messageBase64: string, privateKeyBase64: string): string {
    try {
        const message = base64ToBytes(messageBase64);
        const privateKey = base64ToBytes(privateKeyBase64);

        const signature = ed25519.sign(message, privateKey);

        clearBytes(privateKey);

        return JSON.stringify({
            success: true,
            signatureBase64: bytesToBase64(signature)
        });
    } catch (e) {
        return JSON.stringify({
            success: false,
            error: `Signing failed: ${e instanceof Error ? e.message : 'Unknown error'}`
        });
    }
}

/**
 * Verify an Ed25519 signature
 */
export function ed25519Verify(messageBase64: string, signatureBase64: string, publicKeyBase64: string): boolean {
    try {
        const message = base64ToBytes(messageBase64);
        const signature = base64ToBytes(signatureBase64);
        const publicKey = base64ToBytes(publicKeyBase64);

        return ed25519.verify(signature, message, publicKey);
    } catch (e) {
        return false;
    }
}

// ============================================================
// CHACHA20-POLY1305 SYMMETRIC ENCRYPTION (Noble.js)
// ============================================================

/**
 * Encrypt with XChaCha20-Poly1305
 */
export function encryptChaCha(plaintextBase64: string, keyBase64: string): string {
    try {
        const plaintext = base64ToBytes(plaintextBase64);
        const key = base64ToBytes(keyBase64);

        if (key.length !== KEY_LENGTH) {
            return JSON.stringify({
                success: false,
                error: `Invalid key length: expected ${KEY_LENGTH}, got ${key.length}`
            });
        }

        const nonce = randomBytes(NONCE_LENGTH_CHACHA);
        const cipher = xchacha20poly1305(key, nonce);
        const ciphertext = cipher.encrypt(plaintext);

        clearBytes(key);

        return JSON.stringify({
            success: true,
            ciphertextBase64: bytesToBase64(ciphertext),
            nonceBase64: bytesToBase64(nonce)
        });
    } catch (e) {
        return JSON.stringify({
            success: false,
            error: `Encryption failed: ${e instanceof Error ? e.message : 'Unknown error'}`
        });
    }
}

/**
 * Decrypt with XChaCha20-Poly1305
 */
export function decryptChaCha(ciphertextBase64: string, nonceBase64: string, keyBase64: string): string {
    try {
        const ciphertext = base64ToBytes(ciphertextBase64);
        const nonce = base64ToBytes(nonceBase64);
        const key = base64ToBytes(keyBase64);

        if (key.length !== KEY_LENGTH) {
            return JSON.stringify({
                success: false,
                error: `Invalid key length: expected ${KEY_LENGTH}, got ${key.length}`
            });
        }

        if (nonce.length !== NONCE_LENGTH_CHACHA) {
            return JSON.stringify({
                success: false,
                error: `Invalid nonce length: expected ${NONCE_LENGTH_CHACHA}, got ${nonce.length}`
            });
        }

        const cipher = xchacha20poly1305(key, nonce);
        const plaintext = cipher.decrypt(ciphertext);

        clearBytes(key);

        return JSON.stringify({
            success: true,
            plaintextBase64: bytesToBase64(plaintext)
        });
    } catch (e) {
        return JSON.stringify({
            success: false,
            error: `Decryption failed: ${e instanceof Error ? e.message : 'Unknown error'}`
        });
    }
}

// ============================================================
// AES-GCM SYMMETRIC ENCRYPTION (SubtleCrypto - hardware accelerated)
// ============================================================

/**
 * Encrypt with AES-256-GCM using SubtleCrypto
 */
export async function encryptAesGcm(plaintextBase64: string, keyBase64: string): Promise<string> {
    try {
        const plaintext = base64ToBytes(plaintextBase64);
        const keyBytes = base64ToBytes(keyBase64);

        if (keyBytes.length !== KEY_LENGTH) {
            return JSON.stringify({
                success: false,
                error: `Invalid key length: expected ${KEY_LENGTH}, got ${keyBytes.length}`
            });
        }

        const key = await crypto.subtle.importKey(
            'raw',
            keyBytes,
            { name: 'AES-GCM' },
            false,
            ['encrypt']
        );

        const nonce = randomBytes(NONCE_LENGTH_AES);

        const ciphertext = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: nonce },
            key,
            plaintext
        );

        clearBytes(keyBytes);

        return JSON.stringify({
            success: true,
            ciphertextBase64: bytesToBase64(new Uint8Array(ciphertext)),
            nonceBase64: bytesToBase64(nonce)
        });
    } catch (e) {
        return JSON.stringify({
            success: false,
            error: `AES-GCM encryption failed: ${e instanceof Error ? e.message : 'Unknown error'}`
        });
    }
}

/**
 * Decrypt with AES-256-GCM using SubtleCrypto
 */
export async function decryptAesGcm(ciphertextBase64: string, nonceBase64: string, keyBase64: string): Promise<string> {
    try {
        const ciphertext = base64ToBytes(ciphertextBase64);
        const nonce = base64ToBytes(nonceBase64);
        const keyBytes = base64ToBytes(keyBase64);

        if (keyBytes.length !== KEY_LENGTH) {
            return JSON.stringify({
                success: false,
                error: `Invalid key length: expected ${KEY_LENGTH}, got ${keyBytes.length}`
            });
        }

        if (nonce.length !== NONCE_LENGTH_AES) {
            return JSON.stringify({
                success: false,
                error: `Invalid nonce length: expected ${NONCE_LENGTH_AES}, got ${nonce.length}`
            });
        }

        const key = await crypto.subtle.importKey(
            'raw',
            keyBytes,
            { name: 'AES-GCM' },
            false,
            ['decrypt']
        );

        const plaintext = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: nonce },
            key,
            ciphertext
        );

        clearBytes(keyBytes);

        return JSON.stringify({
            success: true,
            plaintextBase64: bytesToBase64(new Uint8Array(plaintext))
        });
    } catch (e) {
        return JSON.stringify({
            success: false,
            error: `AES-GCM decryption failed: ${e instanceof Error ? e.message : 'Unknown error'}`
        });
    }
}

// ============================================================
// ECIES ASYMMETRIC ENCRYPTION (X25519 + ChaCha20-Poly1305)
// ============================================================

/**
 * Encrypt with ECIES: X25519 key agreement + XChaCha20-Poly1305
 */
export function encryptAsymmetricChaCha(plaintextBase64: string, recipientPublicKeyBase64: string): string {
    try {
        const plaintext = base64ToBytes(plaintextBase64);
        const recipientPublicKey = base64ToBytes(recipientPublicKeyBase64);

        if (recipientPublicKey.length !== KEY_LENGTH) {
            return JSON.stringify({
                success: false,
                error: `Invalid public key length: expected ${KEY_LENGTH}, got ${recipientPublicKey.length}`
            });
        }

        // Generate ephemeral keypair
        const ephemeralPrivate = randomBytes(32);
        const ephemeralPublic = x25519.getPublicKey(ephemeralPrivate);

        // X25519 key agreement
        const sharedSecret = x25519SharedSecret(ephemeralPrivate, recipientPublicKey);

        // Derive encryption key using HKDF
        const encryptionKey = hkdf(sha256, sharedSecret, undefined, 'ecies-xchacha20poly1305', 32);

        // Encrypt with XChaCha20-Poly1305
        const nonce = randomBytes(NONCE_LENGTH_CHACHA);
        const cipher = xchacha20poly1305(encryptionKey, nonce);
        const ciphertext = cipher.encrypt(plaintext);

        // Clear sensitive data
        clearBytes(ephemeralPrivate);
        clearBytes(sharedSecret);
        clearBytes(encryptionKey);

        return JSON.stringify({
            success: true,
            ephemeralPublicKeyBase64: bytesToBase64(ephemeralPublic),
            ciphertextBase64: bytesToBase64(ciphertext),
            nonceBase64: bytesToBase64(nonce)
        });
    } catch (e) {
        return JSON.stringify({
            success: false,
            error: `Asymmetric encryption failed: ${e instanceof Error ? e.message : 'Unknown error'}`
        });
    }
}

/**
 * Decrypt with ECIES: X25519 key agreement + XChaCha20-Poly1305
 */
export function decryptAsymmetricChaCha(
    ephemeralPublicKeyBase64: string,
    ciphertextBase64: string,
    nonceBase64: string,
    privateKeyBase64: string
): string {
    try {
        const ephemeralPublicKey = base64ToBytes(ephemeralPublicKeyBase64);
        const ciphertext = base64ToBytes(ciphertextBase64);
        const nonce = base64ToBytes(nonceBase64);
        const privateKey = base64ToBytes(privateKeyBase64);

        if (privateKey.length !== KEY_LENGTH) {
            return JSON.stringify({
                success: false,
                error: `Invalid private key length: expected ${KEY_LENGTH}, got ${privateKey.length}`
            });
        }

        if (nonce.length !== NONCE_LENGTH_CHACHA) {
            return JSON.stringify({
                success: false,
                error: `Invalid nonce length: expected ${NONCE_LENGTH_CHACHA}, got ${nonce.length}`
            });
        }

        // X25519 key agreement
        const sharedSecret = x25519SharedSecret(privateKey, ephemeralPublicKey);

        // Derive encryption key using HKDF
        const encryptionKey = hkdf(sha256, sharedSecret, undefined, 'ecies-xchacha20poly1305', 32);

        // Decrypt with XChaCha20-Poly1305
        const cipher = xchacha20poly1305(encryptionKey, nonce);
        const plaintext = cipher.decrypt(ciphertext);

        // Clear sensitive data
        clearBytes(privateKey);
        clearBytes(sharedSecret);
        clearBytes(encryptionKey);

        return JSON.stringify({
            success: true,
            plaintextBase64: bytesToBase64(plaintext)
        });
    } catch (e) {
        return JSON.stringify({
            success: false,
            error: `Asymmetric decryption failed: ${e instanceof Error ? e.message : 'Unknown error'}`
        });
    }
}

/**
 * Encrypt with ECIES: X25519 key agreement + AES-256-GCM
 */
export async function encryptAsymmetricAesGcm(plaintextBase64: string, recipientPublicKeyBase64: string): Promise<string> {
    try {
        const plaintext = base64ToBytes(plaintextBase64);
        const recipientPublicKey = base64ToBytes(recipientPublicKeyBase64);

        if (recipientPublicKey.length !== KEY_LENGTH) {
            return JSON.stringify({
                success: false,
                error: `Invalid public key length: expected ${KEY_LENGTH}, got ${recipientPublicKey.length}`
            });
        }

        // Generate ephemeral keypair
        const ephemeralPrivate = randomBytes(32);
        const ephemeralPublic = x25519.getPublicKey(ephemeralPrivate);

        // X25519 key agreement
        const sharedSecret = x25519SharedSecret(ephemeralPrivate, recipientPublicKey);

        // Derive encryption key using HKDF
        const encryptionKeyBytes = hkdf(sha256, sharedSecret, undefined, 'ecies-aes-gcm', 32);

        // Import key for SubtleCrypto
        const encryptionKey = await crypto.subtle.importKey(
            'raw',
            encryptionKeyBytes,
            { name: 'AES-GCM' },
            false,
            ['encrypt']
        );

        // Encrypt with AES-256-GCM
        const nonce = randomBytes(NONCE_LENGTH_AES);
        const ciphertext = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: nonce },
            encryptionKey,
            plaintext
        );

        // Clear sensitive data
        clearBytes(ephemeralPrivate);
        clearBytes(sharedSecret);
        clearBytes(encryptionKeyBytes);

        return JSON.stringify({
            success: true,
            ephemeralPublicKeyBase64: bytesToBase64(ephemeralPublic),
            ciphertextBase64: bytesToBase64(new Uint8Array(ciphertext)),
            nonceBase64: bytesToBase64(nonce)
        });
    } catch (e) {
        return JSON.stringify({
            success: false,
            error: `Asymmetric encryption failed: ${e instanceof Error ? e.message : 'Unknown error'}`
        });
    }
}

/**
 * Decrypt with ECIES: X25519 key agreement + AES-256-GCM
 */
export async function decryptAsymmetricAesGcm(
    ephemeralPublicKeyBase64: string,
    ciphertextBase64: string,
    nonceBase64: string,
    privateKeyBase64: string
): Promise<string> {
    try {
        const ephemeralPublicKey = base64ToBytes(ephemeralPublicKeyBase64);
        const ciphertext = base64ToBytes(ciphertextBase64);
        const nonce = base64ToBytes(nonceBase64);
        const privateKey = base64ToBytes(privateKeyBase64);

        if (privateKey.length !== KEY_LENGTH) {
            return JSON.stringify({
                success: false,
                error: `Invalid private key length: expected ${KEY_LENGTH}, got ${privateKey.length}`
            });
        }

        if (nonce.length !== NONCE_LENGTH_AES) {
            return JSON.stringify({
                success: false,
                error: `Invalid nonce length: expected ${NONCE_LENGTH_AES}, got ${nonce.length}`
            });
        }

        // X25519 key agreement
        const sharedSecret = x25519SharedSecret(privateKey, ephemeralPublicKey);

        // Derive encryption key using HKDF
        const encryptionKeyBytes = hkdf(sha256, sharedSecret, undefined, 'ecies-aes-gcm', 32);

        // Import key for SubtleCrypto
        const encryptionKey = await crypto.subtle.importKey(
            'raw',
            encryptionKeyBytes,
            { name: 'AES-GCM' },
            false,
            ['decrypt']
        );

        // Decrypt with AES-256-GCM
        const plaintext = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: nonce },
            encryptionKey,
            ciphertext
        );

        // Clear sensitive data
        clearBytes(privateKey);
        clearBytes(sharedSecret);
        clearBytes(encryptionKeyBytes);

        return JSON.stringify({
            success: true,
            plaintextBase64: bytesToBase64(new Uint8Array(plaintext))
        });
    } catch (e) {
        return JSON.stringify({
            success: false,
            error: `Asymmetric decryption failed: ${e instanceof Error ? e.message : 'Unknown error'}`
        });
    }
}

// ============================================================
// KEY DERIVATION
// ============================================================

/**
 * Derive X25519 keypair from PRF seed using HKDF
 */
export function deriveX25519KeyPair(prfSeedBase64: string): string {
    try {
        const seed = base64ToBytes(prfSeedBase64);

        // Derive private key using HKDF
        const privateKey = hkdf(sha256, seed, undefined, 'x25519-key', 32);
        const publicKey = x25519.getPublicKey(privateKey);

        const result = JSON.stringify({
            success: true,
            privateKeyBase64: bytesToBase64(privateKey),
            publicKeyBase64: bytesToBase64(publicKey)
        });

        clearBytes(seed);
        clearBytes(privateKey);

        return result;
    } catch (e) {
        return JSON.stringify({
            success: false,
            error: `Key derivation failed: ${e instanceof Error ? e.message : 'Unknown error'}`
        });
    }
}

/**
 * Derive Ed25519 keypair from PRF seed using HKDF
 */
export function deriveEd25519KeyPair(prfSeedBase64: string): string {
    try {
        const seed = base64ToBytes(prfSeedBase64);

        // Derive private key using HKDF
        const privateKey = hkdf(sha256, seed, undefined, 'ed25519-key', 32);
        const publicKey = ed25519.getPublicKey(privateKey);

        const result = JSON.stringify({
            success: true,
            privateKeyBase64: bytesToBase64(privateKey),
            publicKeyBase64: bytesToBase64(publicKey)
        });

        clearBytes(seed);
        clearBytes(privateKey);

        return result;
    } catch (e) {
        return JSON.stringify({
            success: false,
            error: `Key derivation failed: ${e instanceof Error ? e.message : 'Unknown error'}`
        });
    }
}

/**
 * Derive both X25519 and Ed25519 keypairs from PRF seed
 */
export function deriveDualKeyPair(prfSeedBase64: string): string {
    try {
        const seed = base64ToBytes(prfSeedBase64);

        // Derive X25519 keypair
        const x25519Private = hkdf(sha256, seed, undefined, 'x25519-key', 32);
        const x25519Public = x25519.getPublicKey(x25519Private);

        // Derive Ed25519 keypair
        const ed25519Private = hkdf(sha256, seed, undefined, 'ed25519-key', 32);
        const ed25519Public = ed25519.getPublicKey(ed25519Private);

        const result = JSON.stringify({
            success: true,
            x25519PrivateKeyBase64: bytesToBase64(x25519Private),
            x25519PublicKeyBase64: bytesToBase64(x25519Public),
            ed25519PrivateKeyBase64: bytesToBase64(ed25519Private),
            ed25519PublicKeyBase64: bytesToBase64(ed25519Public)
        });

        clearBytes(seed);
        clearBytes(x25519Private);
        clearBytes(ed25519Private);

        return result;
    } catch (e) {
        return JSON.stringify({
            success: false,
            error: `Key derivation failed: ${e instanceof Error ? e.message : 'Unknown error'}`
        });
    }
}

/**
 * Derive a domain-specific key from PRF seed using HKDF
 */
export async function deriveHkdfKey(prfSeedBase64: string, domain: string): Promise<string> {
    try {
        const seed = base64ToBytes(prfSeedBase64);

        // Derive domain-specific key using HKDF
        const domainKey = hkdf(sha256, seed, undefined, domain, 32);

        const result = bytesToBase64(domainKey);

        clearBytes(seed);
        clearBytes(domainKey);

        return result;
    } catch (e) {
        throw new Error(`HKDF key derivation failed: ${e instanceof Error ? e.message : 'Unknown error'}`);
    }
}

// ============================================================
// UTILITY EXPORTS
// ============================================================

/**
 * Generate random bytes (Base64 encoded)
 */
export function generateRandomBytes(length: number): string {
    const bytes = randomBytes(length);
    return bytesToBase64(bytes);
}

/**
 * Check if all crypto features are available
 */
export function isSupported(): boolean {
    try {
        // Check Noble.js works
        const testKey = randomBytes(32);
        x25519.getPublicKey(testKey);
        ed25519.getPublicKey(testKey);

        // Check SubtleCrypto is available
        if (typeof crypto === 'undefined' || typeof crypto.subtle === 'undefined') {
            return false;
        }

        return true;
    } catch {
        return false;
    }
}
