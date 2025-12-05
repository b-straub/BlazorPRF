// ECIES asymmetric encryption using X25519 + ChaCha20-Poly1305

import { chacha20poly1305 } from '@noble/ciphers/chacha';
import { randomBytes } from '@noble/ciphers/webcrypto';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import type { EncryptedMessage } from './types.js';
import { toBase64, fromBase64, zeroFill } from './utils.js';
import { generateEphemeralKeypair, computeSharedSecret } from './keypair.js';

const NONCE_LENGTH = 12;
const HKDF_INFO = new TextEncoder().encode('BlazorPRF-ECIES-v1');

/**
 * Derive an encryption key from shared secret using HKDF.
 *
 * @param sharedSecret The ECDH shared secret
 * @param ephemeralPublicKey The ephemeral public key (used as salt)
 * @returns 32-byte encryption key
 */
function deriveEncryptionKey(
    sharedSecret: Uint8Array,
    ephemeralPublicKey: Uint8Array
): Uint8Array {
    return hkdf(
        sha256,
        sharedSecret,
        ephemeralPublicKey, // Use ephemeral public key as salt
        HKDF_INFO,
        32
    );
}

/**
 * Encrypt a message using ECIES pattern:
 * 1. Generate ephemeral X25519 keypair
 * 2. Compute ECDH shared secret with recipient's public key
 * 3. Derive encryption key using HKDF
 * 4. Encrypt message with ChaCha20-Poly1305
 *
 * This function does NOT require the recipient's private key.
 * Anyone can encrypt to a public key.
 *
 * @param message The plaintext message to encrypt
 * @param recipientPublicKeyBase64 The recipient's X25519 public key (Base64)
 * @returns EncryptedMessage with ephemeral public key, ciphertext, and nonce
 */
export function asymmetricEncrypt(
    message: string,
    recipientPublicKeyBase64: string
): EncryptedMessage {
    const recipientPublicKey = fromBase64(recipientPublicKeyBase64);

    if (recipientPublicKey.length !== 32) {
        throw new Error(`Recipient public key must be 32 bytes, got ${recipientPublicKey.length}`);
    }

    // Generate ephemeral keypair for forward secrecy
    const ephemeral = generateEphemeralKeypair();
    let sharedSecret: Uint8Array | null = null;
    let encryptionKey: Uint8Array | null = null;

    try {
        // Compute ECDH shared secret
        sharedSecret = computeSharedSecret(ephemeral.privateKey, recipientPublicKey);

        // Derive encryption key
        encryptionKey = deriveEncryptionKey(sharedSecret, ephemeral.publicKey);

        // Generate random nonce
        const nonce = randomBytes(NONCE_LENGTH);

        // Encode message to bytes
        const encoder = new TextEncoder();
        const plaintext = encoder.encode(message);

        // Encrypt with ChaCha20-Poly1305
        const cipher = chacha20poly1305(encryptionKey, nonce);
        const ciphertext = cipher.encrypt(plaintext);

        return {
            ephemeralPublicKey: toBase64(ephemeral.publicKey),
            ciphertext: toBase64(ciphertext),
            nonce: toBase64(nonce)
        };
    } finally {
        // Zero all sensitive data
        zeroFill(ephemeral.privateKey);
        if (sharedSecret) {
            zeroFill(sharedSecret);
        }
        if (encryptionKey) {
            zeroFill(encryptionKey);
        }
    }
}

/**
 * Decrypt a message using ECIES pattern:
 * 1. Compute ECDH shared secret with ephemeral public key and our private key
 * 2. Derive encryption key using HKDF
 * 3. Decrypt message with ChaCha20-Poly1305
 *
 * The private key is received from C# (WASM memory) and zeroed after use.
 *
 * @param encrypted The encrypted message
 * @param privateKeyBase64 Our X25519 private key (Base64 encoded from C#)
 * @returns The decrypted plaintext message
 */
export function asymmetricDecrypt(
    encrypted: EncryptedMessage,
    privateKeyBase64: string
): string {
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

    if (nonce.length !== NONCE_LENGTH) {
        throw new Error(`Nonce must be ${NONCE_LENGTH} bytes, got ${nonce.length}`);
    }

    let sharedSecret: Uint8Array | null = null;
    let encryptionKey: Uint8Array | null = null;

    try {
        // Compute ECDH shared secret
        sharedSecret = computeSharedSecret(privateKey, ephemeralPublicKey);

        // Derive encryption key (same derivation as encryption)
        encryptionKey = deriveEncryptionKey(sharedSecret, ephemeralPublicKey);

        // Decrypt with ChaCha20-Poly1305
        const cipher = chacha20poly1305(encryptionKey, nonce);
        const plaintext = cipher.decrypt(ciphertext);

        // Decode bytes to string
        const decoder = new TextDecoder();
        return decoder.decode(plaintext);
    } finally {
        // Zero all sensitive data
        zeroFill(privateKey);
        if (sharedSecret) {
            zeroFill(sharedSecret);
        }
        if (encryptionKey) {
            zeroFill(encryptionKey);
        }
    }
}
