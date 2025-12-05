// Symmetric encryption using ChaCha20-Poly1305

import { chacha20poly1305 } from '@noble/ciphers/chacha';
import { randomBytes } from '@noble/ciphers/webcrypto';
import type { SymmetricEncryptedMessage } from './types.js';
import { toBase64, fromBase64, zeroFill } from './utils.js';

const NONCE_LENGTH = 12; // ChaCha20-Poly1305 uses 12-byte nonce

/**
 * Encrypt a message using ChaCha20-Poly1305 symmetric encryption.
 * The key is received from C# (WASM memory) and zeroed after use.
 *
 * @param message The plaintext message to encrypt
 * @param keyBase64 The 32-byte symmetric key (Base64 encoded from C#)
 * @returns SymmetricEncryptedMessage with ciphertext and nonce
 */
export function symmetricEncrypt(
    message: string,
    keyBase64: string
): SymmetricEncryptedMessage {
    const key = fromBase64(keyBase64);

    try {
        if (key.length !== 32) {
            throw new Error(`Symmetric key must be 32 bytes, got ${key.length}`);
        }

        // Generate random nonce
        const nonce = randomBytes(NONCE_LENGTH);

        // Encode message to bytes
        const encoder = new TextEncoder();
        const plaintext = encoder.encode(message);

        // Encrypt with ChaCha20-Poly1305
        const cipher = chacha20poly1305(key, nonce);
        const ciphertext = cipher.encrypt(plaintext);

        return {
            ciphertext: toBase64(ciphertext),
            nonce: toBase64(nonce)
        };
    } finally {
        // Always zero the key after use
        zeroFill(key);
    }
}

/**
 * Decrypt a message using ChaCha20-Poly1305 symmetric encryption.
 * The key is received from C# (WASM memory) and zeroed after use.
 *
 * @param encrypted The encrypted message with ciphertext and nonce
 * @param keyBase64 The 32-byte symmetric key (Base64 encoded from C#)
 * @returns The decrypted plaintext message
 */
export function symmetricDecrypt(
    encrypted: SymmetricEncryptedMessage,
    keyBase64: string
): string {
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

        // Decrypt with ChaCha20-Poly1305
        const cipher = chacha20poly1305(key, nonce);
        const plaintext = cipher.decrypt(ciphertext);

        // Decode bytes to string
        const decoder = new TextDecoder();
        return decoder.decode(plaintext);
    } finally {
        // Always zero the key after use
        zeroFill(key);
    }
}
