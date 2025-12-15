// Main entry point - exports WebAuthn/PRF functions and Noble crypto functions

import {
    type PrfOptions,
} from './types.js';
import { checkPrfSupport, registerCredentialWithPrf } from './webauthn.js';
import { evaluatePrf, evaluatePrfDiscoverable } from './prf.js';
import * as crypto from './crypto.js';

// ============================================================================
// WebAuthn / PRF Functions
// ============================================================================

/**
 * Check if PRF extension is supported.
 */
export async function isPrfSupported(): Promise<boolean> {
    return checkPrfSupport();
}

/**
 * Register a new credential with PRF support.
 * Returns JSON-serialized PrfResult<PrfCredential>.
 */
export async function register(
    displayName: string | null,
    optionsJson: string
): Promise<string> {
    const options: PrfOptions = JSON.parse(optionsJson);
    const result = await registerCredentialWithPrf(displayName, options);
    return JSON.stringify(result);
}

/**
 * Evaluate PRF with a specific credential.
 * Returns JSON with raw PRF output (Base64) - key derivation happens in C#.
 */
export async function evaluatePrfOutput(
    credentialIdBase64: string,
    salt: string,
    optionsJson: string
): Promise<string> {
    const options: PrfOptions = JSON.parse(optionsJson);

    // Evaluate PRF to get deterministic output
    const prfResult = await evaluatePrf(credentialIdBase64, salt, options);

    if (!prfResult.success || !prfResult.value) {
        return JSON.stringify({
            success: false,
            errorCode: prfResult.errorCode,
            cancelled: prfResult.cancelled
        });
    }

    // Return raw PRF output - C# will derive keys
    return JSON.stringify({
        success: true,
        value: prfResult.value  // Base64-encoded 32-byte PRF output
    });
}

/**
 * Evaluate PRF using discoverable credential (user selects).
 * Returns JSON with credentialId and raw PRF output (Base64).
 */
export async function evaluatePrfDiscoverableOutput(
    salt: string,
    optionsJson: string
): Promise<string> {
    const options: PrfOptions = JSON.parse(optionsJson);

    // Evaluate PRF with discoverable credential
    const prfResult = await evaluatePrfDiscoverable(salt, options);

    if (!prfResult.success || !prfResult.value) {
        return JSON.stringify({
            success: false,
            errorCode: prfResult.errorCode,
            cancelled: prfResult.cancelled
        });
    }

    // Return credential ID and raw PRF output - C# will derive keys
    return JSON.stringify({
        success: true,
        value: {
            credentialId: prfResult.value.credentialId,
            prfOutput: prfResult.value.prfOutput  // Base64-encoded 32-byte PRF output
        }
    });
}

// ============================================================================
// Re-export crypto functions for C# JSImport (blazorPrfNoble module)
// ============================================================================

// X25519 key operations
export const generateX25519KeyPair = crypto.generateX25519KeyPair;
export const getX25519PublicKey = crypto.getX25519PublicKey;
export const deriveX25519KeyPair = crypto.deriveX25519KeyPair;

// Ed25519 signing
export const generateEd25519KeyPair = crypto.generateEd25519KeyPair;
export const getEd25519PublicKey = crypto.getEd25519PublicKey;
export const deriveEd25519KeyPair = crypto.deriveEd25519KeyPair;
export const ed25519Sign = crypto.ed25519Sign;
export const ed25519Verify = crypto.ed25519Verify;

// Dual key derivation
export const deriveDualKeyPair = crypto.deriveDualKeyPair;

// ChaCha20-Poly1305 symmetric encryption
export const encryptChaCha = crypto.encryptChaCha;
export const decryptChaCha = crypto.decryptChaCha;

// AES-GCM symmetric encryption
export const encryptAesGcm = crypto.encryptAesGcm;
export const decryptAesGcm = crypto.decryptAesGcm;

// ECIES asymmetric encryption
export const encryptAsymmetricChaCha = crypto.encryptAsymmetricChaCha;
export const decryptAsymmetricChaCha = crypto.decryptAsymmetricChaCha;
export const encryptAsymmetricAesGcm = crypto.encryptAsymmetricAesGcm;
export const decryptAsymmetricAesGcm = crypto.decryptAsymmetricAesGcm;

// Key derivation
export const deriveHkdfKey = crypto.deriveHkdfKey;

// Utility
export const generateRandomBytes = crypto.generateRandomBytes;
export const isSupported = crypto.isSupported;

// Key cache management
export const storeKeys = crypto.storeKeys;
export const getPublicKeys = crypto.getPublicKeys;
export const hasKey = crypto.hasKey;
export const removeKeys = crypto.removeKeys;
export const clearAllKeys = crypto.clearAllKeys;

// Cached key operations
export const signWithCachedKey = crypto.signWithCachedKey;
export const encryptSymmetricCachedChaCha = crypto.encryptSymmetricCachedChaCha;
export const decryptSymmetricCachedChaCha = crypto.decryptSymmetricCachedChaCha;
export const encryptSymmetricCachedAesGcm = crypto.encryptSymmetricCachedAesGcm;
export const decryptSymmetricCachedAesGcm = crypto.decryptSymmetricCachedAesGcm;
export const decryptAsymmetricCachedChaCha = crypto.decryptAsymmetricCachedChaCha;
export const decryptAsymmetricCachedAesGcm = crypto.decryptAsymmetricCachedAesGcm;
