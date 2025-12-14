// Main entry point - exports WebAuthn/PRF functions and Noble crypto functions

import {
    type PrfOptions,
} from './types.js';
import { checkPrfSupport, checkConditionalMediationAvailable, registerCredentialWithPrf } from './webauthn.js';
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
 * Check if conditional mediation (passkey autofill) is available.
 * When true, the browser can show passkey suggestions in form autofill UI.
 * This indicates that the user may have existing passkeys for this RP.
 */
export async function isConditionalMediationAvailable(): Promise<boolean> {
    return checkConditionalMediationAvailable();
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
// Export to global scope for C# JSImport
// ============================================================================

const blazorPrf = {
    // WebAuthn / PRF functions
    isPrfSupported,
    isConditionalMediationAvailable,
    register,
    evaluatePrfOutput,
    evaluatePrfDiscoverableOutput
};

const blazorPrfNoble = {
    // X25519 key operations
    generateX25519KeyPair: crypto.generateX25519KeyPair,
    getX25519PublicKey: crypto.getX25519PublicKey,
    deriveX25519KeyPair: crypto.deriveX25519KeyPair,

    // Ed25519 signing
    generateEd25519KeyPair: crypto.generateEd25519KeyPair,
    getEd25519PublicKey: crypto.getEd25519PublicKey,
    deriveEd25519KeyPair: crypto.deriveEd25519KeyPair,
    ed25519Sign: crypto.ed25519Sign,
    ed25519Verify: crypto.ed25519Verify,

    // Dual key derivation
    deriveDualKeyPair: crypto.deriveDualKeyPair,

    // ChaCha20-Poly1305 symmetric encryption
    encryptChaCha: crypto.encryptChaCha,
    decryptChaCha: crypto.decryptChaCha,

    // AES-GCM symmetric encryption
    encryptAesGcm: crypto.encryptAesGcm,
    decryptAesGcm: crypto.decryptAesGcm,

    // ECIES asymmetric encryption
    encryptAsymmetricChaCha: crypto.encryptAsymmetricChaCha,
    decryptAsymmetricChaCha: crypto.decryptAsymmetricChaCha,
    encryptAsymmetricAesGcm: crypto.encryptAsymmetricAesGcm,
    decryptAsymmetricAesGcm: crypto.decryptAsymmetricAesGcm,

    // Key derivation
    deriveHkdfKey: crypto.deriveHkdfKey,

    // Utility
    generateRandomBytes: crypto.generateRandomBytes,
    isSupported: crypto.isSupported
};

// Make available globally for JSImport
(globalThis as Record<string, unknown>).blazorPrf = blazorPrf;
(globalThis as Record<string, unknown>).blazorPrfNoble = blazorPrfNoble;

export default { blazorPrf, blazorPrfNoble };
