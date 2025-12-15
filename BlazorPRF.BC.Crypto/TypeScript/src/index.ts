// Main entry point - exports WebAuthn/PRF functions only
// Crypto operations are handled in C#/WASM for security

import {
    type PrfOptions,
} from './types.js';
import { checkPrfSupport, registerCredentialWithPrf } from './webauthn.js';
import { evaluatePrf, evaluatePrfDiscoverable } from './prf.js';

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
// Export to global scope for C# JSImport
// ============================================================================

const blazorPrf = {
    isPrfSupported,
    register,
    evaluatePrfOutput,
    evaluatePrfDiscoverableOutput
};

// Make available globally for JSImport
(globalThis as Record<string, unknown>).blazorPrf = blazorPrf;

export default blazorPrf;
