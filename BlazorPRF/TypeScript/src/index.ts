// Main entry point - exports all functions for C# JSImport
// This module is STATELESS - no key caching in JavaScript

import {
    PrfErrorCode,
    type PrfCredential,
    type PrfOptions,
    type PrfResult,
    type EncryptedMessage,
    type SymmetricEncryptedMessage
} from './types.js';
import { checkPrfSupport, registerCredentialWithPrf } from './webauthn.js';
import { evaluatePrf, evaluatePrfDiscoverable } from './prf.js';
import { deriveKeypairFromPrf } from './keypair.js';
import { symmetricEncrypt, symmetricDecrypt } from './symmetric.js';
import { asymmetricEncrypt, asymmetricDecrypt } from './asymmetric.js';
import { toBase64, fromBase64, zeroFill } from './utils.js';

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
 * Derive keys from PRF with a specific credential.
 * Returns JSON with publicKeyBase64 (private key is cached in C#).
 */
export async function deriveKeys(
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

    // Derive keypair from PRF output
    const prfOutput = fromBase64(prfResult.value);
    const keypair = deriveKeypairFromPrf(prfOutput);

    // Convert keys to Base64
    const privateKeyBase64 = toBase64(keypair.privateKey);
    const publicKeyBase64 = toBase64(keypair.publicKey);

    // Zero sensitive data in JS memory
    zeroFill(prfOutput);
    zeroFill(keypair.privateKey);

    // Return both keys to C# - C# will cache in WASM memory
    return JSON.stringify({
        success: true,
        value: {
            privateKeyBase64,
            publicKeyBase64
        }
    });
}

/**
 * Derive keys using discoverable credential (user selects).
 * Returns JSON with credentialId and keys.
 */
export async function deriveKeysDiscoverable(
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

    // Derive keypair from PRF output
    const prfOutput = fromBase64(prfResult.value.prfOutput);
    const keypair = deriveKeypairFromPrf(prfOutput);

    // Convert keys to Base64
    const privateKeyBase64 = toBase64(keypair.privateKey);
    const publicKeyBase64 = toBase64(keypair.publicKey);

    // Zero sensitive data in JS memory
    zeroFill(prfOutput);
    zeroFill(keypair.privateKey);

    // Return credential ID and both keys to C#
    return JSON.stringify({
        success: true,
        value: {
            credentialId: prfResult.value.credentialId,
            privateKeyBase64,
            publicKeyBase64
        }
    });
}

// ============================================================================
// Symmetric Encryption Functions
// ============================================================================

/**
 * Encrypt a message with symmetric key.
 * Key is passed from C# WASM memory and zeroed after use.
 */
export function encryptSymmetric(
    message: string,
    keyBase64: string
): string {
    const encrypted = symmetricEncrypt(message, keyBase64);
    return JSON.stringify(encrypted);
}

/**
 * Decrypt a message with symmetric key.
 * Key is passed from C# WASM memory and zeroed after use.
 */
export function decryptSymmetric(
    encryptedJson: string,
    keyBase64: string
): string {
    const encrypted: SymmetricEncryptedMessage = JSON.parse(encryptedJson);
    try {
        const plaintext = symmetricDecrypt(encrypted, keyBase64);
        return JSON.stringify({
            success: true,
            value: plaintext
        });
    } catch (error) {
        const rawMessage = error instanceof Error ? error.message : '';
        const errorCode = rawMessage.toLowerCase().includes('tag')
            ? PrfErrorCode.AuthenticationTagMismatch
            : PrfErrorCode.DecryptionFailed;
        return JSON.stringify({
            success: false,
            errorCode
        });
    }
}

// ============================================================================
// Asymmetric (ECIES) Encryption Functions
// ============================================================================

/**
 * Encrypt a message with recipient's public key.
 * No private key needed - anyone can encrypt to a public key.
 */
export function encryptAsymmetric(
    plaintext: string,
    recipientPublicKeyBase64: string
): string {
    try {
        const encrypted = asymmetricEncrypt(plaintext, recipientPublicKeyBase64);
        return JSON.stringify({
            success: true,
            value: encrypted
        });
    } catch {
        return JSON.stringify({
            success: false,
            errorCode: PrfErrorCode.EncryptionFailed
        });
    }
}

/**
 * Decrypt a message with our private key.
 * Private key is passed from C# WASM memory and zeroed after use.
 */
export function decryptAsymmetric(
    encryptedJson: string,
    privateKeyBase64: string
): string {
    const encrypted: EncryptedMessage = JSON.parse(encryptedJson);
    try {
        const plaintext = asymmetricDecrypt(encrypted, privateKeyBase64);
        return JSON.stringify({
            success: true,
            value: plaintext
        });
    } catch (error) {
        const rawMessage = error instanceof Error ? error.message : '';
        const errorCode = rawMessage.toLowerCase().includes('tag')
            ? PrfErrorCode.AuthenticationTagMismatch
            : PrfErrorCode.DecryptionFailed;
        return JSON.stringify({
            success: false,
            errorCode
        });
    }
}

// ============================================================================
// Export to global scope for C# JSImport
// ============================================================================

const blazorPrf = {
    isPrfSupported,
    register,
    deriveKeys,
    deriveKeysDiscoverable,
    encryptSymmetric,
    decryptSymmetric,
    encryptAsymmetric,
    decryptAsymmetric
};

// Make available globally for JSImport
(globalThis as Record<string, unknown>).blazorPrf = blazorPrf;

export default blazorPrf;
