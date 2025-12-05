// WebAuthn registration with PRF extension support

import { PrfErrorCode, type PrfCredential, type PrfOptions, type PrfResult } from './types.js';
import { arrayBufferToBase64 } from './utils.js';

/**
 * Check if the current browser and platform support WebAuthn PRF extension.
 *
 * @returns true if PRF is likely supported
 */
export async function checkPrfSupport(): Promise<boolean> {
    // Check basic WebAuthn support
    if (!window.PublicKeyCredential) {
        return false;
    }

    // Check if platform authenticator is available
    if (typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === 'function') {
        const available = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
        if (!available) {
            return false;
        }
    }

    // PRF extension support can only be truly verified during registration
    // Most modern platform authenticators (iOS 17+, macOS 14+, Windows 10+, Android 14+) support it
    return true;
}

/**
 * Register a new WebAuthn credential with PRF extension enabled.
 *
 * @param displayName Optional human-readable display name. If null, platform generates one.
 * @param options PRF configuration options
 * @returns PrfResult containing the credential or error
 */
export async function registerCredentialWithPrf(
    displayName: string | null,
    options: PrfOptions
): Promise<PrfResult<PrfCredential>> {
    try {
        // Generate random user ID (required by WebAuthn spec, not meaningful for PRF-only use)
        const userId = crypto.getRandomValues(new Uint8Array(16));

        // Display name shown in platform passkey manager
        const effectiveDisplayName = displayName ?? options.rpName;

        // Determine authenticator attachment
        const authenticatorAttachment: AuthenticatorAttachment | undefined =
            options.authenticatorAttachment === 'platform' ? 'platform' : 'cross-platform';

        // Build registration options
        const publicKeyCredentialCreationOptions: PublicKeyCredentialCreationOptions = {
            challenge: crypto.getRandomValues(new Uint8Array(32)),
            rp: {
                name: options.rpName,
                id: options.rpId ?? window.location.hostname
            },
            user: {
                id: userId,
                name: effectiveDisplayName, // Required by spec
                displayName: effectiveDisplayName
            },
            pubKeyCredParams: [
                { alg: -7, type: 'public-key' },   // ES256 (P-256)
                { alg: -257, type: 'public-key' }  // RS256
            ],
            authenticatorSelection: {
                authenticatorAttachment,
                residentKey: 'required',
                userVerification: 'discouraged'
            },
            timeout: options.timeoutMs,
            attestation: 'none',
            extensions: {
                prf: {}
            } as AuthenticationExtensionsClientInputs
        };

        // Create credential using navigator.credentials API
        const credential = await navigator.credentials.create({
            publicKey: publicKeyCredentialCreationOptions
        }) as PublicKeyCredential | null;

        if (credential === null) {
            return {
                success: false,
                cancelled: true
            };
        }

        // Check if PRF extension is enabled
        const extensionResults = credential.getClientExtensionResults() as {
            prf?: { enabled?: boolean };
        };

        if (!extensionResults.prf?.enabled) {
            return {
                success: false,
                errorCode: PrfErrorCode.PrfNotSupported
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
        // User cancelled the registration - not an error
        if (error instanceof DOMException && error.name === 'NotAllowedError') {
            return {
                success: false,
                cancelled: true
            };
        }

        return {
            success: false,
            errorCode: PrfErrorCode.RegistrationFailed
        };
    }
}
