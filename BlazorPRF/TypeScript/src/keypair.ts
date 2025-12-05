// X25519 key derivation using @noble/curves

import { x25519 } from '@noble/curves/ed25519';
import type { DerivedKeys } from './types.js';

/**
 * Derive an X25519 keypair from a 32-byte PRF output.
 * The PRF output is used directly as the private key.
 *
 * IMPORTANT: The returned privateKey must be zero-filled after use.
 *
 * @param prfOutput 32-byte deterministic PRF output
 * @returns DerivedKeys containing privateKey and publicKey
 */
export function deriveKeypairFromPrf(prfOutput: Uint8Array): DerivedKeys {
    if (prfOutput.length !== 32) {
        throw new Error(`PRF output must be 32 bytes, got ${prfOutput.length}`);
    }

    // Use PRF output directly as X25519 private key
    // X25519 will apply clamping internally
    const privateKey = new Uint8Array(prfOutput);
    const publicKey = x25519.getPublicKey(privateKey);

    return {
        privateKey,
        publicKey
    };
}

/**
 * Compute ECDH shared secret using X25519.
 *
 * @param privateKey Our 32-byte private key
 * @param publicKey Their 32-byte public key
 * @returns 32-byte shared secret
 */
export function computeSharedSecret(
    privateKey: Uint8Array,
    publicKey: Uint8Array
): Uint8Array {
    if (privateKey.length !== 32) {
        throw new Error(`Private key must be 32 bytes, got ${privateKey.length}`);
    }
    if (publicKey.length !== 32) {
        throw new Error(`Public key must be 32 bytes, got ${publicKey.length}`);
    }

    return x25519.getSharedSecret(privateKey, publicKey);
}

/**
 * Generate a random ephemeral X25519 keypair for ECIES encryption.
 *
 * @returns DerivedKeys with random ephemeral keys
 */
export function generateEphemeralKeypair(): DerivedKeys {
    const privateKey = x25519.utils.randomPrivateKey();
    const publicKey = x25519.getPublicKey(privateKey);

    return {
        privateKey,
        publicKey
    };
}
