<?php
/**
 * Ed25519 signature verification library.
 * Uses PHP sodium extension (built-in since PHP 7.2).
 */

namespace PrfCrypto;

/**
 * Ed25519 signature operations.
 */
class PrfCrypto
{
    private const ED25519_PUBLIC_KEY_LENGTH = 32;
    private const ED25519_SIGNATURE_LENGTH = 64;

    /**
     * Validates a Base64-encoded Ed25519 public key.
     */
    public static function isValidEd25519PublicKey(string $publicKeyBase64): bool
    {
        try {
            $key = base64_decode($publicKeyBase64, true);
            return $key !== false && strlen($key) === self::ED25519_PUBLIC_KEY_LENGTH;
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Verifies an Ed25519 signature.
     *
     * @param string $message The original message that was signed
     * @param string $signatureBase64 Base64-encoded Ed25519 signature (64 bytes)
     * @param string $publicKeyBase64 Base64-encoded Ed25519 public key (32 bytes)
     * @return bool True if signature is valid
     */
    public static function verify(
        string $message,
        string $signatureBase64,
        string $publicKeyBase64
    ): bool {
        try {
            // Validate and decode public key
            $publicKey = base64_decode($publicKeyBase64, true);
            if ($publicKey === false || strlen($publicKey) !== self::ED25519_PUBLIC_KEY_LENGTH) {
                return false;
            }

            // Validate and decode signature
            $signature = base64_decode($signatureBase64, true);
            if ($signature === false || strlen($signature) !== self::ED25519_SIGNATURE_LENGTH) {
                return false;
            }

            // Verify the signature using libsodium
            return sodium_crypto_sign_verify_detached($signature, $message, $publicKey);
        } catch (\Exception $e) {
            return false;
        }
    }
}
