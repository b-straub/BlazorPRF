using BlazorPRF.BaseCrypto.Wasm.Models;

namespace BlazorPRF.BaseCrypto.Wasm.Services;

/// <summary>
/// Simple unified interface for WebAuthn PRF with encryption and signing.
/// Private keys never leave JavaScript - all crypto operations use salt-based key lookup.
/// </summary>
public interface IBasePrfService
{
    /// <summary>
    /// Event raised when cached keys expire.
    /// </summary>
    event Action<string>? KeyExpired;

    /// <summary>
    /// Returns true if the JS module has been initialized.
    /// Use this before calling synchronous methods like HasCachedKeys.
    /// </summary>
    bool IsInitialized { get; }

    /// <summary>
    /// Check if PRF extension is supported.
    /// </summary>
    bool IsPrfSupported();

    /// <summary>
    /// Check if conditional mediation (passkey autofill) is available.
    /// Returns true if the browser supports passkey autofill UI.
    /// </summary>
    Task<bool> IsConditionalMediationAvailableAsync();

    /// <summary>
    /// Register a new passkey with PRF extension.
    /// </summary>
    /// <param name="displayName">Optional display name for the credential</param>
    /// <returns>Credential ID (Base64) on success</returns>
    Task<BasePrfResult<string>> RegisterAsync(string? displayName = null);

    /// <summary>
    /// Authenticate with a specific credential, derive keys, and cache them in JS.
    /// Keys are cached by salt and can be used for subsequent encrypt/sign operations.
    /// </summary>
    /// <param name="credentialIdBase64">Credential ID from registration</param>
    /// <param name="saltBase64">Salt for key derivation (also used as cache key)</param>
    /// <param name="cacheTtl">Optional TTL for cached keys (null = no expiration)</param>
    /// <returns>Public key and credential ID (private keys stay in JS)</returns>
    Task<BasePrfResult<AuthResult>> AuthenticateAsync(
        string credentialIdBase64,
        string saltBase64,
        TimeSpan? cacheTtl = null);

    /// <summary>
    /// Authenticate with discoverable credential (user selects) and cache keys in JS.
    /// </summary>
    /// <param name="saltBase64">Salt for key derivation (also used as cache key)</param>
    /// <param name="cacheTtl">Optional TTL for cached keys (null = no expiration)</param>
    /// <returns>Public key and credential ID (private keys stay in JS)</returns>
    Task<BasePrfResult<AuthResult>> AuthenticateDiscoverableAsync(
        string saltBase64,
        TimeSpan? cacheTtl = null);

    /// <summary>
    /// Check if keys are cached for the given salt.
    /// </summary>
    /// <param name="saltBase64">The salt used during authentication</param>
    /// <returns>True if keys are cached and not expired</returns>
    bool HasCachedKeys(string saltBase64);

    /// <summary>
    /// Get cached public info for the given salt.
    /// </summary>
    /// <param name="saltBase64">The salt used during authentication</param>
    /// <returns>Public key and credential ID, or null if not cached/expired</returns>
    AuthResult? GetCachedPublicInfo(string saltBase64);

    /// <summary>
    /// Clear cached keys for the given salt.
    /// </summary>
    /// <param name="saltBase64">The salt used during authentication</param>
    void ClearCachedKeys(string saltBase64);

    /// <summary>
    /// Clear all cached keys.
    /// </summary>
    void ClearAllCachedKeys();

    /// <summary>
    /// Encrypt plaintext using AES-256-GCM with cached key.
    /// </summary>
    /// <param name="plaintext">UTF-8 text to encrypt</param>
    /// <param name="saltBase64">Salt identifying the cached key</param>
    /// <returns>Encrypted data with ciphertext and nonce</returns>
    Task<BasePrfResult<EncryptedData>> EncryptAsync(string plaintext, string saltBase64);

    /// <summary>
    /// Decrypt ciphertext using AES-256-GCM with cached key.
    /// </summary>
    /// <param name="encrypted">Encrypted data to decrypt</param>
    /// <param name="saltBase64">Salt identifying the cached key</param>
    /// <returns>Decrypted plaintext</returns>
    Task<BasePrfResult<string>> DecryptAsync(EncryptedData encrypted, string saltBase64);

    /// <summary>
    /// Sign a message using Ed25519 with cached key.
    /// </summary>
    /// <param name="message">UTF-8 message to sign</param>
    /// <param name="saltBase64">Salt identifying the cached key</param>
    /// <returns>64-byte signature (Base64)</returns>
    Task<BasePrfResult<string>> SignAsync(string message, string saltBase64);

    /// <summary>
    /// Verify an Ed25519 signature.
    /// </summary>
    /// <param name="message">Original UTF-8 message</param>
    /// <param name="signatureBase64">64-byte signature (Base64)</param>
    /// <param name="publicKeyBase64">32-byte public key (Base64)</param>
    /// <returns>True if signature is valid</returns>
    Task<bool> VerifyAsync(string message, string signatureBase64, string publicKeyBase64);
}
