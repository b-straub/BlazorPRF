using BlazorPRF.Shared.Crypto.Configuration;
using BlazorPRF.Shared.Crypto.Models;

namespace BlazorPRF.Shared.Crypto.Services;

/// <summary>
/// Service for WebAuthn PRF operations.
/// </summary>
public interface IPrfService
{
    /// <summary>
    /// The configured key caching strategy.
    /// </summary>
    KeyCacheStrategy CacheStrategy { get; }

    /// <summary>
    /// Observable that emits the cache key when keys expire due to TTL.
    /// Format: "prf-key:{salt}"
    /// </summary>
    Observable<string> KeyExpired { get; }

    /// <summary>
    /// Check if PRF extension is supported on this platform.
    /// </summary>
    ValueTask<bool> IsPrfSupportedAsync();

    /// <summary>
    /// Check if conditional mediation (passkey autofill) is available.
    /// When true, the browser can show passkey suggestions in form autofill UI,
    /// indicating that existing passkeys may be available for this RP.
    /// </summary>
    ValueTask<bool> IsConditionalMediationAvailableAsync();

    /// <summary>
    /// Register a new credential with PRF support.
    /// </summary>
    /// <param name="displayName">Optional display name shown in platform passkey manager. If null, platform generates one.</param>
    /// <returns>The created credential or error</returns>
    ValueTask<PrfResult<PrfCredential>> RegisterAsync(string? displayName = null);

    /// <summary>
    /// Derive keys from a specific credential.
    /// Keys are cached in WASM memory according to cache strategy.
    /// </summary>
    /// <param name="credentialId">The credential ID (Base64)</param>
    /// <param name="salt">Salt for key derivation (must be consistent for same keys)</param>
    /// <returns>The public key (private key is cached internally)</returns>
    ValueTask<PrfResult<string>> DeriveKeysAsync(string credentialId, string salt);

    /// <summary>
    /// Derive keys using discoverable credential (user selects).
    /// Keys are cached in WASM memory according to cache strategy.
    /// </summary>
    /// <param name="salt">Salt for key derivation</param>
    /// <returns>The credential ID and public key</returns>
    ValueTask<PrfResult<(string CredentialId, string PublicKey)>> DeriveKeysDiscoverableAsync(string salt);

    /// <summary>
    /// Get the cached public key for a salt, if available.
    /// </summary>
    /// <param name="salt">The salt used for key derivation</param>
    /// <returns>The public key (Base64) or null if not cached</returns>
    string? GetCachedPublicKey(string salt);

    /// <summary>
    /// Check if keys are cached for a given salt.
    /// </summary>
    /// <param name="salt">The salt to check</param>
    /// <returns>True if keys are cached and valid</returns>
    bool HasCachedKeys(string salt);

    /// <summary>
    /// Get the cached Ed25519 signing public key for a salt, if available.
    /// </summary>
    /// <param name="salt">The salt used for key derivation</param>
    /// <returns>The Ed25519 public key (Base64) or null if not cached</returns>
    string? GetEd25519PublicKey(string salt);

    /// <summary>
    /// Clear all cached keys.
    /// </summary>
    void ClearKeys();
}
