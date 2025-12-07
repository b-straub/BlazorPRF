using System.Runtime.Versioning;
using BlazorPRF.Crypto;
using BlazorPRF.Models;
using BlazorPRF.Shared.Models;
using BlazorPRF.Shared.Services;

namespace BlazorPRF.Services;

/// <summary>
/// Service for Ed25519 digital signatures using PRF-derived keys.
/// All crypto operations happen in C#/WASM for security.
/// Keys are accessed directly from unmanaged memory without creating managed copies.
/// </summary>
[SupportedOSPlatform("browser")]
public sealed class SigningService : ISigningService
{
    private readonly ISecureKeyCache _keyCache;
    private readonly IEd25519PublicKeyProvider _publicKeyProvider;

    public SigningService(ISecureKeyCache keyCache, IEd25519PublicKeyProvider publicKeyProvider)
    {
        _keyCache = keyCache;
        _publicKeyProvider = publicKeyProvider;
    }

    /// <inheritdoc />
    public ValueTask<PrfResult<string>> SignAsync(string message, string keyIdentifier)
    {
        ArgumentException.ThrowIfNullOrEmpty(message);
        ArgumentException.ThrowIfNullOrEmpty(keyIdentifier);

        var cacheKey = GetCacheKey(keyIdentifier);

        // Use the Ed25519 private key directly from unmanaged memory
        if (!_keyCache.UseKey(cacheKey, key => CryptoOperations.Sign(message, key), out var result))
        {
            return ValueTask.FromResult(PrfResult<string>.Fail(PrfErrorCode.KeyDerivationFailed));
        }

        return ValueTask.FromResult(result ?? PrfResult<string>.Fail(PrfErrorCode.SigningFailed));
    }

    /// <inheritdoc />
    public ValueTask<bool> VerifyAsync(string message, string signature, string publicKey)
    {
        ArgumentException.ThrowIfNullOrEmpty(message);
        ArgumentException.ThrowIfNullOrEmpty(signature);
        ArgumentException.ThrowIfNullOrEmpty(publicKey);

        // Verification only needs the public key (not sensitive)
        var isValid = CryptoOperations.Verify(message, signature, publicKey);
        return ValueTask.FromResult(isValid);
    }

    /// <inheritdoc />
    public ValueTask<PrfResult<SignedMessage>> CreateSignedMessageAsync(string message, string keyIdentifier)
    {
        ArgumentException.ThrowIfNullOrEmpty(message);
        ArgumentException.ThrowIfNullOrEmpty(keyIdentifier);

        // Get the Ed25519 public key for this salt
        var publicKey = _publicKeyProvider.GetEd25519PublicKey(keyIdentifier);
        if (publicKey is null)
        {
            return ValueTask.FromResult(PrfResult<SignedMessage>.Fail(PrfErrorCode.KeyDerivationFailed));
        }

        var cacheKey = GetCacheKey(keyIdentifier);

        // Use the Ed25519 private key directly from unmanaged memory
        if (!_keyCache.UseKey(cacheKey, key => CryptoOperations.CreateSignedMessage(message, key, publicKey), out var result))
        {
            return ValueTask.FromResult(PrfResult<SignedMessage>.Fail(PrfErrorCode.KeyDerivationFailed));
        }

        return ValueTask.FromResult(result ?? PrfResult<SignedMessage>.Fail(PrfErrorCode.SigningFailed));
    }

    /// <inheritdoc />
    public ValueTask<bool> VerifySignedMessageAsync(SignedMessage signedMessage, int maxAgeSeconds = 300)
    {
        ArgumentNullException.ThrowIfNull(signedMessage);

        var isValid = CryptoOperations.VerifySignedMessage(signedMessage, maxAgeSeconds);
        return ValueTask.FromResult(isValid);
    }

    private static string GetCacheKey(string salt) => $"prf-ed25519-key:{salt}";
}

/// <summary>
/// Provider for Ed25519 public keys.
/// Implemented by PrfService to provide public keys for signing operations.
/// </summary>
public interface IEd25519PublicKeyProvider
{
    /// <summary>
    /// Get the Ed25519 public key for a given key identifier (salt).
    /// </summary>
    /// <param name="keyIdentifier">The key identifier (salt)</param>
    /// <returns>The Ed25519 public key (Base64) or null if not available</returns>
    string? GetEd25519PublicKey(string keyIdentifier);
}
