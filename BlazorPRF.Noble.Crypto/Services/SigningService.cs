using System.Runtime.Versioning;
using BlazorPRF.Shared.Crypto.Abstractions;
using BlazorPRF.Shared.Crypto.Models;
using BlazorPRF.Shared.Crypto.Services;

namespace BlazorPRF.Noble.Crypto.Services;

/// <summary>
/// Service for Ed25519 digital signatures using PRF-derived keys via ICryptoProvider.
/// </summary>
[SupportedOSPlatform("browser")]
public sealed class SigningService : ISigningService
{
    private readonly ISecureKeyCache _keyCache;
    private readonly IEd25519PublicKeyProvider _publicKeyProvider;
    private readonly ICryptoProvider _cryptoProvider;

    public SigningService(
        ISecureKeyCache keyCache,
        IEd25519PublicKeyProvider publicKeyProvider,
        ICryptoProvider cryptoProvider)
    {
        _keyCache = keyCache;
        _publicKeyProvider = publicKeyProvider;
        _cryptoProvider = cryptoProvider;
    }

    /// <inheritdoc />
    public async ValueTask<PrfResult<string>> SignAsync(string message, string keyIdentifier)
    {
        ArgumentException.ThrowIfNullOrEmpty(message);
        ArgumentException.ThrowIfNullOrEmpty(keyIdentifier);

        var cacheKey = GetCacheKey(keyIdentifier);
        var privateKey = _keyCache.TryGet(cacheKey);
        if (privateKey is null)
        {
            return PrfResult<string>.Fail(PrfErrorCode.KeyDerivationFailed);
        }

        var result = await _cryptoProvider.SignAsync(message, privateKey);
        Array.Clear(privateKey, 0, privateKey.Length);
        return result;
    }

    /// <inheritdoc />
    public async ValueTask<bool> VerifyAsync(string message, string signature, string publicKey)
    {
        ArgumentException.ThrowIfNullOrEmpty(message);
        ArgumentException.ThrowIfNullOrEmpty(signature);
        ArgumentException.ThrowIfNullOrEmpty(publicKey);

        return await _cryptoProvider.VerifyAsync(message, signature, publicKey);
    }

    /// <inheritdoc />
    public async ValueTask<PrfResult<SignedMessage>> CreateSignedMessageAsync(string message, string keyIdentifier)
    {
        ArgumentException.ThrowIfNullOrEmpty(message);
        ArgumentException.ThrowIfNullOrEmpty(keyIdentifier);

        // Get the Ed25519 public key for this salt
        var publicKey = _publicKeyProvider.GetEd25519PublicKey(keyIdentifier);
        if (publicKey is null)
        {
            return PrfResult<SignedMessage>.Fail(PrfErrorCode.KeyDerivationFailed);
        }

        var cacheKey = GetCacheKey(keyIdentifier);
        var privateKey = _keyCache.TryGet(cacheKey);
        if (privateKey is null)
        {
            return PrfResult<SignedMessage>.Fail(PrfErrorCode.KeyDerivationFailed);
        }

        // Create timestamped message (Unix timestamp in seconds)
        var timestampUnix = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var dataToSign = $"{timestampUnix}:{message}";

        var signResult = await _cryptoProvider.SignAsync(dataToSign, privateKey);
        Array.Clear(privateKey, 0, privateKey.Length);

        if (!signResult.Success || signResult.Value is null)
        {
            return PrfResult<SignedMessage>.Fail(signResult.ErrorCode ?? PrfErrorCode.SigningFailed);
        }

        var signedMessage = new SignedMessage(message, signResult.Value, publicKey, timestampUnix);

        return PrfResult<SignedMessage>.Ok(signedMessage);
    }

    /// <inheritdoc />
    public async ValueTask<bool> VerifySignedMessageAsync(SignedMessage signedMessage, int maxAgeSeconds = 300)
    {
        ArgumentNullException.ThrowIfNull(signedMessage);

        // Check timestamp age
        var messageTime = DateTimeOffset.FromUnixTimeSeconds(signedMessage.TimestampUnix);
        var age = DateTimeOffset.UtcNow - messageTime;

        if (age.TotalSeconds > maxAgeSeconds)
        {
            return false;
        }

        // Verify signature
        var dataToVerify = $"{signedMessage.TimestampUnix}:{signedMessage.Message}";
        return await _cryptoProvider.VerifyAsync(dataToVerify, signedMessage.Signature, signedMessage.PublicKey);
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
