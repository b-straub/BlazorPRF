using System.Runtime.Versioning;
using BlazorPRF.Shared.Crypto.Abstractions;
using BlazorPRF.Shared.Crypto.Configuration;
using BlazorPRF.Shared.Crypto.Models;
using BlazorPRF.Shared.Crypto.Services;
using Microsoft.Extensions.Options;

namespace BlazorPRF.Noble.Crypto.Services;

/// <summary>
/// Service for asymmetric (ECIES) encryption using PRF-derived keys via ICryptoProvider.
/// </summary>
[SupportedOSPlatform("browser")]
public sealed class AsymmetricEncryptionService : IAsymmetricEncryption
{
    private readonly ISecureKeyCache _keyCache;
    private readonly ICryptoProvider _cryptoProvider;
    private readonly EncryptionAlgorithm _defaultAlgorithm;

    public AsymmetricEncryptionService(
        ISecureKeyCache keyCache,
        ICryptoProvider cryptoProvider,
        IOptions<PrfOptions> options)
    {
        _keyCache = keyCache;
        _cryptoProvider = cryptoProvider;
        _defaultAlgorithm = options.Value.DefaultAlgorithm;
    }

    /// <inheritdoc />
    public async ValueTask<PrfResult<EncryptedMessage>> EncryptAsync(string message, string recipientPublicKey)
    {
        ArgumentException.ThrowIfNullOrEmpty(message);
        ArgumentException.ThrowIfNullOrEmpty(recipientPublicKey);

        // Encryption only needs the public key (not sensitive, no cache lookup needed)
        return await _cryptoProvider.EncryptAsymmetricAsync(message, recipientPublicKey, _defaultAlgorithm);
    }

    /// <inheritdoc />
    public async ValueTask<PrfResult<string>> DecryptAsync(EncryptedMessage encrypted, string salt)
    {
        ArgumentNullException.ThrowIfNull(encrypted);
        ArgumentException.ThrowIfNullOrEmpty(salt);

        var cacheKey = GetCacheKey(salt);
        var privateKey = _keyCache.TryGet(cacheKey);
        if (privateKey is null)
        {
            return PrfResult<string>.Fail(PrfErrorCode.KeyDerivationFailed);
        }

        // Use algorithm from message if available, otherwise use default
        var result = await _cryptoProvider.DecryptAsymmetricAsync(encrypted, privateKey, encrypted.EffectiveAlgorithm);
        Array.Clear(privateKey, 0, privateKey.Length);
        return result;
    }

    private static string GetCacheKey(string salt) => $"prf-key:{salt}";
}
