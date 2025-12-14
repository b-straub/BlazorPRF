using System.Runtime.Versioning;
using BlazorPRF.Shared.Crypto.Abstractions;
using BlazorPRF.Shared.Crypto.Models;
using BlazorPRF.Shared.Crypto.Services;

namespace BlazorPRF.Noble.Crypto.Services;

/// <summary>
/// Service for asymmetric (ECIES) encryption using PRF-derived keys via ICryptoProvider.
/// </summary>
[SupportedOSPlatform("browser")]
public sealed class AsymmetricEncryptionService : IAsymmetricEncryption
{
    private readonly ISecureKeyCache _keyCache;
    private readonly ICryptoProvider _cryptoProvider;

    public AsymmetricEncryptionService(ISecureKeyCache keyCache, ICryptoProvider cryptoProvider)
    {
        _keyCache = keyCache;
        _cryptoProvider = cryptoProvider;
    }

    /// <inheritdoc />
    public async ValueTask<PrfResult<EncryptedMessage>> EncryptAsync(string message, string recipientPublicKey)
    {
        ArgumentException.ThrowIfNullOrEmpty(message);
        ArgumentException.ThrowIfNullOrEmpty(recipientPublicKey);

        // Encryption only needs the public key (not sensitive, no cache lookup needed)
        return await _cryptoProvider.EncryptAsymmetricAsync(message, recipientPublicKey, EncryptionAlgorithm.AesGcm);
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

        var result = await _cryptoProvider.DecryptAsymmetricAsync(encrypted, privateKey, EncryptionAlgorithm.AesGcm);
        Array.Clear(privateKey, 0, privateKey.Length);
        return result;
    }

    private static string GetCacheKey(string salt) => $"prf-key:{salt}";
}
