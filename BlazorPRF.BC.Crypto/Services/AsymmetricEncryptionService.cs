using System.Runtime.Versioning;
using BlazorPRF.Shared.Crypto.Abstractions;
using BlazorPRF.Shared.Crypto.Configuration;
using BlazorPRF.Shared.Crypto.Models;
using BlazorPRF.Shared.Crypto.Services;
using Microsoft.Extensions.Options;

namespace BlazorPRF.BC.Crypto.Services;

/// <summary>
/// Service for asymmetric (ECIES) encryption using PRF-derived keys.
/// All crypto operations happen in C#/WASM for security.
/// Keys are accessed directly from unmanaged memory without creating managed copies.
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

       public async ValueTask<PrfResult<EncryptedMessage>> EncryptAsync(string message, string recipientPublicKey)
    {
        ArgumentException.ThrowIfNullOrEmpty(message);
        ArgumentException.ThrowIfNullOrEmpty(recipientPublicKey);

        // Encryption only needs the public key (not sensitive, no cache lookup needed)
        return await _cryptoProvider.EncryptAsymmetricAsync(message, recipientPublicKey, _defaultAlgorithm);
    }

       public ValueTask<PrfResult<string>> DecryptAsync(EncryptedMessage encrypted, string salt)
    {
        ArgumentNullException.ThrowIfNull(encrypted);
        ArgumentException.ThrowIfNullOrEmpty(salt);

        var cacheKey = GetCacheKey(salt);

        // Use the key directly from unmanaged memory without creating a managed copy
        // Use algorithm from message if available, otherwise use default
        if (!_keyCache.UseKey(cacheKey, key =>
        {
            // DecryptAsymmetricAsync is async but we need sync for UseKey callback
            // Use the sync version from CryptoOperations with effective algorithm
            var effectiveAlgorithm = encrypted.Algorithm ?? _defaultAlgorithm;
            return DecryptWithAlgorithm(encrypted, key, effectiveAlgorithm);
        }, out var result))
        {
            return ValueTask.FromResult(PrfResult<string>.Fail(PrfErrorCode.KEY_DERIVATION_FAILED));
        }

        return ValueTask.FromResult(result ?? PrfResult<string>.Fail(PrfErrorCode.DECRYPTION_FAILED));
    }

    private PrfResult<string> DecryptWithAlgorithm(
        EncryptedMessage encrypted,
        ReadOnlySpan<byte> privateKey,
        EncryptionAlgorithm algorithm)
    {
        // Use the BouncyCastleCryptoProvider's decrypt logic via sync wrapper
        var task = _cryptoProvider.DecryptAsymmetricAsync(encrypted, privateKey.ToArray(), algorithm);
        return task.IsCompleted ? task.Result : task.AsTask().GetAwaiter().GetResult();
    }

    private static string GetCacheKey(string salt) => $"prf-key:{salt}";
}
