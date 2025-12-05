using System.Runtime.Versioning;
using BlazorPRF.Crypto;
using BlazorPRF.Models;

namespace BlazorPRF.Services;

/// <summary>
/// Service for asymmetric (ECIES) encryption using PRF-derived keys.
/// All crypto operations happen in C#/WASM for security.
/// Keys are accessed directly from unmanaged memory without creating managed copies.
/// </summary>
[SupportedOSPlatform("browser")]
public sealed class AsymmetricEncryptionService : IAsymmetricEncryption
{
    private readonly ISecureKeyCache _keyCache;

    public AsymmetricEncryptionService(ISecureKeyCache keyCache)
    {
        _keyCache = keyCache;
    }

    /// <inheritdoc />
    public ValueTask<PrfResult<EncryptedMessage>> EncryptAsync(string message, string recipientPublicKey)
    {
        ArgumentException.ThrowIfNullOrEmpty(message);
        ArgumentException.ThrowIfNullOrEmpty(recipientPublicKey);

        // Encryption only needs the public key (not sensitive, no cache lookup needed)
        return ValueTask.FromResult(WasmCryptoOperations.EncryptAsymmetric(message, recipientPublicKey));
    }

    /// <inheritdoc />
    public ValueTask<PrfResult<string>> DecryptAsync(EncryptedMessage encrypted, string salt)
    {
        ArgumentNullException.ThrowIfNull(encrypted);
        ArgumentException.ThrowIfNullOrEmpty(salt);

        var cacheKey = GetCacheKey(salt);

        // Use the key directly from unmanaged memory without creating a managed copy
        if (!_keyCache.UseKey(cacheKey, key => WasmCryptoOperations.DecryptAsymmetric(encrypted, key), out var result))
        {
            return ValueTask.FromResult(PrfResult<string>.Fail(PrfErrorCode.KeyDerivationFailed));
        }

        return ValueTask.FromResult(result ?? PrfResult<string>.Fail(PrfErrorCode.DecryptionFailed));
    }

    private static string GetCacheKey(string salt) => $"prf-key:{salt}";
}
