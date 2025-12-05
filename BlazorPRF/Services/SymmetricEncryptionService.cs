using System.Runtime.Versioning;
using BlazorPRF.Crypto;
using BlazorPRF.Models;

namespace BlazorPRF.Services;

/// <summary>
/// Service for symmetric encryption using PRF-derived keys.
/// All crypto operations happen in C#/WASM for security.
/// Keys are accessed directly from unmanaged memory without creating managed copies.
/// </summary>
[SupportedOSPlatform("browser")]
public sealed class SymmetricEncryptionService : ISymmetricEncryption
{
    private readonly ISecureKeyCache _keyCache;

    public SymmetricEncryptionService(ISecureKeyCache keyCache)
    {
        _keyCache = keyCache;
    }

    /// <inheritdoc />
    public ValueTask<PrfResult<SymmetricEncryptedMessage>> EncryptAsync(string message, string salt)
    {
        ArgumentException.ThrowIfNullOrEmpty(message);
        ArgumentException.ThrowIfNullOrEmpty(salt);

        var cacheKey = GetCacheKey(salt);

        // Use the key directly from unmanaged memory without creating a managed copy
        if (!_keyCache.UseKey(cacheKey, key => WasmCryptoOperations.EncryptSymmetric(message, key), out var result))
        {
            return ValueTask.FromResult(PrfResult<SymmetricEncryptedMessage>.Fail(PrfErrorCode.KeyDerivationFailed));
        }

        return ValueTask.FromResult(result ?? PrfResult<SymmetricEncryptedMessage>.Fail(PrfErrorCode.EncryptionFailed));
    }

    /// <inheritdoc />
    public ValueTask<PrfResult<string>> DecryptAsync(SymmetricEncryptedMessage encrypted, string salt)
    {
        ArgumentNullException.ThrowIfNull(encrypted);
        ArgumentException.ThrowIfNullOrEmpty(salt);

        var cacheKey = GetCacheKey(salt);

        // Use the key directly from unmanaged memory without creating a managed copy
        if (!_keyCache.UseKey(cacheKey, key => WasmCryptoOperations.DecryptSymmetric(encrypted, key), out var result))
        {
            return ValueTask.FromResult(PrfResult<string>.Fail(PrfErrorCode.KeyDerivationFailed));
        }

        return ValueTask.FromResult(result ?? PrfResult<string>.Fail(PrfErrorCode.DecryptionFailed));
    }

    private static string GetCacheKey(string salt) => $"prf-key:{salt}";
}
