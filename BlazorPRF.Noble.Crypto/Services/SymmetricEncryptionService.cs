using System.Runtime.Versioning;
using BlazorPRF.Shared.Crypto.Abstractions;
using BlazorPRF.Shared.Crypto.Models;
using BlazorPRF.Shared.Crypto.Services;

namespace BlazorPRF.Noble.Crypto.Services;

/// <summary>
/// Service for symmetric encryption using PRF-derived keys via ICryptoProvider.
/// </summary>
[SupportedOSPlatform("browser")]
public sealed class SymmetricEncryptionService : ISymmetricEncryption
{
    private readonly ISecureKeyCache _keyCache;
    private readonly ICryptoProvider _cryptoProvider;

    public SymmetricEncryptionService(ISecureKeyCache keyCache, ICryptoProvider cryptoProvider)
    {
        _keyCache = keyCache;
        _cryptoProvider = cryptoProvider;
    }

    /// <inheritdoc />
    public async ValueTask<PrfResult<SymmetricEncryptedMessage>> EncryptAsync(string message, string keyIdentifier)
    {
        ArgumentException.ThrowIfNullOrEmpty(message);
        ArgumentException.ThrowIfNullOrEmpty(keyIdentifier);

        // Check if this is a domain-specific key request (format: "authSalt:domain")
        var colonIndex = keyIdentifier.IndexOf(':');
        if (colonIndex > 0)
        {
            var authSalt = keyIdentifier[..colonIndex];
            var domain = keyIdentifier[(colonIndex + 1)..];

            // Get PRF seed for domain-specific key derivation
            var prfSeedCacheKey = PrfService.GetPrfSeedCacheKey(authSalt);
            var prfSeed = _keyCache.TryGet(prfSeedCacheKey);
            if (prfSeed is null)
            {
                return PrfResult<SymmetricEncryptedMessage>.Fail(PrfErrorCode.KeyDerivationFailed);
            }

            // Derive domain-specific key using HKDF
            var domainKey = await DeriveDomainKeyAsync(prfSeed, domain);
            Array.Clear(prfSeed, 0, prfSeed.Length);

            return await _cryptoProvider.EncryptSymmetricAsync(message, domainKey, EncryptionAlgorithm.AesGcm);
        }

        // Backward compatible: use X25519 private key directly
        var cacheKey = GetCacheKey(keyIdentifier);
        var key = _keyCache.TryGet(cacheKey);
        if (key is null)
        {
            return PrfResult<SymmetricEncryptedMessage>.Fail(PrfErrorCode.KeyDerivationFailed);
        }

        var result = await _cryptoProvider.EncryptSymmetricAsync(message, key, EncryptionAlgorithm.AesGcm);
        Array.Clear(key, 0, key.Length);
        return result;
    }

    /// <inheritdoc />
    public async ValueTask<PrfResult<string>> DecryptAsync(SymmetricEncryptedMessage encrypted, string keyIdentifier)
    {
        ArgumentNullException.ThrowIfNull(encrypted);
        ArgumentException.ThrowIfNullOrEmpty(keyIdentifier);

        // Check if this is a domain-specific key request (format: "authSalt:domain")
        var colonIndex = keyIdentifier.IndexOf(':');
        if (colonIndex > 0)
        {
            var authSalt = keyIdentifier[..colonIndex];
            var domain = keyIdentifier[(colonIndex + 1)..];

            // Get PRF seed for domain-specific key derivation
            var prfSeedCacheKey = PrfService.GetPrfSeedCacheKey(authSalt);
            var prfSeed = _keyCache.TryGet(prfSeedCacheKey);
            if (prfSeed is null)
            {
                return PrfResult<string>.Fail(PrfErrorCode.KeyDerivationFailed);
            }

            // Derive domain-specific key using HKDF
            var domainKey = await DeriveDomainKeyAsync(prfSeed, domain);
            Array.Clear(prfSeed, 0, prfSeed.Length);

            return await _cryptoProvider.DecryptSymmetricAsync(encrypted, domainKey, EncryptionAlgorithm.AesGcm);
        }

        // Backward compatible: use X25519 private key directly
        var cacheKey = GetCacheKey(keyIdentifier);
        var key = _keyCache.TryGet(cacheKey);
        if (key is null)
        {
            return PrfResult<string>.Fail(PrfErrorCode.KeyDerivationFailed);
        }

        var result = await _cryptoProvider.DecryptSymmetricAsync(encrypted, key, EncryptionAlgorithm.AesGcm);
        Array.Clear(key, 0, key.Length);
        return result;
    }

    /// <summary>
    /// Derive a domain-specific key using HKDF.
    /// </summary>
    private async Task<byte[]> DeriveDomainKeyAsync(byte[] prfSeed, string domain)
    {
        // Use HKDF via Noble.js to derive domain-specific key
        var domainKeyBase64 = await Interop.NobleInterop.DeriveHkdfKey(
            Convert.ToBase64String(prfSeed),
            domain);
        return Convert.FromBase64String(domainKeyBase64);
    }

    private static string GetCacheKey(string salt) => $"prf-key:{salt}";
}
