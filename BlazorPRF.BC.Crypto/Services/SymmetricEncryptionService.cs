using System.Runtime.Versioning;
using BlazorPRF.Shared.Crypto.Abstractions;
using BlazorPRF.Shared.Crypto.Configuration;
using BlazorPRF.Shared.Crypto.Models;
using BlazorPRF.Shared.Crypto.Services;
using Microsoft.Extensions.Options;

namespace BlazorPRF.BC.Crypto.Services;

/// <summary>
/// Service for symmetric encryption using PRF-derived keys.
/// All crypto operations happen in C#/WASM for security.
///
/// Supports domain-specific key derivation: when the keyIdentifier contains a colon (e.g., "my-salt:contacts"),
/// the part before the colon is the authentication salt (used to lookup the PRF seed),
/// and the part after is the domain (used for HKDF derivation).
///
/// For backward compatibility, keyIdentifiers without a colon use the authentication salt's
/// X25519 private key directly.
/// </summary>
[SupportedOSPlatform("browser")]
public sealed class SymmetricEncryptionService : ISymmetricEncryption
{
    private readonly ISecureKeyCache _keyCache;
    private readonly EncryptionAlgorithm _defaultAlgorithm;

    public SymmetricEncryptionService(ISecureKeyCache keyCache, IOptions<PrfOptions> options)
    {
        _keyCache = keyCache;
        _defaultAlgorithm = options.Value.DefaultAlgorithm;
    }

    /// <inheritdoc />
    public ValueTask<PrfResult<SymmetricEncryptedMessage>> EncryptAsync(string message, string keyIdentifier)
    {
        ArgumentException.ThrowIfNullOrEmpty(message);
        ArgumentException.ThrowIfNullOrEmpty(keyIdentifier);

        // Check if this is a domain-specific key request (format: "authSalt:domain")
        var colonIndex = keyIdentifier.IndexOf(':');
        if (colonIndex > 0)
        {
            var authSalt = keyIdentifier[..colonIndex];
            var domain = keyIdentifier[(colonIndex + 1)..];

            // Derive domain-specific key from PRF seed
            var prfSeedCacheKey = PrfService.GetPrfSeedCacheKey(authSalt);
            if (!_keyCache.UseKey(prfSeedCacheKey, prfSeed =>
            {
                var domainKey = KeyGenerator.DeriveDomainKey(prfSeed.ToArray(), domain);
                return CryptoOperations.EncryptSymmetric(message, domainKey, _defaultAlgorithm);
            }, out var domainResult))
            {
                return ValueTask.FromResult(PrfResult<SymmetricEncryptedMessage>.Fail(PrfErrorCode.KeyDerivationFailed));
            }

            return ValueTask.FromResult(domainResult ?? PrfResult<SymmetricEncryptedMessage>.Fail(PrfErrorCode.EncryptionFailed));
        }

        // Backward compatible: use X25519 private key directly
        var cacheKey = GetCacheKey(keyIdentifier);
        if (!_keyCache.UseKey(cacheKey, key => CryptoOperations.EncryptSymmetric(message, key, _defaultAlgorithm), out var result))
        {
            return ValueTask.FromResult(PrfResult<SymmetricEncryptedMessage>.Fail(PrfErrorCode.KeyDerivationFailed));
        }

        return ValueTask.FromResult(result ?? PrfResult<SymmetricEncryptedMessage>.Fail(PrfErrorCode.EncryptionFailed));
    }

    /// <inheritdoc />
    public ValueTask<PrfResult<string>> DecryptAsync(SymmetricEncryptedMessage encrypted, string keyIdentifier)
    {
        ArgumentNullException.ThrowIfNull(encrypted);
        ArgumentException.ThrowIfNullOrEmpty(keyIdentifier);

        // Check if this is a domain-specific key request (format: "authSalt:domain")
        var colonIndex = keyIdentifier.IndexOf(':');
        if (colonIndex > 0)
        {
            var authSalt = keyIdentifier[..colonIndex];
            var domain = keyIdentifier[(colonIndex + 1)..];

            // Derive domain-specific key from PRF seed
            var prfSeedCacheKey = PrfService.GetPrfSeedCacheKey(authSalt);
            if (!_keyCache.UseKey(prfSeedCacheKey, prfSeed =>
            {
                var domainKey = KeyGenerator.DeriveDomainKey(prfSeed.ToArray(), domain);
                return CryptoOperations.DecryptSymmetric(encrypted, domainKey);
            }, out var domainResult))
            {
                return ValueTask.FromResult(PrfResult<string>.Fail(PrfErrorCode.KeyDerivationFailed));
            }

            return ValueTask.FromResult(domainResult ?? PrfResult<string>.Fail(PrfErrorCode.DecryptionFailed));
        }

        // Backward compatible: use X25519 private key directly
        var cacheKey = GetCacheKey(keyIdentifier);
        if (!_keyCache.UseKey(cacheKey, key => CryptoOperations.DecryptSymmetric(encrypted, key), out var result))
        {
            return ValueTask.FromResult(PrfResult<string>.Fail(PrfErrorCode.KeyDerivationFailed));
        }

        return ValueTask.FromResult(result ?? PrfResult<string>.Fail(PrfErrorCode.DecryptionFailed));
    }

    private static string GetCacheKey(string salt) => $"prf-key:{salt}";
}
