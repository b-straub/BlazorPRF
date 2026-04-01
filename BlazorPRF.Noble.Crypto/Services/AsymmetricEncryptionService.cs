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

       public async ValueTask<PrfResult<EncryptedMessage>> EncryptAsync(string message, string recipientPublicKey)
    {
        ArgumentException.ThrowIfNullOrEmpty(message);
        ArgumentException.ThrowIfNullOrEmpty(recipientPublicKey);

        return await _cryptoProvider.EncryptAsymmetricAsync(message, recipientPublicKey, _defaultAlgorithm);
    }

       public async ValueTask<PrfResult<EncryptedMessage>> SignAndEncryptAsync(
        string message,
        string recipientPublicKey,
        ISigningService signingService,
        string senderEd25519PublicKey,
        string keyIdentifier)
    {
        ArgumentException.ThrowIfNullOrEmpty(message);
        ArgumentException.ThrowIfNullOrEmpty(recipientPublicKey);
        ArgumentException.ThrowIfNullOrEmpty(senderEd25519PublicKey);

        // Sign the plaintext first
        var signResult = await signingService.SignAsync(message, keyIdentifier);
        if (!signResult.Success || signResult.Value is null)
        {
            return PrfResult<EncryptedMessage>.Fail(signResult.ErrorCode ?? PrfErrorCode.SIGNING_FAILED);
        }

        // Encrypt the plaintext
        var encryptResult = await _cryptoProvider.EncryptAsymmetricAsync(message, recipientPublicKey, _defaultAlgorithm);
        if (!encryptResult.Success || encryptResult.Value is null)
        {
            return encryptResult;
        }

        // Attach signature and sender key to the encrypted message
        var signed = encryptResult.Value with
        {
            Signature = signResult.Value,
            SenderEd25519PublicKey = senderEd25519PublicKey
        };

        return PrfResult<EncryptedMessage>.Ok(signed);
    }

       public async ValueTask<PrfResult<string>> DecryptAsync(EncryptedMessage encrypted, string salt)
    {
        ArgumentNullException.ThrowIfNull(encrypted);
        ArgumentException.ThrowIfNullOrEmpty(salt);

        var cacheKey = GetCacheKey(salt);
        var privateKey = _keyCache.TryGet(cacheKey);
        if (privateKey is null)
        {
            return PrfResult<string>.Fail(PrfErrorCode.KEY_DERIVATION_FAILED);
        }

        var result = await _cryptoProvider.DecryptAsymmetricAsync(encrypted, privateKey, encrypted.EffectiveAlgorithm);
        Array.Clear(privateKey, 0, privateKey.Length);
        return result;
    }

       public async ValueTask<PrfResult<DecryptedMessage>> DecryptAndVerifyAsync(
        EncryptedMessage encrypted,
        string keyIdentifier,
        ISigningService signingService)
    {
        // Decrypt first
        var decryptResult = await DecryptAsync(encrypted, keyIdentifier);
        if (!decryptResult.Success || decryptResult.Value is null)
        {
            return PrfResult<DecryptedMessage>.Fail(decryptResult.ErrorCode ?? PrfErrorCode.DECRYPTION_FAILED);
        }

        // If message is signed, verify the signature
        if (encrypted.IsSigned)
        {
            var signatureValid = await signingService.VerifyAsync(
                decryptResult.Value,
                encrypted.Signature!,
                encrypted.SenderEd25519PublicKey!);

            return PrfResult<DecryptedMessage>.Ok(new DecryptedMessage(
                decryptResult.Value,
                encrypted.SenderEd25519PublicKey,
                signatureValid));
        }

        // Unsigned message
        return PrfResult<DecryptedMessage>.Ok(new DecryptedMessage(decryptResult.Value));
    }

    private static string GetCacheKey(string salt) => $"prf-key:{salt}";
}
