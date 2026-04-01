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

        // Sign the plaintext
        var signResult = await signingService.SignAsync(message, keyIdentifier);
        if (!signResult.Success || signResult.Value is null)
        {
            return PrfResult<EncryptedMessage>.Fail(signResult.ErrorCode ?? PrfErrorCode.SIGNING_FAILED);
        }

        // Bundle into signed envelope — this entire envelope gets encrypted
        var envelope = new SignedEnvelope(message, signResult.Value, senderEd25519PublicKey);
        var envelopeJson = System.Text.Json.JsonSerializer.Serialize(envelope,
            Shared.Crypto.Json.SharedJsonContext.Default.SignedEnvelope);

        // Encrypt the envelope (not the raw plaintext)
        return await _cryptoProvider.EncryptAsymmetricAsync(envelopeJson, recipientPublicKey, _defaultAlgorithm);
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
        // Decrypt
        var decryptResult = await DecryptAsync(encrypted, keyIdentifier);
        if (!decryptResult.Success || decryptResult.Value is null)
        {
            return PrfResult<DecryptedMessage>.Fail(decryptResult.ErrorCode ?? PrfErrorCode.DECRYPTION_FAILED);
        }

        SignedEnvelope? envelope;
        try
        {
            envelope = System.Text.Json.JsonSerializer.Deserialize(decryptResult.Value,
                Shared.Crypto.Json.SharedJsonContext.Default.SignedEnvelope);
        }
        catch (System.Text.Json.JsonException)
        {
            return PrfResult<DecryptedMessage>.Fail(PrfErrorCode.INCOMPATIBLE_FORMAT);
        }

        if (envelope is null)
        {
            return PrfResult<DecryptedMessage>.Fail(PrfErrorCode.INCOMPATIBLE_FORMAT);
        }

        var signatureValid = await signingService.VerifyAsync(
            envelope.Message,
            envelope.Signature,
            envelope.SenderEd25519PublicKey);

        return PrfResult<DecryptedMessage>.Ok(new DecryptedMessage(
            envelope.Message,
            envelope.SenderEd25519PublicKey,
            signatureValid));
    }

    private static string GetCacheKey(string salt) => $"prf-key:{salt}";
}
