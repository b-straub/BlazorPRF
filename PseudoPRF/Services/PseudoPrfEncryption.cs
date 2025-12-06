using BlazorPRF.Crypto;
using BlazorPRF.Shared.Models;
using BlazorPRF.Shared.Services;

namespace PseudoPRF.Services;

/// <summary>
/// Symmetric encryption service using stored keys.
/// </summary>
public sealed class PseudoSymmetricEncryption : ISymmetricEncryption
{
    private readonly IKeyStore _keyStore;

    public PseudoSymmetricEncryption(IKeyStore keyStore)
    {
        _keyStore = keyStore;
    }

    /// <inheritdoc />
    public async ValueTask<PrfResult<SymmetricEncryptedMessage>> EncryptAsync(string message, string keyIdentifier)
    {
        ArgumentException.ThrowIfNullOrEmpty(message);
        ArgumentException.ThrowIfNullOrEmpty(keyIdentifier);

        var privateKey = await _keyStore.GetPrivateKeyAsync(keyIdentifier);
        if (privateKey is null)
        {
            return PrfResult<SymmetricEncryptedMessage>.Fail(PrfErrorCode.KeyDerivationFailed);
        }

        return CryptoOperations.EncryptSymmetric(message, privateKey);
    }

    /// <inheritdoc />
    public async ValueTask<PrfResult<string>> DecryptAsync(SymmetricEncryptedMessage encrypted, string keyIdentifier)
    {
        ArgumentNullException.ThrowIfNull(encrypted);
        ArgumentException.ThrowIfNullOrEmpty(keyIdentifier);

        var privateKey = await _keyStore.GetPrivateKeyAsync(keyIdentifier);
        if (privateKey is null)
        {
            return PrfResult<string>.Fail(PrfErrorCode.KeyDerivationFailed);
        }

        return CryptoOperations.DecryptSymmetric(encrypted, privateKey);
    }
}

/// <summary>
/// Asymmetric (ECIES) encryption service using stored keys.
/// </summary>
public sealed class PseudoAsymmetricEncryption : IAsymmetricEncryption
{
    private readonly IKeyStore _keyStore;

    public PseudoAsymmetricEncryption(IKeyStore keyStore)
    {
        _keyStore = keyStore;
    }

    /// <inheritdoc />
    public ValueTask<PrfResult<EncryptedMessage>> EncryptAsync(string message, string recipientPublicKey)
    {
        ArgumentException.ThrowIfNullOrEmpty(message);
        ArgumentException.ThrowIfNullOrEmpty(recipientPublicKey);

        // Encryption doesn't need stored keys - just the recipient's public key
        return ValueTask.FromResult(CryptoOperations.EncryptAsymmetric(message, recipientPublicKey));
    }

    /// <inheritdoc />
    public async ValueTask<PrfResult<string>> DecryptAsync(EncryptedMessage encrypted, string keyIdentifier)
    {
        ArgumentNullException.ThrowIfNull(encrypted);
        ArgumentException.ThrowIfNullOrEmpty(keyIdentifier);

        var privateKey = await _keyStore.GetPrivateKeyAsync(keyIdentifier);
        if (privateKey is null)
        {
            return PrfResult<string>.Fail(PrfErrorCode.KeyDerivationFailed);
        }

        return CryptoOperations.DecryptAsymmetric(encrypted, privateKey);
    }
}

/// <summary>
/// Static encryption helpers that don't require key store (for direct key usage).
/// </summary>
public static class PseudoPrfCrypto
{
    /// <summary>
    /// Encrypts a message using ChaCha20-Poly1305 symmetric encryption.
    /// </summary>
    /// <param name="plaintext">The message to encrypt</param>
    /// <param name="keyBase64">The 32-byte symmetric key (Base64)</param>
    /// <returns>The encrypted message</returns>
    public static PrfResult<SymmetricEncryptedMessage> EncryptSymmetric(string plaintext, string keyBase64)
        => CryptoOperations.EncryptSymmetric(plaintext, keyBase64);

    /// <summary>
    /// Decrypts a message using ChaCha20-Poly1305 symmetric encryption.
    /// </summary>
    /// <param name="encrypted">The encrypted message</param>
    /// <param name="keyBase64">The 32-byte symmetric key (Base64)</param>
    /// <returns>The decrypted plaintext</returns>
    public static PrfResult<string> DecryptSymmetric(SymmetricEncryptedMessage encrypted, string keyBase64)
        => CryptoOperations.DecryptSymmetric(encrypted, keyBase64);

    /// <summary>
    /// Encrypts a message using ECIES (X25519 + ChaCha20-Poly1305).
    /// </summary>
    /// <param name="plaintext">The message to encrypt</param>
    /// <param name="recipientPublicKeyBase64">The recipient's X25519 public key (Base64)</param>
    /// <returns>The encrypted message with ephemeral public key</returns>
    public static PrfResult<EncryptedMessage> EncryptAsymmetric(string plaintext, string recipientPublicKeyBase64)
        => CryptoOperations.EncryptAsymmetric(plaintext, recipientPublicKeyBase64);

    /// <summary>
    /// Decrypts a message using ECIES (X25519 + ChaCha20-Poly1305).
    /// </summary>
    /// <param name="encrypted">The encrypted message</param>
    /// <param name="privateKeyBase64">The recipient's X25519 private key (Base64)</param>
    /// <returns>The decrypted plaintext</returns>
    public static PrfResult<string> DecryptAsymmetric(EncryptedMessage encrypted, string privateKeyBase64)
        => CryptoOperations.DecryptAsymmetric(encrypted, privateKeyBase64);
}
