using BlazorPRF.Shared.Crypto.Models;

namespace BlazorPRF.Shared.Crypto.Services;

/// <summary>
/// Service for asymmetric (ECIES) encryption using X25519 + ChaCha20-Poly1305.
/// </summary>
public interface IAsymmetricEncryption
{
    /// <summary>
    /// Encrypt a message for a recipient using their public key.
    /// No private key required - anyone can encrypt to a public key.
    /// </summary>
    /// <param name="message">The plaintext message</param>
    /// <param name="recipientPublicKey">The recipient's X25519 public key (Base64)</param>
    /// <returns>The encrypted message or error</returns>
    ValueTask<PrfResult<EncryptedMessage>> EncryptAsync(string message, string recipientPublicKey);

    /// <summary>
    /// Decrypt a message using the private key.
    /// </summary>
    /// <param name="encrypted">The encrypted message</param>
    /// <param name="keyIdentifier">Identifier for the key (salt for PRF, key ID for PseudoPRF)</param>
    /// <returns>The decrypted plaintext or error</returns>
    ValueTask<PrfResult<string>> DecryptAsync(EncryptedMessage encrypted, string keyIdentifier);
}
