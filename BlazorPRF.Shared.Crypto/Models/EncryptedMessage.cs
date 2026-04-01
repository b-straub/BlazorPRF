using BlazorPRF.Shared.Crypto.Abstractions;

namespace BlazorPRF.Shared.Crypto.Models;

/// <summary>
/// Represents an ECIES encrypted message using X25519 + symmetric cipher.
/// </summary>
/// <param name="EphemeralPublicKey">The ephemeral X25519 public key used for ECDH (Base64, 32 bytes).</param>
/// <param name="Ciphertext">The encrypted ciphertext with auth tag (Base64).</param>
/// <param name="Nonce">The encryption nonce (Base64).</param>
/// <param name="Algorithm">The symmetric algorithm used. Null = legacy ChaCha20Poly1305.</param>
public sealed record EncryptedMessage(
    string EphemeralPublicKey,
    string Ciphertext,
    string Nonce,
    EncryptionAlgorithm? Algorithm = null,
    string? Signature = null,
    string? SenderEd25519PublicKey = null
)
{
    /// <summary>
    /// Gets the effective algorithm (defaults to ChaCha20Poly1305 for backward compatibility).
    /// </summary>
    public EncryptionAlgorithm EffectiveAlgorithm => Algorithm ?? EncryptionAlgorithm.CHA_CHA20_POLY1305;

    /// <summary>
    /// Whether this message includes a sender signature (sign + encrypt).
    /// </summary>
    public bool IsSigned => Signature is not null && SenderEd25519PublicKey is not null;
}

/// <summary>
/// Result of decrypting a message that may include sender verification.
/// </summary>
/// <param name="Plaintext">The decrypted plaintext.</param>
/// <param name="SenderEd25519PublicKey">The sender's Ed25519 public key, if the message was signed.</param>
/// <param name="SignatureValid">Whether the sender's signature was verified. null = message was not signed.</param>
public sealed record DecryptedMessage(
    string Plaintext,
    string? SenderEd25519PublicKey = null,
    bool? SignatureValid = null
)
{
    /// <summary>
    /// Whether the message was signed and the signature is valid.
    /// </summary>
    public bool IsVerified => SignatureValid == true;

    /// <summary>
    /// Whether the message was signed but the signature is invalid.
    /// </summary>
    public bool IsSignatureInvalid => SignatureValid == false;
}

/// <summary>
/// Represents a symmetric encrypted message.
/// </summary>
/// <param name="Ciphertext">The encrypted ciphertext with auth tag (Base64).</param>
/// <param name="Nonce">The encryption nonce (Base64).</param>
/// <param name="Algorithm">The algorithm used. Null = legacy ChaCha20Poly1305.</param>
public sealed record SymmetricEncryptedMessage(
    string Ciphertext,
    string Nonce,
    EncryptionAlgorithm? Algorithm = null
)
{
    /// <summary>
    /// Gets the effective algorithm (defaults to ChaCha20Poly1305 for backward compatibility).
    /// </summary>
    public EncryptionAlgorithm EffectiveAlgorithm => Algorithm ?? EncryptionAlgorithm.CHA_CHA20_POLY1305;
}
