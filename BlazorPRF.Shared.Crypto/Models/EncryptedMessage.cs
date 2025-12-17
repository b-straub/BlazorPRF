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
    EncryptionAlgorithm? Algorithm = null
)
{
    /// <summary>
    /// Gets the effective algorithm (defaults to ChaCha20Poly1305 for backward compatibility).
    /// </summary>
    public EncryptionAlgorithm EffectiveAlgorithm => Algorithm ?? EncryptionAlgorithm.CHA_CHA20_POLY1305;
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
