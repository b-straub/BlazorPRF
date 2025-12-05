namespace BlazorPRF.Shared.Models;

/// <summary>
/// Represents an ECIES encrypted message using X25519 + ChaCha20-Poly1305.
/// </summary>
/// <param name="EphemeralPublicKey">The ephemeral X25519 public key used for ECDH (Base64, 32 bytes).</param>
/// <param name="Ciphertext">The ChaCha20-Poly1305 encrypted ciphertext with auth tag (Base64).</param>
/// <param name="Nonce">The 12-byte encryption nonce (Base64).</param>
public sealed record EncryptedMessage(
    string EphemeralPublicKey,
    string Ciphertext,
    string Nonce
);

/// <summary>
/// Represents a symmetric encrypted message using ChaCha20-Poly1305.
/// </summary>
/// <param name="Ciphertext">The ChaCha20-Poly1305 encrypted ciphertext with auth tag (Base64).</param>
/// <param name="Nonce">The 12-byte encryption nonce (Base64).</param>
public sealed record SymmetricEncryptedMessage(
    string Ciphertext,
    string Nonce
);
