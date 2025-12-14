namespace BlazorPRF.Persistence.Data.Models;

/// <summary>
/// A verified contact with public keys for encryption and signature verification.
/// User data (username, email, comment) is encrypted with PRF-derived symmetric key.
/// </summary>
public sealed class TrustedContact
{
    /// <summary>
    /// Unique identifier.
    /// </summary>
    public Guid Id { get; set; }

    /// <summary>
    /// Encrypted JSON containing username, email, and comment.
    /// Encrypted with PRF-derived symmetric key to demonstrate app-level encryption.
    /// </summary>
    public required string EncryptedUserData { get; set; }

    /// <summary>
    /// X25519 public key (Base64) for asymmetric encryption.
    /// Not sensitive - can be stored in plaintext.
    /// </summary>
    public required string X25519PublicKey { get; set; }

    /// <summary>
    /// Ed25519 public key (Base64) for signature verification.
    /// Not sensitive - can be stored in plaintext.
    /// </summary>
    public required string Ed25519PublicKey { get; set; }

    /// <summary>
    /// Level of trust for this contact.
    /// </summary>
    public TrustLevel TrustLevel { get; set; }

    /// <summary>
    /// How trust was established (sent vs received invitation).
    /// </summary>
    public TrustDirection Direction { get; set; }

    /// <summary>
    /// When the contact was verified via signed invitation.
    /// </summary>
    public DateTime VerifiedAt { get; set; }

    /// <summary>
    /// When the contact record was created.
    /// </summary>
    public DateTime CreatedAt { get; set; }
}
