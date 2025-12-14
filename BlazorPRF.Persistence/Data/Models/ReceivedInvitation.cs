namespace BlazorPRF.Persistence.Data.Models;

/// <summary>
/// Tracks an invitation that was accepted by the user.
/// </summary>
public sealed class ReceivedInvitation
{
    /// <summary>
    /// Unique identifier.
    /// </summary>
    public Guid Id { get; set; }

    /// <summary>
    /// The invite code from the invitation.
    /// </summary>
    public required string InviteCode { get; set; }

    /// <summary>
    /// Ed25519 public key of the inviter (Base64).
    /// Used to identify who invited us.
    /// </summary>
    public required string InviterEd25519PublicKey { get; set; }

    /// <summary>
    /// When the invitation was accepted.
    /// </summary>
    public DateTime AcceptedAt { get; set; }

    /// <summary>
    /// Foreign key to the trusted contact created upon acceptance.
    /// </summary>
    public Guid? TrustedContactId { get; set; }

    /// <summary>
    /// Navigation property to the trusted contact.
    /// </summary>
    public TrustedContact? TrustedContact { get; set; }
}
