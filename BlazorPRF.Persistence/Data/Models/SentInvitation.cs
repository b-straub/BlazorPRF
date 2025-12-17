using System.ComponentModel.DataAnnotations;

namespace BlazorPRF.Persistence.Data.Models;

/// <summary>
/// Tracks an invitation created by the user.
/// </summary>
public sealed class SentInvitation
{
    /// <summary>
    /// Unique identifier.
    /// </summary>
    public Guid Id { get; set; }

    /// <summary>
    /// The invite code (e.g., "INV-abc123XY").
    /// </summary>
    [MaxLength(32)]
    public required string InviteCode { get; set; }

    /// <summary>
    /// Encrypted email address of the invitee.
    /// </summary>
    [MaxLength(1024)]
    public required string EncryptedEmail { get; set; }

    /// <summary>
    /// Full armored invite for re-sending if needed.
    /// </summary>
    [MaxLength(8192)]
    public required string ArmoredInvite { get; set; }

    /// <summary>
    /// Current status of the invitation.
    /// </summary>
    public InviteStatus Status { get; set; }

    /// <summary>
    /// When the invitation was created.
    /// </summary>
    public DateTime CreatedAt { get; set; }

    /// <summary>
    /// When the invitation was accepted (if accepted).
    /// </summary>
    public DateTime? AcceptedAt { get; set; }

    /// <summary>
    /// Foreign key to the trusted contact created upon acceptance.
    /// </summary>
    public Guid? TrustedContactId { get; set; }

    /// <summary>
    /// Navigation property to the trusted contact.
    /// </summary>
    public TrustedContact? TrustedContact { get; set; }
}
