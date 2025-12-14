namespace BlazorPRF.UI.Models;

/// <summary>
/// Event data for when an invite is created.
/// </summary>
public sealed class InviteCreatedEventArgs
{
    /// <summary>
    /// The full invite code (e.g., "INV-ABC123|bob@example.com|1234567890").
    /// </summary>
    public required string InviteCode { get; init; }

    /// <summary>
    /// The email address of the person being invited.
    /// </summary>
    public required string Email { get; init; }

    /// <summary>
    /// The armored signed invite to send to the invitee.
    /// </summary>
    public required string ArmoredInvite { get; init; }

    /// <summary>
    /// The inviter's Ed25519 public key (for signature verification).
    /// </summary>
    public required string InviterEd25519PublicKey { get; init; }
}

/// <summary>
/// Event data for when an invite is accepted (signed by accepter).
/// </summary>
public sealed class InviteAcceptedEventArgs
{
    /// <summary>
    /// The original invite code.
    /// </summary>
    public required string InviteCode { get; init; }

    /// <summary>
    /// The inviter's Ed25519 public key.
    /// </summary>
    public required string InviterEd25519PublicKey { get; init; }

    /// <summary>
    /// The accepter's username.
    /// </summary>
    public required string Username { get; init; }

    /// <summary>
    /// The accepter's email.
    /// </summary>
    public required string Email { get; init; }

    /// <summary>
    /// The armored signed response.
    /// </summary>
    public required string ArmoredResponse { get; init; }
}

/// <summary>
/// Event data for when signatures are verified and trust is established.
/// </summary>
public sealed class InviteVerifiedEventArgs
{
    /// <summary>
    /// The original invite code.
    /// </summary>
    public required string InviteCode { get; init; }

    /// <summary>
    /// The verified user's display name.
    /// </summary>
    public string? Username { get; init; }

    /// <summary>
    /// The verified user's email address.
    /// </summary>
    public required string Email { get; init; }

    /// <summary>
    /// The verified X25519 public key (for encryption).
    /// </summary>
    public required string X25519PublicKey { get; init; }

    /// <summary>
    /// The verified Ed25519 public key (for signature verification).
    /// </summary>
    public required string Ed25519PublicKey { get; init; }
}
