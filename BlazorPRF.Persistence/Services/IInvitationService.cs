using BlazorPRF.Persistence.Data.Models;
using BlazorPRF.Shared.Crypto.Models;

namespace BlazorPRF.Persistence.Services;

/// <summary>
/// Service for managing sent and received invitations.
/// </summary>
public interface IInvitationService
{
    // Sent invitations

    /// <summary>
    /// Get all sent invitations.
    /// </summary>
    Task<PrfResult<List<(SentInvitation Invitation, string? Email)>>> GetSentInvitationsAsync();

    /// <summary>
    /// Create a sent invitation record.
    /// </summary>
    Task<PrfResult<SentInvitation>> CreateSentInvitationAsync(
        string inviteCode,
        string email,
        string armoredInvite);

    /// <summary>
    /// Mark a sent invitation as accepted and link to contact.
    /// </summary>
    Task<bool> MarkSentInvitationAcceptedAsync(string inviteCode, Guid trustedContactId);

    /// <summary>
    /// Update sent invitation status.
    /// </summary>
    Task<bool> UpdateSentInvitationStatusAsync(Guid id, InviteStatus status);

    /// <summary>
    /// Delete a sent invitation.
    /// </summary>
    Task<bool> DeleteSentInvitationAsync(Guid id);

    /// <summary>
    /// Get a sent invitation by invite code.
    /// </summary>
    Task<SentInvitation?> GetSentInvitationByCodeAsync(string inviteCode);

    // Received invitations

    /// <summary>
    /// Get all received invitations.
    /// </summary>
    Task<List<ReceivedInvitation>> GetReceivedInvitationsAsync();

    /// <summary>
    /// Create a received invitation record.
    /// </summary>
    Task<ReceivedInvitation> CreateReceivedInvitationAsync(
        string inviteCode,
        string inviterEd25519PublicKey,
        Guid? trustedContactId = null);

    /// <summary>
    /// Link a received invitation to a trusted contact.
    /// </summary>
    Task<bool> LinkReceivedInvitationToContactAsync(Guid invitationId, Guid trustedContactId);

    /// <summary>
    /// Check if an invitation with this code was already received.
    /// </summary>
    Task<bool> ReceivedInvitationExistsAsync(string inviteCode);
}
