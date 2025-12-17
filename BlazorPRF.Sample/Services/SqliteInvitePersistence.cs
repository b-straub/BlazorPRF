using BlazorPRF.Persistence.Data.Models;
using BlazorPRF.Persistence.Services;
using BlazorPRF.UI.Models;
using BlazorPRF.UI.Services;

namespace BlazorPRF.Sample.Services;

/// <summary>
/// SQLite implementation of IInvitePersistence.
/// Persists invitation events to the local database.
/// Contact modification notifications are handled reactively via InviteModel.ContactsModifiedVersion.
/// </summary>
public sealed class SqliteInvitePersistence : IInvitePersistence
{
    private readonly IInvitationService _invitationService;
    private readonly ITrustedContactService _contactService;
    private readonly ICredentialHintProvider _credentialHintProvider;

    public SqliteInvitePersistence(
        IInvitationService invitationService,
        ITrustedContactService contactService,
        ICredentialHintProvider credentialHintProvider)
    {
        _invitationService = invitationService;
        _contactService = contactService;
        _credentialHintProvider = credentialHintProvider;
    }

       public async Task<bool> SaveCreatedInviteAsync(InviteCreatedEventArgs args, CancellationToken ct)
    {
        var result = await _invitationService.CreateSentInvitationAsync(
            args.InviteCode,
            args.Email,
            args.ArmoredInvite);

        return result.Success;
    }

       public async Task<bool> SaveAcceptedInviteAsync(InviteAcceptedEventArgs args, CancellationToken ct)
    {
        // Create received invitation record
        var receivedInvitation = await _invitationService.CreateReceivedInvitationAsync(
            args.InviteCode,
            args.InviterEd25519PublicKey);

        // Check if inviter is already a contact
        if (await _contactService.ExistsByEd25519PublicKeyAsync(args.InviterEd25519PublicKey))
        {
            return true; // Inviter already in contacts
        }

        // Create TrustedContact for the inviter (bidirectional trust)
        var userData = new ContactUserData
        {
            Username = args.InviterUsername,
            Email = args.InviterEmail,
            Comment = $"Accepted invite: {args.InviteCode}"
        };

        var credentialHint = await _credentialHintProvider.GetCredentialHintAsync();

        var result = await _contactService.CreateAsync(
            userData,
            args.InviterX25519PublicKey,
            args.InviterEd25519PublicKey,
            TrustLevel.FULL,
            TrustDirection.RECEIVED,
            credentialHint?.CredentialId,
            credentialHint?.Metadata?.Name);

        // Link received invitation to the contact
        if (result is { Success: true, Value: not null })
        {
            await _invitationService.LinkReceivedInvitationToContactAsync(
                receivedInvitation.Id,
                result.Value.Id);
        }

        return true;
    }

       public async Task<bool> SaveVerifiedContactAsync(InviteVerifiedEventArgs args, CancellationToken ct)
    {
        // Check if contact already exists
        if (await _contactService.ExistsByEd25519PublicKeyAsync(args.Ed25519PublicKey))
        {
            return false; // Contact already exists
        }

        // Create trusted contact with encrypted user data
        var userData = new ContactUserData
        {
            Username = args.Username ?? "Unknown",
            Email = args.Email,
            Comment = "Verified via signed invite"
        };

        // Get current credential info for tracking which passkey encrypted the data
        var credentialHint = await _credentialHintProvider.GetCredentialHintAsync();

        var result = await _contactService.CreateAsync(
            userData,
            args.X25519PublicKey,
            args.Ed25519PublicKey,
            TrustLevel.FULL,
            TrustDirection.SENT,
            credentialHint?.CredentialId,
            credentialHint?.Metadata?.Name);

        if (result is { Success: true, Value: not null })
        {
            // Link the sent invitation to the contact
            await _invitationService.MarkSentInvitationAcceptedAsync(args.InviteCode, result.Value.Id);

            // Note: Contact modification notification is handled reactively via InviteModel.Status
            // which ContactsModel observes to reload contacts when Status.Severity is SUCCESS
            return true;
        }

        return false;
    }
}
