using BlazorPRF.Persistence.Data.Models;
using BlazorPRF.Persistence.Services;
using BlazorPRF.Sample.Models;
using BlazorPRF.UI.Models;
using BlazorPRF.UI.Services;

namespace BlazorPRF.Sample.Services;

/// <summary>
/// SQLite implementation of IInvitePersistence.
/// Persists invitation events to the local database.
/// </summary>
public sealed class SqliteInvitePersistence : IInvitePersistence
{
    private readonly IInvitationService _invitationService;
    private readonly ITrustedContactService _contactService;
    private readonly ContactsModel _contactsModel;
    private readonly ICredentialHintProvider _credentialHintProvider;

    public SqliteInvitePersistence(
        IInvitationService invitationService,
        ITrustedContactService contactService,
        ContactsModel contactsModel,
        ICredentialHintProvider credentialHintProvider)
    {
        _invitationService = invitationService;
        _contactService = contactService;
        _contactsModel = contactsModel;
        _credentialHintProvider = credentialHintProvider;
    }

    /// <inheritdoc />
    public async Task<bool> SaveCreatedInviteAsync(InviteCreatedEventArgs args, CancellationToken ct)
    {
        var result = await _invitationService.CreateSentInvitationAsync(
            args.InviteCode,
            args.Email,
            args.ArmoredInvite);

        return result.Success;
    }

    /// <inheritdoc />
    public async Task<bool> SaveAcceptedInviteAsync(InviteAcceptedEventArgs args, CancellationToken ct)
    {
        await _invitationService.CreateReceivedInvitationAsync(
            args.InviteCode,
            args.InviterEd25519PublicKey);

        return true;
    }

    /// <inheritdoc />
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
            TrustLevel.Full,
            TrustDirection.Sent,
            credentialHint?.CredentialId,
            credentialHint?.Metadata?.Name);

        if (result is { Success: true, Value: not null })
        {
            // Link the sent invitation to the contact
            await _invitationService.MarkSentInvitationAcceptedAsync(args.InviteCode, result.Value.Id);

            // Notify that contacts have changed so UI can refresh
            _contactsModel.NotifyContactsChanged();

            return true;
        }

        return false;
    }
}
