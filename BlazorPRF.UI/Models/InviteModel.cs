using BlazorPRF.UI.Services;
using RxBlazorV2.Interface;
using RxBlazorV2.Model;
using System.Diagnostics.CodeAnalysis;
using RxBlazorV2.MudBlazor.Components;

namespace BlazorPRF.UI.Models;

/// <summary>
/// Reactive model for invitation events.
/// Model commands own workflows following Service-Model Interaction pattern.
/// Status property signals completion for other models to observe.
/// </summary>
[ObservableModelScope(ModelScope.Singleton)]
[ObservableComponent]
public partial class InviteModel : ObservableModel
{
    /// <summary>
    /// Persistence injection for saving invite events.
    /// </summary>
    [SuppressMessage("RxBlazorGenerator", "RXBG050:Partial constructor parameter type may not be registered in DI", Justification = "IInvitePersistence registered externally")]
    public partial InviteModel(IInvitePersistence persistence, StatusModel statusModel);

    /// <summary>
    /// Latest invite creation event. Set when an invite is created.
    /// Triggers ProcessCreationCommand automatically.
    /// </summary>
    public partial InviteCreatedEventArgs? LastInviteCreated { get; set; }

    /// <summary>
    /// Latest invite acceptance event. Set when an invite is accepted (signed).
    /// Triggers ProcessAcceptanceCommand automatically.
    /// </summary>
    public partial InviteAcceptedEventArgs? LastInviteAccepted { get; set; }

    /// <summary>
    /// Latest invite verification event. Set when signatures are verified.
    /// Triggers ProcessVerificationCommand automatically.
    /// </summary>
    public partial InviteVerifiedEventArgs? LastInviteVerified { get; set; }

    /// <summary>
    /// Timestamp of last successful contact modification (add/update).
    /// Other models can observe this to reload contacts reactively.
    /// </summary>
    public partial DateTime? ContactsModifiedAt { get; set; }

    // Commands - auto-triggered when corresponding event properties are set

    /// <summary>
    /// Processes invite creation - persists and sets status.
    /// </summary>
    [ObservableCommand(nameof(ProcessCreationAsync))]
    [ObservableCommandTrigger(nameof(LastInviteCreated))]
    public partial IObservableCommandAsync ProcessCreationCommand { get; }

    /// <summary>
    /// Processes invite acceptance - persists and sets status.
    /// </summary>
    [ObservableCommand(nameof(ProcessAcceptanceAsync))]
    [ObservableCommandTrigger(nameof(LastInviteAccepted))]
    public partial IObservableCommandAsync ProcessAcceptanceCommand { get; }

    /// <summary>
    /// Processes invite verification - persists contact and sets status.
    /// </summary>
    [ObservableCommand(nameof(ProcessVerificationAsync))]
    [ObservableCommandTrigger(nameof(LastInviteVerified))]
    public partial IObservableCommandAsync ProcessVerificationCommand { get; }

    private async Task ProcessCreationAsync(CancellationToken ct)
    {
        if (LastInviteCreated is null)
        {
            return;
        }

        var success = await Persistence.SaveCreatedInviteAsync(LastInviteCreated, ct);
        if (success)
        {
            StatusModel.AddSuccess("Invitation saved!", ModelID);
        }
        else
        {
            StatusModel.AddError("Failed to save invitation.");
        }
    }

    private async Task ProcessAcceptanceAsync(CancellationToken ct)
    {
        if (LastInviteAccepted is null)
        {
            return;
        }

        var success = await Persistence.SaveAcceptedInviteAsync(LastInviteAccepted, ct);
        if (success)
        {
            ContactsModifiedAt = DateTime.UtcNow;
            StatusModel.AddSuccess("Inviter added to contacts!", ModelID);
        }
        else
        {
            StatusModel.AddError("Failed to record acceptance.");
        }
    }

    private async Task ProcessVerificationAsync(CancellationToken ct)
    {
        if (LastInviteVerified is null)
        {
            return;
        }

        bool success;
        if (LastInviteVerified.IsUpdate)
        {
            success = await Persistence.UpdateVerifiedContactAsync(LastInviteVerified, ct);
            if (success)
            {
                ContactsModifiedAt = DateTime.UtcNow;
                StatusModel.AddSuccess("Contact updated!", ModelID);
            }
            else
            {
                StatusModel.AddError("Failed to update contact.");
            }
        }
        else
        {
            success = await Persistence.SaveVerifiedContactAsync(LastInviteVerified, ct);
            if (success)
            {
                ContactsModifiedAt = DateTime.UtcNow;
                StatusModel.AddSuccess("Contact saved to trusted contacts!", ModelID);
            }
            else
            {
                StatusModel.AddError("Failed to save contact.");
            }
        }
    }

    /// <summary>
    /// Checks if a contact exists by Ed25519 public key.
    /// </summary>
    public Task<bool> ContactExistsAsync(string ed25519PublicKey, CancellationToken ct = default)
    {
        return Persistence.ContactExistsAsync(ed25519PublicKey, ct);
    }
}
