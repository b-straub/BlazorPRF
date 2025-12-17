using BlazorPRF.UI.Services;
using RxBlazorV2.Interface;
using RxBlazorV2.Model;
using System.Diagnostics.CodeAnalysis;

namespace BlazorPRF.UI.Models;

/// <summary>
/// Severity levels for status messages.
/// </summary>
public enum StatusSeverity
{
    INFO,
    SUCCESS,
    WARNING,
    ERROR
}

/// <summary>
/// Status message with severity for reactive UI display.
/// </summary>
public sealed record StatusMessage(string Message, StatusSeverity Severity);

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
    public partial InviteModel(IInvitePersistence persistence);

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
    /// Status message for UI display. Components can react via OnStatusChanged().
    /// Other models observe this to react to completion (e.g., ContactsModel reloads on SUCCESS).
    /// </summary>
    [ObservableComponentTrigger]
    public partial StatusMessage? Status { get; set; }

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
        Status = new StatusMessage(
            success ? "Invitation saved" : "Failed to save invitation",
            success ? StatusSeverity.INFO : StatusSeverity.ERROR);
    }

    private async Task ProcessAcceptanceAsync(CancellationToken ct)
    {
        if (LastInviteAccepted is null)
        {
            return;
        }

        var success = await Persistence.SaveAcceptedInviteAsync(LastInviteAccepted, ct);
        Status = new StatusMessage(
            success ? "Acceptance recorded" : "Failed to record acceptance",
            success ? StatusSeverity.INFO : StatusSeverity.ERROR);
    }

    private async Task ProcessVerificationAsync(CancellationToken ct)
    {
        if (LastInviteVerified is null)
        {
            return;
        }

        var success = await Persistence.SaveVerifiedContactAsync(LastInviteVerified, ct);
        Status = success
            ? new StatusMessage("Contact saved to trusted contacts!", StatusSeverity.SUCCESS)
            : new StatusMessage("Contact already exists or save failed", StatusSeverity.WARNING);
    }
}
