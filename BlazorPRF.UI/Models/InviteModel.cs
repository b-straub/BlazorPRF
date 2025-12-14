using BlazorPRF.UI.Services;
using RxBlazorV2.Model;

namespace BlazorPRF.UI.Models;

/// <summary>
/// Severity levels for status messages.
/// </summary>
public enum StatusSeverity
{
    Info,
    Success,
    Warning,
    Error
}

/// <summary>
/// Status message with severity for reactive UI display.
/// </summary>
public sealed record StatusMessage(string Message, StatusSeverity Severity);

/// <summary>
/// Reactive model for invitation events.
/// InviteService observes property changes via [ObservableModelObserver] and
/// delegates persistence to the app-provided IInvitePersistence implementation.
/// </summary>
[ObservableModelScope(ModelScope.Singleton)]
[ObservableComponent]
public partial class InviteModel : ObservableModel
{
    /// <summary>
    /// Service injection - generator auto-subscribes [ObservableModelObserver] methods.
    /// </summary>
    public partial InviteModel(InviteService inviteService);

    /// <summary>
    /// Latest invite creation event. Set when an invite is created.
    /// Observed by InviteService.HandleInviteCreatedAsync.
    /// </summary>
    public partial InviteCreatedEventArgs? LastInviteCreated { get; set; }

    /// <summary>
    /// Latest invite acceptance event. Set when an invite is accepted (signed).
    /// Observed by InviteService.HandleInviteAcceptedAsync.
    /// </summary>
    public partial InviteAcceptedEventArgs? LastInviteAccepted { get; set; }

    /// <summary>
    /// Latest invite verification event. Set when signatures are verified.
    /// Observed by InviteService.HandleInviteVerifiedAsync.
    /// </summary>
    public partial InviteVerifiedEventArgs? LastInviteVerified { get; set; }

    /// <summary>
    /// Status message for UI display. Components can react via OnStatusChanged().
    /// </summary>
    [ObservableComponentTrigger]
    public partial StatusMessage? Status { get; set; }

    /// <summary>
    /// Helper method to set status message.
    /// </summary>
    public void SetStatus(string message, StatusSeverity severity)
    {
        Status = new StatusMessage(message, severity);
    }
}
