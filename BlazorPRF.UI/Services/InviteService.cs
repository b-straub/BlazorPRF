using BlazorPRF.UI.Models;
using RxBlazorV2.Model;

namespace BlazorPRF.UI.Services;

/// <summary>
/// Service that observes InviteModel property changes and delegates persistence
/// to the application-provided IInvitePersistence implementation.
/// Uses [ObservableModelObserver] pattern for reactive event handling.
/// </summary>
public sealed class InviteService
{
    private readonly IInvitePersistence _persistence;

    public InviteService(IInvitePersistence persistence)
    {
        _persistence = persistence;
    }

    /// <summary>
    /// Handles invite creation events. Called automatically when LastInviteCreated changes.
    /// </summary>
    [ObservableModelObserver(nameof(InviteModel.LastInviteCreated))]
    public async Task HandleInviteCreatedAsync(InviteModel model, CancellationToken ct)
    {
        if (model.LastInviteCreated is null)
        {
            return;
        }

        var success = await _persistence.SaveCreatedInviteAsync(model.LastInviteCreated, ct);
        model.SetStatus(
            success ? "Invitation saved" : "Failed to save invitation",
            success ? StatusSeverity.Info : StatusSeverity.Error);
    }

    /// <summary>
    /// Handles invite acceptance events. Called automatically when LastInviteAccepted changes.
    /// </summary>
    [ObservableModelObserver(nameof(InviteModel.LastInviteAccepted))]
    public async Task HandleInviteAcceptedAsync(InviteModel model, CancellationToken ct)
    {
        if (model.LastInviteAccepted is null)
        {
            return;
        }

        var success = await _persistence.SaveAcceptedInviteAsync(model.LastInviteAccepted, ct);
        model.SetStatus(
            success ? "Acceptance recorded" : "Failed to record acceptance",
            success ? StatusSeverity.Info : StatusSeverity.Error);
    }

    /// <summary>
    /// Handles verified invite events. Called automatically when LastInviteVerified changes.
    /// </summary>
    [ObservableModelObserver(nameof(InviteModel.LastInviteVerified))]
    public async Task HandleInviteVerifiedAsync(InviteModel model, CancellationToken ct)
    {
        if (model.LastInviteVerified is null)
        {
            return;
        }

        var success = await _persistence.SaveVerifiedContactAsync(model.LastInviteVerified, ct);

        if (success)
        {
            model.SetStatus("Contact saved to trusted contacts!", StatusSeverity.Success);
        }
        else
        {
            // Could be duplicate or actual failure - persistence decides the message
            model.SetStatus("Contact already exists or save failed", StatusSeverity.Warning);
        }
    }
}
