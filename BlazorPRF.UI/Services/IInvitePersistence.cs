using BlazorPRF.UI.Models;

namespace BlazorPRF.UI.Services;

/// <summary>
/// Interface for persisting invitation events.
/// Implemented by the application to provide storage-specific logic.
/// </summary>
public interface IInvitePersistence
{
    /// <summary>
    /// Called when a new invite is created.
    /// </summary>
    /// <param name="args">The invite creation event data.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>True if saved successfully.</returns>
    Task<bool> SaveCreatedInviteAsync(InviteCreatedEventArgs args, CancellationToken ct);

    /// <summary>
    /// Called when an invite is accepted (signed by accepter).
    /// </summary>
    /// <param name="args">The invite acceptance event data.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>True if saved successfully.</returns>
    Task<bool> SaveAcceptedInviteAsync(InviteAcceptedEventArgs args, CancellationToken ct);

    /// <summary>
    /// Called when signatures are verified and a trusted contact should be created.
    /// </summary>
    /// <param name="args">The verified invite event data.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>True if contact was saved successfully, false if contact already exists or save failed.</returns>
    Task<bool> SaveVerifiedContactAsync(InviteVerifiedEventArgs args, CancellationToken ct);
}
