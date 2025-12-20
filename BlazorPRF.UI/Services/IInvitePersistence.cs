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
    /// <returns>True if contact was saved successfully.</returns>
    Task<bool> SaveVerifiedContactAsync(InviteVerifiedEventArgs args, CancellationToken ct);

    /// <summary>
    /// Checks if a contact with the given Ed25519 public key already exists.
    /// </summary>
    /// <param name="ed25519PublicKey">The Ed25519 public key to check.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>True if contact exists.</returns>
    Task<bool> ContactExistsAsync(string ed25519PublicKey, CancellationToken ct);

    /// <summary>
    /// Updates an existing verified contact with new data.
    /// </summary>
    /// <param name="args">The verified invite event data.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>True if contact was updated successfully.</returns>
    Task<bool> UpdateVerifiedContactAsync(InviteVerifiedEventArgs args, CancellationToken ct);
}
