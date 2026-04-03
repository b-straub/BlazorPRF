namespace BlazorPRF.UI.Services;

/// <summary>
/// Synchronizes encrypted user profile between local storage and server.
/// </summary>
public interface IProfileSyncService
{
    /// <summary>
    /// Push local encrypted profile to server.
    /// Returns success/failure message, or null if no profile to sync.
    /// </summary>
    Task<(bool Success, string? Message)> SyncToServerAsync();

    /// <summary>
    /// Pull encrypted profile from server and save locally.
    /// Returns true if a profile was restored.
    /// </summary>
    Task<bool> SyncFromServerAsync();
}
