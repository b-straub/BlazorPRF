using BlazorPRF.Persistence.Data.Models;

namespace BlazorPRF.Sample.Services;

/// <summary>
/// Result of loading contacts with enhanced error information.
/// </summary>
public sealed record ContactsLoadResult(
    List<(TrustedContact Contact, ContactUserData UserData)> Contacts,
    string? ErrorMessage,
    bool IsDecryptionError);

/// <summary>
/// Service for managing contacts with enhanced error handling and PRF integration.
/// Wraps ITrustedContactService and adds authentication/error context.
/// </summary>
public interface IContactsService
{
    /// <summary>
    /// Load all contacts with enhanced error messages for decryption failures.
    /// </summary>
    /// <param name="ensureAuthAsync">Function to ensure authentication before loading.</param>
    Task<ContactsLoadResult> LoadContactsAsync(Func<Task<bool>> ensureAuthAsync);

    /// <summary>
    /// Delete a contact by ID.
    /// </summary>
    Task<bool> DeleteContactAsync(Guid id);

    /// <summary>
    /// Reset the database (delete and recreate).
    /// </summary>
    Task ResetDatabaseAsync();
}
