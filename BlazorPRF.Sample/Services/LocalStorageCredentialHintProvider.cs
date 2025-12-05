using Blazored.LocalStorage;
using BlazorPRF.Shared.Formatting;
using BlazorPRF.UI.Services;

namespace BlazorPRF.Sample.Services;

/// <summary>
/// Provides credential ID hints using browser LocalStorage.
/// Uses ISyncLocalStorageService to avoid scoped/singleton lifetime conflicts.
/// </summary>
public sealed class LocalStorageCredentialHintProvider(ISyncLocalStorageService localStorage) : ICredentialHintProvider
{
    private const string StorageKey = "blazorprf:credentialHint";

    public ValueTask<CredentialHint?> GetCredentialHintAsync()
    {
        var stored = localStorage.GetItem<StoredCredentialHint>(StorageKey);
        if (stored is null || string.IsNullOrWhiteSpace(stored.CredentialId))
        {
            return ValueTask.FromResult<CredentialHint?>(null);
        }

        var metadata = (stored.Name is not null || stored.Email is not null || stored.Comment is not null || stored.Created is not null)
            ? new PublicKeyMetadata
            {
                Name = stored.Name,
                Email = stored.Email,
                Comment = stored.Comment,
                Created = stored.Created
            }
            : null;

        return ValueTask.FromResult<CredentialHint?>(new CredentialHint(stored.CredentialId, metadata));
    }

    public ValueTask SetCredentialHintAsync(string credentialId, PublicKeyMetadata? metadata = null)
    {
        var stored = new StoredCredentialHint
        {
            CredentialId = credentialId,
            Name = metadata?.Name,
            Email = metadata?.Email,
            Comment = metadata?.Comment,
            Created = metadata?.Created
        };
        localStorage.SetItem(StorageKey, stored);
        return ValueTask.CompletedTask;
    }

    public ValueTask ClearCredentialHintAsync()
    {
        localStorage.RemoveItem(StorageKey);
        return ValueTask.CompletedTask;
    }

    /// <summary>
    /// Internal storage format for LocalStorage serialization.
    /// </summary>
    private sealed class StoredCredentialHint
    {
        public string? CredentialId { get; init; }
        public string? Name { get; init; }
        public string? Email { get; init; }
        public string? Comment { get; init; }
        public DateOnly? Created { get; init; }
    }
}
