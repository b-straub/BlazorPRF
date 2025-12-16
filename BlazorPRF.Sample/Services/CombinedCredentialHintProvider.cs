using Blazored.LocalStorage;
using BlazorPRF.Persistence.Services;
using BlazorPRF.Shared.Crypto.Formatting;
using BlazorPRF.UI.Services;

namespace BlazorPRF.Sample.Services;

/// <summary>
/// Provides credential hints by checking DB first (authoritative), then LocalStorage (fallback).
///
/// Priority:
/// 1. DB AppSettings (encryption_credential) - the passkey that actually encrypted the data
/// 2. LocalStorage - fallback for new users who registered but haven't encrypted anything yet
/// </summary>
public sealed class CombinedCredentialHintProvider : ICredentialHintProvider
{
    private const string LocalStorageKey = "blazorprf:credentialHint";

    private readonly IEncryptionCredentialService _encryptionCredentialService;
    private readonly ISyncLocalStorageService _localStorage;

    public CombinedCredentialHintProvider(
        IEncryptionCredentialService encryptionCredentialService,
        ISyncLocalStorageService localStorage)
    {
        _encryptionCredentialService = encryptionCredentialService;
        _localStorage = localStorage;
    }

    public async ValueTask<CredentialHint?> GetCredentialHintAsync()
    {
        // 1. Try LocalStorage first - this is the user's most recent passkey
        var localHint = GetFromLocalStorage();

        if (localHint is not null)
        {
            // If LocalStorage has credential but lost the name, try to restore from DB
            if (localHint.Metadata?.Name is null)
            {
                try
                {
                    var dbCredential = await _encryptionCredentialService.GetEncryptionCredentialAsync();
                    if (dbCredential?.CredentialId == localHint.CredentialId && dbCredential?.Name is not null)
                    {
                        // Enrich with name from DB
                        return localHint with { Metadata = new PublicKeyMetadata { Name = dbCredential.Name } };
                    }
                }
                catch
                {
                    // DB not ready - return LocalStorage hint as-is
                }
            }

            return localHint;
        }

        // 2. Fall back to DB (if LocalStorage is empty, e.g., was cleared)
        try
        {
            var dbCredential = await _encryptionCredentialService.GetEncryptionCredentialAsync();
            if (dbCredential is not null && !string.IsNullOrWhiteSpace(dbCredential.CredentialId))
            {
                var metadata = dbCredential.Name is not null
                    ? new PublicKeyMetadata { Name = dbCredential.Name }
                    : null;
                return new CredentialHint(dbCredential.CredentialId, metadata);
            }
        }
        catch
        {
            // DB not ready
        }

        return null;
    }

    public ValueTask SetCredentialHintAsync(string credentialId, PublicKeyMetadata? metadata = null)
    {
        // Store in LocalStorage only - this is just a hint for which passkey to use
        // DB encryption credential is set by TrustedContactService when data is actually encrypted
        var stored = new StoredCredentialHint
        {
            CredentialId = credentialId,
            Name = metadata?.Name,
            Email = metadata?.Email,
            Comment = metadata?.Comment,
            Created = metadata?.Created
        };
        _localStorage.SetItem(LocalStorageKey, stored);
        return ValueTask.CompletedTask;
    }

    public ValueTask ClearCredentialHintAsync()
    {
        // Clear LocalStorage hint only
        // Note: We intentionally do NOT clear the DB encryption credential
        // That records which passkey encrypted the data and should persist
        // for error messages even after sign-out
        _localStorage.RemoveItem(LocalStorageKey);
        return ValueTask.CompletedTask;
    }

    private CredentialHint? GetFromLocalStorage()
    {
        try
        {
            var stored = _localStorage.GetItem<StoredCredentialHint>(LocalStorageKey);
            if (stored is null || string.IsNullOrWhiteSpace(stored.CredentialId))
            {
                return null;
            }

            var metadata = (stored.Name is not null || stored.Email is not null ||
                           stored.Comment is not null || stored.Created is not null)
                ? new PublicKeyMetadata
                {
                    Name = stored.Name,
                    Email = stored.Email,
                    Comment = stored.Comment,
                    Created = stored.Created
                }
                : null;

            return new CredentialHint(stored.CredentialId, metadata);
        }
        catch
        {
            return null;
        }
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
