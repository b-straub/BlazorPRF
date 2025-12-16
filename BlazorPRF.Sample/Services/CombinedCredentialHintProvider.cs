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
        // 1. Try DB first - this is the authoritative source (the passkey that encrypted the data)
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
            // DB not ready or error - fall through to LocalStorage
        }

        // 2. Fall back to LocalStorage (for new users who haven't encrypted anything yet)
        return GetFromLocalStorage();
    }

    public async ValueTask SetCredentialHintAsync(string credentialId, PublicKeyMetadata? metadata = null)
    {
        // Store in LocalStorage for immediate availability
        // DB storage happens automatically when first data is encrypted (via TrustedContactService)
        var stored = new StoredCredentialHint
        {
            CredentialId = credentialId,
            Name = metadata?.Name,
            Email = metadata?.Email,
            Comment = metadata?.Comment,
            Created = metadata?.Created
        };
        _localStorage.SetItem(LocalStorageKey, stored);

        // Also update DB if it already has a credential stored (keeps them in sync)
        try
        {
            var existing = await _encryptionCredentialService.GetEncryptionCredentialAsync();
            if (existing is not null)
            {
                await _encryptionCredentialService.SetEncryptionCredentialAsync(credentialId, metadata?.Name);
            }
        }
        catch
        {
            // DB not ready - LocalStorage is sufficient for now
        }
    }

    public async ValueTask ClearCredentialHintAsync()
    {
        _localStorage.RemoveItem(LocalStorageKey);

        // Note: We intentionally do NOT clear the DB encryption credential
        // That records which passkey encrypted the data and should persist
        // for error messages even after sign-out
        await ValueTask.CompletedTask;
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
