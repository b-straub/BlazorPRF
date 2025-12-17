using BlazorPRF.Persistence.Data;
using BlazorPRF.Persistence.Data.Models;
using BlazorPRF.Persistence.Services;
using BlazorPRF.Shared.Crypto.Models;
using BlazorPRF.UI.Services;
using Microsoft.EntityFrameworkCore;
using SqliteWasmBlazor;

namespace BlazorPRF.Sample.Services;

/// <summary>
/// Service for managing contacts with enhanced error handling and PRF integration.
/// </summary>
public sealed class ContactsService : IContactsService
{
    private readonly ITrustedContactService _contactService;
    private readonly ICredentialHintProvider _credentialHintProvider;
    private readonly IEncryptionCredentialService _encryptionCredentialService;
    private readonly IDbContextFactory<PrfDbContext> _dbContextFactory;

    public ContactsService(
        ITrustedContactService contactService,
        ICredentialHintProvider credentialHintProvider,
        IEncryptionCredentialService encryptionCredentialService,
        IDbContextFactory<PrfDbContext> dbContextFactory)
    {
        _contactService = contactService;
        _credentialHintProvider = credentialHintProvider;
        _encryptionCredentialService = encryptionCredentialService;
        _dbContextFactory = dbContextFactory;
    }

    public async Task<ContactsLoadResult> LoadContactsAsync(Func<Task<bool>> ensureAuthAsync)
    {
        // Ensure user is authenticated to decrypt contact data
        if (!await ensureAuthAsync())
        {
            return new ContactsLoadResult(
                [],
                "Authentication required to view contacts. Please authenticate first.",
                false);
        }

        var result = await _contactService.GetAllAsync();

        if (result is { Success: true, Value: not null })
        {
            return new ContactsLoadResult(result.Value, null, false);
        }

        var isDecryptionError = result.ErrorCode == PrfErrorCode.DECRYPTION_FAILED;
        var errorMessage = await GetEnhancedErrorMessageAsync(result, isDecryptionError);

        return new ContactsLoadResult([], errorMessage, isDecryptionError);
    }

    public Task<bool> DeleteContactAsync(Guid id)
    {
        return _contactService.DeleteAsync(id);
    }

    public async Task ResetDatabaseAsync()
    {
        // Delete the database file from OPFS SAHPool
        await SqliteWasmWorkerBridge.Instance.DeleteDatabaseAsync("BlazorPrf.db");

        // Recreate database schema
        await using var context = await _dbContextFactory.CreateDbContextAsync();
        await context.Database.EnsureCreatedAsync();
    }

    private async Task<string> GetEnhancedErrorMessageAsync(
        PrfResult<List<(TrustedContact Contact, ContactUserData UserData)>> result,
        bool isDecryptionError)
    {
        // If decryption failed, try to provide more context
        if (isDecryptionError)
        {
            var currentHint = await _credentialHintProvider.GetCredentialHintAsync();
            var encryptingCredential = await _encryptionCredentialService.GetEncryptionCredentialAsync();

            var currentPasskeyName = currentHint?.Metadata?.Name;
            var encryptingPasskeyName = encryptingCredential?.Name;

            // Build detailed error message
            if (currentPasskeyName is not null && encryptingPasskeyName is not null)
            {
                return $"Decryption failed. You are signed in with passkey '{currentPasskeyName}', " +
                       $"but your data was encrypted with passkey '{encryptingPasskeyName}'.";
            }

            if (currentPasskeyName is not null)
            {
                return $"Decryption failed. You are signed in with passkey '{currentPasskeyName}', " +
                       "but your data was encrypted with a different passkey.";
            }

            if (encryptingPasskeyName is not null)
            {
                return $"Decryption failed. Your data was encrypted with passkey '{encryptingPasskeyName}', " +
                       "but you are signed in with a different passkey.";
            }

            return "Decryption failed. You may be signed in with a different passkey than " +
                   "the one used to encrypt your data.";
        }

        return result.Error ?? "Failed to load contacts. Please try again.";
    }
}
