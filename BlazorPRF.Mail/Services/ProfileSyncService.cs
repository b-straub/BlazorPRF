using System.Text.Json;
using BlazorPRF.Api.Services;
using BlazorPRF.Persistence.Data;
using BlazorPRF.Persistence.Data.Models;
using BlazorPRF.Crypto.Services;
using Microsoft.EntityFrameworkCore;

namespace BlazorPRF.Mail.Services;

/// <summary>
/// Synchronizes encrypted user profile between local SQLite and the mail relay server.
/// </summary>
public sealed class ProfileSyncService(
    ISigningContextProvider signingContextProvider,
    ISignedApiClient signedApiClient,
    IDbContextFactory<PrfDbContext> dbContextFactory) : IProfileSyncService
{
    public async Task<(bool Success, string? Message)> SyncToServerAsync()
    {
        var localProfile = await GetLocalEncryptedProfileAsync();
        if (string.IsNullOrWhiteSpace(localProfile))
        {
            return (true, null);
        }

        var body = JsonSerializer.Serialize(new { encryptedProfile = localProfile });
        var context = signingContextProvider.CreateSigningContext();
        var result = await signedApiClient.SendUserSignedAsync("profile", body, "POST", context);

        if (result is { Success: true, Value: not null } && result.Value.Contains("true"))
        {
            return (true, "Profile synced to server");
        }

        return (false, $"Profile sync failed: {result.Error ?? result.Value ?? "unknown"}");
    }

    public async Task<bool> SyncFromServerAsync()
    {
        try
        {
            var context = signingContextProvider.CreateSigningContext();
            var result = await signedApiClient.SendUserSignedAsync("profile", "", "GET", context);

            if (!result.Success || result.Value is null)
            {
                return false;
            }

            var doc = JsonDocument.Parse(result.Value);
            if (!doc.RootElement.TryGetProperty("profile", out var profileProp) ||
                profileProp.ValueKind == JsonValueKind.Null)
            {
                return false;
            }

            if (!profileProp.TryGetProperty("encryptedProfile", out var encryptedProp))
            {
                return false;
            }

            var encryptedProfile = encryptedProp.GetString();
            if (string.IsNullOrEmpty(encryptedProfile))
            {
                return false;
            }

            await SaveLocalEncryptedProfileAsync(encryptedProfile);
            return true;
        }
        catch
        {
            // Sync failure is non-critical
            return false;
        }
    }

    private async Task<string?> GetLocalEncryptedProfileAsync()
    {
        await using var db = await dbContextFactory.CreateDbContextAsync();
        var profile = await db.UserProfiles.SingleOrDefaultAsync();
        return profile?.EncryptedData;
    }

    private async Task SaveLocalEncryptedProfileAsync(string encryptedData)
    {
        await using var db = await dbContextFactory.CreateDbContextAsync();
        var existing = await db.UserProfiles.SingleOrDefaultAsync();

        if (existing is null)
        {
            var profile = new UserProfile
            {
                Id = Guid.NewGuid(),
                EncryptedData = encryptedData,
                UpdatedAt = DateTime.UtcNow
            };
            await db.UserProfiles.AddAsync(profile);
        }
        else
        {
            existing.EncryptedData = encryptedData;
            existing.UpdatedAt = DateTime.UtcNow;
        }

        await db.SaveChangesAsync();
    }
}
