using System.Text.Json;
using BlazorPRF.Persistence.Data;
using BlazorPRF.Persistence.Data.Models;
using BlazorPRF.Persistence.Json;
using Microsoft.EntityFrameworkCore;

namespace BlazorPRF.Persistence.Services;

/// <summary>
/// Stores encryption credential info in AppSettings.
/// </summary>
public sealed class EncryptionCredentialService : IEncryptionCredentialService
{
    private const string SettingKey = "encryption_credential";

    private readonly IDbContextFactory<PrfDbContext> _dbContextFactory;

    public EncryptionCredentialService(IDbContextFactory<PrfDbContext> dbContextFactory)
    {
        _dbContextFactory = dbContextFactory;
    }

    public async Task<EncryptionCredentialInfo?> GetEncryptionCredentialAsync()
    {
        await using var db = await _dbContextFactory.CreateDbContextAsync();
        var setting = await db.AppSettings.FindAsync(SettingKey);

        if (setting?.Value is null)
        {
            return null;
        }

        try
        {
            return JsonSerializer.Deserialize(setting.Value, PersistenceJsonContext.Default.EncryptionCredentialInfo);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    public async Task SetEncryptionCredentialAsync(string credentialId, string? name = null)
    {
        var info = new EncryptionCredentialInfo(credentialId, name);
        var json = JsonSerializer.Serialize(info, PersistenceJsonContext.Default.EncryptionCredentialInfo);

        await using var db = await _dbContextFactory.CreateDbContextAsync();
        var setting = await db.AppSettings.FindAsync(SettingKey);

        if (setting is null)
        {
            setting = new AppSetting
            {
                Key = SettingKey,
                Value = json,
                UpdatedAt = DateTime.UtcNow
            };
            await db.AppSettings.AddAsync(setting);
        }
        else
        {
            setting.Value = json;
            setting.UpdatedAt = DateTime.UtcNow;
        }

        await db.SaveChangesAsync();
    }

    public async Task ClearEncryptionCredentialAsync()
    {
        await using var db = await _dbContextFactory.CreateDbContextAsync();
        var setting = await db.AppSettings.FindAsync(SettingKey);

        if (setting is not null)
        {
            db.AppSettings.Remove(setting);
            await db.SaveChangesAsync();
        }
    }
}
