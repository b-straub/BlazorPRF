using System.Text.Json;
using BlazorPRF.Persistence.Data;
using BlazorPRF.Persistence.Data.Models;
using Microsoft.EntityFrameworkCore;

namespace BlazorPRF.Persistence.Services;

/// <summary>
/// Service for managing application settings (key-value storage).
/// Settings are stored in plaintext (not sensitive data).
/// </summary>
public sealed class SettingsService : ISettingsService
{
    private readonly IDbContextFactory<PrfDbContext> _dbContextFactory;

    public SettingsService(IDbContextFactory<PrfDbContext> dbContextFactory)
    {
        _dbContextFactory = dbContextFactory;
    }

    /// <inheritdoc />
    public async Task<T?> GetAsync<T>(string key, T? defaultValue = default)
    {
        var value = await GetStringAsync(key);

        if (value is null)
        {
            return defaultValue;
        }

        try
        {
            return JsonSerializer.Deserialize<T>(value);
        }
        catch (JsonException)
        {
            return defaultValue;
        }
    }

    /// <inheritdoc />
    public async Task<string?> GetStringAsync(string key)
    {
        await using var db = await _dbContextFactory.CreateDbContextAsync();
        var setting = await db.AppSettings.FindAsync(key);
        return setting?.Value;
    }

    /// <inheritdoc />
    public async Task SetAsync<T>(string key, T value)
    {
        var json = JsonSerializer.Serialize(value);
        await SetStringAsync(key, json);
    }

    /// <inheritdoc />
    public async Task SetStringAsync(string key, string value)
    {
        await using var db = await _dbContextFactory.CreateDbContextAsync();
        var setting = await db.AppSettings.FindAsync(key);

        if (setting is null)
        {
            setting = new AppSetting
            {
                Key = key,
                Value = value,
                UpdatedAt = DateTime.UtcNow
            };
            await db.AppSettings.AddAsync(setting);
        }
        else
        {
            setting.Value = value;
            setting.UpdatedAt = DateTime.UtcNow;
        }

        await db.SaveChangesAsync();
    }

    /// <inheritdoc />
    public async Task<bool> DeleteAsync(string key)
    {
        await using var db = await _dbContextFactory.CreateDbContextAsync();
        var setting = await db.AppSettings.FindAsync(key);

        if (setting is null)
        {
            return false;
        }

        db.AppSettings.Remove(setting);
        await db.SaveChangesAsync();

        return true;
    }

    /// <inheritdoc />
    public async Task<bool> ExistsAsync(string key)
    {
        await using var db = await _dbContextFactory.CreateDbContextAsync();
        return await db.AppSettings.AnyAsync(s => s.Key == key);
    }

    /// <inheritdoc />
    public async Task<Dictionary<string, string>> GetAllAsync()
    {
        await using var db = await _dbContextFactory.CreateDbContextAsync();
        return await db.AppSettings
            .ToDictionaryAsync(s => s.Key, s => s.Value);
    }
}
