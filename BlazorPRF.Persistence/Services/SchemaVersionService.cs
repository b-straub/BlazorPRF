using BlazorPRF.Persistence.Data;
using BlazorPRF.Persistence.Data.Models;
using Microsoft.EntityFrameworkCore;

namespace BlazorPRF.Persistence.Services;

/// <summary>
/// Manages database schema versioning for development safety.
/// </summary>
public sealed class SchemaVersionService : ISchemaVersionService
{
    private const string SchemaVersionKey = "schema_version";

    /// <summary>
    /// Current schema version. Increment this when making schema changes.
    /// </summary>
    /// <remarks>
    /// Version history:
    /// 1 - Initial schema (TrustedContacts, SentInvitations, ReceivedInvitations, AppSettings)
    /// 2 - Added encryption_credential setting for tracking which passkey encrypted data
    /// </remarks>
    public int CurrentSchemaVersion => 2;

    private readonly IDbContextFactory<PrfDbContext> _dbContextFactory;

    public SchemaVersionService(IDbContextFactory<PrfDbContext> dbContextFactory)
    {
        _dbContextFactory = dbContextFactory;
    }

    public async Task<SchemaValidationResult> ValidateAndMigrateAsync()
    {
        await using var db = await _dbContextFactory.CreateDbContextAsync();

        // Check if database exists by trying to access it
        bool dbExists;
        try
        {
            // Try to query AppSettings - if table doesn't exist, DB needs creation
            _ = await db.AppSettings.FirstOrDefaultAsync();
            dbExists = true;
        }
        catch
        {
            dbExists = false;
        }

        if (!dbExists)
        {
            // Create new database
            await db.Database.EnsureCreatedAsync();
            await SetSchemaVersionAsync(db);
            return SchemaValidationResult.CREATED;
        }

        // Check stored schema version
        var storedVersion = await GetStoredSchemaVersionInternalAsync(db);

        if (storedVersion is null)
        {
            // Version not set yet - set it now (existing DB from before versioning)
            await SetSchemaVersionAsync(db);
            return SchemaValidationResult.VALID;
        }

        if (storedVersion == CurrentSchemaVersion)
        {
            return SchemaValidationResult.VALID;
        }

        // Schema mismatch detected
#if DEBUG
        // In Debug mode, delete and recreate the database
        Console.WriteLine($"[SchemaVersionService] Schema mismatch: stored={storedVersion}, current={CurrentSchemaVersion}");
        Console.WriteLine("[SchemaVersionService] Recreating database for development...");

        await db.Database.EnsureDeletedAsync();
        await db.Database.EnsureCreatedAsync();
        await SetSchemaVersionAsync(db);

        Console.WriteLine("[SchemaVersionService] Database recreated successfully.");
        return SchemaValidationResult.RECREATED;
#else
        // In Release mode, log warning but don't modify
        Console.WriteLine($"[SchemaVersionService] WARNING: Schema mismatch detected. Stored: {storedVersion}, Current: {CurrentSchemaVersion}");
        Console.WriteLine("[SchemaVersionService] Consider updating the database or incrementing the schema version.");
        return SchemaValidationResult.Valid;
#endif
    }

    public async Task<int?> GetStoredSchemaVersionAsync()
    {
        await using var db = await _dbContextFactory.CreateDbContextAsync();
        return await GetStoredSchemaVersionInternalAsync(db);
    }

    private static async Task<int?> GetStoredSchemaVersionInternalAsync(PrfDbContext db)
    {
        var setting = await db.AppSettings.FindAsync(SchemaVersionKey);
        if (setting?.Value is not null && int.TryParse(setting.Value, out var version))
        {
            return version;
        }

        return null;
    }

    private async Task SetSchemaVersionAsync(PrfDbContext db)
    {
        var setting = await db.AppSettings.FindAsync(SchemaVersionKey);

        if (setting is null)
        {
            setting = new AppSetting
            {
                Key = SchemaVersionKey,
                Value = CurrentSchemaVersion.ToString(),
                UpdatedAt = DateTime.UtcNow
            };
            await db.AppSettings.AddAsync(setting);
        }
        else
        {
            setting.Value = CurrentSchemaVersion.ToString();
            setting.UpdatedAt = DateTime.UtcNow;
        }

        await db.SaveChangesAsync();
    }
}
