namespace BlazorPRF.Persistence.Services;

/// <summary>
/// Result of schema validation.
/// </summary>
public enum SchemaValidationResult
{
    /// <summary>
    /// Schema version matches - database is ready.
    /// </summary>
    VALID,

    /// <summary>
    /// New database created with current schema version.
    /// </summary>
    CREATED,

    /// <summary>
    /// Schema mismatch detected and database was recreated (Debug mode).
    /// </summary>
    RECREATED,

    /// <summary>
    /// Schema mismatch detected but not modified (Release mode).
    /// </summary>
    MISMATCH
}

/// <summary>
/// Service to manage database schema versioning.
/// Used during development to detect schema changes and handle migration.
/// </summary>
public interface ISchemaVersionService
{
    /// <summary>
    /// Current schema version expected by the application.
    /// Increment this when making schema changes during development.
    /// </summary>
    int CurrentSchemaVersion { get; }

    /// <summary>
    /// Validates the schema version and handles migration.
    /// In Debug mode, recreates the database if schema mismatch is detected.
    /// In Release mode, logs a warning but does not modify the database.
    /// </summary>
    /// <returns>The validation result indicating what action was taken.</returns>
    Task<SchemaValidationResult> ValidateAndMigrateAsync();

    /// <summary>
    /// Gets the stored schema version from the database.
    /// </summary>
    /// <returns>The stored version, or null if not set.</returns>
    Task<int?> GetStoredSchemaVersionAsync();
}
