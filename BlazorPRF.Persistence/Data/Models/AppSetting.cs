namespace BlazorPRF.Persistence.Data.Models;

/// <summary>
/// Key-value storage for application settings.
/// Stored in plaintext (not sensitive data).
/// </summary>
public sealed class AppSetting
{
    /// <summary>
    /// Setting key (primary key).
    /// </summary>
    public required string Key { get; set; }

    /// <summary>
    /// Setting value (JSON serialized for complex types).
    /// </summary>
    public required string Value { get; set; }

    /// <summary>
    /// When the setting was last updated.
    /// </summary>
    public DateTime UpdatedAt { get; set; }
}
