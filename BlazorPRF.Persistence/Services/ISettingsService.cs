namespace BlazorPRF.Persistence.Services;

/// <summary>
/// Service for managing application settings (key-value storage).
/// Settings are stored in plaintext (not sensitive data).
/// </summary>
public interface ISettingsService
{
    /// <summary>
    /// Get a setting value by key.
    /// </summary>
    /// <typeparam name="T">Type to deserialize to</typeparam>
    /// <param name="key">Setting key</param>
    /// <param name="defaultValue">Default value if not found</param>
    Task<T?> GetAsync<T>(string key, T? defaultValue = default);

    /// <summary>
    /// Get a string setting value by key.
    /// </summary>
    Task<string?> GetStringAsync(string key);

    /// <summary>
    /// Set a setting value.
    /// </summary>
    /// <typeparam name="T">Type of value</typeparam>
    /// <param name="key">Setting key</param>
    /// <param name="value">Value to store (will be JSON serialized)</param>
    Task SetAsync<T>(string key, T value);

    /// <summary>
    /// Set a string setting value.
    /// </summary>
    Task SetStringAsync(string key, string value);

    /// <summary>
    /// Delete a setting.
    /// </summary>
    Task<bool> DeleteAsync(string key);

    /// <summary>
    /// Check if a setting exists.
    /// </summary>
    Task<bool> ExistsAsync(string key);

    /// <summary>
    /// Get all settings.
    /// </summary>
    Task<Dictionary<string, string>> GetAllAsync();
}
