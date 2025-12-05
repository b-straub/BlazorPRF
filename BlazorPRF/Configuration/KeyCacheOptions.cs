namespace BlazorPRF.Configuration;

/// <summary>
/// Configuration options for key caching.
/// </summary>
public sealed class KeyCacheOptions
{
    /// <summary>
    /// Configuration section name in appsettings.json.
    /// </summary>
    public const string SectionName = "BlazorPRF:KeyCache";

    /// <summary>
    /// Key caching strategy.
    /// </summary>
    public KeyCacheStrategy Strategy { get; set; } = KeyCacheStrategy.Timed;

    /// <summary>
    /// Time-to-live in minutes for cached keys (only used with Timed strategy).
    /// </summary>
    public int TtlMinutes { get; set; } = 15;
}

/// <summary>
/// Key caching strategy.
/// </summary>
public enum KeyCacheStrategy
{
    /// <summary>
    /// No caching - keys are derived fresh for each operation.
    /// Most secure but requires user interaction each time.
    /// </summary>
    None,

    /// <summary>
    /// Session caching - keys are cached until page refresh.
    /// Balance between security and usability.
    /// </summary>
    Session,

    /// <summary>
    /// Timed caching - keys expire after TTL.
    /// Recommended for most applications.
    /// </summary>
    Timed
}
