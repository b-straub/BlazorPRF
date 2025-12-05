namespace BlazorPRF.Configuration;

/// <summary>
/// Configuration options for PRF-based encryption.
/// </summary>
public sealed class PrfOptions
{
    /// <summary>
    /// Configuration section name in appsettings.json.
    /// </summary>
    public const string SectionName = "BlazorPRF";

    /// <summary>
    /// Display name of the relying party shown during WebAuthn registration.
    /// </summary>
    public string RpName { get; set; } = "BlazorPRF App";

    /// <summary>
    /// Relying party ID (domain). If null, uses window.location.hostname.
    /// </summary>
    public string? RpId { get; set; }

    /// <summary>
    /// Timeout in milliseconds for WebAuthn operations.
    /// </summary>
    public int TimeoutMs { get; set; } = 60000;

    /// <summary>
    /// Type of authenticator to use.
    /// Platform = built-in biometrics (Touch ID, Windows Hello)
    /// CrossPlatform = USB/NFC security keys (few support PRF)
    /// </summary>
    public AuthenticatorAttachment AuthenticatorAttachment { get; set; } = AuthenticatorAttachment.Platform;
}

/// <summary>
/// Authenticator attachment type.
/// </summary>
public enum AuthenticatorAttachment
{
    /// <summary>
    /// Platform authenticator (Touch ID, Windows Hello, Face ID).
    /// This is the recommended default as most hardware keys don't support PRF.
    /// </summary>
    Platform,

    /// <summary>
    /// Cross-platform authenticator (USB/NFC security keys).
    /// Warning: Very few hardware keys support the PRF extension.
    /// </summary>
    CrossPlatform
}
