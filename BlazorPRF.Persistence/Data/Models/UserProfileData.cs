namespace BlazorPRF.Persistence.Data.Models;

/// <summary>
/// User profile data stored in encrypted form.
/// Contains personal information and email server configuration.
/// </summary>
public sealed class UserProfileData
{
    /// <summary>
    /// User's display name.
    /// </summary>
    public string Username { get; set; } = string.Empty;

    /// <summary>
    /// User's email address.
    /// </summary>
    public string Email { get; set; } = string.Empty;

    // Mail relay configuration

    /// <summary>
    /// Mail relay API URL (e.g., https://prf.test/api/).
    /// When null, uses the app's base address.
    /// </summary>
    public string? MailRelayUrl { get; set; }

    // SMTP configuration

    /// <summary>
    /// SMTP server hostname.
    /// </summary>
    public string? SmtpHost { get; set; }

    /// <summary>
    /// SMTP server port (default: 587 for TLS).
    /// </summary>
    public int? SmtpPort { get; set; }

    /// <summary>
    /// SMTP authentication username.
    /// </summary>
    public string? SmtpUsername { get; set; }

    /// <summary>
    /// SMTP authentication password.
    /// Stored encrypted with PRF-derived key.
    /// </summary>
    public string? SmtpPassword { get; set; }

    // IMAP configuration

    /// <summary>
    /// IMAP server hostname.
    /// </summary>
    public string? ImapHost { get; set; }

    /// <summary>
    /// IMAP server port (default: 993 for SSL).
    /// </summary>
    public int? ImapPort { get; set; }

    /// <summary>
    /// IMAP authentication username.
    /// </summary>
    public string? ImapUsername { get; set; }

    /// <summary>
    /// IMAP authentication password.
    /// Stored encrypted with PRF-derived key.
    /// </summary>
    public string? ImapPassword { get; set; }
}
