namespace BlazorPRF.Persistence.Data.Models;

/// <summary>
/// User profile data stored in encrypted form.
/// Contains personal information and future email configuration.
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

    // Future SMTP configuration

    /// <summary>
    /// SMTP server hostname (future feature).
    /// </summary>
    public string? SmtpHost { get; set; }

    /// <summary>
    /// SMTP server port (future feature).
    /// </summary>
    public int? SmtpPort { get; set; }

    /// <summary>
    /// SMTP authentication username (future feature).
    /// </summary>
    public string? SmtpUsername { get; set; }

    // Future IMAP configuration

    /// <summary>
    /// IMAP server hostname (future feature).
    /// </summary>
    public string? ImapHost { get; set; }

    /// <summary>
    /// IMAP server port (future feature).
    /// </summary>
    public int? ImapPort { get; set; }

    /// <summary>
    /// IMAP authentication username (future feature).
    /// </summary>
    public string? ImapUsername { get; set; }
}
