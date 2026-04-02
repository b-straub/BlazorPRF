using System.ComponentModel.DataAnnotations;

namespace BlazorPRF.Persistence.Data.Models;

/// <summary>
/// User profile data stored in encrypted form.
/// Contains personal information and email server configuration.
/// Validation attributes drive MudForm validation in the UI.
/// </summary>
public sealed class UserProfileData
{
    [Required(ErrorMessage = "Display name is required")]
    public string Username { get; set; } = string.Empty;

    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Invalid email address")]
    public string Email { get; set; } = string.Empty;

    [Required(ErrorMessage = "Mail relay URL is required")]
    [Url(ErrorMessage = "Invalid URL")]
    public string? MailRelayUrl { get; set; }

    [Required(ErrorMessage = "SMTP host is required")]
    public string? SmtpHost { get; set; }

    [Required(ErrorMessage = "SMTP port is required")]
    [Range(1, 65535, ErrorMessage = "Port must be between 1 and 65535")]
    public int? SmtpPort { get; set; } = 587;

    [Required(ErrorMessage = "SMTP username is required")]
    public string? SmtpUsername { get; set; }

    [Required(ErrorMessage = "SMTP password is required")]
    public string? SmtpPassword { get; set; }

    [Required(ErrorMessage = "IMAP host is required")]
    public string? ImapHost { get; set; }

    [Required(ErrorMessage = "IMAP port is required")]
    [Range(1, 65535, ErrorMessage = "Port must be between 1 and 65535")]
    public int? ImapPort { get; set; } = 993;

    [Required(ErrorMessage = "IMAP username is required")]
    public string? ImapUsername { get; set; }

    [Required(ErrorMessage = "IMAP password is required")]
    public string? ImapPassword { get; set; }
}
