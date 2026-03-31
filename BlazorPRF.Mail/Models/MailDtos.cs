namespace BlazorPRF.Mail.Models;

/// <summary>
/// IMAP mailbox information.
/// </summary>
public sealed record ImapMailboxInfo
{
    public int Messages { get; init; }
    public int Recent { get; init; }
    public int Unseen { get; init; }
}

/// <summary>
/// IMAP email message.
/// </summary>
public sealed class ImapEmail
{
    public int Uid { get; init; }
    public string Subject { get; init; } = "";
    public string From { get; init; } = "";
    public string Date { get; init; } = "";
    public bool Seen { get; init; }
    public bool Flagged { get; init; }
    public string? Body { get; set; }
    public string? BodyHtml { get; set; }
    public bool HasPfaArmor { get; set; }
    public bool HasInviteArmor { get; set; }
    public bool HasResponseArmor { get; set; }
}

/// <summary>
/// Request to send an email via SMTP.
/// </summary>
public sealed record SendMailRequest(
    string To,
    string Subject,
    string Body);

/// <summary>
/// SMTP connection test result.
/// </summary>
public sealed record SmtpTestResult(
    bool Success,
    string? Error);

/// <summary>
/// IMAP connection test result.
/// </summary>
public sealed record ImapTestResult(
    bool Success,
    ImapMailboxInfo? Mailbox,
    string? Error);

/// <summary>
/// Response from IMAP fetch operation.
/// </summary>
public sealed record ImapFetchResponse(
    List<ImapEmail> Emails,
    int TotalMatched,
    ImapMailboxInfo? Mailbox);
