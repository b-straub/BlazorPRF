using System.Text.Json;
using System.Text.Json.Serialization;
using BlazorPRF.Mail.Models;

namespace BlazorPRF.Mail.Json;

/// <summary>
/// Source-generated JSON serializer context for Mail models.
/// Uses camelCase naming (JsonSerializerDefaults.Web) for PHP backend compatibility.
/// </summary>
[JsonSourceGenerationOptions(JsonSerializerDefaults.Web)]
[JsonSerializable(typeof(ImapMailboxInfo))]
[JsonSerializable(typeof(ImapEmail))]
[JsonSerializable(typeof(List<ImapEmail>))]
[JsonSerializable(typeof(SendMailRequest))]
[JsonSerializable(typeof(SmtpTestResult))]
[JsonSerializable(typeof(ImapTestResult))]
[JsonSerializable(typeof(ImapFetchResponse))]
[JsonSerializable(typeof(ImapApiRequest))]
[JsonSerializable(typeof(SmtpApiRequest))]
[JsonSerializable(typeof(SendMailApiRequest))]
public partial class MailJsonContext : JsonSerializerContext;

/// <summary>
/// Request to PHP IMAP test endpoint.
/// </summary>
public sealed record ImapApiRequest(
    string ImapHost,
    int ImapPort,
    string ImapUsername,
    string ImapPassword,
    string Filter = "new",
    string MessageType = "all",
    int? Uid = null,
    int Limit = 10,
    bool FetchBody = false);

/// <summary>
/// Request to PHP SMTP test endpoint.
/// </summary>
public sealed record SmtpApiRequest(
    string SmtpHost,
    int SmtpPort,
    string SmtpUsername,
    string SmtpPassword);

/// <summary>
/// Request to PHP send mail endpoint.
/// </summary>
public sealed record SendMailApiRequest(
    string SmtpHost,
    int SmtpPort,
    string SmtpUsername,
    string SmtpPassword,
    string FromName,
    string FromEmail,
    string To,
    string Subject,
    string Body);
