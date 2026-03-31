using System.Text.Json;
using BlazorPRF.Api.Models;
using BlazorPRF.Api.Services;
using BlazorPRF.Mail.Json;
using BlazorPRF.Mail.Models;
using BlazorPRF.Persistence.Data.Models;

namespace BlazorPRF.Mail.Services;

/// <summary>
/// Service for mail operations via PRF-authenticated backend.
/// </summary>
public sealed class MailService : IMailService
{
    private readonly ISignedApiClient _client;

    public MailService(ISignedApiClient client)
    {
        _client = client;
    }

    /// <inheritdoc />
    public async Task<ApiResult<SmtpTestResult>> TestSmtpAsync(
        UserProfileData profile,
        SigningContext context)
    {
        var request = new SmtpApiRequest(
            profile.SmtpHost ?? "",
            profile.SmtpPort ?? 587,
            profile.SmtpUsername ?? "",
            profile.SmtpPassword ?? "");

        var body = JsonSerializer.Serialize(request, MailJsonContext.Default.SmtpApiRequest);
        var result = await _client.SendUserSignedAsync("test_smtp", body, "POST", context);

        if (!result.Success || result.Value is null)
        {
            return ApiResult<SmtpTestResult>.Failure(result.Error ?? "Request failed");
        }

        try
        {
            using var doc = JsonDocument.Parse(result.Value);
            var success = doc.RootElement.TryGetProperty("success", out var s) && s.GetBoolean();
            var error = doc.RootElement.TryGetProperty("error", out var e) ? e.GetString() : null;

            return ApiResult<SmtpTestResult>.Ok(new SmtpTestResult(success, error));
        }
        catch (JsonException ex)
        {
            return ApiResult<SmtpTestResult>.Failure($"Failed to parse response: {ex.Message}");
        }
    }

    /// <inheritdoc />
    public async Task<ApiResult<ImapTestResult>> TestImapAsync(
        UserProfileData profile,
        SigningContext context)
    {
        var request = new ImapApiRequest(
            profile.ImapHost ?? "",
            profile.ImapPort ?? 993,
            profile.ImapUsername ?? "",
            profile.ImapPassword ?? "",
            Filter: "test");

        var body = JsonSerializer.Serialize(request, MailJsonContext.Default.ImapApiRequest);
        var result = await _client.SendUserSignedAsync("test_imap", body, "POST", context);

        if (!result.Success || result.Value is null)
        {
            return ApiResult<ImapTestResult>.Failure(result.Error ?? "Request failed");
        }

        try
        {
            using var doc = JsonDocument.Parse(result.Value);
            var success = doc.RootElement.TryGetProperty("success", out var s) && s.GetBoolean();

            if (success && doc.RootElement.TryGetProperty("mailbox", out var mb))
            {
                var mailbox = new ImapMailboxInfo
                {
                    Messages = mb.TryGetProperty("messages", out var m) ? m.GetInt32() : 0,
                    Recent = mb.TryGetProperty("recent", out var r) ? r.GetInt32() : 0,
                    Unseen = mb.TryGetProperty("unseen", out var u) ? u.GetInt32() : 0
                };
                return ApiResult<ImapTestResult>.Ok(new ImapTestResult(true, mailbox, null));
            }

            var error = doc.RootElement.TryGetProperty("error", out var e) ? e.GetString() : "Unknown error";
            return ApiResult<ImapTestResult>.Ok(new ImapTestResult(false, null, error));
        }
        catch (JsonException ex)
        {
            return ApiResult<ImapTestResult>.Failure($"Failed to parse response: {ex.Message}");
        }
    }

    /// <inheritdoc />
    public async Task<ApiResult<ImapFetchResponse>> FetchEmailsAsync(
        UserProfileData profile,
        string filter,
        int limit,
        SigningContext context)
    {
        var request = new ImapApiRequest(
            profile.ImapHost ?? "",
            profile.ImapPort ?? 993,
            profile.ImapUsername ?? "",
            profile.ImapPassword ?? "",
            Filter: filter,
            Limit: limit);

        var body = JsonSerializer.Serialize(request, MailJsonContext.Default.ImapApiRequest);
        var result = await _client.SendUserSignedAsync("test_imap", body, "POST", context);

        if (!result.Success || result.Value is null)
        {
            return ApiResult<ImapFetchResponse>.Failure(result.Error ?? "Request failed");
        }

        try
        {
            using var doc = JsonDocument.Parse(result.Value);
            var success = doc.RootElement.TryGetProperty("success", out var s) && s.GetBoolean();

            if (!success)
            {
                var error = doc.RootElement.TryGetProperty("error", out var e) ? e.GetString() : "Unknown error";
                return ApiResult<ImapFetchResponse>.Failure(error ?? "Fetch failed");
            }

            var totalMatched = doc.RootElement.TryGetProperty("totalMatched", out var tm) ? tm.GetInt32() : 0;
            var emails = new List<ImapEmail>();

            if (doc.RootElement.TryGetProperty("emails", out var emailsArray))
            {
                foreach (var email in emailsArray.EnumerateArray())
                {
                    emails.Add(ParseEmail(email));
                }
            }

            ImapMailboxInfo? mailbox = null;
            if (doc.RootElement.TryGetProperty("mailbox", out var mb))
            {
                mailbox = new ImapMailboxInfo
                {
                    Messages = mb.TryGetProperty("messages", out var m) ? m.GetInt32() : 0,
                    Recent = mb.TryGetProperty("recent", out var r) ? r.GetInt32() : 0,
                    Unseen = mb.TryGetProperty("unseen", out var u) ? u.GetInt32() : 0
                };
            }

            return ApiResult<ImapFetchResponse>.Ok(new ImapFetchResponse(emails, totalMatched, mailbox));
        }
        catch (JsonException ex)
        {
            return ApiResult<ImapFetchResponse>.Failure($"Failed to parse response: {ex.Message}");
        }
    }

    /// <inheritdoc />
    public async Task<ApiResult<ImapEmail>> FetchEmailBodyAsync(
        UserProfileData profile,
        int uid,
        SigningContext context)
    {
        var request = new ImapApiRequest(
            profile.ImapHost ?? "",
            profile.ImapPort ?? 993,
            profile.ImapUsername ?? "",
            profile.ImapPassword ?? "",
            Uid: uid);

        var body = JsonSerializer.Serialize(request, MailJsonContext.Default.ImapApiRequest);
        var result = await _client.SendUserSignedAsync("test_imap", body, "POST", context);

        if (!result.Success || result.Value is null)
        {
            return ApiResult<ImapEmail>.Failure(result.Error ?? "Request failed");
        }

        try
        {
            using var doc = JsonDocument.Parse(result.Value);
            var success = doc.RootElement.TryGetProperty("success", out var s) && s.GetBoolean();

            if (!success)
            {
                var error = doc.RootElement.TryGetProperty("error", out var e) ? e.GetString() : "Unknown error";
                return ApiResult<ImapEmail>.Failure(error ?? "Fetch failed");
            }

            if (!doc.RootElement.TryGetProperty("email", out var emailElement))
            {
                return ApiResult<ImapEmail>.Failure("No email in response");
            }

            var email = ParseEmail(emailElement);

            // Check for PFA armor in body
            if (!string.IsNullOrEmpty(email.Body))
            {
                email.HasPfaArmor = email.Body.Contains("-----BEGIN PFA MESSAGE-----");
                email.HasInviteArmor = email.Body.Contains("-----BEGIN PFA SIGNED INVITE-----");
                email.HasResponseArmor = email.Body.Contains("-----BEGIN PFA SIGNED RESPONSE-----");
            }

            return ApiResult<ImapEmail>.Ok(email);
        }
        catch (JsonException ex)
        {
            return ApiResult<ImapEmail>.Failure($"Failed to parse response: {ex.Message}");
        }
    }

    /// <inheritdoc />
    public async Task<ApiResult<bool>> SendEmailAsync(
        UserProfileData profile,
        SendMailRequest request,
        SigningContext context)
    {
        var apiRequest = new SendMailApiRequest(
            profile.SmtpHost ?? "",
            profile.SmtpPort ?? 587,
            profile.SmtpUsername ?? "",
            profile.SmtpPassword ?? "",
            profile.Username ?? profile.SmtpUsername ?? "",
            profile.SmtpUsername ?? "",
            request.To,
            request.Subject,
            request.Body);

        var body = JsonSerializer.Serialize(apiRequest, MailJsonContext.Default.SendMailApiRequest);
        var result = await _client.SendUserSignedAsync("send_mail", body, "POST", context);

        if (!result.Success || result.Value is null)
        {
            return ApiResult<bool>.Failure(result.Error ?? "Request failed");
        }

        try
        {
            using var doc = JsonDocument.Parse(result.Value);
            var success = doc.RootElement.TryGetProperty("success", out var s) && s.GetBoolean();

            if (!success)
            {
                var error = doc.RootElement.TryGetProperty("error", out var e) ? e.GetString() : "Unknown error";
                return ApiResult<bool>.Failure(error ?? "Send failed");
            }

            return ApiResult<bool>.Ok(true);
        }
        catch (JsonException ex)
        {
            return ApiResult<bool>.Failure($"Failed to parse response: {ex.Message}");
        }
    }

    private static ImapEmail ParseEmail(JsonElement email)
    {
        return new ImapEmail
        {
            Uid = email.TryGetProperty("uid", out var uid) ? uid.GetInt32() : 0,
            Subject = email.TryGetProperty("subject", out var subj) ? subj.GetString() ?? "(no subject)" : "(no subject)",
            From = email.TryGetProperty("from", out var from) ? from.GetString() ?? "" : "",
            Date = email.TryGetProperty("date", out var date) ? date.GetString() ?? "" : "",
            Seen = email.TryGetProperty("seen", out var seen) && seen.GetBoolean(),
            Flagged = email.TryGetProperty("flagged", out var flagged) && flagged.GetBoolean(),
            Body = email.TryGetProperty("body", out var body) ? body.GetString() : null,
            BodyHtml = email.TryGetProperty("bodyHtml", out var bodyHtml) ? bodyHtml.GetString() : null
        };
    }
}
