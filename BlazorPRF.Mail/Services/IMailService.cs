using BlazorPRF.Crypto.Abstractions.Services;
using BlazorPRF.Api.Models;
using BlazorPRF.Mail.Models;
using BlazorPRF.Persistence.Data.Models;

namespace BlazorPRF.Mail.Services;

/// <summary>
/// Service for mail operations via PRF-authenticated backend.
/// </summary>
public interface IMailService
{
    /// <summary>
    /// Test SMTP connection.
    /// </summary>
    Task<ApiResult<SmtpTestResult>> TestSmtpAsync(
        UserProfileData profile,
        SigningContext context);

    /// <summary>
    /// Test IMAP connection and get mailbox info.
    /// </summary>
    Task<ApiResult<ImapTestResult>> TestImapAsync(
        UserProfileData profile,
        SigningContext context);

    /// <summary>
    /// Fetch emails from IMAP.
    /// </summary>
    Task<ApiResult<ImapFetchResponse>> FetchEmailsAsync(
        UserProfileData profile,
        string filter,
        string messageType,
        int limit,
        SigningContext context);

    /// <summary>
    /// Fetch a single email body by UID.
    /// </summary>
    Task<ApiResult<ImapEmail>> FetchEmailBodyAsync(
        UserProfileData profile,
        int uid,
        SigningContext context);

    /// <summary>
    /// Send an email via SMTP.
    /// </summary>
    Task<ApiResult<bool>> SendEmailAsync(
        UserProfileData profile,
        SendMailRequest request,
        SigningContext context);
}
