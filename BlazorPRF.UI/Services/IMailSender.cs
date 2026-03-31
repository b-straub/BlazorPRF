namespace BlazorPRF.UI.Services;

/// <summary>
/// Simple interface for sending emails.
/// Allows components to send emails without depending on MailApiModel directly.
/// </summary>
public interface IMailSender
{
    /// <summary>
    /// Sends an email with the given parameters.
    /// </summary>
    Task SendAsync(string to, string subject, string body);
}
