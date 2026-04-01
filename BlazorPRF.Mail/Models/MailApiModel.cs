using System.Diagnostics.CodeAnalysis;
using BlazorPRF.Api.Services;
using BlazorPRF.Mail.Services;
using BlazorPRF.Persistence.Data.Models;
using BlazorPRF.Persistence.Services;
using BlazorPRF.Shared.Crypto.Formatting;
using BlazorPRF.Shared.Crypto.Services;
using BlazorPRF.UI.Models;
using BlazorPRF.UI.Services;
using RxBlazorV2.Interface;
using RxBlazorV2.Model;
using RxBlazorV2.MudBlazor.Components;

namespace BlazorPRF.Mail.Models;

/// <summary>
/// Reactive model for mail operations via PRF-authenticated backend.
/// Manages IMAP fetch, SMTP send, and email decryption state.
/// </summary>
[ObservableModelScope(ModelScope.Singleton)]
[ObservableComponent]
public partial class MailApiModel : ObservableModel, IMailSender
{
    [SuppressMessage("RxBlazorGenerator", "RXBG050:Partial constructor parameter type may not be registered in DI", Justification = "Services registered externally")]
    // ReSharper disable UnusedParameter.Local
    public partial MailApiModel(
        PrfModel prfModel,
        StatusModel statusModel,
        IMailService mailService,
        IUserProfileService userProfileService,
        IAsymmetricEncryption asymmetricEncryption,
        ISigningService signingService,
        ISignedApiClient signedApiClient,
        ITrustedContactService trustedContactService);
    // ReSharper restore UnusedParameter.Local

    // Server state
    /// <summary>
    /// Whether the mail relay server has an admin key configured.
    /// null = not checked yet.
    /// </summary>
    public partial bool? ServerHasAdmin { get; set; }

    // Profile state
    /// <summary>
    /// User's profile with SMTP/IMAP configuration.
    /// </summary>
    [ObservableComponentTrigger]
    public partial UserProfileData? Profile { get; set; }

    // IMAP state
    /// <summary>
    /// Fetched emails from IMAP.
    /// </summary>
    [ObservableComponentTrigger]
    public partial List<ImapEmail> Emails { get; set; } = [];

    /// <summary>
    /// Whether emails are currently being fetched.
    /// </summary>
    public partial bool IsFetchingEmails { get; set; }

    /// <summary>
    /// Current IMAP mailbox info (messages, unseen, recent).
    /// </summary>
    public partial ImapMailboxInfo? MailboxInfo { get; set; }

    /// <summary>
    /// IMAP filter (unseen, all, flagged).
    /// </summary>
    [ObservableTriggerAsync(nameof(AutoFetchEmailsAsync))]
    public partial string ImapFilter { get; set; } = "unseen";

    /// <summary>
    /// Total number of emails matched by filter.
    /// </summary>
    public partial int TotalMatched { get; set; }

    // Email viewer state
    /// <summary>
    /// Currently selected email for viewing.
    /// </summary>
    [ObservableComponentTrigger]
    public partial ImapEmail? SelectedEmail { get; set; }

    /// <summary>
    /// Whether email body is being loaded.
    /// </summary>
    public partial bool IsLoadingEmailBody { get; set; }

    /// <summary>
    /// Decrypted content of the selected email.
    /// </summary>
    public partial string? DecryptedContent { get; set; }

    /// <summary>
    /// Sender's Ed25519 public key from a signed encrypted message.
    /// </summary>
    public partial string? DecryptedSenderKey { get; set; }

    /// <summary>
    /// Resolved sender display name from contacts (e.g., "Alice &lt;alice@example.com&gt;").
    /// </summary>
    public partial string? DecryptedSenderName { get; set; }

    /// <summary>
    /// Whether the sender's signature was verified. null = unsigned message.
    /// </summary>
    public partial bool? DecryptedSignatureValid { get; set; }

    /// <summary>
    /// Error message from decryption attempt.
    /// </summary>
    public partial string? DecryptError { get; set; }

    /// <summary>
    /// Whether decryption is in progress.
    /// </summary>
    public partial bool IsDecrypting { get; set; }

    // Send state
    /// <summary>
    /// Whether email is being sent.
    /// </summary>
    public partial bool IsSending { get; set; }

    /// <summary>
    /// Recipient email address.
    /// </summary>
    public partial string SendTo { get; set; } = "";

    /// <summary>
    /// Email subject.
    /// </summary>
    public partial string SendSubject { get; set; } = "Test email from BlazorPRF";

    /// <summary>
    /// Email body.
    /// </summary>
    public partial string SendBody { get; set; } = "This is a test email sent using PRF-authenticated API.";

    // Connection test state
    /// <summary>
    /// Whether SMTP connection is being tested.
    /// </summary>
    public partial bool IsTestingSmtp { get; set; }

    /// <summary>
    /// Whether IMAP connection is being tested.
    /// </summary>
    public partial bool IsTestingImap { get; set; }

    /// <summary>
    /// Whether the email dialog is visible.
    /// </summary>
    public partial bool EmailDialogVisible { get; set; }

    // Computed properties
    /// <summary>
    /// Whether SMTP is configured in the profile.
    /// </summary>
    public bool IsSmtpConfigured => Profile is not null && !string.IsNullOrEmpty(Profile.SmtpHost);

    /// <summary>
    /// Whether IMAP is configured in the profile.
    /// </summary>
    public bool IsImapConfigured => Profile is not null && !string.IsNullOrEmpty(Profile.ImapHost);

    /// <summary>
    /// Whether an email can be sent (all required fields present).
    /// </summary>
    public bool CanSendMail => IsSmtpConfigured &&
                                !string.IsNullOrWhiteSpace(SendTo) &&
                                !string.IsNullOrWhiteSpace(SendSubject) &&
                                !string.IsNullOrWhiteSpace(SendBody);

    // Commands
    [ObservableCommand(nameof(LoadProfileAsync))]
    public partial IObservableCommandAsync LoadProfile { get; }

    [ObservableCommand(nameof(TestSmtpAsync))]
    public partial IObservableCommandAsync TestSmtp { get; }

    [ObservableCommand(nameof(TestImapAsync))]
    public partial IObservableCommandAsync TestImap { get; }

    [ObservableCommand(nameof(FetchEmailsAsync))]
    public partial IObservableCommandAsync FetchEmails { get; }

    [ObservableCommand(nameof(SendEmailAsync))]
    public partial IObservableCommandAsync SendEmail { get; }

    [ObservableCommand(nameof(DecryptEmailAsync))]
    public partial IObservableCommandAsync DecryptEmail { get; }

    /// <summary>
    /// Creates a signing context for API requests.
    /// </summary>
    private SigningContext CreateSigningContext()
    {
        return new SigningContext(
            PrfModel.Ed25519PublicKey ?? "",
            PrfModel.Salt ?? "",
            async (message, salt) => await SigningService.SignAsync(message, salt));
    }

    private async Task LoadProfileAsync()
    {
        if (!await PrfModel.EnsureKeysAsync())
        {
            StatusModel.AddError("Authentication cancelled or failed");
            return;
        }

        var result = await UserProfileService.GetAsync();
        if (result.Success && result.Value is not null)
        {
            Profile = result.Value;

            // Update API client base URL from profile (must end with / for correct URI resolution)
            if (!string.IsNullOrWhiteSpace(result.Value.MailRelayUrl))
            {
                var url = result.Value.MailRelayUrl.Trim();
                if (!url.EndsWith('/'))
                {
                    url += '/';
                }

                SignedApiClient.BaseUrl = url;
            }
        }
        else if (!result.Success)
        {
            StatusModel.AddError(result.Error ?? "Failed to load profile");
        }
        // result.Success && result.Value is null → no profile exists yet, not an error
    }

    private async Task TestSmtpAsync()
    {
        if (Profile is null)
        {
            return;
        }

        IsTestingSmtp = true;

        try
        {
            if (!await PrfModel.EnsureKeysAsync())
            {
                StatusModel.AddError("Authentication cancelled or failed");
                return;
            }

            var result = await MailService.TestSmtpAsync(Profile, CreateSigningContext());
            if (result.Success && result.Value is not null)
            {
                if (result.Value.Success)
                {
                    StatusModel.AddSuccess("SMTP connection successful!");
                }
                else
                {
                    StatusModel.AddError(result.Value.Error ?? "SMTP connection failed");
                }
            }
            else
            {
                StatusModel.AddError(result.Error ?? "SMTP test failed");
            }
        }
        catch (Exception ex)
        {
            StatusModel.AddError($"SMTP test failed: {ex.Message}");
        }
        finally
        {
            IsTestingSmtp = false;
        }
    }

    private async Task TestImapAsync()
    {
        if (Profile is null)
        {
            return;
        }

        IsTestingImap = true;

        try
        {
            if (!await PrfModel.EnsureKeysAsync())
            {
                StatusModel.AddError("Authentication cancelled or failed");
                return;
            }

            var result = await MailService.TestImapAsync(Profile, CreateSigningContext());
            if (result.Success && result.Value is not null)
            {
                if (result.Value.Success)
                {
                    MailboxInfo = result.Value.Mailbox;
                    StatusModel.AddSuccess("IMAP connection successful!");
                }
                else
                {
                    StatusModel.AddError(result.Value.Error ?? "IMAP connection failed");
                }
            }
            else
            {
                StatusModel.AddError(result.Error ?? "IMAP test failed");
            }
        }
        catch (Exception ex)
        {
            StatusModel.AddError($"IMAP test failed: {ex.Message}");
        }
        finally
        {
            IsTestingImap = false;
        }
    }

    /// <summary>
    /// Ensure the admin's Ed25519 key is also registered as a user key.
    /// Admin auth and user auth are separate — admin needs a user key for mail operations.
    /// </summary>
    private async Task EnsureAdminRegisteredAsUserAsync(SigningContext context)
    {
        var ed25519Key = PrfModel.Ed25519PublicKey;
        if (string.IsNullOrEmpty(ed25519Key))
        {
            return;
        }

        var body = System.Text.Json.JsonSerializer.Serialize(new
        {
            publicKey = ed25519Key,
            userId = "admin"
        });

        // This is idempotent — if already registered, server just updates
        await SignedApiClient.SendAdminSignedAsync("register", body, "POST", context);
    }

    /// <summary>
    /// Auto-fetch emails when IMAP is configured.
    /// Triggered by ImapFilter change or called after profile load on mail page.
    /// </summary>
    private async Task AutoFetchEmailsAsync()
    {
        if (IsImapConfigured)
        {
            await FetchEmailsAsync();
        }
    }

    /// <summary>
    /// Load profile, check admin status, and auto-fetch emails if IMAP is configured.
    /// Use this from the mail page to combine all initialization operations.
    /// </summary>
    public async Task LoadProfileAndFetchAsync()
    {
        await LoadProfileAsync();
        await CheckAdminStatusAsync();

        // Only fetch emails if user is registered on the server
        if (PrfModel.Role is PrfUserRole.ADMIN or PrfUserRole.USER)
        {
            await AutoFetchEmailsAsync();
        }
    }

    /// <summary>
    /// Determine the user's role on the mail relay server.
    /// Tries admin access first, then user access, falls back to unregistered.
    /// Public to avoid auto-detection as internal observer (RXBG031: reads+writes PrfModel.Role).
    /// </summary>
    public async Task CheckAdminStatusAsync()
    {
        if (PrfModel.Role != PrfUserRole.UNKNOWN)
        {
            return;
        }

        var ed25519Key = PrfModel.Ed25519PublicKey;
        if (string.IsNullOrEmpty(ed25519Key))
        {
            return;
        }

        try
        {
            // Check if server is reachable and has an admin configured (unauthenticated)
            var setupResult = await SignedApiClient.GetAsync("admin-setup");
            if (!setupResult.Success)
            {
                // Server unreachable or returned error — show setup instructions
                ServerHasAdmin = null;
                PrfModel.Role = PrfUserRole.UNREGISTERED;
                return;
            }

            var doc = System.Text.Json.JsonDocument.Parse(setupResult.Value!);
            ServerHasAdmin = doc.RootElement.TryGetProperty("hasAdmin", out var ha) && ha.GetBoolean();

            var context = CreateSigningContext();

            // Try admin access first (GET /register lists keys — admin only)
            var adminResult = await SignedApiClient.SendAdminSignedAsync("register", "", "GET", context);
            if (adminResult.Success)
            {
                // Auto-register admin's own key as a user so mail operations work
                await EnsureAdminRegisteredAsUserAsync(context);
                PrfModel.Role = PrfUserRole.ADMIN;
                return;
            }

            // Not admin — try a user-signed request to check if key is registered
            var userResult = await SignedApiClient.SendUserSignedAsync(
                "test_imap",
                System.Text.Json.JsonSerializer.Serialize(new { imapHost = "", filter = "test" }),
                "POST",
                context);

            // If we get past auth (even with a validation error), the key is registered
            // "IMAP host is required" = registered but bad params
            // "Public key not registered" = not registered
            if (userResult.Success || (userResult.Error is not null && !userResult.Error.Contains("not registered")))
            {
                PrfModel.Role = PrfUserRole.USER;
            }
            else
            {
                PrfModel.Role = PrfUserRole.UNREGISTERED;
            }
        }
        catch
        {
            // Server unreachable
            ServerHasAdmin = null;
            PrfModel.Role = PrfUserRole.UNREGISTERED;
        }
    }

    private async Task FetchEmailsAsync()
    {
        if (Profile is null)
        {
            return;
        }

        IsFetchingEmails = true;
        Emails = [];

        try
        {
            if (!await PrfModel.EnsureKeysAsync())
            {
                StatusModel.AddError("Authentication cancelled or failed");
                return;
            }

            var result = await MailService.FetchEmailsAsync(Profile, ImapFilter, 10, CreateSigningContext());
            if (result.Success && result.Value is not null)
            {
                Emails = result.Value.Emails;
                TotalMatched = result.Value.TotalMatched;
                MailboxInfo = result.Value.Mailbox ?? MailboxInfo;
                StatusModel.AddSuccess($"Fetched {Emails.Count} emails");
            }
            else
            {
                StatusModel.AddError(result.Error ?? "Failed to fetch emails");
            }
        }
        catch (Exception ex)
        {
            StatusModel.AddError($"Fetch failed: {ex.Message}");
        }
        finally
        {
            IsFetchingEmails = false;
        }
    }

    /// <summary>
    /// View an email and load its body if needed.
    /// </summary>
    public async Task ViewEmailAsync(ImapEmail email)
    {
        SelectedEmail = email;
        DecryptedContent = null;
        DecryptError = null;
        EmailDialogVisible = true;

        // If body is not loaded yet, fetch it
        if (email.Body is null && Profile is not null)
        {
            IsLoadingEmailBody = true;

            try
            {
                if (!await PrfModel.EnsureKeysAsync())
                {
                    StatusModel.AddError("Authentication cancelled or failed");
                    return;
                }

                var result = await MailService.FetchEmailBodyAsync(Profile, email.Uid, CreateSigningContext());
                if (result.Success && result.Value is not null)
                {
                    email.Body = result.Value.Body;
                    email.BodyHtml = result.Value.BodyHtml;
                    email.HasPfaArmor = result.Value.HasPfaArmor;
                    email.HasInviteArmor = result.Value.HasInviteArmor;
                    email.HasResponseArmor = result.Value.HasResponseArmor;
                }
                else
                {
                    StatusModel.AddError(result.Error ?? "Failed to load email body");
                }
            }
            catch (Exception ex)
            {
                StatusModel.AddError($"Failed to load email: {ex.Message}");
            }
            finally
            {
                IsLoadingEmailBody = false;
            }
        }
    }

    /// <summary>
    /// Close the email dialog.
    /// </summary>
    public void CloseEmailDialog()
    {
        EmailDialogVisible = false;
        SelectedEmail = null;
        DecryptedContent = null;
        DecryptedSenderKey = null;
        DecryptedSenderName = null;
        DecryptedSignatureValid = null;
        DecryptError = null;
    }

    /// <summary>
    /// Resolve sender Ed25519 key to a display name from contacts.
    /// </summary>
    private async Task<string?> ResolveSenderNameAsync(string? ed25519PublicKey)
    {
        if (string.IsNullOrEmpty(ed25519PublicKey))
        {
            return null;
        }

        try
        {
            // Get contact with decrypted user data
            var contact = await TrustedContactService.GetByEd25519PublicKeyAsync(ed25519PublicKey);
            if (contact is null)
            {
                return null;
            }

            // Use GetByIdAsync which returns decrypted user data
            var result = await TrustedContactService.GetByIdAsync(contact.Id);
            if (result is not { Success: true, Value: not null })
            {
                return null;
            }

            var userData = result.Value.Value.UserData;
            var parts = new List<string>();
            if (!string.IsNullOrWhiteSpace(userData.Username))
            {
                parts.Add(userData.Username);
            }

            if (!string.IsNullOrWhiteSpace(userData.Email))
            {
                parts.Add($"<{userData.Email}>");
            }

            return parts.Count > 0 ? string.Join(" ", parts) : null;
        }
        catch
        {
            return null;
        }
    }

    private async Task DecryptEmailAsync()
    {
        if (SelectedEmail?.Body is null)
        {
            return;
        }

        IsDecrypting = true;
        DecryptedContent = null;
        DecryptedSenderKey = null;
        DecryptedSignatureValid = null;
        DecryptError = null;

        try
        {
            if (!await PrfModel.EnsureKeysAsync())
            {
                DecryptError = "Authentication cancelled or failed";
                return;
            }

            // Extract encrypted message from email body
            var encryptedMessage = PrfArmor.ExtractEncryptedMessage(SelectedEmail.Body);
            if (encryptedMessage is null)
            {
                DecryptError = "No valid encrypted message found in email";
                return;
            }

            // Decrypt and verify signature if present
            var result = await AsymmetricEncryption.DecryptAndVerifyAsync(
                encryptedMessage, PrfModel.Salt, SigningService);
            if (result.Success && result.Value is not null)
            {
                DecryptedContent = result.Value.Plaintext;
                DecryptedSenderKey = result.Value.SenderEd25519PublicKey;
                DecryptedSignatureValid = result.Value.SignatureValid;
                DecryptedSenderName = await ResolveSenderNameAsync(result.Value.SenderEd25519PublicKey);
                SelectedEmail.Decrypted = true;
                SelectedEmail.DecryptFailed = false;
                SelectedEmail.SignatureVerified = result.Value.SignatureValid;
            }
            else
            {
                DecryptError = result.Error ?? "Decryption failed";
                SelectedEmail.DecryptFailed = true;
            }
        }
        catch (Exception ex)
        {
            DecryptError = $"Error: {ex.Message}";
        }
        finally
        {
            IsDecrypting = false;
        }
    }

    private async Task SendEmailAsync()
    {
        if (Profile is null || !CanSendMail)
        {
            return;
        }

        IsSending = true;

        try
        {
            if (!await PrfModel.EnsureKeysAsync())
            {
                StatusModel.AddError("Authentication cancelled or failed");
                return;
            }

            var request = new SendMailRequest(SendTo, SendSubject, SendBody);
            var result = await MailService.SendEmailAsync(Profile, request, CreateSigningContext());

            if (result.Success && result.Value)
            {
                StatusModel.AddSuccess("Email sent successfully!");
                // Clear fields after successful send
                SendTo = "";
                SendSubject = "Test email from BlazorPRF";
                SendBody = "This is a test email sent using PRF-authenticated API.";
            }
            else
            {
                StatusModel.AddError(result.Error ?? "Failed to send email");
            }
        }
        catch (Exception ex)
        {
            StatusModel.AddError($"Send failed: {ex.Message}");
        }
        finally
        {
            IsSending = false;
        }
    }

    /// <summary>
    /// Pre-fill the send form with recipient and body.
    /// Used when navigating from encryption panel.
    /// </summary>
    public void PreFillSend(string? to, string? subject, string? body)
    {
        if (!string.IsNullOrEmpty(to))
        {
            SendTo = to;
        }

        if (!string.IsNullOrEmpty(subject))
        {
            SendSubject = subject;
        }

        if (!string.IsNullOrEmpty(body))
        {
            SendBody = body;
        }
    }

    /// <inheritdoc />
    async Task IMailSender.SendAsync(string to, string subject, string body)
    {
        PreFillSend(to, subject, body);
        await SendEmail.ExecuteAsync();
    }
}
