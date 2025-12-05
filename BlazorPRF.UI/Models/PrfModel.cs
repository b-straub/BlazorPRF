using BlazorPRF.Shared.Formatting;
using BlazorPRF.Services;
using BlazorPRF.UI.Services;
using RxBlazorV2.Interface;
using RxBlazorV2.Model;
using System.Diagnostics.CodeAnalysis;

namespace BlazorPRF.UI.Models;

/// <summary>
/// Reactive model for PRF state management.
/// Wraps IPrfService and exposes reactive properties for UI binding.
/// </summary>
[ObservableModelScope(ModelScope.Singleton)]
[ObservableComponent]
public partial class PrfModel : ObservableModel
{
    /// <summary>
    /// Current salt used for key derivation.
    /// </summary>
    public partial string Salt { get; set; } = "my-encryption-keypair";

    /// <summary>
    /// Current credential ID (Base64).
    /// </summary>
    public partial string? CredentialId { get; set; }

    /// <summary>
    /// Public key derived from PRF (Base64).
    /// </summary>
    public partial string? PublicKey { get; set; }

    /// <summary>
    /// Optional metadata for the public key (name, email, etc.).
    /// </summary>
    public partial PublicKeyMetadata? KeyMetadata { get; set; }

    /// <summary>
    /// Whether keys have been derived for the current salt.
    /// </summary>
    public partial bool HasKeys { get; set; }

    /// <summary>
    /// Whether PRF is supported on this platform.
    /// null = not yet checked, true = supported, false = not supported (fatal).
    /// </summary>
    public partial bool? IsPrfSupported { get; set; }

    /// <summary>
    /// Whether any async command is currently executing.
    /// </summary>
    public bool IsExecuting => Register.Executing || DeriveKeys.Executing || DeriveKeysDiscoverable.Executing;

    /// <summary>
    /// Error message from last operation, if any.
    /// </summary>
    public partial string? ErrorMessage { get; set; }

    /// <summary>
    /// Success message from last operation, if any.
    /// </summary>
    public partial string? SuccessMessage { get; set; }

    // Commands
    [ObservableCommand(nameof(RegisterAsync), nameof(CanRegister))]
    public partial IObservableCommandAsync<string?> Register { get; }

    [ObservableCommand(nameof(DeriveKeysAsync), nameof(CanDeriveKeys))]
    public partial IObservableCommandAsync DeriveKeys { get; }

    [ObservableCommand(nameof(DeriveKeysDiscoverableAsync), nameof(CanDeriveKeysDiscoverable))]
    public partial IObservableCommandAsync DeriveKeysDiscoverable { get; }

    [ObservableCommand(nameof(ClearKeysImpl))]
    public partial IObservableCommand ClearKeys { get; }

    [SuppressMessage("RxBlazorGenerator", "RXBG050:Partial constructor parameter type may not be registered in DI", Justification = "Services registered externally")]
    public partial PrfModel(IPrfService prfService, ICredentialHintProvider credentialHintProvider);

    protected override async Task OnContextReadyAsync()
    {
        IsPrfSupported = await PrfService.IsPrfSupportedAsync();

        // Load credential hint to pre-populate the credential ID field
        // User still needs to click "Derive Keys" to authenticate (WebAuthn requires user gesture)
        if (IsPrfSupported == true)
        {
            var hint = await CredentialHintProvider.GetCredentialHintAsync();
            if (hint is not null && !string.IsNullOrWhiteSpace(hint.CredentialId))
            {
                CredentialId = hint.CredentialId;
                KeyMetadata = hint.Metadata;
            }
        }
    }

    private bool CanRegister()
    {
        return IsPrfSupported == true && !IsExecuting;
    }

    private async Task RegisterAsync(string? displayName)
    {
        ErrorMessage = null;
        SuccessMessage = null;

        try
        {
            var result = await PrfService.RegisterAsync(displayName);

            if (result is { Success: true, Value: not null })
            {
                CredentialId = result.Value.Id;
                SuccessMessage = "Passkey registered successfully!";
            }
            else
            {
                ErrorMessage = result.Error ?? "Registration failed";
            }
        }
        catch (Exception ex)
        {
            ErrorMessage = $"Error: {ex.Message}";
        }
    }

    private bool CanDeriveKeys()
    {
        return IsPrfSupported == true &&
               !IsExecuting &&
               !string.IsNullOrWhiteSpace(Salt) &&
               !string.IsNullOrWhiteSpace(CredentialId);
    }

    private async Task DeriveKeysAsync()
    {
        if (CredentialId is null)
        {
            return;
        }

        ErrorMessage = null;
        SuccessMessage = null;

        try
        {
            var result = await PrfService.DeriveKeysAsync(CredentialId, Salt);

            if (result is { Success: true, Value: not null })
            {
                PublicKey = result.Value;
                HasKeys = true;
                SuccessMessage = "Keys derived successfully!";
                await SaveCredentialHintAsync(CredentialId);
            }
            else if (result.Cancelled)
            {
                // User cancelled - clear credential hint and immediately show discoverable credentials
                await ClearCredentialHintAsync();
                await DeriveKeysDiscoverableAsync();
            }
            else
            {
                // Authentication failed - clear credential hint and reset to discoverable mode
                await ClearCredentialHintAsync();
                ErrorMessage = result.Error ?? "Key derivation failed";
                HasKeys = false;
            }
        }
        catch (Exception ex)
        {
            // Authentication failed - clear credential hint and reset to discoverable mode
            await ClearCredentialHintAsync();
            ErrorMessage = $"Error: {ex.Message}";
            HasKeys = false;
        }
    }

    private bool CanDeriveKeysDiscoverable()
    {
        return IsPrfSupported == true &&
               !IsExecuting &&
               !string.IsNullOrWhiteSpace(Salt);
    }

    private async Task DeriveKeysDiscoverableAsync()
    {
        ErrorMessage = null;
        SuccessMessage = null;

        try
        {
            var result = await PrfService.DeriveKeysDiscoverableAsync(Salt);

            if (result.Success)
            {
                CredentialId = result.Value.CredentialId;
                PublicKey = result.Value.PublicKey;
                HasKeys = true;
                SuccessMessage = "Keys derived successfully!";
                await SaveCredentialHintAsync(result.Value.CredentialId);
            }
            else if (!result.Cancelled)
            {
                // Only show error if not cancelled by user
                ErrorMessage = result.Error ?? "Key derivation failed";
                HasKeys = false;
            }
        }
        catch (Exception ex)
        {
            ErrorMessage = $"Error: {ex.Message}";
            HasKeys = false;
        }
    }

    private async Task SaveCredentialHintAsync(string credentialId)
    {
        await CredentialHintProvider.SetCredentialHintAsync(credentialId, KeyMetadata);
    }

    private async Task ClearCredentialHintAsync()
    {
        CredentialId = null;
        KeyMetadata = null;
        await CredentialHintProvider.ClearCredentialHintAsync();
    }

    /// <summary>
    /// Updates the key metadata and persists it.
    /// </summary>
    public async Task UpdateKeyMetadataAsync(PublicKeyMetadata? metadata)
    {
        KeyMetadata = metadata;
        if (CredentialId is not null)
        {
            await SaveCredentialHintAsync(CredentialId);
        }
    }

    private void ClearKeysImpl()
    {
        PrfService.ClearKeys();
        HasKeys = false;
        PublicKey = null;
        KeyMetadata = null;
        SuccessMessage = null;
        ErrorMessage = null;
    }
}
