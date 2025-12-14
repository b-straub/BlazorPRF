using BlazorPRF.Shared.Crypto.Configuration;
using BlazorPRF.Shared.Crypto.Formatting;
using BlazorPRF.Shared.Crypto.Services;
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
    public partial string Salt { get; set; } = KeyDomains.DefaultAuthSalt;

    /// <summary>
    /// Current credential ID (Base64).
    /// </summary>
    public partial string? CredentialId { get; set; }

    /// <summary>
    /// X25519 public key derived from PRF (Base64).
    /// Used for asymmetric encryption.
    /// </summary>
    public partial string? PublicKey { get; set; }

    /// <summary>
    /// Ed25519 public key derived from PRF (Base64).
    /// Used for digital signatures.
    /// </summary>
    public string? Ed25519PublicKey => PrfService.GetEd25519PublicKey(Salt);

    /// <summary>
    /// Optional metadata for the public key (name, email, etc.).
    /// </summary>
    public partial PublicKeyMetadata? KeyMetadata { get; set; }

    /// <summary>
    /// Whether keys have been derived for the current salt.
    /// For Strategy.None, this is always false (re-auth required for each operation).
    /// For Strategy.Timed, this reflects the actual cache state.
    /// </summary>
    [ObservableBatch("SessionState")]
    public partial bool HasKeys { get; set; }

    /// <summary>
    /// Whether PRF is supported on this platform.
    /// null = not yet checked, true = supported, false = not supported (fatal).
    /// </summary>
    public partial bool? IsPrfSupported { get; set; }

    /// <summary>
    /// Whether conditional mediation (passkey autofill) is available.
    /// When true, the browser can show passkey suggestions in form autofill UI,
    /// indicating that existing passkeys may be available for this RP.
    /// null = not yet checked.
    /// </summary>
    public partial bool? IsConditionalMediationAvailable { get; set; }

    /// <summary>
    /// The configured key caching strategy.
    /// </summary>
    public KeyCacheStrategy CacheStrategy => PrfService.CacheStrategy;

    /// <summary>
    /// Whether keys need to be derived before each crypto operation.
    /// True when Strategy is None.
    /// </summary>
    public bool RequiresOnDemandAuth => CacheStrategy == KeyCacheStrategy.None;

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

    /// <summary>
    /// Whether the session has expired and user needs to re-authenticate.
    /// Triggers OnSessionExpiredChanged hook in components.
    /// </summary>
    [ObservableComponentTrigger]
    [ObservableBatch("SessionState")]
    public partial bool SessionExpired { get; set; }

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
    public partial PrfModel(InviteModel inviteModel, IPrfService prfService, ICredentialHintProvider credentialHintProvider);

    protected override async Task OnContextReadyAsync()
    {
        IsPrfSupported = await PrfService.IsPrfSupportedAsync();
        IsConditionalMediationAvailable = await PrfService.IsConditionalMediationAvailableAsync();

        // Subscribe to key expiration events for reactive UI updates
        // Using Subscriptions ensures automatic disposal with the model
        Subscriptions.Add(PrfService.KeyExpired.Subscribe(OnKeyExpired));

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

    /// <summary>
    /// Called when a key expires in the cache.
    /// Updates reactive state so UI can respond.
    /// Note: For Strategy.None, the cache never emits expiration events.
    /// </summary>
    private void OnKeyExpired(string cacheKey)
    {
        // Check if the expired key matches our current salt
        var expectedCacheKey = $"prf-key:{Salt}";
        if (cacheKey == expectedCacheKey)
        {
            // Batch update to ensure AuthenticationStateProvider sees both changes atomically
            using (SuspendNotifications("SessionState"))
            {
                SessionExpired = true;
                HasKeys = false;
            }
        }
    }

    /// <summary>
    /// Dismiss the session expired dialog (user chose to go home).
    /// </summary>
    public void DismissSessionExpired()
    {
        SessionExpired = false;
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
                // For Strategy.None, keys expire immediately - don't set HasKeys
                HasKeys = CacheStrategy != KeyCacheStrategy.None;
                SuccessMessage = CacheStrategy == KeyCacheStrategy.None
                    ? "Authentication successful! Keys will be derived on-demand."
                    : "Keys derived successfully!";
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
                // For Strategy.None, keys expire immediately - don't set HasKeys
                HasKeys = CacheStrategy != KeyCacheStrategy.None;
                SuccessMessage = CacheStrategy == KeyCacheStrategy.None
                    ? "Authentication successful! Keys will be derived on-demand."
                    : "Keys derived successfully!";
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

    /// <summary>
    /// Ensures keys are available for crypto operations.
    /// For Strategy.None: Always triggers WebAuthn authentication.
    /// For Strategy.Timed/Session: Checks cache and re-derives if expired.
    /// </summary>
    /// <returns>True if keys are available, false if user cancelled or error occurred</returns>
    public async Task<bool> EnsureKeysAsync()
    {
        // For Strategy.None, always re-derive
        if (CacheStrategy == KeyCacheStrategy.None)
        {
            return await DeriveKeysInternalAsync();
        }

        // For other strategies, check if keys are still cached
        if (PrfService.HasCachedKeys(Salt))
        {
            return true;
        }

        // Keys expired or not present - need to re-derive
        HasKeys = false; // Update reactive state
        return await DeriveKeysInternalAsync();
    }

    /// <summary>
    /// Internal helper to derive keys using the appropriate method.
    /// </summary>
    private async Task<bool> DeriveKeysInternalAsync()
    {
        if (CredentialId is not null)
        {
            var result = await PrfService.DeriveKeysAsync(CredentialId, Salt);
            if (result is { Success: true, Value: not null })
            {
                PublicKey = result.Value;
                // Don't update HasKeys for Strategy.None
                if (CacheStrategy != KeyCacheStrategy.None)
                {
                    HasKeys = true;
                }
                return true;
            }

            // If credential failed, try discoverable
            if (!result.Cancelled)
            {
                return await DeriveKeysDiscoverableInternalAsync();
            }

            return false;
        }

        return await DeriveKeysDiscoverableInternalAsync();
    }

    /// <summary>
    /// Internal helper for discoverable credential flow.
    /// </summary>
    private async Task<bool> DeriveKeysDiscoverableInternalAsync()
    {
        var result = await PrfService.DeriveKeysDiscoverableAsync(Salt);
        if (result.Success)
        {
            CredentialId = result.Value.CredentialId;
            PublicKey = result.Value.PublicKey;
            // Don't update HasKeys for Strategy.None
            if (CacheStrategy != KeyCacheStrategy.None)
            {
                HasKeys = true;
            }
            await SaveCredentialHintAsync(result.Value.CredentialId);
            return true;
        }

        return false;
    }

    /// <summary>
    /// Handles a key derivation failure from encryption services.
    /// Clears the HasKeys state so UI can prompt for re-authentication.
    /// </summary>
    public void OnKeyDerivationFailed()
    {
        HasKeys = false;
        ErrorMessage = "Keys expired. Please authenticate again.";
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
