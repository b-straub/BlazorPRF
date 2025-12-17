using System.Security.Claims;
using BlazorPRF.UI.Models;
using Microsoft.AspNetCore.Components.Authorization;

namespace BlazorPRF.UI.Services;

/// <summary>
/// Authentication state provider based on PRF key derivation.
/// User is considered authenticated when:
/// - Keys have been derived (HasKeys = true), OR
/// - Strategy is None (on-demand auth) AND a credential is available
/// </summary>
public sealed class PrfAuthenticationStateProvider : AuthenticationStateProvider
{
    private PrfModel? _prfModel;
    private readonly AuthenticationState _anonymous = new(new ClaimsPrincipal(new ClaimsIdentity())); 
    
    public void UpdateAuthenticationState(PrfModel prfModel)
    {
        _prfModel = prfModel;
        NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
    }
    
    public override Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        if (_prfModel is null)
        {
            return Task.FromResult(new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity())));
        }
        
        // For Strategy.None user is "authenticated" (keys derived on-demand)
        var isOnDemandAuthenticated = _prfModel.RequiresOnDemandAuth;

        // Keep user authenticated while showing session expired dialog
        // This prevents redirect to home while the dialog is displayed
        var isShowingExpirationDialog = _prfModel.SessionExpired;

        if (!_prfModel.HasKeys && !isOnDemandAuthenticated && !isShowingExpirationDialog)
        {
            return Task.FromResult(_anonymous);
        }

        // Create authenticated identity
        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, "PRF User"),
            new("CredentialId", _prfModel.CredentialId ?? string.Empty),
            new("OnDemandAuth", _prfModel.RequiresOnDemandAuth.ToString())
        };

        // Only add public key claim if available
        if (_prfModel.PublicKey is not null)
        {
            claims.Add(new Claim(ClaimTypes.NameIdentifier, _prfModel.PublicKey));
        }

        var identity = new ClaimsIdentity(claims, "PRF");
        var principal = new ClaimsPrincipal(identity);

        return Task.FromResult(new AuthenticationState(principal));
    }
}
