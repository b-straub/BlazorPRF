using BlazorPRF.Api.Models;
using BlazorPRF.Shared.Crypto.Models;

namespace BlazorPRF.Api.Services;

/// <summary>
/// Client for making Ed25519-signed HTTP requests to PRF-authenticated backends.
/// </summary>
public interface ISignedApiClient
{
    /// <summary>
    /// Send an admin-signed request.
    /// </summary>
    /// <param name="endpoint">API endpoint (appended to base URL)</param>
    /// <param name="body">Request body (JSON string, empty for GET/DELETE)</param>
    /// <param name="method">HTTP method</param>
    /// <param name="context">Signing context with keys and signer</param>
    /// <returns>Response body or error result</returns>
    Task<ApiResult<string>> SendAdminSignedAsync(
        string endpoint,
        string body,
        string method,
        SigningContext context);

    /// <summary>
    /// Send a user-signed request.
    /// </summary>
    /// <param name="endpoint">API endpoint (appended to base URL)</param>
    /// <param name="body">Request body (JSON string, empty for GET/DELETE)</param>
    /// <param name="method">HTTP method</param>
    /// <param name="context">Signing context with keys and signer</param>
    /// <returns>Response body or error result</returns>
    Task<ApiResult<string>> SendUserSignedAsync(
        string endpoint,
        string body,
        string method,
        SigningContext context);
}

/// <summary>
/// Context for signing API requests.
/// </summary>
public sealed record SigningContext(
    string PublicKey,
    string Salt,
    Func<string, string, Task<PrfResult<string>>> SignAsync);
