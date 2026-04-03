using BlazorPRF.Shared.Crypto.Models;

namespace BlazorPRF.Shared.Crypto.Services;

/// <summary>
/// Context for signing API requests.
/// </summary>
public sealed record SigningContext(
    string PublicKey,
    string Salt,
    Func<string, string, Task<PrfResult<string>>> SignAsync);
