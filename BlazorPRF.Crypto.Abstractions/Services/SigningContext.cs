using BlazorPRF.Crypto.Abstractions.Models;

namespace BlazorPRF.Crypto.Abstractions.Services;

/// <summary>
/// Context for signing API requests.
/// </summary>
public sealed record SigningContext(
    string PublicKey,
    string Salt,
    Func<string, string, Task<PrfResult<string>>> SignAsync);
