namespace BlazorPRF.Api.Models;

/// <summary>
/// Result type for API operations with string error messages.
/// Unlike PrfResult which uses typed error codes, ApiResult uses
/// string errors to capture dynamic HTTP response details.
/// </summary>
/// <typeparam name="T">The value type on success</typeparam>
public sealed record ApiResult<T>
{
    /// <summary>
    /// Whether the operation succeeded.
    /// </summary>
    public required bool Success { get; init; }

    /// <summary>
    /// The result value (only present if Success is true).
    /// </summary>
    public T? Value { get; init; }

    /// <summary>
    /// The error message (only present if Success is false).
    /// </summary>
    public string? Error { get; init; }

    /// <summary>
    /// Creates a successful result.
    /// </summary>
    public static ApiResult<T> Ok(T value) => new()
    {
        Success = true,
        Value = value
    };

    /// <summary>
    /// Creates a failed result with an error message.
    /// </summary>
    public static ApiResult<T> Failure(string error) => new()
    {
        Success = false,
        Error = error
    };
}
