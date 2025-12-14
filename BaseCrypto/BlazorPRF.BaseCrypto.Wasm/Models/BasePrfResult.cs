namespace BlazorPRF.BaseCrypto.Wasm.Models;

/// <summary>
/// Result type for all BlazorPRF.BaseCrypto.Wasm operations.
/// </summary>
public sealed record BasePrfResult<T>
{
    public bool Success { get; init; }
    public T? Value { get; init; }
    public string? Error { get; init; }

    private BasePrfResult() { }

    public static BasePrfResult<T> Ok(T value) => new() { Success = true, Value = value };
    public static BasePrfResult<T> Fail(string error) => new() { Success = false, Error = error };
}
