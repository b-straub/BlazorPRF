using R3;

namespace BlazorPRF.Services;

/// <summary>
/// Interface for secure key caching in WASM linear memory.
/// Keys are stored with TTL and zero-filled on disposal.
/// </summary>
public interface ISecureKeyCache : IDisposable
{
    /// <summary>
    /// Observable that emits the cache key when a key expires due to TTL.
    /// Note: For Strategy.None, this never emits (keys are removed immediately after use).
    /// </summary>
    Observable<string> KeyExpired { get; }

    /// <summary>
    /// Store a key in the cache.
    /// </summary>
    /// <param name="keyId">Unique identifier for the key</param>
    /// <param name="key">The key material</param>
    void Store(string keyId, byte[] key);

    /// <summary>
    /// Execute a function with direct access to the key without creating a managed copy.
    /// For Strategy.None, the key is removed immediately after this call.
    /// </summary>
    /// <typeparam name="TResult">The result type</typeparam>
    /// <param name="keyId">The key identifier</param>
    /// <param name="func">Function to execute with the key span</param>
    /// <param name="result">The result of the function, or default if key not found</param>
    /// <returns>True if the key was found and function executed, false otherwise</returns>
    bool UseKey<TResult>(string keyId, ReadOnlySpanFunc<byte, TResult> func, out TResult? result);

    /// <summary>
    /// Check if a key exists and is not expired.
    /// </summary>
    /// <param name="keyId">The key identifier</param>
    /// <returns>True if the key exists and is valid</returns>
    bool Contains(string keyId);

    /// <summary>
    /// Clear all keys from the cache.
    /// </summary>
    void Clear();
}

/// <summary>
/// Delegate for functions that operate on a ReadOnlySpan and return a result.
/// </summary>
public delegate TResult ReadOnlySpanFunc<T, out TResult>(ReadOnlySpan<T> span);
