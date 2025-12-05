using BlazorPRF.Models;
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
    /// </summary>
    Observable<string> KeyExpired { get; }

    /// <summary>
    /// Store a key in the cache.
    /// </summary>
    /// <param name="keyId">Unique identifier for the key</param>
    /// <param name="key">The key material</param>
    void Store(string keyId, byte[] key);

    /// <summary>
    /// Retrieve a key from the cache.
    /// </summary>
    /// <param name="keyId">The key identifier</param>
    /// <returns>A copy of the key, or null if not found or expired</returns>
    byte[]? TryGet(string keyId);

    /// <summary>
    /// Execute an action with direct access to the key without creating a managed copy.
    /// This is the preferred method for using keys securely.
    /// </summary>
    /// <param name="keyId">The key identifier</param>
    /// <param name="action">Action to execute with the key span</param>
    /// <returns>True if the key was found and action executed, false otherwise</returns>
    bool UseKey(string keyId, ReadOnlySpanAction<byte> action);

    /// <summary>
    /// Execute a function with direct access to the key without creating a managed copy.
    /// This is the preferred method for using keys securely.
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
    /// Remove a specific key from the cache.
    /// </summary>
    /// <param name="keyId">The key identifier</param>
    void Remove(string keyId);

    /// <summary>
    /// Clear all keys from the cache.
    /// </summary>
    void Clear();

    /// <summary>
    /// Remove expired keys from the cache.
    /// </summary>
    void CleanupExpired();
}

/// <summary>
/// Delegate for functions that operate on a ReadOnlySpan and return a result.
/// </summary>
public delegate TResult ReadOnlySpanFunc<T, out TResult>(ReadOnlySpan<T> span);
