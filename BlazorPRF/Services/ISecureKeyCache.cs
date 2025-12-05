namespace BlazorPRF.Services;

/// <summary>
/// Interface for secure key caching in WASM linear memory.
/// Keys are stored with TTL and zero-filled on disposal.
/// </summary>
public interface ISecureKeyCache : IDisposable
{
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
