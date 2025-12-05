using BlazorPRF.Shared.Models;

namespace PseudoPRF.Services;

/// <summary>
/// Interface for secure storage of private keys.
/// Implementations should provide appropriate security for their environment.
/// </summary>
public interface IKeyStore
{
    /// <summary>
    /// Stores a private key securely.
    /// </summary>
    /// <param name="keyId">Unique identifier for the key</param>
    /// <param name="privateKeyBase64">The private key (Base64, 32 bytes)</param>
    /// <returns>True if stored successfully</returns>
    ValueTask<bool> StorePrivateKeyAsync(string keyId, string privateKeyBase64);

    /// <summary>
    /// Retrieves a private key.
    /// </summary>
    /// <param name="keyId">Unique identifier for the key</param>
    /// <returns>The private key (Base64) or null if not found</returns>
    ValueTask<string?> GetPrivateKeyAsync(string keyId);

    /// <summary>
    /// Deletes a private key.
    /// </summary>
    /// <param name="keyId">Unique identifier for the key</param>
    /// <returns>True if deleted successfully</returns>
    ValueTask<bool> DeletePrivateKeyAsync(string keyId);

    /// <summary>
    /// Checks if a key exists.
    /// </summary>
    /// <param name="keyId">Unique identifier for the key</param>
    /// <returns>True if the key exists</returns>
    ValueTask<bool> HasKeyAsync(string keyId);

    /// <summary>
    /// Lists all key IDs in the store.
    /// </summary>
    /// <returns>Collection of key IDs</returns>
    ValueTask<IReadOnlyCollection<string>> ListKeysAsync();
}

/// <summary>
/// In-memory key store for testing or short-lived scenarios.
/// WARNING: Keys are lost when the application terminates!
/// </summary>
public sealed class InMemoryKeyStore : IKeyStore
{
    private readonly Dictionary<string, string> _keys = new();
    private readonly Lock _lock = new();

    public ValueTask<bool> StorePrivateKeyAsync(string keyId, string privateKeyBase64)
    {
        lock (_lock)
        {
            _keys[keyId] = privateKeyBase64;
        }
        return ValueTask.FromResult(true);
    }

    public ValueTask<string?> GetPrivateKeyAsync(string keyId)
    {
        lock (_lock)
        {
            return ValueTask.FromResult(_keys.TryGetValue(keyId, out var key) ? key : null);
        }
    }

    public ValueTask<bool> DeletePrivateKeyAsync(string keyId)
    {
        lock (_lock)
        {
            return ValueTask.FromResult(_keys.Remove(keyId));
        }
    }

    public ValueTask<bool> HasKeyAsync(string keyId)
    {
        lock (_lock)
        {
            return ValueTask.FromResult(_keys.ContainsKey(keyId));
        }
    }

    public ValueTask<IReadOnlyCollection<string>> ListKeysAsync()
    {
        lock (_lock)
        {
            return ValueTask.FromResult<IReadOnlyCollection<string>>(_keys.Keys.ToList());
        }
    }
}
