using System.Collections.Concurrent;
using BlazorPRF.Configuration;
using BlazorPRF.Models;
using Microsoft.Extensions.Options;

namespace BlazorPRF.Services;

/// <summary>
/// Secure key cache storing keys in unmanaged memory outside .NET GC control.
/// Keys are stored with configurable TTL and cryptographically zero-filled on disposal/expiration.
/// </summary>
public sealed class SecureKeyCache : ISecureKeyCache
{
    private readonly ConcurrentDictionary<string, SecureKeyEntry> _cache = new();
    private readonly KeyCacheOptions _options;
    private readonly Timer? _cleanupTimer;
    private bool _disposed;

    public SecureKeyCache(IOptions<KeyCacheOptions> options)
    {
        _options = options.Value;

        // Start cleanup timer if TTL is configured
        if (_options is { Strategy: KeyCacheStrategy.Timed, TtlMinutes: > 0 })
        {
            var cleanupInterval = TimeSpan.FromMinutes(Math.Max(1, _options.TtlMinutes / 2));
            _cleanupTimer = new Timer(
                _ => CleanupExpired(),
                null,
                cleanupInterval,
                cleanupInterval
            );
        }
    }

    /// <inheritdoc />
    public void Store(string keyId, byte[] key)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrEmpty(keyId);
        ArgumentNullException.ThrowIfNull(key);

        // Remove existing entry if present
        if (_cache.TryRemove(keyId, out var existing))
        {
            existing.Dispose();
        }

        // Determine TTL based on strategy
        TimeSpan? ttl = _options.Strategy switch
        {
            KeyCacheStrategy.None => TimeSpan.Zero, // Immediate expiration
            KeyCacheStrategy.Session => null, // No expiration (until page refresh)
            KeyCacheStrategy.Timed => TimeSpan.FromMinutes(_options.TtlMinutes),
            _ => TimeSpan.FromMinutes(15) // Default
        };

        // For 'None' strategy, we still store briefly to allow immediate retrieval
        // but the key will be cleaned up on next cleanup cycle
        if (_options.Strategy == KeyCacheStrategy.None)
        {
            ttl = TimeSpan.FromSeconds(1);
        }

        var entry = new SecureKeyEntry(key, ttl);
        _cache[keyId] = entry;
    }

    /// <inheritdoc />
    public byte[]? TryGet(string keyId)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (string.IsNullOrEmpty(keyId))
        {
            return null;
        }

        if (!_cache.TryGetValue(keyId, out var entry))
        {
            return null;
        }

        if (entry.IsExpired)
        {
            Remove(keyId);
            return null;
        }

        try
        {
            return entry.GetKey();
        }
        catch
        {
            Remove(keyId);
            return null;
        }
    }

    /// <inheritdoc />
    public bool Contains(string keyId)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (string.IsNullOrEmpty(keyId))
        {
            return false;
        }

        if (!_cache.TryGetValue(keyId, out var entry))
        {
            return false;
        }

        if (entry.IsExpired)
        {
            Remove(keyId);
            return false;
        }

        return true;
    }

    /// <inheritdoc />
    public void Remove(string keyId)
    {
        if (string.IsNullOrEmpty(keyId))
        {
            return;
        }

        if (_cache.TryRemove(keyId, out var entry))
        {
            entry.Dispose();
        }
    }

    /// <inheritdoc />
    public void Clear()
    {
        foreach (var keyId in _cache.Keys.ToList())
        {
            if (_cache.TryRemove(keyId, out var entry))
            {
                entry.Dispose();
            }
        }
    }

    /// <inheritdoc />
    public void CleanupExpired()
    {
        if (_disposed)
        {
            return;
        }

        foreach (var keyId in _cache.Keys.ToList())
        {
            if (_cache.TryGetValue(keyId, out var entry) && entry.IsExpired)
            {
                Remove(keyId);
            }
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        _cleanupTimer?.Dispose();

        // Zero all keys
        Clear();
    }
}
