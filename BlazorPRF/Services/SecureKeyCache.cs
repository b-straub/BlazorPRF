using System.Collections.Concurrent;
using BlazorPRF.Configuration;
using BlazorPRF.Models;
using Microsoft.Extensions.Options;
using R3;

namespace BlazorPRF.Services;

/// <summary>
/// Secure key cache storing keys in unmanaged memory outside .NET GC control.
/// Keys are stored with configurable TTL and cryptographically zero-filled on disposal/expiration.
/// Keys trigger their own expiration via one-shot timers for immediate cleanup.
/// </summary>
public sealed class SecureKeyCache : ISecureKeyCache
{
    private readonly ConcurrentDictionary<string, SecureKeyEntry> _cache = new();
    private readonly KeyCacheOptions _options;
    private readonly Subject<string> _keyExpiredSubject = new();
    private bool _disposed;

    /// <inheritdoc />
    public Observable<string> KeyExpired => _keyExpiredSubject;

    public SecureKeyCache(IOptions<KeyCacheOptions> options)
    {
        _options = options.Value;
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

        // Subscribe to key's one-shot expiration observable
        // Capture keyId for the callback
        var capturedKeyId = keyId;
        entry.Expired.Subscribe(_ => RemoveExpired(capturedKeyId));

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
            RemoveExpired(keyId);
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
    public bool UseKey(string keyId, ReadOnlySpanAction<byte> action)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(action);

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
            RemoveExpired(keyId);
            return false;
        }

        try
        {
            entry.UseKey(action);
            return true;
        }
        catch
        {
            Remove(keyId);
            return false;
        }
    }

    /// <inheritdoc />
    public bool UseKey<TResult>(string keyId, ReadOnlySpanFunc<byte, TResult> func, out TResult? result)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(func);

        result = default;

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
            RemoveExpired(keyId);
            return false;
        }

        try
        {
            TResult? capturedResult = default;
            entry.UseKey(span => capturedResult = func(span));
            result = capturedResult;
            return true;
        }
        catch
        {
            Remove(keyId);
            return false;
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
            RemoveExpired(keyId);
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
                RemoveExpired(keyId);
            }
        }
    }

    /// <summary>
    /// Remove a key that has expired and emit via KeyExpired observable.
    /// </summary>
    private void RemoveExpired(string keyId)
    {
        if (_cache.TryRemove(keyId, out var entry))
        {
            entry.Dispose();
            _keyExpiredSubject.OnNext(keyId);
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

        _keyExpiredSubject.Dispose();

        // Zero all keys
        Clear();
    }
}
