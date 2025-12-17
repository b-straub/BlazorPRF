using BlazorPRF.BC.Crypto.Services;
using BlazorPRF.Shared.Crypto.Configuration;
using Microsoft.Extensions.Options;

namespace BlazorPRF.Tests.Unit;

public class SecureKeyCacheTests
{
    private static SecureKeyCache CreateCache(KeyCacheStrategy strategy = KeyCacheStrategy.TIMED, int ttlMinutes = 15)
    {
        var options = Options.Create(new KeyCacheOptions
        {
            Strategy = strategy,
            TtlMinutes = ttlMinutes
        });
        return new SecureKeyCache(options);
    }

    [Fact]
    public void Store_And_TryGet_ReturnsKey()
    {
        // Arrange
        using var cache = CreateCache();
        var keyId = "test-key";
        var key = new byte[] { 1, 2, 3, 4, 5 };

        // Act
        cache.Store(keyId, key);
        var retrieved = cache.TryGet(keyId);

        // Assert
        Assert.NotNull(retrieved);
        Assert.Equal(key, retrieved);
    }

    [Fact]
    public void TryGet_ReturnsNull_WhenKeyNotFound()
    {
        // Arrange
        using var cache = CreateCache();

        // Act
        var result = cache.TryGet("nonexistent");

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public void Contains_ReturnsTrue_WhenKeyExists()
    {
        // Arrange
        using var cache = CreateCache();
        var keyId = "test-key";
        var key = new byte[] { 1, 2, 3 };
        cache.Store(keyId, key);

        // Act & Assert
        Assert.True(cache.Contains(keyId));
    }

    [Fact]
    public void Contains_ReturnsFalse_WhenKeyNotFound()
    {
        // Arrange
        using var cache = CreateCache();

        // Act & Assert
        Assert.False(cache.Contains("nonexistent"));
    }

    [Fact]
    public void Remove_DeletesKey()
    {
        // Arrange
        using var cache = CreateCache();
        var keyId = "test-key";
        var key = new byte[] { 1, 2, 3 };
        cache.Store(keyId, key);

        // Act
        cache.Remove(keyId);

        // Assert
        Assert.False(cache.Contains(keyId));
        Assert.Null(cache.TryGet(keyId));
    }

    [Fact]
    public void Clear_RemovesAllKeys()
    {
        // Arrange
        using var cache = CreateCache();
        cache.Store("key1", new byte[] { 1 });
        cache.Store("key2", new byte[] { 2 });
        cache.Store("key3", new byte[] { 3 });

        // Act
        cache.Clear();

        // Assert
        Assert.False(cache.Contains("key1"));
        Assert.False(cache.Contains("key2"));
        Assert.False(cache.Contains("key3"));
    }

    [Fact]
    public void Store_OverwritesExistingKey()
    {
        // Arrange
        using var cache = CreateCache();
        var keyId = "test-key";
        var key1 = new byte[] { 1, 2, 3 };
        var key2 = new byte[] { 4, 5, 6 };

        // Act
        cache.Store(keyId, key1);
        cache.Store(keyId, key2);
        var retrieved = cache.TryGet(keyId);

        // Assert
        Assert.NotNull(retrieved);
        Assert.Equal(key2, retrieved);
    }

    [Fact]
    public void Dispose_ClearsAllKeys()
    {
        // Arrange
        var cache = CreateCache();
        cache.Store("key1", new byte[] { 1 });

        // Act
        cache.Dispose();

        // Assert
        Assert.Throws<ObjectDisposedException>(() => cache.Store("key2", new byte[] { 2 }));
    }
}
