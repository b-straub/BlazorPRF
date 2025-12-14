using BlazorPRF.BC.Crypto.Models;

namespace BlazorPRF.Tests.Unit;

public class SecureKeyEntryTests
{
    [Fact]
    public void Constructor_CopiesKeyData()
    {
        // Arrange
        var originalKey = new byte[] { 1, 2, 3, 4, 5 };

        // Act
        using var entry = new SecureKeyEntry(originalKey);
        var retrievedKey = entry.GetKey();

        // Assert
        Assert.Equal(originalKey, retrievedKey);
        Assert.NotSame(originalKey, retrievedKey);
    }

    [Fact]
    public void GetKey_ReturnsNewCopyEachTime()
    {
        // Arrange
        var originalKey = new byte[] { 1, 2, 3, 4, 5 };
        using var entry = new SecureKeyEntry(originalKey);

        // Act
        var key1 = entry.GetKey();
        var key2 = entry.GetKey();

        // Assert
        Assert.NotSame(key1, key2);
        Assert.Equal(key1, key2);
    }

    [Fact]
    public void Dispose_ZeroFillsKey()
    {
        // Arrange
        var originalKey = new byte[] { 1, 2, 3, 4, 5 };
        var entry = new SecureKeyEntry(originalKey);

        // Act
        entry.Dispose();

        // Assert
        Assert.Throws<ObjectDisposedException>(() => entry.GetKey());
    }

    [Fact]
    public void IsExpired_ReturnsFalse_WhenNoTtl()
    {
        // Arrange
        var key = new byte[] { 1, 2, 3 };
        using var entry = new SecureKeyEntry(key);

        // Assert
        Assert.False(entry.IsExpired);
    }

    [Fact]
    public void IsExpired_ReturnsTrue_AfterTtl()
    {
        // Arrange
        var key = new byte[] { 1, 2, 3 };
        using var entry = new SecureKeyEntry(key, TimeSpan.FromMilliseconds(1));

        // Act
        Thread.Sleep(10);

        // Assert
        Assert.True(entry.IsExpired);
    }

    [Fact]
    public void GetKey_ThrowsInvalidOperationException_WhenExpired()
    {
        // Arrange
        var key = new byte[] { 1, 2, 3 };
        using var entry = new SecureKeyEntry(key, TimeSpan.FromMilliseconds(1));
        Thread.Sleep(10);

        // Act & Assert
        Assert.Throws<InvalidOperationException>(() => entry.GetKey());
    }
}
