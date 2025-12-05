using System.Text.Json;
using BlazorPRF.Json;
using BlazorPRF.Models;
using BlazorPRF.Shared.Models;

namespace BlazorPRF.Tests.Unit;

public class EncryptedMessageTests
{
    [Fact]
    public void EncryptedMessage_SerializesToJson()
    {
        // Arrange
        var message = new EncryptedMessage(
            "ephemeralKey123",
            "ciphertext456",
            "nonce789"
        );

        // Act
        var json = JsonSerializer.Serialize(message, PrfJsonContext.Default.EncryptedMessage);
        var deserialized = JsonSerializer.Deserialize(json, PrfJsonContext.Default.EncryptedMessage);

        // Assert
        Assert.NotNull(deserialized);
        Assert.Equal(message.EphemeralPublicKey, deserialized.EphemeralPublicKey);
        Assert.Equal(message.Ciphertext, deserialized.Ciphertext);
        Assert.Equal(message.Nonce, deserialized.Nonce);
    }

    [Fact]
    public void SymmetricEncryptedMessage_SerializesToJson()
    {
        // Arrange
        var message = new SymmetricEncryptedMessage(
            "ciphertext456",
            "nonce789"
        );

        // Act
        var json = JsonSerializer.Serialize(message, PrfJsonContext.Default.SymmetricEncryptedMessage);
        var deserialized = JsonSerializer.Deserialize(json, PrfJsonContext.Default.SymmetricEncryptedMessage);

        // Assert
        Assert.NotNull(deserialized);
        Assert.Equal(message.Ciphertext, deserialized.Ciphertext);
        Assert.Equal(message.Nonce, deserialized.Nonce);
    }

    [Fact]
    public void PrfCredential_SerializesToJson()
    {
        // Arrange
        var credential = new PrfCredential("testId", "testRawId");

        // Act
        var json = JsonSerializer.Serialize(credential, PrfJsonContext.Default.PrfCredential);
        var deserialized = JsonSerializer.Deserialize(json, PrfJsonContext.Default.PrfCredential);

        // Assert
        Assert.NotNull(deserialized);
        Assert.Equal(credential.Id, deserialized.Id);
        Assert.Equal(credential.RawId, deserialized.RawId);
    }
}
