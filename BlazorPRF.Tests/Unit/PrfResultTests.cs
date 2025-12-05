using BlazorPRF.Models;
using BlazorPRF.Shared.Models;

namespace BlazorPRF.Tests.Unit;

public class PrfResultTests
{
    [Fact]
    public void Ok_CreatesSuccessfulResult()
    {
        // Act
        var result = PrfResult<string>.Ok("test value");

        // Assert
        Assert.True(result.Success);
        Assert.Equal("test value", result.Value);
        Assert.Null(result.Error);
        Assert.Null(result.ErrorCode);
    }

    [Fact]
    public void Fail_CreatesFailedResult()
    {
        // Act
        var result = PrfResult<string>.Fail(PrfErrorCode.DecryptionFailed);

        // Assert
        Assert.False(result.Success);
        Assert.Null(result.Value);
        Assert.Equal(PrfErrorCode.DecryptionFailed, result.ErrorCode);
        Assert.NotNull(result.Error);
        Assert.Contains("Decryption failed", result.Error);
    }

    [Fact]
    public void UserCancelled_CreatesCancelledResult()
    {
        // Act
        var result = PrfResult<string>.UserCancelled();

        // Assert
        Assert.False(result.Success);
        Assert.True(result.Cancelled);
        Assert.Null(result.Value);
        Assert.Null(result.ErrorCode);
        Assert.Null(result.Error);
    }

    [Fact]
    public void Ok_WithComplexType_WorksCorrectly()
    {
        // Arrange
        var credential = new PrfCredential("id123", "rawId123");

        // Act
        var result = PrfResult<PrfCredential>.Ok(credential);

        // Assert
        Assert.True(result.Success);
        Assert.NotNull(result.Value);
        Assert.Equal("id123", result.Value.Id);
        Assert.Equal("rawId123", result.Value.RawId);
    }

    [Theory]
    [InlineData(PrfErrorCode.Unknown, "unknown error")]
    [InlineData(PrfErrorCode.PrfNotSupported, "PRF extension")]
    [InlineData(PrfErrorCode.AuthenticationTagMismatch, "wrong key")]
    [InlineData(PrfErrorCode.KeyDerivationFailed, "Key derivation failed")]
    [InlineData(PrfErrorCode.EncryptionFailed, "Encryption failed")]
    [InlineData(PrfErrorCode.DecryptionFailed, "Decryption failed")]
    [InlineData(PrfErrorCode.RegistrationFailed, "registration failed")]
    public void ErrorMessages_ContainExpectedText(PrfErrorCode errorCode, string expectedSubstring)
    {
        // Act
        var message = PrfErrorMessages.GetMessage(errorCode);

        // Assert
        Assert.Contains(expectedSubstring, message, StringComparison.OrdinalIgnoreCase);
    }
}
