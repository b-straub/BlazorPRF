using BlazorPRF.Crypto;
using BlazorPRF.Shared.Models;
using PseudoPRF.Services;

namespace BlazorPRF.Tests.Unit;

/// <summary>
/// Tests for PseudoPRF cryptographic operations.
/// These tests verify cross-platform compatibility with BlazorPRF.
/// </summary>
public class PseudoPrfTests
{
    [Fact]
    public void GenerateKeyPair_CreatesValidKeys()
    {
        // Act
        var keyPair = KeyGenerator.GenerateKeyPair();

        // Assert
        Assert.NotNull(keyPair.PrivateKeyBase64);
        Assert.NotNull(keyPair.PublicKeyBase64);
        Assert.True(KeyGenerator.IsValidPrivateKey(keyPair.PrivateKeyBase64));
        Assert.True(KeyGenerator.IsValidPublicKey(keyPair.PublicKeyBase64));

        // Keys should be 32 bytes (256 bits) base64 encoded
        var privateBytes = Convert.FromBase64String(keyPair.PrivateKeyBase64);
        var publicBytes = Convert.FromBase64String(keyPair.PublicKeyBase64);
        Assert.Equal(32, privateBytes.Length);
        Assert.Equal(32, publicBytes.Length);
    }

    [Fact]
    public void GetPublicKey_DerivesSamePublicKeyFromPrivate()
    {
        // Arrange
        var keyPair = KeyGenerator.GenerateKeyPair();

        // Act
        var derivedPublicKey = KeyGenerator.GetPublicKey(keyPair.PrivateKeyBase64);

        // Assert
        Assert.Equal(keyPair.PublicKeyBase64, derivedPublicKey);
    }

    [Fact]
    public void SymmetricEncryption_RoundTrip_Success()
    {
        // Arrange
        var keyPair = KeyGenerator.GenerateKeyPair();
        const string plaintext = "Hello, World! 🌍";

        // Act
        var encryptResult = PseudoPrfCrypto.EncryptSymmetric(plaintext, keyPair.PrivateKeyBase64);

        Assert.True(encryptResult.Success);
        Assert.NotNull(encryptResult.Value);

        var decryptResult = PseudoPrfCrypto.DecryptSymmetric(encryptResult.Value, keyPair.PrivateKeyBase64);

        // Assert
        Assert.True(decryptResult.Success);
        Assert.Equal(plaintext, decryptResult.Value);
    }

    [Fact]
    public void SymmetricDecryption_WrongKey_ReturnsTagMismatch()
    {
        // Arrange
        var keyPair1 = KeyGenerator.GenerateKeyPair();
        var keyPair2 = KeyGenerator.GenerateKeyPair();
        const string plaintext = "Secret message";

        // Act
        var encryptResult = PseudoPrfCrypto.EncryptSymmetric(plaintext, keyPair1.PrivateKeyBase64);
        Assert.True(encryptResult.Success);

        var decryptResult = PseudoPrfCrypto.DecryptSymmetric(encryptResult.Value!, keyPair2.PrivateKeyBase64);

        // Assert
        Assert.False(decryptResult.Success);
        Assert.Equal(PrfErrorCode.AuthenticationTagMismatch, decryptResult.ErrorCode);
    }

    [Fact]
    public void AsymmetricEncryption_RoundTrip_Success()
    {
        // Arrange
        var recipientKeyPair = KeyGenerator.GenerateKeyPair();
        const string plaintext = "Confidential data for recipient";

        // Act - Encrypt to recipient's public key
        var encryptResult = PseudoPrfCrypto.EncryptAsymmetric(plaintext, recipientKeyPair.PublicKeyBase64);

        Assert.True(encryptResult.Success, $"Encryption failed: {encryptResult.ErrorCode}");
        Assert.NotNull(encryptResult.Value);
        Assert.NotNull(encryptResult.Value.EphemeralPublicKey);
        Assert.NotNull(encryptResult.Value.Ciphertext);
        Assert.NotNull(encryptResult.Value.Nonce);

        // Act - Decrypt with recipient's private key
        var decryptResult = PseudoPrfCrypto.DecryptAsymmetric(encryptResult.Value, recipientKeyPair.PrivateKeyBase64);

        // Assert
        Assert.True(decryptResult.Success, $"Decryption failed: {decryptResult.ErrorCode}");
        Assert.Equal(plaintext, decryptResult.Value);
    }

    [Fact]
    public void AsymmetricDecryption_WrongPrivateKey_ReturnsTagMismatch()
    {
        // Arrange
        var recipientKeyPair = KeyGenerator.GenerateKeyPair();
        var wrongKeyPair = KeyGenerator.GenerateKeyPair();
        const string plaintext = "Secret";

        // Act
        var encryptResult = PseudoPrfCrypto.EncryptAsymmetric(plaintext, recipientKeyPair.PublicKeyBase64);
        Assert.True(encryptResult.Success);

        var decryptResult = PseudoPrfCrypto.DecryptAsymmetric(encryptResult.Value!, wrongKeyPair.PrivateKeyBase64);

        // Assert
        Assert.False(decryptResult.Success);
        Assert.Equal(PrfErrorCode.AuthenticationTagMismatch, decryptResult.ErrorCode);
    }

    [Fact]
    public void EncryptedMessage_ContainsValidBase64()
    {
        // Arrange
        var recipientKeyPair = KeyGenerator.GenerateKeyPair();

        // Act
        var encryptResult = PseudoPrfCrypto.EncryptAsymmetric("test", recipientKeyPair.PublicKeyBase64);

        // Assert
        Assert.True(encryptResult.Success);
        var msg = encryptResult.Value!;

        // All fields should be valid base64
        Assert.NotNull(Convert.FromBase64String(msg.EphemeralPublicKey));
        Assert.NotNull(Convert.FromBase64String(msg.Ciphertext));
        Assert.NotNull(Convert.FromBase64String(msg.Nonce));

        // Ephemeral public key should be 32 bytes (X25519)
        Assert.Equal(32, Convert.FromBase64String(msg.EphemeralPublicKey).Length);

        // Nonce should be 12 bytes (ChaCha20-Poly1305)
        Assert.Equal(12, Convert.FromBase64String(msg.Nonce).Length);
    }

    [Fact]
    public void GenerateSalt_CreatesRandomValues()
    {
        // Act
        var salt1 = KeyGenerator.GenerateSalt();
        var salt2 = KeyGenerator.GenerateSalt();

        // Assert
        Assert.NotEqual(salt1, salt2);

        // Default is 32 bytes
        var saltBytes = Convert.FromBase64String(salt1);
        Assert.Equal(32, saltBytes.Length);
    }

    [Fact]
    public void GenerateSalt_CustomLength_CreatesCorrectSize()
    {
        // Act
        var salt = KeyGenerator.GenerateSalt(16);

        // Assert
        var saltBytes = Convert.FromBase64String(salt);
        Assert.Equal(16, saltBytes.Length);
    }
}
