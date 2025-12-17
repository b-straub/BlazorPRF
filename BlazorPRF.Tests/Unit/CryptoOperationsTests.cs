using BlazorPRF.BC.Crypto;
using BlazorPRF.Shared.Crypto.Models;

namespace BlazorPRF.Tests.Unit;

/// <summary>
/// Tests for BouncyCastle cryptographic operations.
/// These tests verify the crypto primitives work correctly.
/// </summary>
public class CryptoOperationsTests
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
        var encryptResult = CryptoOperations.EncryptSymmetric(plaintext, keyPair.PrivateKeyBase64);

        Assert.True(encryptResult.Success);
        Assert.NotNull(encryptResult.Value);

        var decryptResult = CryptoOperations.DecryptSymmetric(encryptResult.Value, keyPair.PrivateKeyBase64);

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
        var encryptResult = CryptoOperations.EncryptSymmetric(plaintext, keyPair1.PrivateKeyBase64);
        Assert.True(encryptResult.Success);
        Assert.NotNull(encryptResult.Value);

        var decryptResult = CryptoOperations.DecryptSymmetric(encryptResult.Value, keyPair2.PrivateKeyBase64);

        // Assert
        Assert.False(decryptResult.Success);
        Assert.Equal(PrfErrorCode.AUTHENTICATION_TAG_MISMATCH, decryptResult.ErrorCode);
    }

    [Fact]
    public void AsymmetricEncryption_RoundTrip_Success()
    {
        // Arrange
        var recipientKeyPair = KeyGenerator.GenerateKeyPair();
        const string plaintext = "Confidential data for recipient";

        // Act - Encrypt to recipient's public key
        var encryptResult = CryptoOperations.EncryptAsymmetric(plaintext, recipientKeyPair.PublicKeyBase64);

        Assert.True(encryptResult.Success, $"Encryption failed: {encryptResult.ErrorCode}");
        Assert.NotNull(encryptResult.Value);
        Assert.NotNull(encryptResult.Value.EphemeralPublicKey);
        Assert.NotNull(encryptResult.Value.Ciphertext);
        Assert.NotNull(encryptResult.Value.Nonce);

        // Act - Decrypt with recipient's private key
        var decryptResult = CryptoOperations.DecryptAsymmetric(encryptResult.Value, recipientKeyPair.PrivateKeyBase64);

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
        var encryptResult = CryptoOperations.EncryptAsymmetric(plaintext, recipientKeyPair.PublicKeyBase64);
        Assert.True(encryptResult.Success);
        Assert.NotNull(encryptResult.Value);

        var decryptResult = CryptoOperations.DecryptAsymmetric(encryptResult.Value, wrongKeyPair.PrivateKeyBase64);

        // Assert
        Assert.False(decryptResult.Success);
        Assert.Equal(PrfErrorCode.AUTHENTICATION_TAG_MISMATCH, decryptResult.ErrorCode);
    }

    [Fact]
    public void EncryptedMessage_ContainsValidBase64()
    {
        // Arrange
        var recipientKeyPair = KeyGenerator.GenerateKeyPair();

        // Act
        var encryptResult = CryptoOperations.EncryptAsymmetric("test", recipientKeyPair.PublicKeyBase64);

        // Assert
        Assert.True(encryptResult.Success);
        Assert.NotNull(encryptResult.Value);
        var msg = encryptResult.Value;

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

    // ============================================================
    // ED25519 SIGNING TESTS
    // ============================================================

    [Fact]
    public void GenerateEd25519KeyPair_CreatesValidKeys()
    {
        // Act
        var keyPair = KeyGenerator.GenerateEd25519KeyPair();

        // Assert
        Assert.NotNull(keyPair.PrivateKeyBase64);
        Assert.NotNull(keyPair.PublicKeyBase64);
        Assert.True(KeyGenerator.IsValidEd25519PrivateKey(keyPair.PrivateKeyBase64));
        Assert.True(KeyGenerator.IsValidEd25519PublicKey(keyPair.PublicKeyBase64));

        // Keys should be 32 bytes (256 bits) base64 encoded
        var privateBytes = Convert.FromBase64String(keyPair.PrivateKeyBase64);
        var publicBytes = Convert.FromBase64String(keyPair.PublicKeyBase64);
        Assert.Equal(32, privateBytes.Length);
        Assert.Equal(32, publicBytes.Length);
    }

    [Fact]
    public void GetEd25519PublicKey_DerivesSamePublicKeyFromPrivate()
    {
        // Arrange
        var keyPair = KeyGenerator.GenerateEd25519KeyPair();

        // Act
        var derivedPublicKey = KeyGenerator.GetEd25519PublicKey(keyPair.PrivateKeyBase64);

        // Assert
        Assert.Equal(keyPair.PublicKeyBase64, derivedPublicKey);
    }

    [Fact]
    public void Sign_CreatesValidSignature()
    {
        // Arrange
        var keyPair = KeyGenerator.GenerateEd25519KeyPair();
        const string message = "Hello, World!";

        // Act
        var signResult = CryptoOperations.Sign(message, keyPair.PrivateKeyBase64);

        // Assert
        Assert.True(signResult.Success);
        Assert.NotNull(signResult.Value);

        // Ed25519 signature is 64 bytes
        var signatureBytes = Convert.FromBase64String(signResult.Value);
        Assert.Equal(64, signatureBytes.Length);
    }

    [Fact]
    public void SignAndVerify_RoundTrip_Success()
    {
        // Arrange
        var keyPair = KeyGenerator.GenerateEd25519KeyPair();
        const string message = "Hello, World! 🌍";

        // Act
        var signResult = CryptoOperations.Sign(message, keyPair.PrivateKeyBase64);
        Assert.True(signResult.Success);
        Assert.NotNull(signResult.Value);

        var isValid = CryptoOperations.Verify(message, signResult.Value, keyPair.PublicKeyBase64);

        // Assert
        Assert.True(isValid);
    }

    [Fact]
    public void Verify_WrongMessage_ReturnsFalse()
    {
        // Arrange
        var keyPair = KeyGenerator.GenerateEd25519KeyPair();
        const string originalMessage = "Hello, World!";
        const string tamperedMessage = "Hello, World!!";

        // Act
        var signResult = CryptoOperations.Sign(originalMessage, keyPair.PrivateKeyBase64);
        Assert.True(signResult.Success);
        Assert.NotNull(signResult.Value);

        var isValid = CryptoOperations.Verify(tamperedMessage, signResult.Value, keyPair.PublicKeyBase64);

        // Assert
        Assert.False(isValid);
    }

    [Fact]
    public void Verify_WrongPublicKey_ReturnsFalse()
    {
        // Arrange
        var keyPair1 = KeyGenerator.GenerateEd25519KeyPair();
        var keyPair2 = KeyGenerator.GenerateEd25519KeyPair();
        const string message = "Secret message";

        // Act
        var signResult = CryptoOperations.Sign(message, keyPair1.PrivateKeyBase64);
        Assert.True(signResult.Success);
        Assert.NotNull(signResult.Value);

        var isValid = CryptoOperations.Verify(message, signResult.Value, keyPair2.PublicKeyBase64);

        // Assert
        Assert.False(isValid);
    }

    [Fact]
    public void DeriveDualKeyPair_CreatesBothKeyPairs()
    {
        // Arrange
        var seed = new byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(seed);

        // Act
        var dualKeys = KeyGenerator.DeriveDualKeyPair(seed);

        // Assert
        Assert.True(KeyGenerator.IsValidPrivateKey(dualKeys.X25519PrivateKey));
        Assert.True(KeyGenerator.IsValidPublicKey(dualKeys.X25519PublicKey));
        Assert.True(KeyGenerator.IsValidEd25519PrivateKey(dualKeys.Ed25519PrivateKey));
        Assert.True(KeyGenerator.IsValidEd25519PublicKey(dualKeys.Ed25519PublicKey));

        // Keys should be different due to different HKDF contexts
        Assert.NotEqual(dualKeys.X25519PrivateKey, dualKeys.Ed25519PrivateKey);
        Assert.NotEqual(dualKeys.X25519PublicKey, dualKeys.Ed25519PublicKey);
    }

    [Fact]
    public void DeriveDualKeyPair_DeterministicFromSameSeed()
    {
        // Arrange
        var seed = new byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(seed);

        // Act
        var dualKeys1 = KeyGenerator.DeriveDualKeyPair(seed);
        var dualKeys2 = KeyGenerator.DeriveDualKeyPair(seed);

        // Assert - Same seed produces same keys
        Assert.Equal(dualKeys1.X25519PrivateKey, dualKeys2.X25519PrivateKey);
        Assert.Equal(dualKeys1.X25519PublicKey, dualKeys2.X25519PublicKey);
        Assert.Equal(dualKeys1.Ed25519PrivateKey, dualKeys2.Ed25519PrivateKey);
        Assert.Equal(dualKeys1.Ed25519PublicKey, dualKeys2.Ed25519PublicKey);
    }

    [Fact]
    public void DeriveDualKeyPair_EncryptionAndSigningWork()
    {
        // Arrange
        var seed = new byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(seed);
        var dualKeys = KeyGenerator.DeriveDualKeyPair(seed);
        const string message = "Test message";

        // Act & Assert - X25519 encryption works
        var encryptResult = CryptoOperations.EncryptAsymmetric(message, dualKeys.X25519PublicKey);
        Assert.True(encryptResult.Success);
        Assert.NotNull(encryptResult.Value);

        var decryptResult = CryptoOperations.DecryptAsymmetric(encryptResult.Value, dualKeys.X25519PrivateKey);
        Assert.True(decryptResult.Success);
        Assert.Equal(message, decryptResult.Value);

        // Act & Assert - Ed25519 signing works
        var signResult = CryptoOperations.Sign(message, dualKeys.Ed25519PrivateKey);
        Assert.True(signResult.Success);
        Assert.NotNull(signResult.Value);

        var isValid = CryptoOperations.Verify(message, signResult.Value, dualKeys.Ed25519PublicKey);
        Assert.True(isValid);
    }

    [Fact]
    public void DualKeyPair_PublicKeysProperty_ReturnsCorrectKeys()
    {
        // Arrange
        var seed = new byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(seed);

        // Act
        var dualKeys = KeyGenerator.DeriveDualKeyPair(seed);
        var publicKeys = dualKeys.PublicKeys;

        // Assert
        Assert.Equal(dualKeys.X25519PublicKey, publicKeys.X25519PublicKey);
        Assert.Equal(dualKeys.Ed25519PublicKey, publicKeys.Ed25519PublicKey);
    }

    [Fact]
    public void CreateSignedMessage_CreatesValidStructure()
    {
        // Arrange
        var keyPair = KeyGenerator.GenerateEd25519KeyPair();
        const string message = "Token data";

        // Act
        var result = CryptoOperations.CreateSignedMessage(message, keyPair.PrivateKeyBase64, keyPair.PublicKeyBase64);

        // Assert
        Assert.True(result.Success);
        Assert.NotNull(result.Value);
        Assert.Equal(message, result.Value.Message);
        Assert.NotNull(result.Value.Signature);
        Assert.Equal(keyPair.PublicKeyBase64, result.Value.PublicKey);
        Assert.True(result.Value.TimestampUnix <= (long)(DateTime.UtcNow - DateTime.UnixEpoch).TotalSeconds);
    }

    [Fact]
    public void VerifySignedMessage_ValidMessage_ReturnsTrue()
    {
        // Arrange
        var keyPair = KeyGenerator.GenerateEd25519KeyPair();
        const string message = "Token data";
        var signedMessage = CryptoOperations.CreateSignedMessage(message, keyPair.PrivateKeyBase64, keyPair.PublicKeyBase64);
        Assert.True(signedMessage.Success);
        Assert.NotNull(signedMessage.Value);

        // Act
        var isValid = CryptoOperations.VerifySignedMessage(signedMessage.Value);

        // Assert
        Assert.True(isValid);
    }

    [Fact]
    public void VerifySignedMessage_TamperedMessage_ReturnsFalse()
    {
        // Arrange
        var keyPair = KeyGenerator.GenerateEd25519KeyPair();
        const string message = "Token data";
        var signedMessage = CryptoOperations.CreateSignedMessage(message, keyPair.PrivateKeyBase64, keyPair.PublicKeyBase64);
        Assert.True(signedMessage.Success);
        Assert.NotNull(signedMessage.Value);

        // Tamper with the message
        var tamperedMessage = signedMessage.Value with { Message = "Tampered data" };

        // Act
        var isValid = CryptoOperations.VerifySignedMessage(tamperedMessage);

        // Assert
        Assert.False(isValid);
    }
}
