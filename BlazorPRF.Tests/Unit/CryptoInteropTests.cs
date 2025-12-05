using BlazorPRF.Crypto;
using PseudoPRF.Services;

namespace BlazorPRF.Tests.Unit;

/// <summary>
/// Tests to verify interoperability between NSec (PseudoPRF) and BouncyCastle (WasmCryptoOperations).
/// These tests ensure that messages encrypted by one implementation can be decrypted by the other.
/// </summary>
public class CryptoInteropTests
{
    [Fact]
    public void SymmetricEncryption_NSec_To_BouncyCastle()
    {
        // Arrange - Generate key using NSec (PseudoPRF)
        var keyPair = KeyGenerator.GenerateKeyPair();
        const string plaintext = "Hello from NSec! 🔐";

        // Act - Encrypt with NSec
        var encryptResult = PseudoPrfCrypto.EncryptSymmetric(plaintext, keyPair.PrivateKeyBase64);
        Assert.True(encryptResult.Success, $"NSec encryption failed: {encryptResult.ErrorCode}");

        // Decrypt with BouncyCastle
        var decryptResult = WasmCryptoOperations.DecryptSymmetric(encryptResult.Value!, keyPair.PrivateKeyBase64);

        // Assert
        Assert.True(decryptResult.Success, $"BouncyCastle decryption failed: {decryptResult.ErrorCode}");
        Assert.Equal(plaintext, decryptResult.Value);
    }

    [Fact]
    public void SymmetricEncryption_BouncyCastle_To_NSec()
    {
        // Arrange - Generate key using NSec (PseudoPRF)
        var keyPair = KeyGenerator.GenerateKeyPair();
        const string plaintext = "Hello from BouncyCastle! 🏰";

        // Act - Encrypt with BouncyCastle
        var encryptResult = WasmCryptoOperations.EncryptSymmetric(plaintext, keyPair.PrivateKeyBase64);
        Assert.True(encryptResult.Success, $"BouncyCastle encryption failed: {encryptResult.ErrorCode}");

        // Decrypt with NSec
        var decryptResult = PseudoPrfCrypto.DecryptSymmetric(encryptResult.Value!, keyPair.PrivateKeyBase64);

        // Assert
        Assert.True(decryptResult.Success, $"NSec decryption failed: {decryptResult.ErrorCode}");
        Assert.Equal(plaintext, decryptResult.Value);
    }

    [Fact]
    public void AsymmetricEncryption_NSec_To_BouncyCastle()
    {
        // Arrange - Generate key pair using NSec
        var keyPair = KeyGenerator.GenerateKeyPair();
        const string plaintext = "Asymmetric message from NSec! 🔑";

        // Act - Encrypt with NSec
        var encryptResult = PseudoPrfCrypto.EncryptAsymmetric(plaintext, keyPair.PublicKeyBase64);
        Assert.True(encryptResult.Success, $"NSec encryption failed: {encryptResult.ErrorCode}");

        // Decrypt with BouncyCastle
        var decryptResult = WasmCryptoOperations.DecryptAsymmetric(encryptResult.Value!, keyPair.PrivateKeyBase64);

        // Assert
        Assert.True(decryptResult.Success, $"BouncyCastle decryption failed: {decryptResult.ErrorCode}");
        Assert.Equal(plaintext, decryptResult.Value);
    }

    [Fact]
    public void AsymmetricEncryption_BouncyCastle_To_NSec()
    {
        // Arrange - Generate key pair using NSec
        var keyPair = KeyGenerator.GenerateKeyPair();
        const string plaintext = "Asymmetric message from BouncyCastle! 🏰";

        // Act - Encrypt with BouncyCastle
        var encryptResult = WasmCryptoOperations.EncryptAsymmetric(plaintext, keyPair.PublicKeyBase64);
        Assert.True(encryptResult.Success, $"BouncyCastle encryption failed: {encryptResult.ErrorCode}");

        // Decrypt with NSec
        var decryptResult = PseudoPrfCrypto.DecryptAsymmetric(encryptResult.Value!, keyPair.PrivateKeyBase64);

        // Assert
        Assert.True(decryptResult.Success, $"NSec decryption failed: {decryptResult.ErrorCode}");
        Assert.Equal(plaintext, decryptResult.Value);
    }

    [Fact]
    public void KeyDerivation_BouncyCastle_ProducesCompatibleKeys()
    {
        // Arrange - Simulate PRF output (32 random bytes)
        var prfOutput = new byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(prfOutput);
        var prfOutputBase64 = Convert.ToBase64String(prfOutput);

        // Act - Derive keypair using BouncyCastle
        var keypair = KeyDerivation.DeriveKeypairFromPrf(prfOutputBase64);

        // Verify keys are valid - encrypt with BouncyCastle, decrypt with NSec
        const string testMessage = "Testing key derivation compatibility";

        var encryptResult = WasmCryptoOperations.EncryptAsymmetric(testMessage, keypair.PublicKeyBase64);
        Assert.True(encryptResult.Success, $"Encryption failed: {encryptResult.ErrorCode}");

        var decryptResult = PseudoPrfCrypto.DecryptAsymmetric(encryptResult.Value!, keypair.PrivateKeyBase64);

        // Assert
        Assert.True(decryptResult.Success, $"Decryption failed: {decryptResult.ErrorCode}");
        Assert.Equal(testMessage, decryptResult.Value);
    }

    [Fact]
    public void KeyDerivation_BouncyCastle_DeterministicOutput()
    {
        // Arrange - Fixed 32-byte PRF output (deterministic test data)
        var prfOutput = new byte[32];
        for (int i = 0; i < 32; i++)
        {
            prfOutput[i] = (byte)(i * 7);
        }

        // Act - Derive keypair twice
        var keypair1 = KeyDerivation.DeriveKeypairFromPrf(prfOutput);
        var keypair2 = KeyDerivation.DeriveKeypairFromPrf(prfOutput);

        // Assert - Same input should produce same output
        Assert.Equal(keypair1.PrivateKeyBase64, keypair2.PrivateKeyBase64);
        Assert.Equal(keypair1.PublicKeyBase64, keypair2.PublicKeyBase64);
    }

    [Fact]
    public void LongMessage_Interop_Works()
    {
        // Arrange - Generate key pair and create a longer message
        var keyPair = KeyGenerator.GenerateKeyPair();
        var plaintext = new string('A', 10000) + "🚀" + new string('B', 10000);

        // Act - Encrypt with BouncyCastle, decrypt with NSec
        var encryptResult = WasmCryptoOperations.EncryptAsymmetric(plaintext, keyPair.PublicKeyBase64);
        Assert.True(encryptResult.Success);

        var decryptResult = PseudoPrfCrypto.DecryptAsymmetric(encryptResult.Value!, keyPair.PrivateKeyBase64);

        // Assert
        Assert.True(decryptResult.Success);
        Assert.Equal(plaintext, decryptResult.Value);
    }

    [Fact]
    public void EmptyMessage_Interop_Works()
    {
        // Arrange
        var keyPair = KeyGenerator.GenerateKeyPair();
        const string plaintext = "";

        // Act - Encrypt with NSec, decrypt with BouncyCastle
        var encryptResult = PseudoPrfCrypto.EncryptSymmetric(plaintext, keyPair.PrivateKeyBase64);
        Assert.True(encryptResult.Success);

        var decryptResult = WasmCryptoOperations.DecryptSymmetric(encryptResult.Value!, keyPair.PrivateKeyBase64);

        // Assert
        Assert.True(decryptResult.Success);
        Assert.Equal(plaintext, decryptResult.Value);
    }
}
