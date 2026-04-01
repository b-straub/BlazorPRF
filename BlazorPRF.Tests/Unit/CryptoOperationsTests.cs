using System.Text.Json;
using BlazorPRF.BC.Crypto;
using BlazorPRF.Shared.Crypto.Json;
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

    // ============================================================
    // SIGN+ENCRYPT TESTS (SignedEnvelope inside encrypted payload)
    // ============================================================

    [Fact]
    public void SignedEnvelope_SerializationRoundTrip()
    {
        // Arrange
        var envelope = new SignedEnvelope("Hello!", "sig123", "pubkey456");

        // Act
        var json = JsonSerializer.Serialize(envelope, SharedJsonContext.Default.SignedEnvelope);
        var deserialized = JsonSerializer.Deserialize(json, SharedJsonContext.Default.SignedEnvelope);

        // Assert
        Assert.NotNull(deserialized);
        Assert.Equal(envelope.Message, deserialized.Message);
        Assert.Equal(envelope.Signature, deserialized.Signature);
        Assert.Equal(envelope.SenderEd25519PublicKey, deserialized.SenderEd25519PublicKey);
    }

    [Fact]
    public void SignAndEncrypt_DecryptAndVerify_RoundTrip()
    {
        // Arrange
        var seed = new byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(seed);
        var senderKeys = KeyGenerator.DeriveDualKeyPair(seed);

        var recipientX25519 = KeyGenerator.GenerateKeyPair();
        const string plaintext = "Secret signed message";

        // Sign
        var signResult = CryptoOperations.Sign(plaintext, senderKeys.Ed25519PrivateKey);
        Assert.True(signResult.Success);

        // Bundle into envelope and encrypt
        var envelope = new SignedEnvelope(plaintext, signResult.Value!, senderKeys.Ed25519PublicKey);
        var envelopeJson = JsonSerializer.Serialize(envelope, SharedJsonContext.Default.SignedEnvelope);
        var encryptResult = CryptoOperations.EncryptAsymmetric(envelopeJson, recipientX25519.PublicKeyBase64);
        Assert.True(encryptResult.Success);

        // Decrypt
        var decryptResult = CryptoOperations.DecryptAsymmetric(encryptResult.Value!, recipientX25519.PrivateKeyBase64);
        Assert.True(decryptResult.Success);

        // Parse envelope and verify
        var decryptedEnvelope = JsonSerializer.Deserialize(decryptResult.Value!, SharedJsonContext.Default.SignedEnvelope);
        Assert.NotNull(decryptedEnvelope);
        Assert.Equal(plaintext, decryptedEnvelope.Message);

        var isValid = CryptoOperations.Verify(
            decryptedEnvelope.Message,
            decryptedEnvelope.Signature,
            decryptedEnvelope.SenderEd25519PublicKey);
        Assert.True(isValid);
    }

    [Fact]
    public void SignAndEncrypt_WrongSenderKey_VerificationFails()
    {
        // Arrange
        var senderKeys = KeyGenerator.GenerateEd25519KeyPair();
        var attackerKeys = KeyGenerator.GenerateEd25519KeyPair();
        var recipientX25519 = KeyGenerator.GenerateKeyPair();
        const string plaintext = "Signed message";

        // Sign with sender's key
        var signResult = CryptoOperations.Sign(plaintext, senderKeys.PrivateKeyBase64);
        Assert.True(signResult.Success);

        // Bundle with ATTACKER's public key (substitution attempt)
        var envelope = new SignedEnvelope(plaintext, signResult.Value!, attackerKeys.PublicKeyBase64);
        var envelopeJson = JsonSerializer.Serialize(envelope, SharedJsonContext.Default.SignedEnvelope);
        var encryptResult = CryptoOperations.EncryptAsymmetric(envelopeJson, recipientX25519.PublicKeyBase64);
        Assert.True(encryptResult.Success);

        // Decrypt and verify — should fail because signature doesn't match attacker's key
        var decryptResult = CryptoOperations.DecryptAsymmetric(encryptResult.Value!, recipientX25519.PrivateKeyBase64);
        Assert.True(decryptResult.Success);

        var decryptedEnvelope = JsonSerializer.Deserialize(decryptResult.Value!, SharedJsonContext.Default.SignedEnvelope);
        Assert.NotNull(decryptedEnvelope);

        var isValid = CryptoOperations.Verify(
            decryptedEnvelope.Message,
            decryptedEnvelope.Signature,
            decryptedEnvelope.SenderEd25519PublicKey);
        Assert.False(isValid);
    }

    [Fact]
    public void SignedEnvelope_CannotBeStripped_FromEncryptedPayload()
    {
        // Arrange
        var senderKeys = KeyGenerator.GenerateEd25519KeyPair();
        var recipientX25519 = KeyGenerator.GenerateKeyPair();
        const string plaintext = "Cannot strip my signature";

        var signResult = CryptoOperations.Sign(plaintext, senderKeys.PrivateKeyBase64);
        Assert.True(signResult.Success);

        var envelope = new SignedEnvelope(plaintext, signResult.Value!, senderKeys.PublicKeyBase64);
        var envelopeJson = JsonSerializer.Serialize(envelope, SharedJsonContext.Default.SignedEnvelope);
        var encryptResult = CryptoOperations.EncryptAsymmetric(envelopeJson, recipientX25519.PublicKeyBase64);
        Assert.True(encryptResult.Success);

        // The EncryptedMessage has no Signature field — it's inside the ciphertext
        // An attacker cannot strip it without decrypting first
        var encrypted = encryptResult.Value!;
        Assert.NotNull(encrypted.EphemeralPublicKey);
        Assert.NotNull(encrypted.Ciphertext);
        Assert.NotNull(encrypted.Nonce);

        // Decrypt — envelope is intact inside
        var decryptResult = CryptoOperations.DecryptAsymmetric(encrypted, recipientX25519.PrivateKeyBase64);
        Assert.True(decryptResult.Success);

        var decryptedEnvelope = JsonSerializer.Deserialize(decryptResult.Value!, SharedJsonContext.Default.SignedEnvelope);
        Assert.NotNull(decryptedEnvelope);
        Assert.NotNull(decryptedEnvelope.Signature);
        Assert.NotNull(decryptedEnvelope.SenderEd25519PublicKey);
        Assert.Equal(plaintext, decryptedEnvelope.Message);
    }

    // ============================================================
    // ATTACK SIMULATION TESTS
    // ============================================================

    [Fact]
    public void Attack_CiphertextTampering_DetectedByAead()
    {
        // An attacker modifies the ciphertext — AEAD tag mismatch detects it
        var recipientKeys = KeyGenerator.GenerateKeyPair();
        var encryptResult = CryptoOperations.EncryptAsymmetric("Secret", recipientKeys.PublicKeyBase64);
        Assert.True(encryptResult.Success);

        // Tamper with ciphertext
        var ciphertextBytes = Convert.FromBase64String(encryptResult.Value!.Ciphertext);
        ciphertextBytes[0] ^= 0xFF;
        var tampered = encryptResult.Value with { Ciphertext = Convert.ToBase64String(ciphertextBytes) };

        var decryptResult = CryptoOperations.DecryptAsymmetric(tampered, recipientKeys.PrivateKeyBase64);
        Assert.False(decryptResult.Success);
        Assert.Equal(PrfErrorCode.AUTHENTICATION_TAG_MISMATCH, decryptResult.ErrorCode);
    }

    [Fact]
    public void Attack_NonceTampering_DetectedByAead()
    {
        // An attacker modifies the nonce — decryption fails
        var recipientKeys = KeyGenerator.GenerateKeyPair();
        var encryptResult = CryptoOperations.EncryptAsymmetric("Secret", recipientKeys.PublicKeyBase64);
        Assert.True(encryptResult.Success);

        var nonceBytes = Convert.FromBase64String(encryptResult.Value!.Nonce);
        nonceBytes[0] ^= 0xFF;
        var tampered = encryptResult.Value with { Nonce = Convert.ToBase64String(nonceBytes) };

        var decryptResult = CryptoOperations.DecryptAsymmetric(tampered, recipientKeys.PrivateKeyBase64);
        Assert.False(decryptResult.Success);
    }

    [Fact]
    public void Attack_EphemeralKeySwap_DetectedByAead()
    {
        // An attacker replaces the ephemeral public key — derived shared secret differs
        var recipientKeys = KeyGenerator.GenerateKeyPair();
        var attackerKeys = KeyGenerator.GenerateKeyPair();
        var encryptResult = CryptoOperations.EncryptAsymmetric("Secret", recipientKeys.PublicKeyBase64);
        Assert.True(encryptResult.Success);

        // Replace ephemeral key with attacker's key
        var tampered = encryptResult.Value! with { EphemeralPublicKey = attackerKeys.PublicKeyBase64 };

        var decryptResult = CryptoOperations.DecryptAsymmetric(tampered, recipientKeys.PrivateKeyBase64);
        Assert.False(decryptResult.Success);
        Assert.Equal(PrfErrorCode.AUTHENTICATION_TAG_MISMATCH, decryptResult.ErrorCode);
    }

    [Fact]
    public void Attack_SignatureForgedWithDifferentKey_Detected()
    {
        // An attacker signs the same message with their own key — verification against original key fails
        var legitimateKeys = KeyGenerator.GenerateEd25519KeyPair();
        var attackerKeys = KeyGenerator.GenerateEd25519KeyPair();
        const string message = "Transfer $1000";

        var attackerSignature = CryptoOperations.Sign(message, attackerKeys.PrivateKeyBase64);
        Assert.True(attackerSignature.Success);

        // Verify against legitimate key — fails
        var isValid = CryptoOperations.Verify(message, attackerSignature.Value!, legitimateKeys.PublicKeyBase64);
        Assert.False(isValid);
    }

    [Fact]
    public void Attack_SignedEnvelope_MessageTampering_Detected()
    {
        // An attacker decrypts, modifies the message, re-encrypts — signature check fails
        var senderKeys = KeyGenerator.GenerateEd25519KeyPair();
        var recipientKeys = KeyGenerator.GenerateKeyPair();
        const string originalMessage = "Transfer $100";

        // Sender creates signed envelope
        var signResult = CryptoOperations.Sign(originalMessage, senderKeys.PrivateKeyBase64);
        Assert.True(signResult.Success);

        // Attacker creates tampered envelope with original signature
        var tamperedEnvelope = new SignedEnvelope("Transfer $10000", signResult.Value!, senderKeys.PublicKeyBase64);
        var tamperedJson = JsonSerializer.Serialize(tamperedEnvelope, SharedJsonContext.Default.SignedEnvelope);
        var encryptResult = CryptoOperations.EncryptAsymmetric(tamperedJson, recipientKeys.PublicKeyBase64);
        Assert.True(encryptResult.Success);

        // Recipient decrypts and verifies — signature doesn't match tampered message
        var decryptResult = CryptoOperations.DecryptAsymmetric(encryptResult.Value!, recipientKeys.PrivateKeyBase64);
        Assert.True(decryptResult.Success);

        var envelope = JsonSerializer.Deserialize(decryptResult.Value!, SharedJsonContext.Default.SignedEnvelope);
        Assert.NotNull(envelope);

        var isValid = CryptoOperations.Verify(envelope.Message, envelope.Signature, envelope.SenderEd25519PublicKey);
        Assert.False(isValid);
    }

    [Fact]
    public void Attack_SignedEnvelope_CrossMessageReplay_Detected()
    {
        // An attacker takes a signed envelope from one message and puts it in another encryption
        // Since the envelope is inside the ciphertext, this only works if attacker can decrypt
        // But even then, the envelope contains the original message — recipient sees the original, not a forged one
        var senderKeys = KeyGenerator.GenerateEd25519KeyPair();
        var recipientKeys = KeyGenerator.GenerateKeyPair();

        // Message 1
        var signResult1 = CryptoOperations.Sign("Approve request A", senderKeys.PrivateKeyBase64);
        Assert.True(signResult1.Success);
        var envelope1 = new SignedEnvelope("Approve request A", signResult1.Value!, senderKeys.PublicKeyBase64);

        // Message 2 — attacker tries to use envelope1's signature for a different message
        var envelope2 = new SignedEnvelope("Approve request B", signResult1.Value!, senderKeys.PublicKeyBase64);
        var json2 = JsonSerializer.Serialize(envelope2, SharedJsonContext.Default.SignedEnvelope);
        var encryptResult = CryptoOperations.EncryptAsymmetric(json2, recipientKeys.PublicKeyBase64);
        Assert.True(encryptResult.Success);

        var decryptResult = CryptoOperations.DecryptAsymmetric(encryptResult.Value!, recipientKeys.PrivateKeyBase64);
        Assert.True(decryptResult.Success);

        var envelope = JsonSerializer.Deserialize(decryptResult.Value!, SharedJsonContext.Default.SignedEnvelope);
        Assert.NotNull(envelope);

        // Signature was for "Approve request A" but message says "Approve request B" — fails
        var isValid = CryptoOperations.Verify(envelope.Message, envelope.Signature, envelope.SenderEd25519PublicKey);
        Assert.False(isValid);
    }

    [Fact]
    public void Attack_SymmetricKeyReuse_DifferentNonces()
    {
        // Verify that encrypting the same plaintext twice produces different ciphertexts (random nonce)
        var keys = KeyGenerator.GenerateKeyPair();
        const string plaintext = "Same message twice";

        var result1 = CryptoOperations.EncryptSymmetric(plaintext, keys.PrivateKeyBase64);
        var result2 = CryptoOperations.EncryptSymmetric(plaintext, keys.PrivateKeyBase64);
        Assert.True(result1.Success);
        Assert.True(result2.Success);

        // Nonces must differ
        Assert.NotEqual(result1.Value!.Nonce, result2.Value!.Nonce);
        // Ciphertexts must differ (different nonce → different ciphertext)
        Assert.NotEqual(result1.Value.Ciphertext, result2.Value.Ciphertext);
    }

    [Fact]
    public void Attack_DifferentSeedsDifferentKeys()
    {
        // Two different PRF seeds must produce completely different key material
        var seed1 = new byte[32];
        var seed2 = new byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(seed1);
        System.Security.Cryptography.RandomNumberGenerator.Fill(seed2);

        var keys1 = KeyGenerator.DeriveDualKeyPair(seed1);
        var keys2 = KeyGenerator.DeriveDualKeyPair(seed2);

        Assert.NotEqual(keys1.X25519PublicKey, keys2.X25519PublicKey);
        Assert.NotEqual(keys1.Ed25519PublicKey, keys2.Ed25519PublicKey);
        Assert.NotEqual(keys1.X25519PrivateKey, keys2.X25519PrivateKey);
        Assert.NotEqual(keys1.Ed25519PrivateKey, keys2.Ed25519PrivateKey);
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
