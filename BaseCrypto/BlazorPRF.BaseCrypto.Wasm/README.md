# BlazorPRF.BaseCrypto.Wasm

Simple WebAuthn PRF-based encryption library for Blazor WebAssembly.

## Features

- **Secure by Design**: Private keys never leave JavaScript - stored as non-extractable CryptoKey objects
- **Salt-Based Key Lookup**: All crypto operations use salt identifiers, not raw keys
- **AES-256-GCM Encryption**: Hardware-accelerated symmetric encryption via SubtleCrypto
- **Ed25519 Signing**: Digital signatures for message authentication
- **Key Caching**: Automatic TTL-based key expiration with event notifications
- **Discoverable Credentials**: Support for passkey autofill UI

## Installation

```bash
dotnet add package BlazorPRF.BaseCrypto.Wasm
```

## Usage

### Register Services

```csharp
builder.Services.AddBasePrf();
```

### Register a Passkey

```csharp
@inject IBasePrfService PrfService

var result = await PrfService.RegisterAsync("My Passkey");
if (result.Success)
{
    var credentialId = result.Value; // Store this for later authentication
}
```

### Authenticate and Cache Keys

```csharp
// Keys are derived from PRF output and cached in JS by salt
var authResult = await PrfService.AuthenticateAsync(
    credentialId,
    saltBase64,
    cacheTtl: TimeSpan.FromMinutes(15));

if (authResult.Success)
{
    // authResult.Value.PublicKey - Ed25519 public key (safe to share)
    // Private keys stay in JS, referenced by salt
}
```

### Encrypt/Decrypt

```csharp
// Encrypt - uses cached key identified by salt
var encrypted = await PrfService.EncryptAsync("Hello, World!", saltBase64);

// Decrypt
var decrypted = await PrfService.DecryptAsync(encrypted.Value, saltBase64);
```

### Sign/Verify

```csharp
// Sign - uses cached Ed25519 key
var signature = await PrfService.SignAsync("message to sign", saltBase64);

// Verify - can use any public key
var isValid = await PrfService.VerifyAsync("message to sign", signature.Value, publicKeyBase64);
```

### Key Expiration

```csharp
PrfService.KeyExpired += salt =>
{
    Console.WriteLine($"Keys expired for salt: {salt}");
    // Re-authenticate if needed
};
```

## Architecture

```
C# (.NET WASM)                    JavaScript (WebCrypto)
    |                                    |
    |-- Authenticate(salt) ------------>|
    |                                    |-- WebAuthn PRF
    |                                    |-- Derive keys (HKDF)
    |                                    |-- Cache as CryptoKey (non-extractable)
    |<-- PublicKey only -----------------|
    |                                    |
    |-- Encrypt(plaintext, salt) ------>|
    |                                    |-- Lookup key by salt
    |                                    |-- AES-GCM encrypt
    |<-- Ciphertext + Nonce ------------|
```

## Security Model

- PRF output from WebAuthn is used as key material
- Keys are derived using HKDF with domain separation
- Private keys are stored as non-extractable CryptoKey objects in JavaScript
- C# only receives public keys and references keys by salt
- All encryption uses authenticated encryption (AES-GCM)

## Browser Requirements

- WebAuthn Level 2 with PRF extension support
- SubtleCrypto API
- Modern browsers: Chrome 109+, Edge 109+, Safari 16.4+

## Related Packages

- `BlazorPRF.Noble.Crypto` - Full crypto provider using Noble.js (X25519, Ed25519, ChaCha20-Poly1305)
- `BlazorPRF.BC.Crypto` - BouncyCastle-based crypto for server-side scenarios

## License

MIT
