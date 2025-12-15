# BlazorPRF.BaseCrypto.Server

PRF-compatible encryption library for server applications using NSec/libsodium.

## Compatibility

This library is **fully compatible** with `BlazorPRF.Wasm.Crypto`:
- Data encrypted in the browser can be decrypted on the server
- Signatures created in WASM can be verified on the server
- Same key derivation produces identical keys on both platforms

## Features

- **AES-256-GCM Encryption**: Hardware-accelerated symmetric encryption
- **Ed25519 Signing**: Digital signatures for message authentication
- **NSec/libsodium**: Battle-tested native cryptography

## Installation

```bash
dotnet add package BlazorPRF.BaseCrypto.Server
```

## Usage

```csharp
// Decrypt data that was encrypted in the browser
var plaintext = await cryptoService.DecryptAsync(encryptedData, key);

// Verify a signature created in WASM
var isValid = await cryptoService.VerifyAsync(message, signature, publicKey);
```

## Use Cases

- **Server-side decryption**: Process data encrypted by WASM clients
- **Signature verification**: Verify client signatures on the server
- **Background services**: Process encrypted data in server workers
- **API endpoints**: Handle encrypted payloads from browser clients

## Related Packages

- `BlazorPRF.Wasm.Crypto` - Browser/WASM version (keys stay in JS)

## License

MIT
