# BlazorPRF

PRF-based deterministic encryption for Blazor WebAssembly using the WebAuthn PRF extension.

## Security Disclaimer

> **This is a hobby project and has NOT been audited for security vulnerabilities.**
>
> While BlazorPRF uses established, well-reviewed cryptographic libraries (BouncyCastle, NSec, libsodium), the integration and implementation have not undergone professional security review.
>
> **Do NOT use this in production systems handling sensitive data without a thorough security audit.**
>
> The cryptographic primitives used (X25519, ChaCha20-Poly1305, HKDF) are industry-standard, but correct implementation is critical for security.

## Overview

BlazorPRF enables client-side encryption in Blazor WebAssembly applications using biometric authentication. Keys are derived deterministically from the WebAuthn PRF (Pseudo-Random Function) extension output, meaning the same passkey always produces the same encryption keys.

### Key Features

- **Biometric Key Derivation**: Use your fingerprint, Face ID, or security key to derive encryption keys
- **Deterministic Keys**: Same passkey + salt = same keys across all synced devices
- **Client-Side Encryption**: All cryptography happens in the browser - keys never leave the client
- **Symmetric Encryption**: Encrypt data for yourself using ChaCha20-Poly1305
- **Asymmetric Encryption**: Share your public key; others can encrypt messages only you can decrypt (ECIES with X25519)
- **Secure Key Storage**: Keys stored in unmanaged memory, cryptographically zeroed on disposal

## Packages

| Package | Description |
|---------|-------------|
| [BlazorPRF](./BlazorPRF/) | Core library - WebAuthn PRF integration, key derivation, encryption services |
| [BlazorPRF.UI](./BlazorPRF.UI/) | MudBlazor UI components for encryption workflows |
| [BlazorPRF.Crypto](./BlazorPRF.Crypto/) | WASM-compatible crypto operations using BouncyCastle |
| [BlazorPRF.Shared](./BlazorPRF.Shared/) | Shared models and interfaces |
| [PseudoPRF](./PseudoPRF/) | Standalone encryption library compatible with BlazorPRF (for non-WASM environments) |

## Quick Start

### 1. Install the packages

```bash
dotnet add package BlazorPRF
dotnet add package BlazorPRF.UI  # Optional: MudBlazor components
```

### 2. Configure services

```csharp
// Program.cs
builder.Services.AddBlazorPrf(builder.Configuration);

// For UI components
ObservableModels.Initialize(builder.Services);
builder.Services.AddSingleton<PrfAuthenticationStateProvider>();
builder.Services.AddSingleton<AuthenticationStateProvider>(sp =>
    sp.GetRequiredService<PrfAuthenticationStateProvider>());
```

### 3. Add configuration

```json
// appsettings.json
{
  "BlazorPRF": {
    "RpName": "Your App Name",
    "TimeoutMs": 60000,
    "AuthenticatorAttachment": "Platform",
    "KeyCache": {
      "Strategy": "Timed",
      "TtlMinutes": 15
    }
  }
}
```

### Key Caching Strategies

| Strategy | Description |
|----------|-------------|
| `None` | Keys derived fresh for each operation (most secure) |
| `Session` | Keys cached until page refresh |
| `Timed` | Keys cached with configurable TTL (recommended) |

## Cryptographic Primitives

- **Key Derivation**: HKDF-SHA256 from WebAuthn PRF output
- **Symmetric Encryption**: ChaCha20-Poly1305 (AEAD)
- **Asymmetric Encryption**: X25519 ECDH + ChaCha20-Poly1305 (ECIES)
- **Key Storage**: Unmanaged memory with cryptographic zeroing

## Browser Support

Requires browsers supporting the WebAuthn PRF extension:
- Chrome 116+ (with platform authenticator)
- Edge 116+
- Safari 17+ (with iCloud Keychain)

## Sample Application

See [BlazorPRF.Sample](./BlazorPRF.Sample/) for a complete example application demonstrating:
- Passkey registration
- Symmetric encryption/decryption
- Asymmetric encryption with public key sharing
- Session management with different caching strategies

## License

MIT License - see [LICENSE](./LICENSE) for details.

## Contributing

Contributions are welcome! Please note that any security-related changes should be carefully reviewed.
