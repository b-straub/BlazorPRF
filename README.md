# BlazorPRF

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![.NET](https://img.shields.io/badge/.NET-10.0-purple.svg)](https://dotnet.microsoft.com/)
[![NuGet](https://img.shields.io/nuget/v/BlazorPRF.Noble.Crypto)](https://www.nuget.org/packages/BlazorPRF.Noble.Crypto)
[![Build and Test](https://github.com/b-straub/BlazorPRF/actions/workflows/build.yml/badge.svg)](https://github.com/b-straub/BlazorPRF/actions/workflows/build.yml)
[![GitHub Repo stars](https://img.shields.io/github/stars/b-straub/BlazorPRF)](https://github.com/b-straub/BlazorPRF/stargazers)

PRF-based deterministic encryption for Blazor WebAssembly using the WebAuthn PRF extension.

## Security Disclaimer

> **This is an experimental project and has NOT been audited for security vulnerabilities.**
>
> While BlazorPRF uses established, well-reviewed cryptographic libraries (Noble.js and BouncyCastle for WASM, browser-native SubtleCrypto), the integration and implementation have not undergone professional security review.
>
> **Do NOT use this in production systems handling sensitive data without a thorough security audit.**
>
> The cryptographic primitives used (X25519, ChaCha20-Poly1305, AES-GCM, Ed25519, HKDF) are industry-standard, but correct implementation is critical for security.

## Overview

BlazorPRF enables client-side encryption in Blazor WebAssembly applications using biometric authentication. Keys are derived deterministically from the WebAuthn PRF (Pseudo-Random Function) extension output, meaning the same passkey always produces the same encryption keys.

**[Live Demo](https://b-straub.github.io/BlazorPRF/)**

### Key Features

- **Biometric Key Derivation**: Use your fingerprint, Face ID, or security key to derive encryption keys
- **Deterministic Keys**: Same passkey + salt = same keys across all synced devices
- **Client-Side Encryption**: All cryptography happens in the browser - keys never leave the client
- **Symmetric Encryption**: Encrypt data for yourself using ChaCha20-Poly1305 or AES-GCM
- **Asymmetric Encryption**: Share your public key; others can encrypt messages only you can decrypt (ECIES with X25519)
- **Digital Signatures**: Sign and verify messages with Ed25519 for authentication and integrity
- **Identity Verification**: Establish trust through dual-signed invites (like PGP "full trust")
- **Secure Key Storage**: Keys cached in JS, cryptographically zeroed on disposal

## Packages

### Crypto Providers (choose one)

| Package | Crypto Library | Description |
|---------|----------------|-------------|
| [BlazorPRF.Noble.Crypto](https://www.nuget.org/packages/BlazorPRF.Noble.Crypto) | Noble.js + SubtleCrypto | X25519, Ed25519, ChaCha20-Poly1305, AES-GCM. Keys cached in JS. |
| [BlazorPRF.BC.Crypto](https://www.nuget.org/packages/BlazorPRF.BC.Crypto) | BouncyCastle | Full BouncyCastle crypto stack for WASM. |

### UI Components (matches your crypto provider)

| Package | Description |
|---------|-------------|
| [BlazorPRF.Noble.UI](https://www.nuget.org/packages/BlazorPRF.Noble.UI) | MudBlazor UI components + services for Noble.Crypto |
| [BlazorPRF.BC.UI](https://www.nuget.org/packages/BlazorPRF.BC.UI) | MudBlazor UI components + services for BC.Crypto |

### Standalone Libraries

| Package | Description |
|---------|-------------|
| [BlazorPRF.Wasm.Crypto](https://www.nuget.org/packages/BlazorPRF.Wasm.Crypto) | Simple WebAuthn PRF library. Keys never leave JS - salt-based lookup with AES-GCM and Ed25519. |
| [BlazorPRF.Server.Crypto](https://www.nuget.org/packages/BlazorPRF.Server.Crypto) | Server-side crypto using BouncyCastle for .NET backends. |

### Choosing a Crypto Provider

```
Noble.Crypto (recommended):
  └─ Uses Noble.js - audited, lightweight JavaScript crypto
  └─ Hardware-accelerated AES-GCM via SubtleCrypto

BC.Crypto (alternative):
  └─ Uses BouncyCastle - full-featured .NET crypto library
  └─ All crypto runs in WASM (no JS interop for crypto ops)

Simple use case (just encrypt/sign):
  └─ Use BlazorPRF.Wasm.Crypto (standalone, minimal dependencies)
```

## Quick Start

### 1. Install the packages

```bash
# Noble flavor (recommended)
dotnet add package BlazorPRF.Noble.UI
dotnet add package BlazorPRF.Noble.Crypto

# OR BC flavor
dotnet add package BlazorPRF.BC.UI
dotnet add package BlazorPRF.BC.Crypto
```

### 2. Configure services

```csharp
// Program.cs
builder.Services.AddBlazorPrfUI(builder.Configuration);

// Add crypto provider (matches your UI package)
builder.Services.AddNobleCrypto();     // For Noble flavor
// builder.Services.AddBcCrypto();     // For BC flavor
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
- **Symmetric Encryption**: ChaCha20-Poly1305 or AES-256-GCM (AEAD)
- **Asymmetric Encryption**: X25519 ECDH + symmetric cipher (ECIES)
- **Digital Signatures**: Ed25519 (sign/verify)
- **Key Storage**: Keys cached in JS as non-extractable CryptoKey objects with cryptographic zeroing

## Dual Key Derivation

BlazorPRF derives two independent key pairs from a single PRF seed:

```
PRF Seed (32 bytes)
       │
       ├─── HKDF(context: "x25519-encryption") ──→ X25519 Key Pair (encryption)
       │
       └─── HKDF(context: "ed25519-signing")  ──→ Ed25519 Key Pair (signatures)
```

This enables:
- **X25519**: Asymmetric encryption (ECIES) - share public key, receive encrypted messages
- **Ed25519**: Digital signatures - sign messages to prove identity/integrity

## Identity Verification (Signed Invites)

BlazorPRF implements a dual-signature invite flow for secure identity verification:

```
USER A (Inviter)                    USER B (Invitee)
     │                                    │
     │ 1. Create invite for email         │
     │ 2. Sign invite with Ed25519        │
     │ 3. Send signed invite ─────────────┼───→ 4. Verify A's signature
     │                                    │    5. Sign acceptance with B's keys
     │    7. Verify A's original sig ←────┼─── 6. Send signed response
     │    8. Verify B's signature         │
     │                                    │
     ▼                                    ▼
 ✅ Both signatures valid = Trusted identity
```

**Security guarantees:**
- A's signature proves the invite is authentic (not forged)
- B's signature proves key ownership (B controls the private keys)
- Combined verification prevents invite tampering and key substitution

## Browser Support

Requires browsers supporting the WebAuthn PRF extension:
- Chrome 109+ / Edge 109+ (with platform authenticator)
- Safari 16.4+ (with iCloud Keychain)
- Firefox: Not yet supported

> **Note**: PRF support depends on both the browser AND the authenticator (passkey provider). Platform authenticators (Windows Hello, Touch ID, Face ID) generally have good support.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    BlazorPRF.*.UI                               │
│  (WebAuthn PRF, Key Derivation, Services, MudBlazor Components) │
└─────────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────────┐
│                   BlazorPRF.Shared.Crypto                       │
│        (ICryptoProvider, Models, Abstractions)                  │
└─────────────────────────────────────────────────────────────────┘
                              │
            ┌─────────────────┴─────────────────┐
            │                                   │
┌───────────────────────┐           ┌───────────────────────┐
│ BlazorPRF.Noble.Crypto│           │  BlazorPRF.BC.Crypto  │
│                       │           │                       │
│  - Noble.js           │           │  - BouncyCastle       │
│  - SubtleCrypto       │           │  - Pure .NET crypto   │
│  - Keys stay in JS    │           │  - Keys stay in JS    │
└───────────────────────┘           └───────────────────────┘
```

## Sample Application

See [BlazorPRF.Sample](./BlazorPRF.Sample/) for a complete example application demonstrating:
- Passkey registration
- Symmetric encryption/decryption
- Asymmetric encryption with public key sharing
- Digital signatures (sign and verify)
- Identity verification via signed invites
- Session management with different caching strategies

## License

MIT License - see [LICENSE](./LICENSE) for details.

## Contributing

Contributions are welcome! Please note that any security-related changes should be carefully reviewed.
