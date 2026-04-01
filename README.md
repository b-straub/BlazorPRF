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
- **Sign + Encrypt**: Sign plaintext with Ed25519 before encrypting — recipient can verify sender identity after decryption (like PGP sign+encrypt)
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
- **Sign + Encrypt**: Messages are signed with Ed25519 before encryption. The signature and sender's public key are included in the encrypted payload. On decryption, the sender's identity is verified against trusted contacts.

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
- Sign + encrypt with sender verification on decrypt
- Identity verification via signed invites
- Session management with different caching strategies
- Encrypted mail sending via PRF-authenticated mail relay

## Mail Relay (Site/)

The `Site/` directory contains a PHP backend that acts as an authenticated mail relay. Browsers cannot make raw SMTP/IMAP socket connections, so this server relays mail on behalf of authenticated users.

### How it works

```
Blazor WASM Client                    PHP Mail Relay                    Mail Server
       │                                    │                               │
       │ 1. Sign request with Ed25519       │                               │
       │ 2. Include SMTP credentials        │                               │
       │ 3. POST /send_mail ───────────────→│                               │
       │                                    │ 4. Verify Ed25519 signature   │
       │                                    │ 5. Check key is registered    │
       │                                    │ 6. Check timestamp + nonce    │
       │                                    │ 7. Open SMTP connection ─────→│
       │                                    │ 8. Send email                 │
       │                          ←─────────│ 9. Return result              │
```

Every API request is signed with the user's PRF-derived Ed25519 private key. The server verifies the signature against registered public keys before executing any action. This prevents unauthorized use of the relay.

### Security model

- **No stored credentials**: SMTP/IMAP passwords are sent per-request (encrypted in the user's profile on the client, decrypted only when needed). The server never stores them.
- **Ed25519 request signing**: Every request includes timestamp, nonce, body hash, and signature. Replay attacks are prevented by nonce tracking and timestamp tolerance.
- **Admin key registration**: Only an admin (whose Ed25519 public key is configured server-side) can register user keys. Unregistered keys are rejected.
- **SSRF protection**: SMTP/IMAP host parameters are validated against private/reserved IP ranges.
- **No open relay**: Without a registered key, the server rejects all mail operations.

### API endpoints

| Endpoint | Auth | Description |
|----------|------|-------------|
| `GET /` | None | Health check |
| `GET /admin-setup` | None | Check if admin is configured |
| `POST /register` | Admin | Register a user's Ed25519 public key |
| `GET /keys` | Admin | List registered keys |
| `DELETE /keys?keyId=...` | Admin | Revoke a key |
| `POST /send_mail` | User | Send email via SMTP |
| `POST /test_smtp` | User | Test SMTP connection |
| `POST /test_imap` | User | Test IMAP / fetch emails |

### Secure setup guide

#### Prerequisites

- PHP 8.1+ with `sodium` and `imap` extensions
- Apache with `mod_rewrite` (or nginx with equivalent rules)
- HTTPS (required for signature security)

#### 1. Deploy the Site/ directory

```bash
# Copy to your web server
cp -r Site/ /var/www/mail-relay/

# Set ownership
chown -R www-data:www-data /var/www/mail-relay/

# Restrict permissions on secure directory
chmod 700 /var/www/mail-relay/secure/
chmod 600 /var/www/mail-relay/secure/config.php
chmod 600 /var/www/mail-relay/secure/admin_keys.json
```

#### 2. Create the configuration

```bash
cp /var/www/mail-relay/secure/config.php.dist /var/www/mail-relay/secure/config.php
```

Edit `config.php`:

```php
<?php
return [
    'dbPath' => __DIR__ . '/data/app.db',
    'allowedOrigins' => [
        'https://your-blazor-app.example.com',
        // Do NOT include localhost in production
    ],
    'timestampTolerance' => 300 // 5 minutes
];
```

#### 3. Create the data directory

```bash
mkdir -p /var/www/mail-relay/secure/data/
chmod 700 /var/www/mail-relay/secure/data/
# The SQLite database is created automatically on first request
```

#### 4. Bootstrap the admin key

This is a two-step process because the admin key comes from your passkey, which is only available in the browser.

**Step 1: Get your Ed25519 public key**

1. Open the BlazorPRF app and authenticate with your passkey
2. Navigate to the Mail page — it shows your Ed25519 signing key with a copy button
3. Copy the Base64 key (44 characters)

**Step 2: Install the admin key on the server**

```bash
# Via SSH to your server (never commit this file)
cat > /var/www/mail-relay/secure/admin_keys.json << 'EOF'
{
    "admin": "YOUR_ED25519_PUBLIC_KEY_BASE64_HERE"
}
EOF
chmod 600 /var/www/mail-relay/secure/admin_keys.json
```

**Step 3: Verify admin access**

1. Navigate to the Mail page in the app
2. The app automatically checks your key against the server
3. If your key matches `admin_keys.json`, the "Admin" section appears
4. You should see "Register New Key" and "Registered Keys" panels

#### 5. Register user keys

Once you have admin access:

1. Each user authenticates with their passkey and copies their Ed25519 public key from the Mail page
2. The admin pastes the user's key into "Register New Key" on the Mail page
3. Registered users can now send/receive mail through the relay

**Important**: Both the admin key (in `admin_keys.json`) and user keys (in `app.db`) are Ed25519 **signing** keys, not the X25519 encryption keys. Each user has both, derived from the same PRF seed.

#### 6. Configure your web server

**Apache** (`.htaccess` is included, ensure `AllowOverride All`):

```apache
<VirtualHost *:443>
    ServerName mail-relay.example.com
    DocumentRoot /var/www/mail-relay

    # Ensure .htaccess is respected
    <Directory /var/www/mail-relay>
        AllowOverride All
        Require all granted
    </Directory>

    # URL rewriting for single entry point
    FallbackResource /index.php

    SSLEngine on
    SSLCertificateFile /path/to/cert.pem
    SSLCertificateKeyFile /path/to/key.pem
</VirtualHost>
```

**nginx**:

```nginx
server {
    listen 443 ssl;
    server_name mail-relay.example.com;
    root /var/www/mail-relay;

    # Block access to sensitive directories
    location ~ ^/(secure|lib|actions|PrfCrypto)/ {
        deny all;
    }

    # Route all requests to index.php
    location / {
        try_files $uri /index.php?path=$uri&$args;
    }

    location ~ \.php$ {
        fastcgi_pass unix:/run/php/php-fpm.sock;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
}
```

#### 6. Register users

After deploying, use the BlazorPRF admin panel (visible to the admin key holder) to register user Ed25519 public keys. Only registered users can send/receive mail through the relay.

### Local development (Laravel Herd / Valet)

The `Site/` directory includes a `LocalValetDriver.php` for local development with Laravel Herd or Valet:

1. Link the site: `cd Site && herd link prf`
2. Secure it: `herd secure prf` (creates `https://prf.test`)
3. Create `secure/config.php` from `secure/config.php.dist`
4. Add `https://localhost:7212` (or your Blazor dev port) to `allowedOrigins`
5. Configure the API URL in `Program.cs`: `builder.Services.AddPrfApi("https://prf.test/api/")`
6. Follow the admin bootstrap steps above

### Production deployment checklist

- [ ] HTTPS enabled (required for Ed25519 signature security)
- [ ] `secure/` directory permissions: `700`
- [ ] `config.php` permissions: `600`, no localhost origins
- [ ] `admin_keys.json` permissions: `600`, deployed via SSH
- [ ] PHP `sodium` and `imap` extensions enabled
- [ ] `.htaccess` rules active (Apache) or equivalent nginx location blocks
- [ ] Verify health check: `curl https://your-relay.example.com/api/`

### Directory structure

```
Site/
  index.php                  # Single entry point, request routing
  LocalValetDriver.php       # Laravel Valet driver (local dev)
  .htaccess                  # Apache rewrite rules + directory protection
  actions/
    SendMail.php             # SMTP mail sending with TLS
    TestSmtp.php             # SMTP connection testing
    TestImap.php             # IMAP connection + email fetching
    .htaccess                # Deny direct access
  lib/
    Auth.php                 # Ed25519 signature verification, nonce tracking
    Database.php             # SQLite for registered keys + nonce storage
    Response.php             # JSON response helpers, CORS
    .htaccess                # Deny direct access
  PrfCrypto/
    PrfCrypto.php            # Ed25519 verify via libsodium
  secure/                    # NOT in git (see .gitignore)
    config.php               # Allowed origins, DB path, timestamp tolerance
    config.php.dist          # Template (in git)
    admin_keys.json          # Admin Ed25519 public key
    data/
      app.db                 # SQLite database (auto-created)
    .htaccess                # Deny all access
```

## License

MIT License - see [LICENSE](./LICENSE) for details.

## Contributing

Contributions are welcome! Please note that any security-related changes should be carefully reviewed.
