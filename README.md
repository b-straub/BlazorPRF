# BlazorPRF

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![.NET](https://img.shields.io/badge/.NET-10.0-purple.svg)](https://dotnet.microsoft.com/)
[![NuGet](https://img.shields.io/nuget/v/BlazorPRF.Noble.Crypto)](https://www.nuget.org/packages/BlazorPRF.Noble.Crypto)
[![Build and Test](https://github.com/b-straub/BlazorPRF/actions/workflows/build.yml/badge.svg)](https://github.com/b-straub/BlazorPRF/actions/workflows/build.yml)
[![GitHub Repo stars](https://img.shields.io/github/stars/b-straub/BlazorPRF)](https://github.com/b-straub/BlazorPRF/stargazers)

PRF-based deterministic encryption for Blazor WebAssembly using the WebAuthn PRF extension.

## Breaking Changes

- **Mandatory Sign+Encrypt**: Asymmetric encryption now always uses **sign+encrypt** — the sender's Ed25519 signature is embedded inside the encrypted payload (`SignedEnvelope`). This prevents signature stripping, sender substitution, and cross-message replay attacks. Messages encrypted with previous versions cannot be decrypted by this version. Re-encrypt any existing data.
- **ChaCha20-Poly1305 removed**: All encryption now uses AES-256-GCM exclusively. The `EncryptionAlgorithm` enum and algorithm selection parameters have been removed. Messages encrypted with ChaCha20-Poly1305 in earlier pre-release versions cannot be decrypted.

## Security Disclaimer

> **This is an experimental project and has NOT been audited for security vulnerabilities.**
>
> While BlazorPRF uses established, well-reviewed cryptographic libraries (Noble.js and BouncyCastle for WASM, browser-native SubtleCrypto), the integration and implementation have not undergone professional security review.
>
> **Do NOT use this in production systems handling sensitive data without a thorough security audit.**
>
> The cryptographic primitives used (X25519, AES-256-GCM, Ed25519, HKDF) are industry-standard, but correct implementation is critical for security.

## Overview

BlazorPRF enables client-side encryption in Blazor WebAssembly applications using biometric authentication. Keys are derived deterministically from the WebAuthn PRF (Pseudo-Random Function) extension output, meaning the same passkey always produces the same encryption keys.

**[Live Demo](https://b-straub.github.io/BlazorPRF/)**

### Key Features

- **Biometric Key Derivation**: Use your fingerprint, Face ID, or security key to derive encryption keys
- **Deterministic Keys**: Same passkey + salt = same keys across all synced devices
- **Client-Side Encryption**: All cryptography happens in the browser - keys never leave the client
- **Symmetric Encryption**: Encrypt data for yourself using AES-256-GCM
- **Asymmetric Encryption**: Share your public key; others can encrypt messages only you can decrypt (ECIES with X25519)
- **Digital Signatures**: Sign and verify messages with Ed25519 for authentication and integrity
- **Sign + Encrypt**: Sign plaintext with Ed25519 before encrypting — recipient can verify sender identity after decryption (like PGP sign+encrypt)
- **Identity Verification**: Establish trust through dual-signed invites (like PGP "full trust")
- **Secure Key Storage**: Keys cached in JS, cryptographically zeroed on disposal

## Packages

### Crypto Providers (choose one)

| Package | Crypto Library | Description |
|---------|----------------|-------------|
| [BlazorPRF.Noble.Crypto](https://www.nuget.org/packages/BlazorPRF.Noble.Crypto) | Noble.js + SubtleCrypto | X25519, Ed25519, AES-256-GCM. Non-extractable CryptoKey caching. |
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
- **Symmetric Encryption**: AES-256-GCM (AEAD, hardware accelerated via SubtleCrypto)
- **Asymmetric Encryption**: X25519 ECDH + AES-256-GCM (ECIES)
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

#### Recommended deployment layout

The Blazor app and PHP relay share the same domain. Place the relay in an `api/` subdirectory to avoid conflicts between `index.html` (Blazor) and `index.php` (PHP):

```
/var/www/niceprf/
  index.html              ← Blazor WASM app
  _framework/             ← Blazor runtime files
  _content/               ← Static web assets
  api/                    ← PHP mail relay
    index.php
    .htaccess
    lib/
    actions/
    PrfCrypto/
    secure/               ← NOT in git
      config.php
      admin_keys.json
      data/app.db
```

This way the relay URL is `https://your-domain.example.com/api/` — same origin, no CORS needed.

#### Prerequisites

- PHP 8.1+ with `sodium` and `imap` extensions
- Apache with `mod_rewrite` (or nginx with equivalent rules)
- HTTPS (required for signature security)

#### 1. Publish the Blazor app and deploy the relay

```bash
# Publish Blazor WASM
dotnet publish BlazorPRF.Sample -c Release -o ./publish

# Copy Blazor app to web root
cp -r ./publish/wwwroot/* /var/www/niceprf/

# Copy PHP relay into api/ subdirectory
cp -r Site/ /var/www/niceprf/api/

# Set ownership
chown -R www-data:www-data /var/www/niceprf/

# Restrict permissions on secure directory
chmod 700 /var/www/niceprf/api/secure/
chmod 600 /var/www/niceprf/api/secure/config.php
chmod 600 /var/www/niceprf/api/secure/admin_keys.json
```

#### 2. Create the configuration

```bash
cp /var/www/niceprf/api/secure/config.php.dist /var/www/niceprf/api/secure/config.php
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

The web root serves both the Blazor SPA (static files) and the PHP relay (in `api/`). Blazor WASM is a single-page app — all non-file routes must fall back to `index.html`.

**Apache** (ensure `AllowOverride All` for `.htaccess` support):

Create `/var/www/niceprf/.htaccess` in the web root:

```apache
RewriteEngine On

# Let api/ handle its own routing via its own .htaccess
RewriteRule ^api/ - [L]

# Blazor SPA fallback — serve index.html for all non-file, non-directory routes
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule .* index.html [L]
```

The `api/` subdirectory already has its own `.htaccess` (from `Site/`) for PHP routing and security.

```apache
<VirtualHost *:443>
    ServerName niceprf.example.com
    DocumentRoot /var/www/niceprf

    <Directory /var/www/niceprf>
        AllowOverride All
        Require all granted
    </Directory>

    # PHP for api/ subdirectory
    <Directory /var/www/niceprf/api>
        FallbackResource /api/index.php
    </Directory>

    SSLEngine on
    SSLCertificateFile /path/to/cert.pem
    SSLCertificateKeyFile /path/to/key.pem
</VirtualHost>
```

**nginx**:

```nginx
server {
    listen 443 ssl;
    server_name niceprf.example.com;
    root /var/www/niceprf;

    # PHP relay in api/ subdirectory
    location ^~ /api/ {
        # Block sensitive directories
        location ~ ^/api/(secure|lib|actions|PrfCrypto)/ {
            deny all;
        }

        # Route all api/ requests to api/index.php
        try_files $uri /api/index.php?path=$uri&$args;
    }

    location ~ \.php$ {
        fastcgi_pass unix:/run/php/php-fpm.sock;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }

    # Blazor SPA fallback
    location / {
        try_files $uri $uri/ /index.html;
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

## Testing

### Unit tests

```bash
dotnet test BlazorPRF.Tests/
```

Runs 62+ crypto unit and attack simulation tests (no server required):
- Key derivation, symmetric/asymmetric encryption round-trips
- Sign+encrypt with SignedEnvelope integrity
- Attack simulations: ciphertext tampering, nonce tampering, ephemeral key swap, signature forgery, sender substitution, cross-message replay, nonce reuse detection

### API integration tests

Requires a running mail relay. Tests are skipped automatically when no server is configured.

```bash
# Against local dev server (Herd/Valet)
PRF_API_URL="https://prf.test/api/" dotnet test BlazorPRF.Tests/

# Against production
PRF_API_URL="https://your-relay.example.com/api/" dotnet test BlazorPRF.Tests/

# Or use a .runsettings file (not committed, see .gitignore)
dotnet test --settings BlazorPRF.Tests/test.runsettings
```

API tests cover:
- **Auth attacks**: missing headers, invalid signature, unregistered key, expired timestamp, body tampering, method tampering, admin privilege escalation
- **Access control**: sensitive directories (`secure/`, `lib/`, `actions/`, `PrfCrypto/`), config files, database, PHP source code, `.htaccess`, path traversal

To create a `.runsettings` file:

```xml
<?xml version="1.0" encoding="utf-8"?>
<RunSettings>
  <RunConfiguration>
    <EnvironmentVariables>
      <PRF_API_URL>https://prf.test/api/</PRF_API_URL>
    </EnvironmentVariables>
  </RunConfiguration>
</RunSettings>
```

## License

MIT License - see [LICENSE](./LICENSE) for details.

## Contributing

Contributions are welcome! Please note that any security-related changes should be carefully reviewed.
