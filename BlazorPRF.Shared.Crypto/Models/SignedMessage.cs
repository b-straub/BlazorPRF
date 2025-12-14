namespace BlazorPRF.Shared.Crypto.Models;

/// <summary>
/// A signed message with its Ed25519 signature.
/// </summary>
public sealed record SignedMessage(
    /// <summary>The original message content.</summary>
    string Message,
    /// <summary>Base64-encoded Ed25519 signature (64 bytes).</summary>
    string Signature,
    /// <summary>Base64-encoded Ed25519 public key for verification.</summary>
    string PublicKey,
    /// <summary>Unix timestamp (seconds since 1970-01-01 UTC) when the message was signed.</summary>
    long TimestampUnix
);
