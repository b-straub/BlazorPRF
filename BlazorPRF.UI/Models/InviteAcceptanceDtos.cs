using System.Text.Json;
using System.Text.Json.Serialization;

namespace BlazorPRF.UI.Models;

/// <summary>
/// Signed invite data from the original invitation.
/// Used for JSON deserialization of invite acceptance responses.
/// </summary>
public sealed record SignedInvite(
    string? InviteCode,
    string? InviterSignature,
    string? InviterEd25519PublicKey,
    string? InviterX25519PublicKey,
    string? InviterUsername,
    string? InviterEmail);

/// <summary>
/// Response structure when accepting an invitation.
/// Contains the accepter's identity and cryptographic keys.
/// </summary>
public sealed record InviteAcceptanceResponse(
    SignedInvite? SignedInvite,
    string? Username,
    string? Email,
    string? X25519PublicKey,
    string? Ed25519PublicKey,
    long Timestamp,
    string? Message,
    string? Signature);

/// <summary>
/// Source-generated JSON serializer context for invite DTOs.
/// Uses camelCase naming and is AOT/trimming compatible.
/// </summary>
[JsonSourceGenerationOptions(
    JsonSerializerDefaults.Web,
    WriteIndented = true)]
[JsonSerializable(typeof(SignedInvite))]
[JsonSerializable(typeof(InviteAcceptanceResponse))]
public partial class InviteJsonContext : JsonSerializerContext;
