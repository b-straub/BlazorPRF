using System.Text.Json.Serialization;

namespace BlazorPRF.Sample.Models;

/// <summary>
/// Registered public key from the backend.
/// </summary>
public sealed record RegisteredKey(
    string KeyId,
    string? PublicKey,
    string? UserId,
    long CreatedAt,
    long? RevokedAt)
{
    /// <summary>
    /// Created timestamp as local DateTime.
    /// </summary>
    public DateTime CreatedDateTime => DateTimeOffset.FromUnixTimeSeconds(CreatedAt).LocalDateTime;
}

/// <summary>
/// Response from /register GET endpoint listing registered keys.
/// </summary>
public sealed record KeysListResponse(List<RegisteredKey> Keys);

/// <summary>
/// Response from debug verification endpoints.
/// </summary>
public sealed record VerifyResponse(
    bool Verified,
    string? Error,
    string? KeyId,
    string? Note);

/// <summary>
/// Response from registration/key operations.
/// </summary>
public sealed record KeyOperationResponse(
    bool Success,
    string? KeyId,
    string? Error);

/// <summary>
/// Source-generated JSON serializer context for Admin API models.
/// Uses camelCase naming (JsonSerializerDefaults.Web) for PHP backend compatibility.
/// </summary>
[JsonSourceGenerationOptions(System.Text.Json.JsonSerializerDefaults.Web)]
[JsonSerializable(typeof(RegisteredKey))]
[JsonSerializable(typeof(List<RegisteredKey>))]
[JsonSerializable(typeof(KeysListResponse))]
[JsonSerializable(typeof(VerifyResponse))]
[JsonSerializable(typeof(KeyOperationResponse))]
public partial class AdminApiJsonContext : JsonSerializerContext;
