namespace BlazorPRF.Api.Models;

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
/// Request to register a new public key.
/// </summary>
public sealed record RegisterKeyRequest(
    string KeyId,
    string PublicKey,
    string? UserId);
