using System.Text.Json;
using System.Text.Json.Serialization;
using BlazorPRF.Models;

namespace BlazorPRF.Json;

/// <summary>
/// Source-generated JSON serialization context for PRF types.
/// </summary>
[JsonSourceGenerationOptions(
    JsonSerializerDefaults.Web,
    UseStringEnumConverter = true)]
[JsonSerializable(typeof(PrfCredential))]
[JsonSerializable(typeof(EncryptedMessage))]
[JsonSerializable(typeof(SymmetricEncryptedMessage))]
[JsonSerializable(typeof(PrfResult<PrfCredential>))]
[JsonSerializable(typeof(PrfResult<DerivedKeysResult>))]
[JsonSerializable(typeof(PrfResult<DiscoverableDerivedKeysResult>))]
[JsonSerializable(typeof(PrfResult<EncryptedMessage>))]
[JsonSerializable(typeof(PrfResult<string>))]
[JsonSerializable(typeof(JsPrfOptions))]
public partial class PrfJsonContext : JsonSerializerContext;

/// <summary>
/// PRF options as expected by JavaScript.
/// </summary>
public sealed record JsPrfOptions(
    string RpName,
    string? RpId,
    int TimeoutMs,
    string AuthenticatorAttachment
);
