using System.Text.Json;
using System.Text.Json.Serialization;
using BlazorPRF.Crypto.Abstractions.Models;

namespace BlazorPRF.Crypto.Abstractions.Json;

/// <summary>
/// Source-generated JSON serialization context for shared PRF types.
/// </summary>
[JsonSourceGenerationOptions(
    JsonSerializerDefaults.Web,
    UseStringEnumConverter = true)]
[JsonSerializable(typeof(EncryptedMessage))]
[JsonSerializable(typeof(SignedEnvelope))]
[JsonSerializable(typeof(SymmetricEncryptedMessage))]
[JsonSerializable(typeof(SignedMessage))]
[JsonSerializable(typeof(KeyPair))]
[JsonSerializable(typeof(PrfResult<EncryptedMessage>))]
[JsonSerializable(typeof(PrfResult<SymmetricEncryptedMessage>))]
[JsonSerializable(typeof(PrfResult<SignedMessage>))]
[JsonSerializable(typeof(PrfResult<string>))]
[JsonSerializable(typeof(PrfResult<KeyPair>))]
public partial class SharedJsonContext : JsonSerializerContext;

/// <summary>
/// Source-generated JSON serialization context for SignedMessage.
/// </summary>
[JsonSourceGenerationOptions(JsonSerializerDefaults.Web)]
[JsonSerializable(typeof(SignedMessage))]
public partial class SignedMessageJsonContext : JsonSerializerContext;
