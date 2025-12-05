using System.Text.Json;
using System.Text.Json.Serialization;
using BlazorPRF.Shared.Models;

namespace BlazorPRF.Shared.Json;

/// <summary>
/// Source-generated JSON serialization context for shared PRF types.
/// </summary>
[JsonSourceGenerationOptions(
    JsonSerializerDefaults.Web,
    UseStringEnumConverter = true)]
[JsonSerializable(typeof(EncryptedMessage))]
[JsonSerializable(typeof(SymmetricEncryptedMessage))]
[JsonSerializable(typeof(KeyPair))]
[JsonSerializable(typeof(PrfResult<EncryptedMessage>))]
[JsonSerializable(typeof(PrfResult<SymmetricEncryptedMessage>))]
[JsonSerializable(typeof(PrfResult<string>))]
[JsonSerializable(typeof(PrfResult<KeyPair>))]
public partial class SharedJsonContext : JsonSerializerContext;
