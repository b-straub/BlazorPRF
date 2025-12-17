using System.Text.Json;
using System.Text.Json.Serialization;
using BlazorPRF.Persistence.Data.Models;
using BlazorPRF.Persistence.Services;
using BlazorPRF.Shared.Crypto.Models;

namespace BlazorPRF.Persistence.Json;

/// <summary>
/// Source-generated JSON serialization context for persistence types.
/// </summary>
[JsonSourceGenerationOptions(
    JsonSerializerDefaults.Web,
    UseStringEnumConverter = true)]
[JsonSerializable(typeof(ContactUserData))]
[JsonSerializable(typeof(EncryptionCredentialInfo))]
[JsonSerializable(typeof(SymmetricEncryptedMessage))]
public partial class PersistenceJsonContext : JsonSerializerContext;
