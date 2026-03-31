using System.Text.Json;
using System.Text.Json.Serialization;
using BlazorPRF.Api.Models;

namespace BlazorPRF.Api.Json;

/// <summary>
/// Source-generated JSON serializer context for API models.
/// Uses camelCase naming (JsonSerializerDefaults.Web) for PHP backend compatibility.
/// </summary>
[JsonSourceGenerationOptions(JsonSerializerDefaults.Web)]
[JsonSerializable(typeof(RegisteredKey))]
[JsonSerializable(typeof(List<RegisteredKey>))]
[JsonSerializable(typeof(KeysListResponse))]
[JsonSerializable(typeof(VerifyResponse))]
[JsonSerializable(typeof(KeyOperationResponse))]
[JsonSerializable(typeof(RegisterKeyRequest))]
public partial class ApiJsonContext : JsonSerializerContext;
