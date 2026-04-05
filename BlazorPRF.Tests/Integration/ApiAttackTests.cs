using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using BlazorPRF.Crypto.Testing;

namespace BlazorPRF.Tests.Integration;

/// <summary>
/// API attack simulation tests against the PHP mail relay.
/// These tests require a running relay server.
/// Set environment variable PRF_API_URL to enable (e.g., "https://prf.test/api/").
/// </summary>
public class ApiAttackTests : IDisposable
{
    private readonly HttpClient? _client;
    private readonly bool _enabled;

    public ApiAttackTests()
    {
        var apiUrl = Environment.GetEnvironmentVariable("PRF_API_URL");
        _enabled = !string.IsNullOrEmpty(apiUrl);

        if (_enabled)
        {
            var handler = new HttpClientHandler
            {
                // Allow self-signed certs for local dev
                ServerCertificateCustomValidationCallback = (_, _, _, _) => true
            };
            _client = new HttpClient(handler) { BaseAddress = new Uri(apiUrl!) };
        }
    }

    public void Dispose()
    {
        _client?.Dispose();
    }

    [Fact]
    public async Task Attack_NoSignature_Rejected()
    {
        Assert.SkipWhen(!_enabled, "PRF_API_URL not set");

        // Send a request with no signature headers — should be rejected
        var response = await _client!.PostAsync("send_mail",
            new StringContent("{}", Encoding.UTF8, "application/json"),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Attack_InvalidSignature_Rejected()
    {
        Assert.SkipWhen(!_enabled, "PRF_API_URL not set");

        var keys = KeyGenerator.GenerateEd25519KeyPair();
        var body = "{}";
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
        var nonce = Guid.NewGuid().ToString("N")[..16];
        var bodyHash = Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(body)));

        var request = new HttpRequestMessage(HttpMethod.Post, "send_mail")
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json")
        };

        // Valid headers but garbage signature — server rejects (either "not registered" or "Invalid signature")
        request.Headers.Add("X-Public-Key", keys.PublicKeyBase64);
        request.Headers.Add("X-Timestamp", timestamp);
        request.Headers.Add("X-Nonce", nonce);
        request.Headers.Add("X-BodyHash", bodyHash);
        request.Headers.Add("X-Signature", Convert.ToBase64String(new byte[64]));

        var response = await _client!.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Attack_UnregisteredKey_Rejected()
    {
        Assert.SkipWhen(!_enabled, "PRF_API_URL not set");

        var keys = KeyGenerator.GenerateEd25519KeyPair();
        var body = "{}";
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
        var nonce = Guid.NewGuid().ToString("N")[..16];
        var bodyHash = Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(body)));
        var message = $"POST|{timestamp}|{nonce}|{bodyHash}";

        // Sign correctly but with an unregistered key
        var signResult = CryptoOperations.Sign(message, keys.PrivateKeyBase64);
        Assert.True(signResult.Success);

        var request = new HttpRequestMessage(HttpMethod.Post, "send_mail")
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json")
        };

        request.Headers.Add("X-Public-Key", keys.PublicKeyBase64);
        request.Headers.Add("X-Timestamp", timestamp);
        request.Headers.Add("X-Nonce", nonce);
        request.Headers.Add("X-BodyHash", bodyHash);
        request.Headers.Add("X-Signature", signResult.Value!);

        var response = await _client!.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

        var responseBody = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains("not registered", responseBody);
    }

    [Fact]
    public async Task Attack_ExpiredTimestamp_Rejected()
    {
        Assert.SkipWhen(!_enabled, "PRF_API_URL not set");

        var keys = KeyGenerator.GenerateEd25519KeyPair();
        var body = "{}";
        // Timestamp 10 minutes ago — should exceed tolerance
        var timestamp = (DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 600).ToString();
        var nonce = Guid.NewGuid().ToString("N")[..16];
        var bodyHash = Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(body)));
        var message = $"POST|{timestamp}|{nonce}|{bodyHash}";

        var signResult = CryptoOperations.Sign(message, keys.PrivateKeyBase64);
        Assert.True(signResult.Success);

        var request = new HttpRequestMessage(HttpMethod.Post, "send_mail")
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json")
        };

        request.Headers.Add("X-Public-Key", keys.PublicKeyBase64);
        request.Headers.Add("X-Timestamp", timestamp);
        request.Headers.Add("X-Nonce", nonce);
        request.Headers.Add("X-BodyHash", bodyHash);
        request.Headers.Add("X-Signature", signResult.Value!);

        var response = await _client!.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

        var responseBody = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains("timestamp", responseBody, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Attack_TamperedBody_Rejected()
    {
        Assert.SkipWhen(!_enabled, "PRF_API_URL not set");

        var keys = KeyGenerator.GenerateEd25519KeyPair();
        var originalBody = """{"action":"test"}""";
        var tamperedBody = """{"action":"send_all_data"}""";
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
        var nonce = Guid.NewGuid().ToString("N")[..16];
        // Hash the original body but send the tampered one
        var bodyHash = Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(originalBody)));
        var message = $"POST|{timestamp}|{nonce}|{bodyHash}";

        var signResult = CryptoOperations.Sign(message, keys.PrivateKeyBase64);
        Assert.True(signResult.Success);

        var request = new HttpRequestMessage(HttpMethod.Post, "send_mail")
        {
            Content = new StringContent(tamperedBody, Encoding.UTF8, "application/json")
        };

        request.Headers.Add("X-Public-Key", keys.PublicKeyBase64);
        request.Headers.Add("X-Timestamp", timestamp);
        request.Headers.Add("X-Nonce", nonce);
        request.Headers.Add("X-BodyHash", bodyHash);
        request.Headers.Add("X-Signature", signResult.Value!);

        var response = await _client!.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

        var responseBody = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains("hash", responseBody, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Attack_AdminEndpoint_WithUserKey_Rejected()
    {
        Assert.SkipWhen(!_enabled, "PRF_API_URL not set");

        // Try to access admin endpoint with user-style headers
        var keys = KeyGenerator.GenerateEd25519KeyPair();
        var body = "";
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
        var nonce = Guid.NewGuid().ToString("N")[..16];
        var bodyHash = Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(body)));
        var message = $"GET|{timestamp}|{nonce}|{bodyHash}";

        var signResult = CryptoOperations.Sign(message, keys.PrivateKeyBase64);
        Assert.True(signResult.Success);

        var request = new HttpRequestMessage(HttpMethod.Get, "register");

        // Use admin headers with a random (non-admin) key
        request.Headers.Add("X-Admin-PublicKey", keys.PublicKeyBase64);
        request.Headers.Add("X-Admin-Timestamp", timestamp);
        request.Headers.Add("X-Admin-Nonce", nonce);
        request.Headers.Add("X-Admin-BodyHash", bodyHash);
        request.Headers.Add("X-Admin-Signature", signResult.Value!);

        var response = await _client!.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Attack_MethodTampering_Rejected()
    {
        Assert.SkipWhen(!_enabled, "PRF_API_URL not set");

        // Sign for POST but send as GET — method is part of the signed message
        var keys = KeyGenerator.GenerateEd25519KeyPair();
        var body = "";
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
        var nonce = Guid.NewGuid().ToString("N")[..16];
        var bodyHash = Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(body)));
        var message = $"POST|{timestamp}|{nonce}|{bodyHash}"; // Signed for POST

        var signResult = CryptoOperations.Sign(message, keys.PrivateKeyBase64);
        Assert.True(signResult.Success);

        var request = new HttpRequestMessage(HttpMethod.Get, "send_mail"); // Sent as GET

        request.Headers.Add("X-Public-Key", keys.PublicKeyBase64);
        request.Headers.Add("X-Timestamp", timestamp);
        request.Headers.Add("X-Nonce", nonce);
        request.Headers.Add("X-BodyHash", bodyHash);
        request.Headers.Add("X-Signature", signResult.Value!);

        var response = await _client!.SendAsync(request, TestContext.Current.CancellationToken);
        // Either 401 (signature mismatch) or 405 (method not allowed)
        Assert.True(
            response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.MethodNotAllowed,
            $"Expected 401 or 405, got {response.StatusCode}");
    }

    [Fact]
    public async Task HealthCheck_NoAuth_ReturnsOk()
    {
        Assert.SkipWhen(!_enabled, "PRF_API_URL not set");

        var response = await _client!.GetAsync("", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        var doc = JsonDocument.Parse(body);
        Assert.Equal("ok", doc.RootElement.GetProperty("status").GetString());
    }
}
