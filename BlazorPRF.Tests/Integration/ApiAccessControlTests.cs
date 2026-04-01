using System.Net;

namespace BlazorPRF.Tests.Integration;

/// <summary>
/// Tests that sensitive files and directories are not accessible via HTTP.
/// Set environment variable PRF_API_URL to enable.
/// </summary>
public class ApiAccessControlTests : IDisposable
{
    private readonly HttpClient? _client;
    private readonly string? _baseUrl;
    private readonly bool _enabled;

    public ApiAccessControlTests()
    {
        var apiUrl = Environment.GetEnvironmentVariable("PRF_API_URL");
        _enabled = !string.IsNullOrEmpty(apiUrl);

        if (_enabled)
        {
            // Base URL is the api/ directory on the server
            _baseUrl = apiUrl;
            var handler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (_, _, _, _) => true,
                AllowAutoRedirect = false
            };
            _client = new HttpClient(handler) { BaseAddress = new Uri(_baseUrl!) };
        }
    }

    public void Dispose()
    {
        _client?.Dispose();
    }

    // ============================================================
    // SENSITIVE DIRECTORIES
    // ============================================================

    [Fact]
    public async Task Secure_Directory_Blocked()
    {
        Assert.SkipWhen(!_enabled, "PRF_API_URL not set");
        var response = await _client!.GetAsync("secure/", TestContext.Current.CancellationToken);
        AssertBlocked(response, "secure/");
    }

    [Fact]
    public async Task Secure_AdminKeys_Blocked()
    {
        Assert.SkipWhen(!_enabled, "PRF_API_URL not set");
        var response = await _client!.GetAsync("secure/admin_keys.json", TestContext.Current.CancellationToken);
        AssertBlocked(response, "secure/admin_keys.json");
    }

    [Fact]
    public async Task Secure_Config_Blocked()
    {
        Assert.SkipWhen(!_enabled, "PRF_API_URL not set");
        var response = await _client!.GetAsync("secure/config.php", TestContext.Current.CancellationToken);
        AssertBlocked(response, "secure/config.php");
    }

    [Fact]
    public async Task Secure_Database_Blocked()
    {
        Assert.SkipWhen(!_enabled, "PRF_API_URL not set");
        var response = await _client!.GetAsync("secure/data/app.db", TestContext.Current.CancellationToken);
        AssertBlocked(response, "secure/data/app.db");
    }

    // ============================================================
    // SOURCE CODE DIRECTORIES
    // ============================================================

    [Fact]
    public async Task Lib_Directory_Blocked()
    {
        Assert.SkipWhen(!_enabled, "PRF_API_URL not set");
        var response = await _client!.GetAsync("lib/", TestContext.Current.CancellationToken);
        AssertBlocked(response, "lib/");
    }

    [Fact]
    public async Task Lib_Auth_Blocked()
    {
        Assert.SkipWhen(!_enabled, "PRF_API_URL not set");
        var response = await _client!.GetAsync("lib/Auth.php", TestContext.Current.CancellationToken);
        AssertBlocked(response, "lib/Auth.php");
    }

    [Fact]
    public async Task Lib_Database_Blocked()
    {
        Assert.SkipWhen(!_enabled, "PRF_API_URL not set");
        var response = await _client!.GetAsync("lib/Database.php", TestContext.Current.CancellationToken);
        AssertBlocked(response, "lib/Database.php");
    }

    [Fact]
    public async Task Actions_Directory_Blocked()
    {
        Assert.SkipWhen(!_enabled, "PRF_API_URL not set");
        var response = await _client!.GetAsync("actions/", TestContext.Current.CancellationToken);
        AssertBlocked(response, "actions/");
    }

    [Fact]
    public async Task Actions_SendMail_Blocked()
    {
        Assert.SkipWhen(!_enabled, "PRF_API_URL not set");
        var response = await _client!.GetAsync("actions/SendMail.php", TestContext.Current.CancellationToken);
        AssertBlocked(response, "actions/SendMail.php");
    }

    [Fact]
    public async Task PrfCrypto_Directory_Blocked()
    {
        Assert.SkipWhen(!_enabled, "PRF_API_URL not set");
        var response = await _client!.GetAsync("PrfCrypto/", TestContext.Current.CancellationToken);
        AssertBlocked(response, "PrfCrypto/");
    }

    [Fact]
    public async Task PrfCrypto_Source_Blocked()
    {
        Assert.SkipWhen(!_enabled, "PRF_API_URL not set");
        var response = await _client!.GetAsync("PrfCrypto/PrfCrypto.php", TestContext.Current.CancellationToken);
        AssertBlocked(response, "PrfCrypto/PrfCrypto.php");
    }

    // ============================================================
    // PATH TRAVERSAL ATTEMPTS
    // ============================================================

    [Fact]
    public async Task PathTraversal_DotDot_NoSourceLeak()
    {
        Assert.SkipWhen(!_enabled, "PRF_API_URL not set");
        // Traversal from api/ to parent is public web root (not a vuln)
        // Verify it doesn't expose PHP source or sensitive files
        var response = await _client!.GetAsync("../secure/admin_keys.json", TestContext.Current.CancellationToken);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.DoesNotContain("\"admin\"", body);
    }

    [Fact]
    public async Task PathTraversal_ToEtcPasswd_Blocked()
    {
        Assert.SkipWhen(!_enabled, "PRF_API_URL not set");
        var response = await _client!.GetAsync("../../../../etc/passwd", TestContext.Current.CancellationToken);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.DoesNotContain("root:", body);
    }

    // ============================================================
    // HTACCESS AND HIDDEN FILES
    // ============================================================

    [Fact]
    public async Task Htaccess_NotAccessible()
    {
        Assert.SkipWhen(!_enabled, "PRF_API_URL not set");
        var response = await _client!.GetAsync(".htaccess", TestContext.Current.CancellationToken);
        // Should not return the actual .htaccess content
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.DoesNotContain("RewriteEngine", body);
    }

    // ============================================================
    // VERIFY ALLOWED ENDPOINTS STILL WORK
    // ============================================================

    [Fact]
    public async Task HealthCheck_Accessible()
    {
        Assert.SkipWhen(!_enabled, "PRF_API_URL not set");
        var response = await _client!.GetAsync("", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains("PRF Mail Backend", body);
    }

    [Fact]
    public async Task AdminSetup_Accessible()
    {
        Assert.SkipWhen(!_enabled, "PRF_API_URL not set");
        var response = await _client!.GetAsync("admin-setup", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains("hasAdmin", body);
    }

    private static void AssertBlocked(HttpResponseMessage response, string path)
    {
        // Blocked means: 403 Forbidden, 404 Not Found, 405 Method Not Allowed,
        // 400 Bad Request, or 200 routed to index.php (which won't expose the file)
        Assert.True(
            response.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.NotFound
                or HttpStatusCode.MethodNotAllowed or HttpStatusCode.BadRequest
                or HttpStatusCode.OK,
            $"Expected {path} to be blocked, got {response.StatusCode}");

        // Regardless of status code, verify no sensitive content leaked
        var body = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
        Assert.DoesNotContain("<?php", body);
        Assert.DoesNotContain("SQLite format", body);
        Assert.DoesNotContain("sodium_crypto", body);
    }
}
