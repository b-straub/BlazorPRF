using System.Security.Cryptography;
using System.Text;
using BlazorPRF.Api.Models;

namespace BlazorPRF.Api.Services;

/// <summary>
/// Client for making Ed25519-signed HTTP requests to PRF-authenticated backends.
/// </summary>
public sealed class SignedApiClient : ISignedApiClient
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly string _httpClientName;

    /// <summary>
    /// Creates a new signed API client.
    /// </summary>
    /// <param name="httpClientFactory">Factory for creating HTTP clients</param>
    /// <param name="httpClientName">Named HTTP client to use (default: "PrfApi")</param>
    public SignedApiClient(IHttpClientFactory httpClientFactory, string httpClientName = "PrfApi")
    {
        _httpClientFactory = httpClientFactory;
        _httpClientName = httpClientName;
    }

    /// <inheritdoc />
    public async Task<ApiResult<string>> GetAsync(string endpoint)
    {
        try
        {
            var client = _httpClientFactory.CreateClient(_httpClientName);
            var response = await client.GetAsync(endpoint);
            var responseBody = await response.Content.ReadAsStringAsync();

            if (response.IsSuccessStatusCode)
            {
                return ApiResult<string>.Ok(responseBody);
            }

            return ApiResult<string>.Failure($"Request failed ({response.StatusCode}): {responseBody}");
        }
        catch (Exception ex)
        {
            return ApiResult<string>.Failure($"Request error: {ex.Message}");
        }
    }

    /// <inheritdoc />
    public async Task<ApiResult<string>> SendAdminSignedAsync(
        string endpoint,
        string body,
        string method,
        SigningContext context)
    {
        return await SendSignedRequestAsync(endpoint, body, method, context, isAdmin: true);
    }

    /// <inheritdoc />
    public async Task<ApiResult<string>> SendUserSignedAsync(
        string endpoint,
        string body,
        string method,
        SigningContext context)
    {
        return await SendSignedRequestAsync(endpoint, body, method, context, isAdmin: false);
    }

    private async Task<ApiResult<string>> SendSignedRequestAsync(
        string endpoint,
        string body,
        string method,
        SigningContext context,
        bool isAdmin)
    {
        if (string.IsNullOrEmpty(context.PublicKey))
        {
            return ApiResult<string>.Failure("No public key available");
        }

        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
        var nonce = Guid.NewGuid().ToString("N")[..16];
        var bodyBytes = Encoding.UTF8.GetBytes(body);
        var hashBytes = SHA256.HashData(bodyBytes);
        var bodyHash = Convert.ToBase64String(hashBytes);

        var message = $"{method}|{timestamp}|{nonce}|{bodyHash}";
        var signResult = await context.SignAsync(message, context.Salt);
        if (!signResult.Success || signResult.Value is null)
        {
            return ApiResult<string>.Failure(signResult.Error ?? "Signing failed");
        }

        var httpClient = _httpClientFactory.CreateClient(_httpClientName);
        using var request = new HttpRequestMessage(new HttpMethod(method), endpoint);

        if (method is "POST" or "PUT" or "PATCH")
        {
            request.Content = new StringContent(body, Encoding.UTF8, "application/json");
        }

        // Use X-Admin-* prefix for admin requests, X-* for user requests
        // Note: User headers use X-Public-Key (with hyphen), admin uses X-Admin-PublicKey
        if (isAdmin)
        {
            request.Headers.Add("X-Admin-PublicKey", context.PublicKey);
            request.Headers.Add("X-Admin-Timestamp", timestamp);
            request.Headers.Add("X-Admin-Nonce", nonce);
            request.Headers.Add("X-Admin-BodyHash", bodyHash);
            request.Headers.Add("X-Admin-Signature", signResult.Value);
        }
        else
        {
            request.Headers.Add("X-Public-Key", context.PublicKey);
            request.Headers.Add("X-Timestamp", timestamp);
            request.Headers.Add("X-Nonce", nonce);
            request.Headers.Add("X-BodyHash", bodyHash);
            request.Headers.Add("X-Signature", signResult.Value);
        }

        try
        {
            var response = await httpClient.SendAsync(request);
            var responseBody = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                return ApiResult<string>.Failure($"Request failed ({response.StatusCode}): {responseBody}");
            }

            return ApiResult<string>.Ok(responseBody);
        }
        catch (HttpRequestException ex)
        {
            return ApiResult<string>.Failure($"HTTP request failed: {ex.Message}");
        }
    }
}
