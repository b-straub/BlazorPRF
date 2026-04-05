using BlazorPRF.Crypto.Abstractions.Formatting;
using BlazorPRF.UI.Services;

namespace BlazorPRF.Sample.Services;

/// <summary>
/// Simple in-memory credential hint provider for the core sample.
/// Credential hint is lost on page refresh.
/// </summary>
public sealed class InMemoryCredentialHintProvider : ICredentialHintProvider
{
    private CredentialHint? _hint;

    public ValueTask<CredentialHint?> GetCredentialHintAsync()
    {
        return ValueTask.FromResult(_hint);
    }

    public ValueTask SetCredentialHintAsync(string credentialId, PublicKeyMetadata? metadata = null)
    {
        _hint = new CredentialHint(credentialId, metadata);
        return ValueTask.CompletedTask;
    }

    public ValueTask ClearCredentialHintAsync()
    {
        _hint = null;
        return ValueTask.CompletedTask;
    }
}
