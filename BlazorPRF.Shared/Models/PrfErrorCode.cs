namespace BlazorPRF.Shared.Models;

/// <summary>
/// Error codes for PRF/PseudoPRF operations.
/// </summary>
public enum PrfErrorCode
{
    Unknown,
    PrfNotSupported,
    CredentialNotFound,
    AuthenticationTagMismatch,
    InvalidData,
    KeyDerivationFailed,
    EncryptionFailed,
    DecryptionFailed,
    RegistrationFailed,
    InvalidPublicKey,
    InvalidPrivateKey,
}

/// <summary>
/// Provides user-friendly error messages for PRF error codes.
/// </summary>
public static class PrfErrorMessages
{
    /// <summary>
    /// Gets the user-friendly error message for the given error code.
    /// </summary>
    public static string GetMessage(PrfErrorCode errorCode) => errorCode switch
    {
        PrfErrorCode.PrfNotSupported =>
            "The selected passkey does not support PRF extension. Please select a passkey that was created with PRF support, or register a new one.",
        PrfErrorCode.CredentialNotFound =>
            "The credential was not found. It may have been deleted or is not available on this device.",
        PrfErrorCode.AuthenticationTagMismatch =>
            "Decryption failed: wrong key or corrupted data. This data was encrypted with a different key.",
        PrfErrorCode.InvalidData =>
            "The data is invalid or corrupted.",
        PrfErrorCode.KeyDerivationFailed =>
            "Key derivation failed. Please try again.",
        PrfErrorCode.EncryptionFailed =>
            "Encryption failed. Please try again.",
        PrfErrorCode.DecryptionFailed =>
            "Decryption failed. The data may be corrupted.",
        PrfErrorCode.RegistrationFailed =>
            "Passkey registration failed. Please try again.",
        PrfErrorCode.InvalidPublicKey =>
            "The public key is invalid or malformed.",
        PrfErrorCode.InvalidPrivateKey =>
            "The private key is invalid or malformed.",
        _ =>
            "An unknown error occurred."
    };
}
