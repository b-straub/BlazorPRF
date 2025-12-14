namespace BlazorPRF.Persistence.Data.Models;

/// <summary>
/// Trust level for a contact (PGP-style).
/// </summary>
public enum TrustLevel
{
    /// <summary>No trust assigned.</summary>
    None = 0,

    /// <summary>Marginal trust - partially verified.</summary>
    Marginal = 1,

    /// <summary>Full trust - identity verified via signed invitation.</summary>
    Full = 2
}

/// <summary>
/// Direction of trust establishment.
/// </summary>
public enum TrustDirection
{
    /// <summary>I created the invitation (I invited them).</summary>
    Sent = 0,

    /// <summary>I accepted their invitation (they invited me).</summary>
    Received = 1
}

/// <summary>
/// Status of a sent invitation.
/// </summary>
public enum InviteStatus
{
    /// <summary>Invitation sent, awaiting response.</summary>
    Pending = 0,

    /// <summary>Invitation accepted and verified.</summary>
    Accepted = 1,

    /// <summary>Invitation expired (time-based).</summary>
    Expired = 2,

    /// <summary>Invitation revoked by sender.</summary>
    Revoked = 3
}
