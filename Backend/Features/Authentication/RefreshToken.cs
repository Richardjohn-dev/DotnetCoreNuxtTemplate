namespace Backend.Features.Authentication;

// --- Refresh Token ---
// Request is empty as token is read from HttpOnly cookie
public class RefreshTokenRequest { }

// --- External Login Challenge ---
public class ExternalLoginRequest
{
    public string Provider { get; set; } = default!; // e.g., "Google"
    public string? ReturnUrl { get; set; }
}






