namespace Backend.Infrastructure.Persistence.Entity;
public class RefreshToken
{
    public int Id { get; set; } // Primary Key

    public required string UserId { get; set; } // Foreign Key to ApplicationUser
    public ApplicationUser User { get; set; } = default!; // Navigation property

    public required string Token { get; set; } // The actual refresh token value (secure random string)
    public required string JwtId { get; set; } // The JTI (JWT ID) of the access token this refresh token belongs to

    public bool IsUsed { get; set; } // Flag to indicate if the token has been used
    public bool IsRevoked { get; set; } // Flag to indicate if the token has been revoked (e.g., logout, password change)

    public DateTime CreationDate { get; set; }
    public DateTime ExpiryDate { get; set; }

    // Optional: Store info for detection of token theft/reuse attempts
    // public string? ReplacedByToken { get; set; } // Store the token that replaced this one
    // public DateTime? RevokedDate { get; set; }
    // public string? ReasonRevoked { get; set; }
}


