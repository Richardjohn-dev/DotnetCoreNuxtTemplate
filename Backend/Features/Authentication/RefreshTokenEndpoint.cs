using Backend.Core;
using Backend.Infrastructure.Persistence;
using Backend.Infrastructure.Persistence.Entity;
using FastEndpoints;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

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


public class RefreshTokenEndpoint : Endpoint<RefreshTokenRequest, ApiResponse<bool>>
{
    private readonly ApplicationDbContext _dbContext; // Inject DbContext
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IConfiguration _config;
    private readonly IAntiforgery _antiforgery;
    private readonly ILogger<RefreshTokenEndpoint> _logger; // Inject Logger

    public RefreshTokenEndpoint(
        ApplicationDbContext dbContext,
        UserManager<ApplicationUser> userManager,
        IConfiguration config,
        IAntiforgery antiforgery,
        ILogger<RefreshTokenEndpoint> logger)
    {
        _dbContext = dbContext;
        _userManager = userManager;
        _config = config;
        _antiforgery = antiforgery;
        _logger = logger;
    }

    public override void Configure()
    {
        Post("/auth/refresh");
        AllowAnonymous();
        Description(b => b.WithTags("Authentication").WithName("RefreshToken"));
        DontThrowIfValidationFails();
    }

    public override async Task HandleAsync(RefreshTokenRequest req, CancellationToken ct)
    {
        var refreshTokenValueFromCookie = HttpContext.Request.Cookies["refresh_token"];
        if (string.IsNullOrEmpty(refreshTokenValueFromCookie))
        {
            Logger.LogWarning("Refresh token cookie not found.");
            await SendUnauthorizedAsync(ct); return;
        }

        // Find the token in the database, including the User
        var storedToken = await _dbContext.RefreshTokens
                                    .Include(rt => rt.User) // Eager load user data
                                    .SingleOrDefaultAsync(rt => rt.Token == refreshTokenValueFromCookie, ct);

        // Validate Stored Token
        if (storedToken == null || storedToken.IsRevoked || storedToken.IsUsed || storedToken.ExpiryDate < DateTime.UtcNow)
        {
            if (storedToken != null)
            {
                _logger.LogWarning("Invalid refresh token used for User {UserId}. Revoked={IsRevoked}, Used={IsUsed}, Expired={IsExpired}", storedToken.UserId, storedToken.IsRevoked, storedToken.IsUsed, storedToken.ExpiryDate < DateTime.UtcNow);
            }
            else
            {
                _logger.LogWarning("Refresh token from cookie not found in DB.");
            }
            // Optional: Revoke token family if potential reuse detected?
            await ClearCookiesAndSendUnauthorized(ct); return;
        }



        // --- Token is valid - Proceed with rotation ---
        try
        {
            // Mark the current token as used (prevents replay)
            storedToken.IsUsed = true;
            _dbContext.RefreshTokens.Update(storedToken);
            // Don't save changes immediately if generating new token fails

            // Generate NEW Access Token and NEW Refresh Token (value + entity)
            var user = storedToken.User; // User loaded via Include()
            var (newAccessToken, newJti) = AuthHelpers.GenerateJwtToken(user, await _userManager.GetRolesAsync(user), _config, isAccessToken: true);
            var newRefreshTokenValue = AuthHelpers.GenerateRefreshTokenValue();

            var newRefreshTokenEntity = new RefreshToken
            {
                UserId = user.Id,
                Token = newRefreshTokenValue,
                JwtId = newJti,
                IsUsed = false,
                IsRevoked = false,
                CreationDate = DateTime.UtcNow,
                ExpiryDate = DateTime.UtcNow.AddDays(7) // New expiry for the new token
                // Optional: Link the new token to the old one
                // ReplacedByToken = newRefreshTokenValue on the old storedToken?
            };

            // Add new token and save changes (marks old as used, adds new)
            await _dbContext.RefreshTokens.AddAsync(newRefreshTokenEntity, ct);
            var saved = await _dbContext.SaveChangesAsync(ct) > 0;

            if (!saved)
            {
                Logger.LogError("Failed to save refresh token changes to database for User {UserId}.", user.Id);
                // Don't issue new cookies if DB save failed
                await SendErrorsAsync(500, ct);
                return;
            }


            // --- Set NEW Cookies ---
            var cookieOptions = new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Lax, Expires = DateTime.UtcNow.AddMinutes(15) };
            HttpContext.Response.Cookies.Append("access_token", newAccessToken, cookieOptions);

            var refreshCookieOptions = new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Strict, Expires = newRefreshTokenEntity.ExpiryDate };
            HttpContext.Response.Cookies.Append("refresh_token", newRefreshTokenValue, refreshCookieOptions);

            // Also reset CSRF token cookie
            var csrfTokens = _antiforgery.GetAndStoreTokens(HttpContext);
            HttpContext.Response.Cookies.Append("CSRF-TOKEN", csrfTokens.RequestToken!, new CookieOptions { HttpOnly = false, Secure = true, SameSite = SameSiteMode.Strict });

            Logger.LogInformation("Token refreshed successfully for User {UserId}", user.Id);
            await SendOkAsync(ApiResponse<bool>.Success("Token refreshed successfully."), ct);



        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "An unexpected error occurred during token refresh for User {UserId}.", storedToken?.UserId ?? "Unknown");
            await SendErrorsAsync(500, ct);
        }
    }

    private async Task ClearCookiesAndSendUnauthorized(CancellationToken ct)
    {
        HttpContext.Response.Cookies.Delete("access_token");
        HttpContext.Response.Cookies.Delete("refresh_token");
        HttpContext.Response.Cookies.Delete("CSRF-TOKEN"); // Also clear CSRF token
        await SendUnauthorizedAsync(ct);
    }
}