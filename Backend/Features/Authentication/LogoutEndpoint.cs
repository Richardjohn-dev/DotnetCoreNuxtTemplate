using Backend.Core;
using Backend.Infrastructure.Persistence;
using FastEndpoints;
using Microsoft.EntityFrameworkCore;

namespace Backend.Features.Authentication;

public class LogoutEndpoint : EndpointWithoutRequest
{
    private readonly ApplicationDbContext _dbContext;
    private readonly ILogger<LogoutEndpoint> _logger;
    public LogoutEndpoint(ApplicationDbContext dbContext, ILogger<LogoutEndpoint> logger) { _dbContext = dbContext; _logger = logger; }

    public override void Configure()
    {
        Post("/auth/logout");
        AllowAnonymous();
        Description(b => b.WithTags("Authentication"));
        DontThrowIfValidationFails();
    }

    public override async Task HandleAsync(CancellationToken ct)
    {
        var refreshTokenValue = HttpContext.Request.Cookies["refresh_token"];
        if (!string.IsNullOrEmpty(refreshTokenValue))
        {
            var storedToken = await _dbContext.RefreshTokens.FirstOrDefaultAsync(rt => rt.Token == refreshTokenValue, ct);
            if (storedToken != null && !storedToken.IsRevoked)
            {
                storedToken.IsRevoked = true;
                _dbContext.RefreshTokens.Update(storedToken);
                try
                {
                    await _dbContext.SaveChangesAsync(ct);
                    _logger.LogInformation("Refresh token revoked for User {UserId}.", storedToken.UserId);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to revoke refresh token for User {UserId}.", storedToken.UserId);
                }
            }
        }

        var secureOption = new CookieOptions { Secure = true };

        // Create separate cookie options for each cookie
        var accessTokenOptions = new CookieOptions
        {
            Secure = true,
            HttpOnly = true,
            SameSite = SameSiteMode.Lax
        };

        var refreshTokenOptions = new CookieOptions
        {
            Secure = true,
            HttpOnly = true,
            SameSite = SameSiteMode.Strict
        };

        var csrfTokenOptions = new CookieOptions
        {
            Secure = true,
            HttpOnly = false,
            SameSite = SameSiteMode.Strict
        };

        HttpContext.Response.Cookies.Delete("access_token", accessTokenOptions);
        HttpContext.Response.Cookies.Delete("refresh_token", refreshTokenOptions);
        HttpContext.Response.Cookies.Delete("CSRF-TOKEN", csrfTokenOptions);

        await SendOkAsync(ApiResponse<bool>.Success("Logged out successfully."), ct);
    }
}
