using Backend.Core;
using Backend.Infrastructure.Persistence.Entity;
using FastEndpoints;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Backend.Features.Authentication;

// --- Logout ---
public class LogoutEndpoint : EndpointWithoutRequest
{
    // Inject SignInManager if using Identity cookies for signout, otherwise just clear custom cookies
    // private readonly SignInManager<ApplicationUser> _signInManager;
    // public LogoutEndpoint(SignInManager<ApplicationUser> signInManager) => _signInManager = signInManager;

    public override void Configure()
    {
        Post("/auth/logout");
        // Should generally require authentication to logout, but depends on flow
        // AllowAnonymous(); // Or use [Authorize]
        Description(b => b.Tags("Authentication"));
    }

    public override async Task HandleAsync(CancellationToken ct)
    {
        // await _signInManager.SignOutAsync(); // Use if Identity ApplicationScheme cookie used

        // Clear custom JWT cookies
        HttpContext.Response.Cookies.Delete("access_token", new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Lax });
        HttpContext.Response.Cookies.Delete("refresh_token", new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Strict });
        // Optionally clear CSRF token cookie too
        HttpContext.Response.Cookies.Delete("CSRF-TOKEN", new CookieOptions { HttpOnly = false, Secure = true, SameSite = SameSiteMode.Strict });


        await SendOkAsync(ApiResponse<bool>.Success("Logged out successfully."), ct);
    }
}


// --- Helper Methods --- (Place within the file or move to a shared service)
 internal static async Task SetAuthCookies(ApplicationUser user, HttpResponse response, UserManager<ApplicationUser> userManager, IConfiguration config)
    {
        var userRoles = await userManager.GetRolesAsync(user);
        var accessToken = GenerateJwtToken(user, userRoles, config, isAccessToken: true);
        var refreshToken = GenerateJwtToken(user, userRoles, config, isAccessToken: false);

        var cookieOptions = new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Lax, Expires = DateTime.UtcNow.AddMinutes(15) }; // Access token expiry
        response.Cookies.Append("access_token", accessToken, cookieOptions);

        var refreshCookieOptions = new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Strict, Expires = DateTime.UtcNow.AddDays(7) }; // Refresh token expiry
        response.Cookies.Append("refresh_token", refreshToken, refreshCookieOptions);
    }

    internal static string GenerateJwtToken(ApplicationUser user, IList<string> roles, IConfiguration config, bool isAccessToken)
    {
        var jwtSettings = config.GetSection("JWT");
        var secret = jwtSettings["SecretKey"] ?? throw new InvalidOperationException("JWT SecretKey not configured");
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var claims = new List<Claim> {
         new(JwtRegisteredClaimNames.Sub, user.Id), new(JwtRegisteredClaimNames.Email, user.Email!), new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
     };
        claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));
        var expiry = isAccessToken ? DateTime.UtcNow.AddMinutes(15) : DateTime.UtcNow.AddDays(7);
        var token = new JwtSecurityToken(issuer: jwtSettings["Issuer"], audience: jwtSettings["Audience"], claims: claims, expires: expiry, signingCredentials: creds);
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    internal static ClaimsPrincipal ValidateToken(string token, IConfiguration config, bool isAccessToken)
    {
        var jwtSettings = config.GetSection("JWT");
        var secret = jwtSettings["SecretKey"] ?? throw new InvalidOperationException("JWT SecretKey not configured");
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));

        var tokenHandler = new JwtSecurityTokenHandler();
        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = key,
            ValidateIssuer = true,
            ValidIssuer = jwtSettings["Issuer"],
            ValidateAudience = true,
            ValidAudience = jwtSettings["Audience"],
            ValidateLifetime = true, // Check expiration
            ClockSkew = TimeSpan.Zero
        };

        var principal = tokenHandler.ValidateToken(token, validationParameters, out SecurityToken validatedToken);
        // Could add further checks (e.g., expected algorithm)
        return principal;
    }