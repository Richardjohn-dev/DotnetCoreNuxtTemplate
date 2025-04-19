namespace Backend.Features.Authentication;

using Backend.Infrastructure.Persistence;
using Backend.Infrastructure.Persistence.Entity;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
// Inside PasswordEndpoints.cs or a shared Auth service

using System.Security.Cryptography; // For RNGCryptoServiceProvider
using System.Text;

//internal static class AuthHelpers // Example static class for helpers
//{
//    // Modified SetAuthCookies method
//    internal static async Task SetAuthCookiesAndStoreRefreshToken(
//        ApplicationUser user,
//        HttpResponse response,
//        UserManager<ApplicationUser> userManager,
//        IConfiguration config,
//        ApplicationDbContext dbContext, // Inject DbContext
//        CancellationToken ct = default)
//    {
//        var userRoles = await userManager.GetRolesAsync(user);
//        // Generate JWT Access Token (includes JTI claim)
//        var (accessToken, jti) = GenerateJwtToken(user, userRoles, config, isAccessToken: true);

//        // Generate secure random string for Refresh Token value
//        var refreshTokenValue = GenerateRefreshTokenValue();

//        // Create RefreshToken entity
//        var refreshTokenEntity = new RefreshToken
//        {
//            UserId = user.Id,
//            Token = refreshTokenValue, // Store the random string value
//            JwtId = jti, // Link to the access token ID
//            IsUsed = false,
//            IsRevoked = false,
//            CreationDate = DateTime.UtcNow,
//            ExpiryDate = DateTime.UtcNow.AddDays(7) // Match refresh token cookie expiry
//        };

//        // --- Database Operation: Store Refresh Token ---
//        // Optional: Revoke previous tokens for the user if implementing strict single-session
//        // var existingTokens = await dbContext.RefreshTokens
//        //                             .Where(rt => rt.UserId == user.Id && !rt.IsRevoked && !rt.IsUsed)
//        //                             .ToListAsync(ct);
//        // foreach(var token in existingTokens) { token.IsRevoked = true; }

//        await dbContext.RefreshTokens.AddAsync(refreshTokenEntity, ct);
//        await dbContext.SaveChangesAsync(ct); // Save to DB

//        // --- Set Cookies ---
//        var cookieOptions = new CookieOptions
//        {
//            HttpOnly = true,
//            Secure = true,
//            SameSite = SameSiteMode.Lax,
//            Expires = DateTime.UtcNow.AddMinutes(15) // Access token expiry
//        };
//        response.Cookies.Append("access_token", accessToken, cookieOptions);

//        var refreshCookieOptions = new CookieOptions
//        {
//            HttpOnly = true,
//            Secure = true,
//            SameSite = SameSiteMode.Strict,
//            Expires = refreshTokenEntity.ExpiryDate // Use DB expiry for cookie
//        };
//        // Set the cookie value to the generated random string
//        response.Cookies.Append("refresh_token", refreshTokenValue, refreshCookieOptions);
//    }

//    // Modified JWT generation to return JTI
//    internal static (string Token, string Jti) GenerateJwtToken(ApplicationUser user, IList<string> roles, IConfiguration config, bool isAccessToken)
//    {
//        var jwtSettings = config.GetSection("JWT");
//        var secret = jwtSettings["SecretKey"] ?? throw new InvalidOperationException("JWT SecretKey not configured");
//        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
//        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
//        var jti = Guid.NewGuid().ToString(); // Generate unique JWT ID
//        var claims = new List<Claim> {
//            new(JwtRegisteredClaimNames.Sub, user.Id),
//            new(JwtRegisteredClaimNames.Email, user.Email!),
//            new(JwtRegisteredClaimNames.Jti, jti) // Include JTI claim
//        };
//        claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));
//        var expiry = isAccessToken ? DateTime.UtcNow.AddMinutes(15) : DateTime.UtcNow.AddDays(7); // Note: Refresh JWT expiry irrelevant now
//        var tokenDescriptor = new SecurityTokenDescriptor // Use SecurityTokenDescriptor for more control
//        {
//            Subject = new ClaimsIdentity(claims),
//            Expires = expiry,
//            Issuer = jwtSettings["Issuer"],
//            Audience = jwtSettings["Audience"],
//            SigningCredentials = creds
//        };

//        var tokenHandler = new JwtSecurityTokenHandler();
//        var securityToken = tokenHandler.CreateToken(tokenDescriptor);
//        var token = tokenHandler.WriteToken(securityToken);

//        return (token, jti);
//    }

//    // Helper to generate secure random string for refresh token value
//    internal static string GenerateRefreshTokenValue(int length = 64)
//    {
//        var randomNumber = new byte[length];
//        using var rng = RandomNumberGenerator.Create();
//        rng.GetBytes(randomNumber);
//        return Convert.ToBase64String(randomNumber);
//    }

//    // ValidateToken helper remains the same (validates JWT structure/signature/claims)
//    internal static ClaimsPrincipal ValidateToken(string token, IConfiguration config, bool isAccessToken)
//    {
//        var jwtSettings = config.GetSection("JWT");
//        var secret = jwtSettings["SecretKey"] ?? throw new InvalidOperationException("JWT SecretKey not configured");
//        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));

//        var tokenHandler = new JwtSecurityTokenHandler();
//        var validationParameters = new TokenValidationParameters
//        {
//            ValidateIssuerSigningKey = true,
//            IssuerSigningKey = key,
//            ValidateIssuer = true,
//            ValidIssuer = jwtSettings["Issuer"],
//            ValidateAudience = true,
//            ValidAudience = jwtSettings["Audience"],
//            ValidateLifetime = true, // Check expiration
//            ClockSkew = TimeSpan.Zero
//        };

//        var principal = tokenHandler.ValidateToken(token, validationParameters, out SecurityToken validatedToken);
//        // Could add further checks (e.g., expected algorithm)
//        return principal;
//    }
//}

internal static class AuthHelpers
{
    // --- Generate JWT Access Token ---
    internal static (string Token, string Jti) GenerateJwtToken(ApplicationUser user, IList<string> roles, IConfiguration config, bool isAccessToken = true)
    {
        var jwtSettings = config.GetSection("JWT");
        var secret = jwtSettings["SecretKey"] ?? throw new InvalidOperationException("JWT SecretKey not configured");
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var jti = Guid.NewGuid().ToString(); // Unique JWT ID
        var claims = new List<Claim> {
            new(ClaimTypes.NameIdentifier, user.Id),
            new(ClaimTypes.Email, user.Email!),
            new(JwtRegisteredClaimNames.Jti, jti) // Include JTI claim
        };
        claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));
        // Access token expiry is short, refresh token expiry is handled by DB record
        var expiry = DateTime.UtcNow.AddMinutes(15); // Example: 15 minutes
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = expiry,
            Issuer = jwtSettings["Issuer"],
            Audience = jwtSettings["Audience"],
            SigningCredentials = creds
        };
        var tokenHandler = new JwtSecurityTokenHandler();
        var securityToken = tokenHandler.CreateToken(tokenDescriptor);
        var token = tokenHandler.WriteToken(securityToken);
        return (token, jti);
    }

    // --- Generate Refresh Token Value ---
    internal static string GenerateRefreshTokenValue(int length = 64)
    {
        var randomNumber = new byte[length];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);
        return Convert.ToBase64String(randomNumber);
    }

    // --- Set Cookies & Store Refresh Token in DB ---
    internal static async Task SetAuthCookiesAndStoreRefreshToken(
        ApplicationUser user,
        HttpResponse response,
        UserManager<ApplicationUser> userManager,
        IConfiguration config,
        ApplicationDbContext dbContext, // Inject DbContext
        CancellationToken ct = default)
    {
        var userRoles = await userManager.GetRolesAsync(user);
        var (accessToken, jti) = GenerateJwtToken(user, userRoles, config, isAccessToken: true);
        var refreshTokenValue = GenerateRefreshTokenValue();
        var refreshTokenEntity = new RefreshToken
        {
            UserId = user.Id,
            Token = refreshTokenValue,
            JwtId = jti,
            IsUsed = false,
            IsRevoked = false,
            CreationDate = DateTime.UtcNow,
            ExpiryDate = DateTime.UtcNow.AddDays(7) // Refresh token DB expiry
        };

        // --- Store Refresh Token in DB ---
        await dbContext.RefreshTokens.AddAsync(refreshTokenEntity, ct);
        await dbContext.SaveChangesAsync(ct);

        // --- Set Cookies ---
        var cookieOptions = new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Lax, Expires = DateTime.UtcNow.AddMinutes(15) };
        response.Cookies.Append("access_token", accessToken, cookieOptions);
        var refreshCookieOptions = new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Strict, Expires = refreshTokenEntity.ExpiryDate };
        response.Cookies.Append("refresh_token", refreshTokenValue, refreshCookieOptions); // Store the random value in cookie
    }
}