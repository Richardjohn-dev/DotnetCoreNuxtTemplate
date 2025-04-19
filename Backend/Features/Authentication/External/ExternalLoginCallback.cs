using Backend.Infrastructure.Identity.Constants;
using Backend.Infrastructure.Persistence;
using Backend.Infrastructure.Persistence.Entity;
using FastEndpoints;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using System.Security.Claims;

namespace Backend.Features.Authentication.External;



public class ExternalLoginCallbackEndpoint : EndpointWithoutRequest
{
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IConfiguration _config;
    private readonly IAntiforgery _antiforgery;
    private readonly ApplicationDbContext _dbContext; // Inject DbContext
    private readonly ILogger<ExternalLoginCallbackEndpoint> _logger;

    public ExternalLoginCallbackEndpoint(
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager,
        IConfiguration config,
        IAntiforgery antiforgery,
        ApplicationDbContext dbContext,
        ILogger<ExternalLoginCallbackEndpoint> logger)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _config = config;
        _antiforgery = antiforgery;
        _dbContext = dbContext;
        _logger = logger;
    }

    public override void Configure()
    {
        Get("/auth/google-callback");
        AllowAnonymous();
        Description(b => b.WithTags("Authentication"));
        DontThrowIfValidationFails();
    }

    public override async Task HandleAsync(CancellationToken ct)
    {
        var info = await _signInManager.GetExternalLoginInfoAsync();
        if (info == null)
        {
            await SendFailureRedirect("External login failed.", ct);
            return;
        }

        info.AuthenticationProperties.Items.TryGetValue("ReturnUrl", out var returnUrl); returnUrl ??= "/";

        var signInResult = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, false, true);
        if (signInResult.Succeeded)
        {
            var user = await _userManager.FindByLoginAsync(info.LoginProvider, info.ProviderKey);
            if (user != null)
            {
                await SetCookiesAndRedirect(user, returnUrl, ct);
            }
            else
            {
                _logger.LogError("User not found after successful ExternalLoginSignInAsync.");
                await SendFailureRedirect("Login error.", ct);
            }
            return;
        }

        if (signInResult.IsLockedOut || signInResult.IsNotAllowed)
        {
            await SendFailureRedirect("Account locked or not allowed.", ct);
            return;
        }


        var email = info.Principal.FindFirstValue(ClaimTypes.Email);
        if (string.IsNullOrEmpty(email))
        {
            await SendFailureRedirect("Email not provided.", ct);
            return;
        }

        var existingUser = await _userManager.FindByEmailAsync(email);
        if (existingUser != null) // Link account
        {
            var addLoginRes = await _userManager.AddLoginAsync(existingUser, info);
            if (!addLoginRes.Succeeded)
            {
                await SendFailureRedirect("Could not link account.", ct);
                return;
            }
            await _signInManager.SignInAsync(existingUser, false, info.LoginProvider); // Sign in after linking
            await SetCookiesAndRedirect(existingUser, returnUrl, ct);
        }
        else // Create new user
        {
            var newUser = new ApplicationUser { UserName = email, Email = email, EmailConfirmed = true };
            var createRes = await _userManager.CreateAsync(newUser);
            if (!createRes.Succeeded)
            {
                /* Log errors */
                await SendFailureRedirect("Registration failed.", ct); return;
            }
            await _userManager.AddToRoleAsync(newUser, ApplicationRole.User);
            var addLoginRes = await _userManager.AddLoginAsync(newUser, info);
            if (!addLoginRes.Succeeded)
            {
                /* Log errors */
                await SendFailureRedirect("Could not link account after registration.", ct); return;
            }
            await _signInManager.SignInAsync(newUser, false, info.LoginProvider); // Sign in new user
            await SetCookiesAndRedirect(newUser, returnUrl, ct);
        }
    }
    // --- Helper Methods for Callback ---
    private async Task SetCookiesAndRedirect(ApplicationUser user, string returnUrl, CancellationToken ct)
    {
        // Use the shared helper method
        await AuthHelpers.SetAuthCookiesAndStoreRefreshToken(user, HttpContext.Response, _userManager, _config, _dbContext, ct);
        // Also set CSRF token cookie
        var tokens = _antiforgery.GetAndStoreTokens(HttpContext);
        HttpContext.Response.Cookies.Append("CSRF-TOKEN", tokens.RequestToken!, new CookieOptions { HttpOnly = false, Secure = true, SameSite = SameSiteMode.Strict });
        await SendRedirectAsync(GetFrontendRedirectUrl(success: true, returnUrl: returnUrl), allowRemoteRedirects: true);
    }

    private async Task SendFailureRedirect(string error, CancellationToken ct)
    {
        Logger.LogWarning("External login callback failed: {Error}", error);
        await SendRedirectAsync(GetFrontendRedirectUrl(success: false, error: error), allowRemoteRedirects: true);
    }

    private string GetFrontendRedirectUrl(bool success, string? error = null, string? returnUrl = null)
    {
        var frontendBaseUrl = _config["FrontendBaseUrl"] ?? "https://localhost:3000";
        var redirectUri = $"{frontendBaseUrl}/auth/external-callback";
        var queryParams = new Dictionary<string, string?> { { "success", success.ToString().ToLowerInvariant() } };
        if (!string.IsNullOrEmpty(error)) queryParams["error"] = error;
        if (!string.IsNullOrEmpty(returnUrl) && returnUrl != "/") queryParams["returnUrl"] = returnUrl;
        return QueryHelpers.AddQueryString(redirectUri, queryParams!);
    }

    //private string GetFrontendRedirectUrl(bool success, string? error = null, string? returnUrl = null)
    //{ /* Reads config["FrontendBaseUrl"], appends /auth/external-callback, adds query params */ return $"{_config["FrontendBaseUrl"] ?? "http://localhost:3000"}/auth/external-callback?success={success.ToString().ToLowerInvariant()}&error={Uri.EscapeDataString(error ?? string.Empty)}&returnUrl={Uri.EscapeDataString(returnUrl ?? string.Empty)}"; }
}