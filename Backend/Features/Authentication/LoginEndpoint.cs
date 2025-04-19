using Backend.Core;
using Backend.Infrastructure.Persistence;
using Backend.Infrastructure.Persistence.Entity;
using FastEndpoints;
using FluentValidation;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Identity;

namespace Backend.Features.Authentication;

// --- Login ---
public class LoginEndpoint : Endpoint<LoginRequest, ApiResponse<UserInfoResponse>>
{
    private readonly ApplicationDbContext _context;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IConfiguration _config;
    private readonly IAntiforgery _antiforgery;
    public LoginEndpoint(
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager,
        IConfiguration config,
        IAntiforgery antiforgery,
        ApplicationDbContext context)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _config = config;
        _antiforgery = antiforgery;
        _context = context;
    }

    public override void Configure()
    {
        Post("/auth/login");
        AllowAnonymous();
        Description(b => b.WithTags("Authentication"));
    }

    public override async Task HandleAsync(LoginRequest req, CancellationToken ct)
    {
        var user = await _userManager.FindByEmailAsync(req.Email);
        if (user == null) { await SendUnauthorizedAsync(ct); return; }
        var result = await _signInManager.CheckPasswordSignInAsync(user, req.Password, lockoutOnFailure: false);
        if (!result.Succeeded) { await SendUnauthorizedAsync(ct); return; }

        // Set CSRF token cookie for subsequent requests
        var tokens = _antiforgery.GetAndStoreTokens(HttpContext);
        HttpContext.Response.Cookies.Append("CSRF-TOKEN", tokens.RequestToken!, new CookieOptions { HttpOnly = false, Secure = true, SameSite = SameSiteMode.Strict });

        // Set JWT Auth Cookies
        await AuthHelpers.SetAuthCookiesAndStoreRefreshToken(user, HttpContext.Response, _userManager, _config, _context, ct);

        var userRoles = await _userManager.GetRolesAsync(user);
        var responseDto = new UserInfoResponse(user.Id, user.Email!, userRoles);
        await SendOkAsync(ApiResponse<UserInfoResponse>.Success(responseDto), ct);
    }
}
public class LoginRequest
{
    public required string Email { get; set; }
    public required string Password { get; set; }
}
public class LoginValidator : Validator<LoginRequest>
{
    public LoginValidator()
    {
        RuleFor(x => x.Email).NotEmpty().EmailAddress();
        RuleFor(x => x.Password).NotEmpty();
    }
}
