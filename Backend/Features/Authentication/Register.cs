using Backend.Core;
using Backend.Infrastructure.Identity.Constants;
using Backend.Infrastructure.Persistence.Entity;
using FastEndpoints;
using FluentValidation;
using Microsoft.AspNetCore.Identity;

namespace Backend.Features.Authentication;


// --- Register ---
public class RegisterEndpoint : Endpoint<RegisterRequest, ApiResponse<UserInfoResponse>>
{
    private readonly UserManager<ApplicationUser> _userManager;
    public RegisterEndpoint(UserManager<ApplicationUser> userManager) => _userManager = userManager;

    public override void Configure()
    {
        Post("/auth/register");
        AllowAnonymous();
        Description(b => b.WithTags("Authentication"));
    }

    public override async Task HandleAsync(RegisterRequest req, CancellationToken ct)
    {
        var newUser = new ApplicationUser { UserName = req.Email, Email = req.Email };
        var result = await _userManager.CreateAsync(newUser, req.Password);
        if (!result.Succeeded)
        {
            foreach (var error in result.Errors) AddError(error.Description, error.Code);
            await SendErrorsAsync(400, ct); return;
        }
        await _userManager.AddToRoleAsync(newUser, ApplicationRole.User);
        var roles = await _userManager.GetRolesAsync(newUser);
        var response = new UserInfoResponse(newUser.Id, newUser.Email!, roles);
        await SendOkAsync(ApiResponse<UserInfoResponse>.Success(response, "Registration successful."), ct);
    }
}


// Request DTO
public class RegisterRequest
{
    public required string Email { get; set; }
    public required string Password { get; set; }
    public required string ConfirmPassword { get; set; }
    // Add other fields like DisplayName if needed
}

// Response DTO (defined later in UserInfoResponse)

// Validator
public class RegisterValidator : Validator<RegisterRequest>
{
    public RegisterValidator()
    {
        RuleFor(x => x.Email).NotEmpty().EmailAddress();
        RuleFor(x => x.Password).NotEmpty().MinimumLength(8); // Match Identity settings
        RuleFor(x => x.ConfirmPassword).NotEmpty().Equal(x => x.Password)
            .WithMessage("Passwords do not match.");
    }
}