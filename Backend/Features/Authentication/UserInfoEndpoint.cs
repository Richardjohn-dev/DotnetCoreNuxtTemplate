using Backend.Core;
using Backend.Infrastructure.Persistence.Entity;
using FastEndpoints;
using FluentValidation;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace Backend.Features.Authentication;

public class UserInfoEndpoint : EndpointWithoutRequest<ApiResponse<UserInfoResponse>>
{
    private readonly UserManager<ApplicationUser> _userManager;
    public UserInfoEndpoint(UserManager<ApplicationUser> userManager) => _userManager = userManager;

    public override void Configure()
    {
        Get("/users/me");
        Options(x => x.RequireAuthorization()); // Require valid JWT via cookie
        Description(b => b.WithTags("Authentication").WithName("GetMyInfo"));
    }

    public override async Task HandleAsync(CancellationToken ct)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (string.IsNullOrEmpty(userId))
        {
            await SendUnauthorizedAsync(ct); return;
        }

        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            await SendUnauthorizedAsync(ct); return;
        }

        var roles = await _userManager.GetRolesAsync(user);
        var response = new UserInfoResponse(user.Id, user.Email!, roles);
        await SendOkAsync(ApiResponse<UserInfoResponse>.Success(response), ct);
    }
}

public record UserInfoResponse(string UserId, string Email, IList<string> Roles);

