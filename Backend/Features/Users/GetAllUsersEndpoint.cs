using Backend.Core;
using Backend.Infrastructure.Identity.Constants;
using Backend.Infrastructure.Persistence.Entity;
using FastEndpoints;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Backend.Features.Users;



public class GetAllUsersEndpoint : EndpointWithoutRequest<ApiResponse<IEnumerable<UserSummaryDto>>>
{
    private readonly UserManager<ApplicationUser> _userManager;
    public GetAllUsersEndpoint(UserManager<ApplicationUser> userManager) => _userManager = userManager;

    public override void Configure() // Roles() must be inside Configure()
    {
        Get("/users");
        // Use policy name defined during Authorization setup for clarity
        // Or directly use Roles constant if preferred and policy not defined
        Options(x => x.RequireAuthorization(policyNames: ApplicationPolicy.AdminAccess)); // Example using policy
                                                                                          // Alternatively: Roles(Roles.Admin);
        Description(b => b.WithTags("Users").WithName("GetAllUsers"));
    }

    public override async Task HandleAsync(CancellationToken ct)
    {
        var users = await _userManager.Users
                            .Select(u => new UserSummaryDto(u.Id, u.UserName!, u.Email!))
                            .ToListAsync(ct);
        await SendOkAsync(ApiResponse<IEnumerable<UserSummaryDto>>.Success(users), ct);
    }
}

public record UserSummaryDto(string Id, string UserName, string Email);

public record UserDetailDto(string Id, string UserName, string Email, IList<string> Roles);

public record UpdateUserRolesRequest
{
    public required IList<string> Roles { get; set; }
}
