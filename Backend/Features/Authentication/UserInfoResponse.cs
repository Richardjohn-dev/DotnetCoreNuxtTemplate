namespace Backend.Features.Authentication;

public record UserInfoResponse(string UserId, string Email, IList<string> Roles);