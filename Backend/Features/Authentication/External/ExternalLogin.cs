
using FastEndpoints;
using Microsoft.AspNetCore.Authentication;

namespace Backend.Features.Authentication.External;

public class ExternalLoginRequest
{
    public string Provider { get; set; } = default!; // e.g., "Google"
    public string? ReturnUrl { get; set; }
}



public class ExternalLoginEndpoint : Endpoint<ExternalLoginRequest> // Using DTO from DtosAndValidators.cs
{
    public override void Configure()
    {
        Get("/auth/external-login");
        AllowAnonymous();
        Description(b => b.WithTags("Authentication"));
    }
    public override async Task HandleAsync(ExternalLoginRequest req, CancellationToken ct)
    {
        var currentRequest = HttpContext.Request;
        var host = currentRequest.Host.ToUriComponent();
        var scheme = currentRequest.Scheme;
        var callbackPath = "/api/auth/google-callback"; // Match registration
        var redirectUrl = $"{scheme}://{host}{callbackPath}";

        var properties = new AuthenticationProperties { RedirectUri = redirectUrl };
        properties.Items.Add("LoginProvider", req.Provider);

        if (!string.IsNullOrEmpty(req.ReturnUrl))
            properties.Items.Add("ReturnUrl", req.ReturnUrl);

        await HttpContext.ChallengeAsync(req.Provider, properties); // Triggers redirect to Google
    }
}




