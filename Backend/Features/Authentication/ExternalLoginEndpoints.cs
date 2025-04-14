//namespace Backend.Features.Authentication;

//public class ExternalLoginEndpoint : Endpoint<ExternalLoginRequest> // Using DTO from DtosAndValidators.cs
//{
//    public override void Configure()
//    {
//        Get("/auth/external-login"); AllowAnonymous(); Description(b => b.Tags("Authentication"));
//    }
//    public override async Task HandleAsync(ExternalLoginRequest req, CancellationToken ct)
//    {
//        var redirectUrl = Url.EndpointUrl<ExternalLoginCallbackEndpoint>(); // Auto-detects route for the specified endpoint
//        var properties = new AuthenticationProperties { RedirectUri = redirectUrl };
//        properties.Items.Add("LoginProvider", req.Provider);
//        if (!string.IsNullOrEmpty(req.ReturnUrl)) properties.Items.Add("ReturnUrl", req.ReturnUrl);
//        await HttpContext.ChallengeAsync(req.Provider, properties); // Triggers redirect to Google
//    }
//}}
