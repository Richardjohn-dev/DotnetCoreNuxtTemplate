using Microsoft.AspNetCore.Identity;

namespace Backend.Infrastructure.Persistence.Entity;
public class ApplicationUser : IdentityUser
{
    // Add custom properties if needed
    public string? DisplayName { get; set; }
}