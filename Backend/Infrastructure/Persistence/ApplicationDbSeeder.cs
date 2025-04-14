using Backend.Infrastructure.Identity.Constants;
using Backend.Infrastructure.Persistence.Entity;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Backend.Infrastructure.Persistence;

public class ApplicationDbSeeder
{
    private readonly ApplicationDbContext _context;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly ILogger<ApplicationDbSeeder> _logger;
    public ApplicationDbSeeder(ApplicationDbContext context, UserManager<ApplicationUser> userManager, ILogger<ApplicationDbSeeder> logger, RoleManager<IdentityRole> roleManager)
    {
        _context = context;
        _userManager = userManager;
        _logger = logger;
        _roleManager = roleManager;
    }

    public async Task ManageDataAsync(IConfiguration configuration)
    {
        await _context.Database.MigrateAsync();
        await SeedUsers(configuration);
    }

    public async Task SeedUsers(IConfiguration configuration)
    {

        // Seed Roles
        string[] roleNames = { ApplicationRole.Admin, ApplicationRole.User };
        foreach (var roleName in roleNames)
        {
            var roleExist = await _roleManager.RoleExistsAsync(roleName);
            if (!roleExist)
            {
                _logger.LogInformation("Creating role {RoleName}", roleName);
                await _roleManager.CreateAsync(new IdentityRole(roleName));
            }
        }

        // Seed Admin User (get details from config/secrets)
        var adminEmail = configuration["AdminUser:Email"];
        var adminPassword = configuration["AdminUser:Password"];

        if (string.IsNullOrEmpty(adminEmail) || string.IsNullOrEmpty(adminPassword))
        {
            _logger.LogWarning("Admin User email or password not configured. Skipping admin user seed.");
            return; // Exit if admin user not configured
        }


        var adminUser = await _userManager.FindByEmailAsync(adminEmail);
        if (adminUser == null)
        {
            adminUser = new ApplicationUser { UserName = adminEmail, Email = adminEmail, EmailConfirmed = true };
            _logger.LogInformation("Creating admin user {AdminEmail}", adminEmail);
            var createAdminResult = await _userManager.CreateAsync(adminUser, adminPassword);
            if (createAdminResult.Succeeded)
            {
                _logger.LogInformation("Assigning Admin role to {AdminEmail}", adminEmail);
                await _userManager.AddToRoleAsync(adminUser, ApplicationRole.Admin);
            }
            else
            {
                _logger.LogError("Error creating admin user: {Errors}", string.Join(", ", createAdminResult.Errors.Select(e => e.Description)));
            }
        }
        else
        {
            _logger.LogInformation("Admin user {AdminEmail} already exists.", adminEmail);
        }
    }

}



