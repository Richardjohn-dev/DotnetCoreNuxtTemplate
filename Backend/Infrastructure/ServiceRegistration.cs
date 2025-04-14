using Backend.Infrastructure.Identity;
using Backend.Infrastructure.Persistence;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Backend.Infrastructure;
public static class ServicesRegistration
{
    public static IServiceCollection ConfigureSPACors(this IServiceCollection services, IConfiguration configuration)
    {
        //var allowedOrigins = configuration.GetSection("AppSettings:CORS-Settings:Allow-Origins").Get<string[]>();

        services.AddCors(options =>
        {
            options.AddPolicy("NuxtFrontend",
               builder =>
               builder.WithOrigins(["http://localhost:3000", "http://localhost:3001"])
                    .AllowAnyMethod()
                    .AllowAnyHeader()
                    .AllowCredentials());
        });

        return services;
    }

    public static IServiceCollection ConfigureDatabase(this IServiceCollection services, IConfiguration configuration)
    {
        var connectionString = configuration.GetConnectionString("DefaultConnection");

        services.AddDbContext<ApplicationDbContext>(options =>
            options.UseSqlServer(connectionString)); // Get from config

        return services;

    }

    public static IServiceCollection ConfigureIdentity(this IServiceCollection services, IConfiguration configuration)
    {
        // Configure Identity
        services.AddIdentity<ApplicationUser, IdentityRole>(options =>
        {
            // Adjust as needed
            options.Password.RequireDigit = true;
            options.Password.RequiredLength = 8;
            options.Password.RequireLowercase = true;
            options.Password.RequireUppercase = true;
            options.Password.RequireNonAlphanumeric = false;
            options.SignIn.RequireConfirmedAccount = false; // Set to true if email confirmation is needed
            options.User.RequireUniqueEmail = true;
        })
        .AddEntityFrameworkStores<ApplicationDbContext>()
        .AddDefaultTokenProviders(); // For password reset, email confirmation tokens

        return services;

    }

    public static IServiceCollection ConfigureAntiForgery(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddAntiforgery(options =>
        {
            options.HeaderName = "X-CSRF-TOKEN"; // Match header name expected by frontend
                                                 // HttpOnly = false is needed for the frontend to read the token from the cookie
            options.Cookie.Name = "CSRF-TOKEN";
            options.Cookie.HttpOnly = false;
            options.Cookie.SecurePolicy = CookieSecurePolicy.Always; // Ensure Secure flag
            options.Cookie.SameSite = SameSiteMode.Strict; // Or Lax, depending on needs
        });
        return services;

    }
};
