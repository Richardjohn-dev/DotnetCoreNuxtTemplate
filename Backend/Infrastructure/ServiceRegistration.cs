using Backend.Infrastructure.Identity.Constants;
using Backend.Infrastructure.Persistence;
using Backend.Infrastructure.Persistence.Entity;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;

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


        services.AddScoped<ApplicationDbSeeder>(); // seed data / ensure migrations applied inside


        return services;

    }

    public static IServiceCollection ConfigureAuthenticationAndAuthorization(this IServiceCollection services, IConfiguration configuration)
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


        // Configure Antiforgery (for CSRF protection with cookies)
        services.AddAntiforgery(options =>
        {
            options.HeaderName = "X-CSRF-TOKEN"; // Match header name expected by frontend
                                                 // HttpOnly = false is needed for the frontend to read the token from the cookie
            options.Cookie.Name = "CSRF-TOKEN";
            options.Cookie.HttpOnly = false;
            options.Cookie.SecurePolicy = CookieSecurePolicy.Always; // Ensure Secure flag
            options.Cookie.SameSite = SameSiteMode.Strict; // Or Lax, depending on needs
        });



        // Configure Authentication (JWT and Google)
        var jwtSettings = configuration.GetSection("JWT");
        var key = Encoding.ASCII.GetBytes(jwtSettings["SecretKey"] ?? throw new InvalidOperationException("JWT SecretKey not configured"));

        services.AddAuthentication(options =>
         {
             options.DefaultScheme = IdentityConstants.ApplicationScheme; // Use Identity's cookie scheme
             options.DefaultSignInScheme = IdentityConstants.ExternalScheme; // Default for external logins
         })
             .AddJwtBearer(options => // Configure JWT Bearer for API access validation
             {
                 //options.RequireHttpsMetadata = builder.Environment.IsProduction();
                 options.SaveToken = false; // Don't need to save token when using cookies
                 options.TokenValidationParameters = new TokenValidationParameters
                 {
                     ValidateIssuerSigningKey = true,
                     IssuerSigningKey = new SymmetricSecurityKey(key),
                     ValidateIssuer = true,
                     ValidIssuer = jwtSettings["Issuer"],
                     ValidateAudience = true,
                     ValidAudience = jwtSettings["Audience"],
                     ValidateLifetime = true,
                     ClockSkew = TimeSpan.Zero
                 };
                 options.Events = new JwtBearerEvents // Read token from HttpOnly cookie
                 {
                     OnMessageReceived = context =>
                     {
                         context.Token = context.Request.Cookies["access_token"];
                         return Task.CompletedTask;
                     }
                 };
             })
             .AddGoogle(options => // Add Google Authentication Handler
             {
                 var googleAuthNSection = configuration.GetSection("Authentication:Google");
                 options.ClientId = googleAuthNSection["ClientId"] ?? throw new InvalidOperationException("Google ClientId not configured");
                 options.ClientSecret = googleAuthNSection["ClientSecret"] ?? throw new InvalidOperationException("Google ClientSecret not configured");
                 options.CallbackPath = "/api/auth/google-callback";
                 options.SaveTokens = true; // Optional: Save external tokens
                 options.Scope.Add("profile");
                 options.Scope.Add("email");
             })
             .AddCookie(IdentityConstants.ExternalScheme); // Needed for external login flow state


        services.AddAuthorization(options =>
        {
            options.AddPolicy(ApplicationPolicy.AdminAccess, policy => policy.RequireRole(ApplicationRole.Admin)); // Defined in SeedData later
            options.AddPolicy(ApplicationPolicy.UserAccess, policy => policy.RequireRole(ApplicationRole.User, ApplicationRole.Admin)); // Defined in SeedData later
        });

        //services.AddAuthorization(options =>
        //{
        //    options.AddPolicy(ApplicationPolicy.UserAccess, policy =>
        //           policy.RequireAssertion(context =>
        //                       context.User.IsInRole(ApplicationRole.Admin)
        //                       || context.User.IsInRole(ApplicationRole.User)));

        //    //options.FallbackPolicy = options.DefaultPolicy;
        //    //Todo : why does this make CORS issue? probably https
        //});

        return services;

    }


};
