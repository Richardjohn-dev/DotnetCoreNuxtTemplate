using Backend.Infrastructure.Identity.Constants;
using Backend.Infrastructure.Persistence;
using Backend.Infrastructure.Persistence.Entity;
using FastEndpoints;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace Backend.Infrastructure.Extensions;


public static class ServicesRegistrationExtensions
{
    public static WebApplicationBuilder RegisterServices(this WebApplicationBuilder builder)
    {
        builder.Services.ConfigureErrorHandling();

        // Database
        builder.Services.ConfigureDatabase(builder.Configuration);

        // Identity (must come before Authentication)
        builder.Services.ConfigureIdentity();

        // Authentication (JWT & Google) & Application Cookie Config
        builder.Services.ConfigureAuthenticationAndCookies(builder.Configuration, builder.Environment);

        // Antiforgery
        builder.Services.ConfigureAntiforgery();

        // Authorization policies
        builder.Services.ConfigureAuthorization();

        // CORS policies
        builder.Services.ConfigureSPACors(builder.Configuration);

        // FastEndpoints and Swagger
        builder.Services.ConfigureFastEndpoints();

        // Health checks
        //services.ConfigureHealthChecks(configuration);

        return builder;
    }

    public static IServiceCollection ConfigureErrorHandling(this IServiceCollection services)
    {
        services.AddExceptionHandler<GlobalExceptionHandler>();
        services.AddProblemDetails(options => options.CustomizeProblemDetails = problemContext =>
        {
            problemContext.ProblemDetails.Instance = $"{problemContext.HttpContext.Request.Method} {problemContext.HttpContext.Request.Path}";
            problemContext.ProblemDetails.Extensions.TryAdd("requestId", problemContext.HttpContext.TraceIdentifier);
            var activity = problemContext.HttpContext.Features.Get<IHttpActivityFeature>()?.Activity;
            problemContext.ProblemDetails.Extensions.TryAdd("traceId", activity?.Id);
        });

        return services;
    }


    public static IServiceCollection ConfigureDatabase(this IServiceCollection services, IConfiguration configuration)
    {
        var connectionString = configuration.GetConnectionString("DefaultConnection");
        if (string.IsNullOrEmpty(connectionString))
            throw new InvalidOperationException("Database connection string 'DefaultConnection' not configured.");

        services.AddDbContext<ApplicationDbContext>(options =>
            options.UseSqlServer(connectionString)); // Get from config


        services.AddScoped<ApplicationDbSeeder>(); // seed data / ensure migrations applied inside


        return services;

    }

    public static IServiceCollection ConfigureIdentity(this IServiceCollection services)
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

            options.SignIn.RequireConfirmedAccount = true;// adjust as needed

            options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
            options.Lockout.MaxFailedAccessAttempts = 5;

            options.User.RequireUniqueEmail = true;
        })
        .AddEntityFrameworkStores<ApplicationDbContext>()
        .AddDefaultTokenProviders(); // For password reset, email confirmation tokens


        return services;


    }
    //public static IServiceCollection ConfigureAuthentication(this IServiceCollection services, IConfiguration configuration)
    //{


    //    // Configure Authentication (JWT and Google)
    //    var jwtSettings = configuration.GetSection("JWT");
    //    var key = Encoding.ASCII.GetBytes(jwtSettings["SecretKey"]
    //        ?? throw new InvalidOperationException("JWT SecretKey not configured"));

    //    services.AddAuthentication(options =>
    //    {
    //        options.DefaultScheme = IdentityConstants.ApplicationScheme; // Use Identity's cookie scheme
    //        options.DefaultSignInScheme = IdentityConstants.ExternalScheme; // Default for external logins
    //    })
    //    .AddJwtBearer(options => // Configure JWT Bearer for API access validation
    //    {
    //        //options.RequireHttpsMetadata = builder.Environment.IsProduction();
    //        options.SaveToken = false; // Don't need to save token when using cookies
    //        options.TokenValidationParameters = new TokenValidationParameters
    //        {
    //            ValidateIssuerSigningKey = true,
    //            IssuerSigningKey = new SymmetricSecurityKey(key),
    //            ValidateIssuer = true,
    //            ValidIssuer = jwtSettings["Issuer"],
    //            ValidateAudience = true,
    //            ValidAudience = jwtSettings["Audience"],
    //            ValidateLifetime = true,
    //            ClockSkew = TimeSpan.Zero
    //        };
    //        options.Events = new JwtBearerEvents // Read token from HttpOnly cookie
    //        {
    //            OnMessageReceived = context =>
    //            {
    //                context.Token = context.Request.Cookies["access_token"];
    //                return Task.CompletedTask;
    //            }
    //        };
    //    })
    //    .AddGoogle(options => // Add Google Authentication Handler
    //    {
    //        var googleAuthNSection = configuration.GetSection("Authentication:Google");
    //        options.ClientId = googleAuthNSection["ClientId"] ?? throw new InvalidOperationException("Google ClientId not configured");
    //        options.ClientSecret = googleAuthNSection["ClientSecret"] ?? throw new InvalidOperationException("Google ClientSecret not configured");
    //        options.CallbackPath = "/api/auth/google-callback";
    //        options.SaveTokens = true; // Optional: Save external tokens
    //        options.Scope.Add("profile");
    //        options.Scope.Add("email");
    //    });
    //    //.AddCookie(IdentityConstants.ExternalScheme); // Needed for external login flow state

    //    return services;
    //}

    public static IServiceCollection ConfigureAuthenticationAndCookies(this IServiceCollection services, IConfiguration configuration, IWebHostEnvironment environment)
    {
        var jwtSettings = configuration.GetSection("JWT");
        var key = Encoding.ASCII.GetBytes(jwtSettings["SecretKey"]
            ?? throw new InvalidOperationException("JWT SecretKey not configured"));

        services.AddAuthentication(options =>
        {
            // Set Default schemes for API authorization
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            // Set Default scheme for external logins (used by Identity)
            options.DefaultSignInScheme = IdentityConstants.ExternalScheme;
        })
        .AddJwtBearer(options => // Configure JWT Bearer for API access validation
        {
            options.RequireHttpsMetadata = environment.IsProduction(); // Use environment check
            options.SaveToken = false;
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
                // Add OnChallenge / OnAuthenticationFailed handlers here if needed
                //OnAuthenticationFailed = context => {
                //    // Optional: Add logging for failed JWT validation
                //    Console.WriteLine("JWT Auth Failed: " + context.Exception.Message);
                //    return Task.CompletedTask;
                //},
                //OnChallenge = context => {
                //    // Optional: Customize challenge response if needed (e.g., avoid redirect for APIs)
                //    // context.HandleResponse(); // Prevent default redirect behavior if Identity Challenges
                //    // context.Response.StatusCode = 401;
                //    // return Task.CompletedTask;
                //    return Task.CompletedTask; // Let default behavior proceed for now
                //}
            };
        })
        .AddGoogle(options => // Add Google Authentication Handler
        {
            var googleAuthNSection = configuration.GetSection("Authentication:Google");
            options.ClientId = googleAuthNSection["ClientId"] ?? throw new InvalidOperationException("Google ClientId not configured");
            options.ClientSecret = googleAuthNSection["ClientSecret"] ?? throw new InvalidOperationException("Google ClientSecret not configured");
            options.CallbackPath = "/api/auth/google-callback"; // Ensure this matches endpoint route & Google Console
            options.SaveTokens = true;
            options.Scope.Add("profile");
            options.Scope.Add("email");
        });

        // --- Configure Identity's Application Cookie ---
        // Even though JWT is primary for API, Identity uses this cookie internally.
        // Configuring it helps prevent conflicts and unwanted redirects.
        services.ConfigureApplicationCookie(options =>
        {
            options.Cookie.HttpOnly = true;
            options.Cookie.SecurePolicy = CookieSecurePolicy.Always; // Enforce HTTPS
            options.Cookie.SameSite = SameSiteMode.Lax;
            options.ExpireTimeSpan = TimeSpan.FromDays(14); // Identity session cookie expiry
            options.SlidingExpiration = true;

            // Prevent Identity's default redirects for API calls (return status codes instead)
            options.Events.OnRedirectToLogin = context =>
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return Task.CompletedTask;
            };
            options.Events.OnRedirectToAccessDenied = context =>
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                return Task.CompletedTask;
            };
        });

        return services;
    }

    public static IServiceCollection ConfigureAuthorization(this IServiceCollection services)
    {
        services.AddAuthorization(options =>
        {
            options.AddPolicy(ApplicationPolicy.AdminAccess, policy => policy.RequireRole(ApplicationRole.Admin)); // Defined in SeedData later
            options.AddPolicy(ApplicationPolicy.UserAccess, policy => policy.RequireRole(ApplicationRole.User, ApplicationRole.Admin)); // Defined in SeedData later
        });

        return services;
    }







    public static IServiceCollection ConfigureAntiforgery(this IServiceCollection services)
    {
        // Configure Antiforgery (for CSRF protection with cookies)
        services.AddAntiforgery(options =>
        {
            options.HeaderName = "X-CSRF-TOKEN"; // Match header name expected by frontend

            options.Cookie.Name = "CSRF-TOKEN";
            options.Cookie.HttpOnly = false;  // HttpOnly = false is needed for the frontend to read the token from the cookie
            options.Cookie.SecurePolicy = CookieSecurePolicy.Always; // Ensure Secure flag
            options.Cookie.SameSite = SameSiteMode.Strict; // Or Lax, depending on needs
        });
        return services;
    }


    //public static IServiceCollection ConfigureHealthChecks(this IServiceCollection services, IConfiguration configuration)
    //{
    //    services.AddHealthChecks()
    //        .AddSqlServer(
    //            configuration.GetConnectionString("DefaultConnection")!,
    //            name: "database-check");

    //    return services;
    //}
    //public static IServiceCollection ConfigureHealthChecks(this IServiceCollection services, IConfiguration configuration)
    //{
    //    services.AddHealthChecks()
    //        .AddSqlServer(
    //            configuration.GetConnectionString("DefaultConnection")!,
    //            name: "database-check",
    //            tags: new[] { "db", "sql" });
    //    return services;
    //}

    public static IServiceCollection ConfigureFastEndpoints(this IServiceCollection services)
    {
        services.AddOpenApi();

        services.AddFastEndpoints();
        services.AddSwaggerDocument();


        return services;
    }

    //public static IServiceCollection ConfigureFastEndpoints(this IServiceCollection services)
    //{
    //    // Register FastEndpoints
    //    services.AddFastEndpoints();

    //    // Configure Swagger/OpenAPI document generation via FastEndpoints extensions
    //    services.SwaggerDocument(o =>
    //    {
    //        o.DocumentSettings = s =>
    //        {
    //            s.Title = "MyTemplate API";
    //            s.Version = "v1";
    //            // Add more OpenAPI document configurations here
    //        };
    //        // Configure JWT Bearer security scheme for Swagger UI
    //        o.EnableJWTBearerAuth = true;
    //    });

    //    return services;
    //}


    public static IServiceCollection ConfigureSPACors(this IServiceCollection services, IConfiguration configuration)
    {
        //var allowedOrigins = configuration.GetSection("AppSettings:CORS-Settings:Allow-Origins").Get<string[]>();

        services.AddCors(options =>
        {
            options.AddPolicy("AllowNuxtFrontend",
               policyBuilder =>
               {
                   policyBuilder.WithOrigins(["http://localhost:3000", "http://localhost:3001"])
                    .AllowAnyMethod()
                    .AllowAnyHeader()
                    .AllowCredentials();
               });

        });

        return services;
    }



};
