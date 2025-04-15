using Backend.Infrastructure;
using Backend.Infrastructure.Persistence;
using FastEndpoints;
using FastEndpoints.Swagger;
using Microsoft.AspNetCore.Http.Features;

// Configure Serilog Bootstrap Logger (if applicable, from Phase 5)
// Log.Logger = new LoggerConfiguration()...CreateBootstrapLogger();

try
{
    // Log.Information("Starting web application"); // Serilog

    var builder = WebApplication.CreateBuilder(args);

    RegisterServices(builder.Services, builder.Configuration);



    var app = builder.Build();

    await EnsureDB(app, builder.Configuration);





    app.UseCors("NuxtFrontend");

    app.UseHttpsRedirection();

    app.UseExceptionHandler();

    app.UseStatusCodePages();


    // app.UseCors(...);
    // app.UseAuthentication();
    // app.UseAuthorization();

    //app.UseFastEndpoints(c =>
    //{
    //    c.Endpoints.RoutePrefix = "api"; // Set API route prefix
    //                                     // Configure serialization, error handling etc. as needed
    //    c.Errors.ResponseBuilder = (failures, ctx, statusCode) =>
    //    {
    //        // Map validation failures to ProblemDetails
    //        return new Microsoft.AspNetCore.Mvc.ValidationProblemDetails(
    //            failures.GroupBy(f => f.PropertyName)
    //                    .ToDictionary(g => g.Key, g => g.Select(f => f.ErrorMessage).ToArray())
    //            )
    //        { Status = statusCode };
    //    };
    //})
    //   .UseSwaggerGen(); // Serves Swagger UI at /swagger


    app.UseAuthentication(); // Enable AuthN middleware BEFORE Authorization
    app.UseAuthorization();  // Enable AuthZ middleware

    // Add Antiforgery Middleware AFTER AuthN/AuthZ
    app.UseAntiforgery();


    app.UseFastEndpoints(x => x.Errors.UseProblemDetails());


    // Configure the HTTP request pipeline.
    if (app.Environment.IsDevelopment())
    {
        //app.MapOpenApi();
        app.UseSwaggerGen();

    }


    app.Run();

}
catch (Exception ex) { /* Log fatal startup errors */ }
finally
{ /* Serilog CloseAndFlush() */ }

static void RegisterServices(IServiceCollection services, IConfiguration configuration)
{
    services.AddOpenApi();


    services.AddFastEndpoints();
    services.AddSwaggerDocument();


    services.ConfigureSPACors(configuration)
            .ConfigureDatabase(configuration)
            .ConfigureAuthenticationAndAuthorization(configuration);

    // Add Health Checks (from Phase 5 setup)
    //services.AddHealthChecks()
    //    .(configuration.GetConnectionString("DefaultConnection")!, "database-check");



    services.AddExceptionHandler<GlobalExceptionHandler>();

    services.AddProblemDetails(options => options.CustomizeProblemDetails = problemContext =>
    {
        problemContext.ProblemDetails.Instance = $"{problemContext.HttpContext.Request.Method} {problemContext.HttpContext.Request.Path}";
        problemContext.ProblemDetails.Extensions.TryAdd("requestId", problemContext.HttpContext.TraceIdentifier);
        var activity = problemContext.HttpContext.Features.Get<IHttpActivityFeature>()?.Activity;
        problemContext.ProblemDetails.Extensions.TryAdd("traceId", activity?.Id);
    });





    // Add services to the container.
    // Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi

    //builder.Services.AddFastEndpoints()
    //                .SwaggerDocument(o => // Configure Swagger/OpenAPI
    //                {
    //                    o.DocumentSettings = s =>
    //                    {
    //                        s.Title = "MyTemplate API";
    //                        s.Version = "v1";
    //                    };
    //                });

    // builder.Services.AddDbContext<ApplicationDbContext>(...);
    // builder.Services.AddIdentity<ApplicationUser, IdentityRole>(...)
    // builder.Services.AddAuthenticationJwtBearer(...);
    // builder.Services.AddAuthorization(...);


}



static async Task EnsureDB(WebApplication app, IConfiguration config)
{
    using var scope = app.Services.CreateScope();
    var services = scope.ServiceProvider;
    var context = services.GetRequiredService<ApplicationDbSeeder>();

    await context.ManageDataAsync(config);

}
