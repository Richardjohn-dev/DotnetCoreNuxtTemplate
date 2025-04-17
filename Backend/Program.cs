using Backend.Infrastructure.Extensions;
using Backend.Infrastructure.Persistence;

// Configure Serilog Bootstrap Logger (if applicable, from Phase 5)
// Log.Logger = new LoggerConfiguration()...CreateBootstrapLogger();

try
{
    // Log.Information("Starting web application"); // Serilog

    var builder = WebApplication.CreateBuilder(args);

    builder.RegisterServices();

    var app = builder.Build();

    await MigrateDatabase(app, builder.Configuration);

    // Configure middleware pipeline
    app.ConfigureMiddlewarePipeline();


    app.Run();

}
catch (Exception ex) { /* Log fatal startup errors */ }
finally
{ /* Serilog CloseAndFlush() */ }


static async Task MigrateDatabase(WebApplication app, IConfiguration config)
{
    try
    {
        using var scope = app.Services.CreateScope();
        var services = scope.ServiceProvider;
        var seeder = services.GetRequiredService<ApplicationDbSeeder>();
        await seeder.ManageDataAsync(config);

        // Optional logging
        var logger = services.GetRequiredService<ILogger<Program>>();
        logger.LogInformation("Database migration completed successfully");
    }
    catch (Exception ex)
    {
        // Log the error and optionally rethrow depending on your error handling strategy
        var logger = app.Services.GetRequiredService<ILogger<Program>>();
        logger.LogError(ex, "An error occurred while migrating the database");
        throw; // Rethrow if you want to prevent application startup on migration failure
    }
}