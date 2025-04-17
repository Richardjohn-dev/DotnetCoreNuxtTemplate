using Backend.Infrastructure.Extensions;
using Backend.Infrastructure.Persistence;


//var logger = new LoggerConfiguration()

//                .WriteTo.File("logs/errorlog-.txt",
//                    restrictedToMinimumLevel: Serilog.Events.LogEventLevel.Warning, rollingInterval: RollingInterval.Day)
//                .CreateLogger();
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
catch (Exception ex)
{
    var sdfs = "";
    //Log.Fatal(ex, "Host terminated unexpectedly");
}
finally
{
    //Log.Information("Closing service complete");
    //Log.CloseAndFlush();
}

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

