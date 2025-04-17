// Infrastructure/ApplicationBuilderExtensions.cs
using Backend.Infrastructure.Persistence;
using FastEndpoints;
using FastEndpoints.Swagger;
using Microsoft.EntityFrameworkCore;

namespace Backend.Infrastructure.Extensions;

public static class ApplicationBuilderExtensions
{
    public static WebApplication ConfigureMiddlewarePipeline(this WebApplication app)
    {
        // Exception handling should come first in pipeline
        if (app.Environment.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
        }
        else
        {
            app.UseExceptionHandler();
            app.UseHsts();
        }

        // Configure Serilog request logging if used
        // app.UseSerilogRequestLogging();

        // HTTPS redirection
        app.UseHttpsRedirection();

        // Static files before auth if needed
        // app.UseStaticFiles();

        // CORS before auth
        app.UseCors("NuxtFrontend");

        // Authentication and Authorization
        app.UseAuthentication();
        app.UseAuthorization();


        //app.UseStatusCodePages();

        // Anti-forgery after auth
        app.UseAntiforgery();

        // Endpoints
        app.UseFastEndpoints(x => x.Errors.UseProblemDetails());


        // Swagger UI
        app.UseSwaggerGen();

        // Health checks
        //app.MapHealthChecks("/healthz");

        return app;
    }

    public static WebApplication MigrateDatabase(this WebApplication app)
    {
        using (var scope = app.Services.CreateScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            dbContext.Database.Migrate();

            // Call seed data if needed
            // var seeder = scope.ServiceProvider.GetRequiredService<ApplicationDbSeeder>();
            // seeder.SeedAsync().GetAwaiter().GetResult();
        }

        return app;
    }
}