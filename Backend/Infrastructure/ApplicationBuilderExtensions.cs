// Infrastructure/ApplicationBuilderExtensions.cs
using FastEndpoints;
using FastEndpoints.Swagger;

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

        // CORS before auth
        app.UseCors("AllowNuxtFrontend");

        // Endpoints
        app.UseFastEndpoints(x => x.Errors.UseProblemDetails());


        // Authentication and Authorization
        app.UseAuthentication();
        app.UseAuthorization();

        // Anti-forgery after auth
        app.UseAntiforgery();

        // Swagger UI
        app.UseSwaggerGen();

        // Health checks
        //app.MapHealthChecks("/healthz");

        return app;
    }

}