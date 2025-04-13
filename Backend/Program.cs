using FastEndpoints;
using FastEndpoints.Swagger;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

builder.Services.AddFastEndpoints()
                .SwaggerDocument(o => // Configure Swagger/OpenAPI
                {
                    o.DocumentSettings = s =>
                    {
                        s.Title = "MyTemplate API";
                        s.Version = "v1";
                    };
                });

// builder.Services.AddDbContext<ApplicationDbContext>(...);
// builder.Services.AddIdentity<ApplicationUser, IdentityRole>(...)
// builder.Services.AddAuthenticationJwtBearer(...);
// builder.Services.AddAuthorization(...);


var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();

// app.UseCors(...);
// app.UseAuthentication();
// app.UseAuthorization();

app.UseFastEndpoints(c =>
{
    c.Endpoints.RoutePrefix = "api"; // Set API route prefix
                                     // Configure serialization, error handling etc. as needed
    c.Errors.ResponseBuilder = (failures, ctx, statusCode) =>
    {
        // Map validation failures to ProblemDetails
        return new Microsoft.AspNetCore.Mvc.ValidationProblemDetails(
            failures.GroupBy(f => f.PropertyName)
                    .ToDictionary(g => g.Key, g => g.Select(f => f.ErrorMessage).ToArray())
            )
        { Status = statusCode };
    };
})
   .UseSwaggerGen(); // Serves Swagger UI at /swagger

app.Run();


app.Run();

internal record WeatherForecast(DateOnly Date, int TemperatureC, string? Summary)
{
    public int TemperatureF => 32 + (int)(TemperatureC / 0.5556);
}
