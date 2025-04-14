using Backend.Infrastructure;
using FastEndpoints;
using FastEndpoints.Swagger;
using Microsoft.AspNetCore.Http.Features;

var builder = WebApplication.CreateBuilder(args);

RegisterServices(builder.Services, builder.Configuration);



var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    //app.MapOpenApi();
    app.UseSwaggerGen();

}

app.UseFastEndpoints(x => x.Errors.UseProblemDetails());


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




app.Run();



static void RegisterServices(IServiceCollection services, IConfiguration configuration)
{
    services.AddOpenApi();

    services.AddFastEndpoints();
    services.AddSwaggerDocument();

    services.ConfigureSPACors(configuration)
            .ConfigureDatabase(configuration)
            .ConfigureIdentity(configuration)
            .ConfigureAntiForgery(configuration);




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
