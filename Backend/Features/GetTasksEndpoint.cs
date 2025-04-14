
using Backend.Core;
using FastEndpoints;

public class GetTasksEndpoint : EndpointWithoutRequest<ApiResponse<string[]>>
{
    public override void Configure()
    {
        Get("/api/sample-data/");
        AllowAnonymous();

    }

    public override async Task HandleAsync(CancellationToken ct)
    {
        var data = SampleData.GetAll;
        await SendAsync(ApiResponse<string[]>.Success(data));
    }
}



public static class SampleData
{
    public static string[] GetAll { get; } = ["asd", "dffds"];


}