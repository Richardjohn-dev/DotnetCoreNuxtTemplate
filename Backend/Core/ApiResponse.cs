namespace Backend.Core;

// For successful Api Responses. 

// Note: Errors should generally be handled via ProblemDetails (RFC 7807)
// by FastEndpoints/ASP.NET Core, not this wrapper.
public record ApiResponse<T>(T Payload, string? Message = null)
{
    public static ApiResponse<T> Success(T payload, string? message = "Operation successful.")
    {
        return new ApiResponse<T>(payload, message);
    }

    public static ApiResponse<bool> Success(string? message = "Operation successful.")
    {
        return new ApiResponse<bool>(true, message);
    }


}