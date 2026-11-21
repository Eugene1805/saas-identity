using System.Globalization;
using Microsoft.AspNetCore.Mvc;
using Saas.Identity.Domain.Common;

namespace Saas.Identity.Api.Endpoints;

internal static class ProblemDetailsMapper
{
    public static IResult ToProblem(DomainError error, HttpContext httpContext)
    {
        var extensions = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["code"] = error.Code,
        };

        if (error.Extensions is not null)
        {
            foreach (var (key, value) in error.Extensions)
            {
                extensions[key] = value;
            }

            if (error.Extensions.TryGetValue("retryAfterSeconds", out var retryObj) &&
                retryObj is int retryAfterSeconds)
            {
                httpContext.Response.Headers.RetryAfter = retryAfterSeconds.ToString(CultureInfo.InvariantCulture);
            }
        }

        return Results.Problem(
            title: error.Code,
            detail: error.Message,
            statusCode: error.HttpStatus,
            instance: httpContext.Request.Path,
            extensions: extensions);
    }
}
