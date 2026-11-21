using Saas.Identity.Domain.Common;
using Saas.Identity.Infrastructure.Persistence;

namespace Saas.Identity.Api.Endpoints;

public sealed record HealthResponse(
    string Status,
    string Service,
    string Database,
    string TimestampGmt6);

internal static class HealthEndpoints
{
    public static void MapHealthEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/health", async (
                IdentityDbContext dbContext,
                CancellationToken cancellationToken) =>
            {
                var nowGmt6 = Gmt6Clock.FormatIsoGmt6(DateTimeOffset.UtcNow);
                var canConnect = false;
                try
                {
                    canConnect = await dbContext.Database.CanConnectAsync(cancellationToken);
                }
                catch
                {
                    canConnect = false;
                }

                if (!canConnect)
                {
                    return Results.Json(
                        new HealthResponse("Unhealthy", "saas-identity", "Disconnected", nowGmt6),
                        statusCode: StatusCodes.Status503ServiceUnavailable);
                }

                return Results.Ok(
                    new HealthResponse("Healthy", "saas-identity", "Connected", nowGmt6));
            })
            .WithName("GetHealth")
            .WithTags("Health")
            .WithSummary("Estado de salud del servicio y PostgreSQL")
            .AllowAnonymous()
            .Produces<HealthResponse>(StatusCodes.Status200OK)
            .Produces<HealthResponse>(StatusCodes.Status503ServiceUnavailable);
    }
}
