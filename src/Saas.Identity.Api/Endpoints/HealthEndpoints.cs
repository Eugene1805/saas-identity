using Microsoft.EntityFrameworkCore;
using Saas.Identity.Domain.Common;
using Saas.Identity.Infrastructure.Persistence;

namespace Saas.Identity.Api.Endpoints;

public sealed record HealthResponse(
    string Status,
    string Service,
    string Database,
    string TimestampGmt6);

public sealed record LivenessHealthResponse(
    string Status,
    string Service,
    string Probe,
    string Scope,
    string TimestampGmt6);

public sealed record ReadinessHealthResponse(
    string Status,
    string Service,
    string Probe,
    string Scope,
    string Database,
    string TimestampGmt6);

internal static class HealthEndpoints
{
    public static void MapHealthEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/health", async (
                IDbContextFactory<GlobalIdentityDbContext> dbContextFactory,
                CancellationToken cancellationToken) =>
            {
                var nowGmt6 = Gmt6Clock.FormatIsoGmt6(DateTimeOffset.UtcNow);
                var canConnect = await TryCanConnectAsync(dbContextFactory, cancellationToken);

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

        endpoints.MapGet("/health/live", () =>
            {
                var nowGmt6 = Gmt6Clock.FormatIsoGmt6(DateTimeOffset.UtcNow);
                return Results.Ok(
                    new LivenessHealthResponse("Healthy", "saas-identity", "live", "process-only", nowGmt6));
            })
            .WithName("GetHealthLive")
            .WithTags("Health")
            .WithSummary("Sonda de liveness para Kubernetes")
            .AllowAnonymous()
            .Produces<LivenessHealthResponse>(StatusCodes.Status200OK);

        endpoints.MapGet("/health/ready", async (
                IDbContextFactory<GlobalIdentityDbContext> dbContextFactory,
                CancellationToken cancellationToken) =>
            {
                var nowGmt6 = Gmt6Clock.FormatIsoGmt6(DateTimeOffset.UtcNow);
                var canConnect = await TryCanConnectAsync(dbContextFactory, cancellationToken);

                if (!canConnect)
                {
                    return Results.Json(
                        new ReadinessHealthResponse("Unhealthy", "saas-identity", "ready", "database", "Disconnected", nowGmt6),
                        statusCode: StatusCodes.Status503ServiceUnavailable);
                }

                return Results.Ok(
                    new ReadinessHealthResponse("Healthy", "saas-identity", "ready", "database", "Connected", nowGmt6));
            })
            .WithName("GetHealthReady")
            .WithTags("Health")
            .WithSummary("Sonda de readiness con conectividad PostgreSQL")
            .AllowAnonymous()
            .Produces<ReadinessHealthResponse>(StatusCodes.Status200OK)
            .Produces<ReadinessHealthResponse>(StatusCodes.Status503ServiceUnavailable);
    }

    private static async Task<bool> TryCanConnectAsync(
        IDbContextFactory<GlobalIdentityDbContext> dbContextFactory,
        CancellationToken cancellationToken)
    {
        try
        {
            await using var dbContext = await dbContextFactory.CreateDbContextAsync(cancellationToken);
            return await dbContext.Database.CanConnectAsync(cancellationToken);
        }
        catch
        {
            return false;
        }
    }
}
