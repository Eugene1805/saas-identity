using System.Net.Sockets;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using Saas.Identity.Application.Ports;
using Saas.Identity.Domain.Entities;
using Saas.Identity.Domain.ValueObjects;
using Saas.Identity.Infrastructure.Persistence.Tenancy;

namespace Saas.Identity.Infrastructure.Persistence.Repositories;

internal static class TenantPersistenceHelper
{
    public static void SyncAccountState(
        DbContext dbContext,
        IdentityAccount tracked,
        IdentityAccount source)
    {
        dbContext.Entry(tracked).CurrentValues.SetValues(source);
        dbContext.Entry(tracked).Reference(a => a.Permissions).TargetEntry?.CurrentValues.SetValues(source.Permissions);

        if (source.Role != OrgRole.SUPER_ADMIN)
        {
            var attributionCopy = source.ProfessionalAttribution is null
                ? null
                : source.ProfessionalAttribution with { };

            tracked.UpdateRoleAndPermissions(
                source.Role,
                source.Specialty,
                attributionCopy,
                source.Permissions);
            tracked.UpdateLinkedSpecialists(source.LinkedSpecialistIds);
        }
    }

    public static async Task<T> ExecuteAsync<T>(
        ITenantDbContextFactory factory,
        Guid tenantId,
        Func<TenantIdentityDbContext, Task<T>> operation)
    {
        try
        {
            await using var dbContext = factory.CreateDbContext(tenantId);
            return await operation(dbContext);
        }
        catch (Exception ex) when (ex is not OperationCanceledException &&
                                   ex is not TenantDatabaseUnavailableException &&
                                   IsConnectivityFailure(ex))
        {
            throw new TenantDatabaseUnavailableException(
                tenantId,
                "TENANT_DATABASE_UNAVAILABLE",
                $"Error de conectividad al consultar la base de datos del tenant {tenantId}.",
                ex);
        }
    }

    public static async Task ExecuteAsync(
        ITenantDbContextFactory factory,
        Guid tenantId,
        Func<TenantIdentityDbContext, Task> operation)
    {
        await ExecuteAsync(
            factory,
            tenantId,
            async dbContext =>
            {
                await operation(dbContext);
                return true;
            });
    }

    public static bool IsConnectivityFailure(Exception exception)
    {
        for (Exception? current = exception; current is not null; current = current.InnerException)
        {
            if (current is TimeoutException or SocketException)
            {
                return true;
            }

            if (current is PostgresException postgresException)
            {
                if (postgresException.IsTransient ||
                    postgresException.SqlState.StartsWith("08", StringComparison.Ordinal) ||
                    postgresException.SqlState.StartsWith("57", StringComparison.Ordinal) ||
                    postgresException.SqlState.StartsWith("53", StringComparison.Ordinal))
                {
                    return true;
                }

                return false;
            }

            if (current is NpgsqlException)
            {
                return true;
            }
        }

        return false;
    }
}
