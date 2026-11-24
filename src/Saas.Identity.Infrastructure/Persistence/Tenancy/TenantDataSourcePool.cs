using System.Collections.Concurrent;
using Npgsql;
using Saas.Identity.Application.Ports;

namespace Saas.Identity.Infrastructure.Persistence.Tenancy;

internal sealed class TenantDataSourcePool(ITenantConnectionResolver connectionResolver) : IAsyncDisposable
{
    private readonly ConcurrentDictionary<string, NpgsqlDataSource> _dataSources = new(StringComparer.Ordinal);

    public (string ConnectionString, NpgsqlDataSource DataSource) GetConnection(Guid tenantId)
    {
        if (!connectionResolver.TryResolveConnectionString(tenantId, out var connectionString) ||
            string.IsNullOrWhiteSpace(connectionString))
        {
            throw new TenantDatabaseUnavailableException(
                tenantId,
                "TENANT_DATABASE_NOT_CONFIGURED",
                $"No existe una base de datos configurada para el tenant {tenantId}.");
        }

        var dataSource = _dataSources.GetOrAdd(connectionString, static cs => NpgsqlDataSource.Create(cs));
        return (connectionString, dataSource);
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var dataSource in _dataSources.Values)
        {
            await dataSource.DisposeAsync();
        }

        _dataSources.Clear();
    }
}
