namespace Saas.Identity.Application.Ports;

public interface ITenantDatabaseMigratorPort
{
    Task EnsureMigratedAsync(Guid tenantId, CancellationToken cancellationToken = default);
}
