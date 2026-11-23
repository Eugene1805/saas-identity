using Microsoft.EntityFrameworkCore;
using Npgsql;
using Saas.Identity.Application.Ports;
using Saas.Identity.Domain.Entities;
using Saas.Identity.Infrastructure.Persistence.Tenancy;

namespace Saas.Identity.Infrastructure.Persistence.Repositories;

internal sealed class EfProvisioningRecordRepository(
    ITenantDbContextFactory tenantDbContextFactory,
    TenantDataSourcePool dataSourcePool) : IProvisioningRecordRepository
{
    public async Task<T> ExecuteWithTenantLockAsync<T>(
        Guid tenantId,
        Func<CancellationToken, Task<T>> action,
        CancellationToken cancellationToken = default)
    {
        var (_, dataSource) = dataSourcePool.GetConnection(tenantId);
        var lockKey = EfTenantDatabaseMigrator.ComputeAdvisoryLockKey(tenantId, salt: 0x50524F56_41444D49); // PROVADMI

        NpgsqlConnection? lockConn = null;
        try
        {
            lockConn = await dataSource.OpenConnectionAsync(cancellationToken);
            await using (var lockCmd = lockConn.CreateCommand())
            {
                lockCmd.CommandText = "SELECT pg_advisory_lock(@key);";
                lockCmd.Parameters.AddWithValue("key", lockKey);
                await lockCmd.ExecuteNonQueryAsync(cancellationToken);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException &&
                                   ex is not TenantDatabaseUnavailableException &&
                                   TenantPersistenceHelper.IsConnectivityFailure(ex))
        {
            if (lockConn is not null)
            {
                await lockConn.DisposeAsync();
            }

            throw new TenantDatabaseUnavailableException(
                tenantId,
                "TENANT_DATABASE_UNAVAILABLE",
                $"Error al adquirir bloqueo de aprovisionamiento para el tenant {tenantId}.",
                ex);
        }

        try
        {
            return await action(cancellationToken);
        }
        finally
        {
            try
            {
                await using var unlockCmd = lockConn.CreateCommand();
                unlockCmd.CommandText = "SELECT pg_advisory_unlock(@key);";
                unlockCmd.Parameters.AddWithValue("key", lockKey);
                await unlockCmd.ExecuteNonQueryAsync(CancellationToken.None);
            }
            catch
            {
                // Cerrar la conexión libera automáticamente cualquier advisory lock pendiente.
            }

            await lockConn.DisposeAsync();
        }
    }

    public Task<ProvisioningRecord?> FindByRequestIdAsync(
        Guid tenantId,
        string provisioningRequestId,
        CancellationToken cancellationToken = default)
    {
        return TenantPersistenceHelper.ExecuteAsync(
            tenantDbContextFactory,
            tenantId,
            db => db.ProvisioningRecords
                .AsNoTracking()
                .FirstOrDefaultAsync(
                    p => p.TenantId == tenantId && p.ProvisioningRequestId == provisioningRequestId,
                    cancellationToken));
    }

    public Task<ProvisioningRecord?> FindAnyByTenantAsync(
        Guid tenantId,
        CancellationToken cancellationToken = default)
    {
        return TenantPersistenceHelper.ExecuteAsync(
            tenantDbContextFactory,
            tenantId,
            db => db.ProvisioningRecords
                .AsNoTracking()
                .FirstOrDefaultAsync(p => p.TenantId == tenantId, cancellationToken));
    }

    public Task<ProvisioningInsertOutcome> AddWithAccountAsync(
        Guid tenantId,
        ProvisioningRecord record,
        IdentityAccount account,
        CancellationToken cancellationToken = default)
    {
        if (record.TenantId != tenantId || account.TenantId != tenantId)
        {
            throw new InvalidOperationException("Los registros de aprovisionamiento no coinciden con el tenant de destino.");
        }

        return TenantPersistenceHelper.ExecuteAsync(
            tenantDbContextFactory,
            tenantId,
            async db =>
            {
                await db.Accounts.AddAsync(account, cancellationToken);
                await db.ProvisioningRecords.AddAsync(record, cancellationToken);

                try
                {
                    await db.SaveChangesAsync(cancellationToken);
                    return ProvisioningInsertOutcome.Inserted;
                }
                catch (DbUpdateException ex) when (ex.InnerException is PostgresException pg &&
                                                   pg.SqlState == PostgresErrorCodes.UniqueViolation)
                {
                    return pg.ConstraintName switch
                    {
                        "ux_provisioning_records_request_id" => ProvisioningInsertOutcome.DuplicateRequestId,
                        "ux_provisioning_records_tenant_id" => ProvisioningInsertOutcome.TenantAlreadyProvisioned,
                        "ux_accounts_tenant_email" => ProvisioningInsertOutcome.DuplicateEmail,
                        _ => throw new InvalidOperationException(
                            $"Violación de restricción única no esperada en aprovisionamiento: {pg.ConstraintName}",
                            ex),
                    };
                }
            });
    }

    public Task UpdateAsync(
        Guid tenantId,
        ProvisioningRecord record,
        CancellationToken cancellationToken = default)
    {
        if (record.TenantId != tenantId)
        {
            throw new InvalidOperationException("El registro de aprovisionamiento no pertenece al tenant indicado.");
        }

        return TenantPersistenceHelper.ExecuteAsync(
            tenantDbContextFactory,
            tenantId,
            async db =>
            {
                var tracked = await db.ProvisioningRecords.FirstAsync(
                    p => p.Id == record.Id && p.TenantId == tenantId,
                    cancellationToken);
                db.Entry(tracked).CurrentValues.SetValues(record);
                await db.SaveChangesAsync(cancellationToken);
            });
    }

    public Task UpdateWithAccountAsync(
        Guid tenantId,
        ProvisioningRecord record,
        IdentityAccount account,
        CancellationToken cancellationToken = default)
    {
        if (record.TenantId != tenantId || account.TenantId != tenantId)
        {
            throw new InvalidOperationException("La actualización de aprovisionamiento no coincide con el tenant indicado.");
        }

        return TenantPersistenceHelper.ExecuteAsync(
            tenantDbContextFactory,
            tenantId,
            async db =>
            {
                var trackedAccount = await db.Accounts.FirstAsync(
                    a => a.Id == account.Id && a.TenantId == tenantId,
                    cancellationToken);
                TenantPersistenceHelper.SyncAccountState(db, trackedAccount, account);

                var trackedRecord = await db.ProvisioningRecords.FirstAsync(
                    p => p.Id == record.Id && p.TenantId == tenantId,
                    cancellationToken);
                db.Entry(trackedRecord).CurrentValues.SetValues(record);

                await db.SaveChangesAsync(cancellationToken);
            });
    }
}
