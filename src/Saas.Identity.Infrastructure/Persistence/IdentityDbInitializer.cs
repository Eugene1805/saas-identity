using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Saas.Identity.Application.Ports;
using Saas.Identity.Domain.Entities;
using Saas.Identity.Domain.ValueObjects;
using Saas.Identity.Infrastructure.Persistence.Tenancy;

namespace Saas.Identity.Infrastructure.Persistence;

public sealed class IdentityDbInitializer(
    IDbContextFactory<GlobalIdentityDbContext> globalDbContextFactory,
    ITenantDbContextFactory tenantDbContextFactory,
    ITenantDatabaseMigratorPort tenantDatabaseMigrator,
    ITenantConnectionResolver tenantConnectionResolver,
    IPasswordHasherPort passwordHasher,
    IConfiguration configuration)
{
    public static readonly Guid NorteTenantId = Guid.Parse("10000000-0000-0000-0000-000000000001");
    public static readonly Guid ValleTenantId = Guid.Parse("10000000-0000-0000-0000-000000000002");
    public static readonly Guid AuroraTenantId = Guid.Parse("10000000-0000-0000-0000-000000000003");

    public async Task InitializeGlobalAsync(
        bool isProduction,
        CancellationToken cancellationToken = default)
    {
        await using var dbContext = await globalDbContextFactory.CreateDbContextAsync(cancellationToken);
        await dbContext.Database.MigrateAsync(cancellationToken);

        var demoPassword = ResolveAuthorizedDemoPassword(isProduction);
        if (demoPassword is null)
        {
            return;
        }

        if (await dbContext.Accounts.AnyAsync(cancellationToken))
        {
            return;
        }

        var superAdmin = IdentityAccount.Create(
            Guid.Parse("20000000-0000-0000-0000-000000000001"),
            null,
            "Operador Plataforma SaaS",
            "superadmin@vital.demo",
            passwordHasher.Hash(demoPassword),
            OrgRole.SUPER_ADMIN,
            true,
            null,
            null,
            StaffPermissions.None,
            null,
            DateTimeOffset.Parse("2026-10-01T08:00:00-06:00").ToUniversalTime());

        await dbContext.Accounts.AddAsync(superAdmin, cancellationToken);
        await dbContext.SaveChangesAsync(cancellationToken);
    }

    public async Task InitializeConfiguredDemoTenantsAsync(
        bool isProduction,
        CancellationToken cancellationToken = default)
    {
        var demoPassword = ResolveAuthorizedDemoPassword(isProduction);
        if (demoPassword is null)
        {
            return;
        }

        var demoHash = passwordHasher.Hash(demoPassword);

        if (tenantConnectionResolver.TryResolveConnectionString(NorteTenantId, out _))
        {
            await SeedTenantIfEmptyAsync(
                NorteTenantId,
                () => BuildNorteSeedAccounts(demoHash),
                cancellationToken);
        }

        if (tenantConnectionResolver.TryResolveConnectionString(ValleTenantId, out _))
        {
            await SeedTenantIfEmptyAsync(
                ValleTenantId,
                () => BuildValleSeedAccounts(demoHash),
                cancellationToken);
        }
    }

    private string? ResolveAuthorizedDemoPassword(bool isProduction)
    {
        if (isProduction || !configuration.GetValue("SeedDemoData", false))
        {
            return null;
        }

        var demoPassword = configuration["DemoSeed:Password"];
        return string.IsNullOrWhiteSpace(demoPassword) ? null : demoPassword;
    }

    private async Task SeedTenantIfEmptyAsync(
        Guid tenantId,
        Func<IReadOnlyList<IdentityAccount>> accountFactory,
        CancellationToken cancellationToken)
    {
        await tenantDatabaseMigrator.EnsureMigratedAsync(tenantId, cancellationToken);
        await using var dbContext = tenantDbContextFactory.CreateDbContext(tenantId);

        if (await dbContext.Accounts.AnyAsync(cancellationToken))
        {
            return;
        }

        await dbContext.Accounts.AddRangeAsync(accountFactory(), cancellationToken);
        await dbContext.SaveChangesAsync(cancellationToken);
    }

    private static IReadOnlyList<IdentityAccount> BuildNorteSeedAccounts(string defaultHash)
    {
        var mendozaNorteId = Guid.Parse("20000000-0000-0000-0000-000000000003");
        return
        [
            IdentityAccount.Create(
                Guid.Parse("20000000-0000-0000-0000-000000000002"),
                NorteTenantId,
                "Lic. Mariana Paredes",
                "admin@norte.vital.demo",
                defaultHash,
                OrgRole.ADMIN_CLINICA,
                true,
                null,
                null,
                StaffPermissions.ForAdminClinica(),
                null,
                DateTimeOffset.Parse("2026-11-10T09:02:00-06:00").ToUniversalTime()),
            IdentityAccount.Create(
                mendozaNorteId,
                NorteTenantId,
                "Dra. Sofía Mendoza",
                "dra.mendoza@norte.vital.demo",
                defaultHash,
                OrgRole.ESPECIALISTA,
                true,
                "Cardiología",
                new ProfessionalAttribution(
                    "CED-FICT-4012",
                    "Médico Especialista en Cardiología",
                    "2026-11-10T09:30:00-06:00"),
                new StaffPermissions(true, true, false, false),
                null,
                DateTimeOffset.Parse("2026-11-10T09:30:00-06:00").ToUniversalTime()),
            IdentityAccount.Create(
                Guid.Parse("20000000-0000-0000-0000-000000000004"),
                NorteTenantId,
                "Dr. Mateo Salazar",
                "dr.salazar@norte.vital.demo",
                defaultHash,
                OrgRole.ESPECIALISTA,
                true,
                "Medicina General",
                null,
                StaffPermissions.None,
                null,
                DateTimeOffset.Parse("2026-11-11T10:15:00-06:00").ToUniversalTime()),
            IdentityAccount.Create(
                Guid.Parse("20000000-0000-0000-0000-000000000005"),
                NorteTenantId,
                "Enf. Clara Ramírez",
                "aux.ramirez@norte.vital.demo",
                defaultHash,
                OrgRole.AUXILIAR,
                true,
                null,
                null,
                new StaffPermissions(false, true, true, true),
                [mendozaNorteId],
                DateTimeOffset.Parse("2026-11-11T10:45:00-06:00").ToUniversalTime()),
            IdentityAccount.Create(
                Guid.Parse("20000000-0000-0000-0000-000000000006"),
                NorteTenantId,
                "Dr. Nicolás Vega",
                "dr.vega@norte.vital.demo",
                defaultHash,
                OrgRole.ESPECIALISTA,
                false,
                "Pediatría",
                new ProfessionalAttribution(
                    "CED-FICT-2984",
                    "Médico Pediatra",
                    "2026-11-10T10:00:00-06:00"),
                new StaffPermissions(true, false, false, false),
                null,
                DateTimeOffset.Parse("2026-11-10T10:00:00-06:00").ToUniversalTime()),
        ];
    }

    private static IReadOnlyList<IdentityAccount> BuildValleSeedAccounts(string defaultHash) =>
    [
        IdentityAccount.Create(
            Guid.Parse("20000000-0000-0000-0000-000000000007"),
            ValleTenantId,
            "Ing. Rodrigo Téllez",
            "admin@valle.vital.demo",
            defaultHash,
            OrgRole.ADMIN_CLINICA,
            true,
            null,
            null,
            StaffPermissions.ForAdminClinica(),
            null,
            DateTimeOffset.Parse("2026-10-15T11:32:00-06:00").ToUniversalTime()),
        IdentityAccount.Create(
            Guid.Parse("20000000-0000-0000-0000-000000000008"),
            ValleTenantId,
            "Dra. Sofía Mendoza (Cuenta Valle)",
            "dra.mendoza@valle.vital.demo",
            defaultHash,
            OrgRole.ESPECIALISTA,
            true,
            "Cardiología",
            new ProfessionalAttribution(
                "CED-FICT-4012",
                "Médico Especialista en Cardiología",
                "2026-10-15T12:00:00-06:00"),
            new StaffPermissions(true, false, false, false),
            null,
            DateTimeOffset.Parse("2026-10-15T12:00:00-06:00").ToUniversalTime()),
    ];
}
