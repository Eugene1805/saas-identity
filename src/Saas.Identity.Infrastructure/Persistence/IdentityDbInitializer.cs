using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Saas.Identity.Application.Ports;
using Saas.Identity.Domain.Entities;
using Saas.Identity.Domain.ValueObjects;

namespace Saas.Identity.Infrastructure.Persistence;

public sealed class IdentityDbInitializer(
    IdentityDbContext dbContext,
    IPasswordHasherPort passwordHasher,
    IConfiguration configuration)
{
    public static readonly Guid NorteTenantId = Guid.Parse("10000000-0000-0000-0000-000000000001");
    public static readonly Guid ValleTenantId = Guid.Parse("10000000-0000-0000-0000-000000000002");
    public static readonly Guid AuroraTenantId = Guid.Parse("10000000-0000-0000-0000-000000000003");

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        await dbContext.Database.MigrateAsync(cancellationToken);

        var seedDemoData = configuration.GetValue("SeedDemoData", false);
        if (!seedDemoData)
        {
            return;
        }

        if (await dbContext.Accounts.AnyAsync(cancellationToken))
        {
            return;
        }

        var defaultHash = passwordHasher.Hash("Vital2026!");
        var mendozaNorteId = Guid.Parse("20000000-0000-0000-0000-000000000003");

        var seedAccounts = new[]
        {
            IdentityAccount.Create(
                Guid.Parse("20000000-0000-0000-0000-000000000001"),
                null,
                "Operador Plataforma SaaS",
                "superadmin@vital.demo",
                defaultHash,
                OrgRole.SUPER_ADMIN,
                true,
                null,
                null,
                StaffPermissions.None,
                null,
                DateTimeOffset.Parse("2026-10-01T08:00:00-06:00").ToUniversalTime()),
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
        };

        await dbContext.Accounts.AddRangeAsync(seedAccounts, cancellationToken);
        await dbContext.SaveChangesAsync(cancellationToken);
    }
}
