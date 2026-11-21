using Saas.Identity.Application.UseCases.Staff;
using Saas.Identity.Domain.Entities;
using Saas.Identity.Domain.Policies;
using Saas.Identity.Domain.ValueObjects;
using Saas.Identity.Infrastructure.Security;

namespace Saas.Identity.UnitTests;

public sealed class StaffManagementTests
{
    private static readonly Guid NorteId = Guid.Parse("10000000-0000-0000-0000-000000000001");
    private static readonly Guid ValleId = Guid.Parse("10000000-0000-0000-0000-000000000002");

    private static (InMemoryAccountRepo Accounts, InMemoryRefreshRepo Refresh, FakeTenantPort Tenants, FakeClock Clock, IdentityAccount Admin)
        CreateFixture(int maxQuota = 4)
    {
        var clock = new FakeClock(DateTimeOffset.Parse("2026-11-21T14:00:00Z"));
        var hasher = new Pbkdf2PasswordHasherAdapter();
        var accountRepo = new InMemoryAccountRepo();
        var refreshRepo = new InMemoryRefreshRepo();
        var tenantPort = new FakeTenantPort();

        tenantPort.BySlug["clinica-norte"] = new TenantAccessState(
            NorteId,
            "clinica-norte",
            "Clínica Norte",
            TenantOperationalState.ACTIVA,
            true,
            maxQuota,
            "2026-11-21T08:00:00-06:00");

        var admin = IdentityAccount.Create(
            Guid.Parse("20000000-0000-0000-0000-000000000002"),
            NorteId,
            "Lic. Mariana Paredes",
            "admin@norte.vital.demo",
            hasher.Hash("Vital2026!"),
            OrgRole.ADMIN_CLINICA,
            true,
            null,
            null,
            StaffPermissions.ForAdminClinica(),
            null,
            clock.UtcNow);
        accountRepo.Items.Add(admin);

        return (accountRepo, refreshRepo, tenantPort, clock, admin);
    }

    [Fact]
    public async Task CreateStaff_GeneratesTemporaryPassword_AndEnforcesRulesAndQuota()
    {
        var (accounts, _, tenants, clock, admin) = CreateFixture(maxQuota: 2);
        var hasher = new Pbkdf2PasswordHasherAdapter();
        var tempGen = new TemporaryPasswordGeneratorAdapter();
        var emailDelivery = new FakeEmailDeliveryPort();
        var useCase = new CreateStaffUseCase(accounts, tenants, hasher, tempGen, emailDelivery, clock);

        var weak = await useCase.ExecuteAsync(new CreateStaffCommand(
            admin.Id, "Dr. Débil", "debil@norte.vital.demo", "12345678", false,
            "ESPECIALISTA", "General", null, null, StaffPermissions.None));
        Assert.Equal("WEAK_PASSWORD", weak.Error.Code);

        var escalation = await useCase.ExecuteAsync(new CreateStaffCommand(
            admin.Id, "Intento Escalación", "sa@norte.vital.demo", null, true,
            "SUPER_ADMIN", null, null, null, StaffPermissions.None));
        Assert.Equal("PRIVILEGE_ESCALATION_BLOCKED", escalation.Error.Code);

        var noAttribution = await useCase.ExecuteAsync(new CreateStaffCommand(
            admin.Id, "Sin Cédula", "noced@norte.vital.demo", null, true,
            "ESPECIALISTA", "General", null, null, new StaffPermissions(true, true, false, false)));
        Assert.Equal("ATTRIBUTION_REQUIRED", noAttribution.Error.Code);

        var created = await useCase.ExecuteAsync(new CreateStaffCommand(
            admin.Id, "Dra. Laura Gómez", "laura@norte.vital.demo", null, true,
            "ESPECIALISTA", "Cardiología", "CED-901", "Cardióloga", new StaffPermissions(true, true, false, false)));
        Assert.True(created.IsSuccess);
        Assert.NotNull(created.Value.TemporaryPassword);
        Assert.True(created.Value.TemporaryPasswordEmailSent);
        Assert.Single(emailDelivery.SentMessages);
        Assert.True(PasswordPolicy.Validate(created.Value.TemporaryPassword).IsSuccess);
        Assert.True(created.Value.Account.MustChangePassword);

        var duplicate = await useCase.ExecuteAsync(new CreateStaffCommand(
            admin.Id, "Duplicado", "laura@norte.vital.demo", null, true,
            "AUXILIAR", null, null, null, StaffPermissions.None));
        Assert.Equal("QUOTA_REACHED", duplicate.Error.Code);
    }

    [Fact]
    public async Task UpdateStaffRole_RecordsAudit_BlocksLastAdminAndClearsLinksWhenRoleChanges()
    {
        var (accounts, _, tenants, clock, admin) = CreateFixture(maxQuota: 8);
        var aux = IdentityAccount.Create(
            Guid.NewGuid(),
            NorteId,
            "Enf. Clara Ramírez",
            "aux@norte.vital.demo",
            "hash",
            OrgRole.AUXILIAR,
            true,
            null,
            null,
            new StaffPermissions(false, true, true, true),
            [Guid.NewGuid()],
            clock.UtcNow);
        accounts.Items.Add(aux);

        var useCase = new UpdateStaffRoleUseCase(accounts, tenants, clock);

        var demoteLastAdmin = await useCase.ExecuteAsync(new UpdateStaffRoleCommand(
            admin.Id, admin.Id, "ESPECIALISTA", "General", null, null, false, true, false, false, null));
        Assert.Equal("LAST_ADMIN_PROTECTED", demoteLastAdmin.Error.Code);

        var promoteAux = await useCase.ExecuteAsync(new UpdateStaffRoleCommand(
            admin.Id,
            aux.Id,
            "ESPECIALISTA",
            "Pediatría",
            "CED-PED-01",
            "Pediatra",
            true,
            true,
            false,
            false,
            "Cambio de puesto"));
        Assert.True(promoteAux.IsSuccess);
        Assert.Empty(promoteAux.Value.LinkedSpecialistIds);
        Assert.Single(promoteAux.Value.RoleAuditLog);
        Assert.Equal("AUXILIAR", promoteAux.Value.RoleAuditLog[0].PreviousRole);
        Assert.Equal("ESPECIALISTA", promoteAux.Value.RoleAuditLog[0].NextRole);
    }

    [Fact]
    public async Task UpdateStaffStatus_ProtectsLastAdmin_RevokesRefreshTokens_AndRespectsQuota()
    {
        var (accounts, refresh, tenants, clock, admin) = CreateFixture(maxQuota: 2);
        var spec = IdentityAccount.Create(
            Guid.NewGuid(), NorteId, "Dr. Uno", "uno@norte.vital.demo", "hash",
            OrgRole.ESPECIALISTA, true, "General", null, StaffPermissions.None, null, clock.UtcNow);
        var specExtra = IdentityAccount.Create(
            Guid.NewGuid(), NorteId, "Dr. Dos", "dos@norte.vital.demo", "hash",
            OrgRole.ESPECIALISTA, false, "General", null, StaffPermissions.None, null, clock.UtcNow);
        accounts.Items.AddRange([spec, specExtra]);

        refresh.Sessions.Add(RefreshTokenSession.Create(
            Guid.NewGuid(), spec.Id, NorteId, "hash-spec", clock.UtcNow.AddDays(7), clock.UtcNow));

        var useCase = new UpdateStaffStatusUseCase(accounts, refresh, tenants, clock);

        var lastAdminBlock = await useCase.ExecuteAsync(new UpdateStaffStatusCommand(admin.Id, admin.Id, false));
        Assert.Equal("LAST_ADMIN_PROTECTED", lastAdminBlock.Error.Code);

        var quotaReactivateBlock = await useCase.ExecuteAsync(new UpdateStaffStatusCommand(admin.Id, specExtra.Id, true));
        Assert.Equal("QUOTA_REACHED", quotaReactivateBlock.Error.Code);

        var disableSpec = await useCase.ExecuteAsync(new UpdateStaffStatusCommand(admin.Id, spec.Id, false));
        Assert.True(disableSpec.IsSuccess);
        Assert.False(disableSpec.Value.Active);
        Assert.All(refresh.Sessions, s => Assert.True(s.IsRevoked));

        var reactivateExtra = await useCase.ExecuteAsync(new UpdateStaffStatusCommand(admin.Id, specExtra.Id, true));
        Assert.True(reactivateExtra.IsSuccess);
        Assert.True(reactivateExtra.Value.Active);
    }

    [Fact]
    public async Task UpdateAuxiliaryLinks_RequiresActiveSameTenantSpecialists()
    {
        var (accounts, _, tenants, clock, admin) = CreateFixture(maxQuota: 8);
        var aux = IdentityAccount.Create(
            Guid.NewGuid(), NorteId, "Enf. Clara", "aux@norte.vital.demo", "hash",
            OrgRole.AUXILIAR, true, null, null, StaffPermissions.None, null, clock.UtcNow);
        var activeSpec = IdentityAccount.Create(
            Guid.NewGuid(), NorteId, "Dra. Activa", "act@norte.vital.demo", "hash",
            OrgRole.ESPECIALISTA, true, "Cardio", null, StaffPermissions.None, null, clock.UtcNow);
        var inactiveSpec = IdentityAccount.Create(
            Guid.NewGuid(), NorteId, "Dr. Inactivo", "inact@norte.vital.demo", "hash",
            OrgRole.ESPECIALISTA, false, "Pediatría", null, StaffPermissions.None, null, clock.UtcNow);
        var otherTenantSpec = IdentityAccount.Create(
            Guid.NewGuid(), ValleId, "Dra. Valle", "valle@valle.vital.demo", "hash",
            OrgRole.ESPECIALISTA, true, "Cardio", null, StaffPermissions.None, null, clock.UtcNow);
        accounts.Items.AddRange([aux, activeSpec, inactiveSpec, otherTenantSpec]);

        var useCase = new UpdateAuxiliaryLinksUseCase(accounts, tenants);

        var badTarget = await useCase.ExecuteAsync(new UpdateAuxiliaryLinksCommand(admin.Id, activeSpec.Id, [activeSpec.Id]));
        Assert.Equal("INVALID_AUXILIARY", badTarget.Error.Code);

        var badInactive = await useCase.ExecuteAsync(new UpdateAuxiliaryLinksCommand(admin.Id, aux.Id, [inactiveSpec.Id]));
        Assert.Equal("INVALID_LINKED_SPECIALIST", badInactive.Error.Code);

        var badOtherTenant = await useCase.ExecuteAsync(new UpdateAuxiliaryLinksCommand(admin.Id, aux.Id, [otherTenantSpec.Id]));
        Assert.Equal("INVALID_LINKED_SPECIALIST", badOtherTenant.Error.Code);

        var valid = await useCase.ExecuteAsync(new UpdateAuxiliaryLinksCommand(admin.Id, aux.Id, [activeSpec.Id]));
        Assert.True(valid.IsSuccess);
        Assert.Equal([activeSpec.Id], valid.Value.LinkedSpecialistIds);
    }
}
