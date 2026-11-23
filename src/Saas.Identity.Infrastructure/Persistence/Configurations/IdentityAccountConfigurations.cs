using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using Saas.Identity.Domain.Entities;

namespace Saas.Identity.Infrastructure.Persistence.Configurations;

internal static class IdentityAccountConfigurationHelper
{
    public static void ConfigureCommon(EntityTypeBuilder<IdentityAccount> builder)
    {
        builder.HasKey(a => a.Id);

        builder.Property(a => a.Id).HasColumnName("id");
        builder.Property(a => a.FullName).HasColumnName("full_name").HasMaxLength(160).IsRequired();
        builder.Property(a => a.Email).HasColumnName("email").HasMaxLength(200).IsRequired();
        builder.Property(a => a.NormalizedEmail).HasColumnName("normalized_email").HasMaxLength(200).IsRequired();
        builder.Property(a => a.PasswordHash).HasColumnName("password_hash").HasMaxLength(300).IsRequired();
        builder.Property(a => a.Role).HasColumnName("role").HasConversion<string>().HasMaxLength(32).IsRequired();
        builder.Property(a => a.Active).HasColumnName("active").IsRequired();
        builder.Property(a => a.MustChangePassword).HasColumnName("must_change_password").HasDefaultValue(false).IsRequired();
        builder.Property(a => a.FailedLoginAttempts).HasColumnName("failed_login_attempts").HasDefaultValue(0).IsRequired();
        builder.Property(a => a.LockoutUntilUtc).HasColumnName("lockout_until_utc");
        builder.Property(a => a.Specialty).HasColumnName("specialty").HasMaxLength(120);
        builder.Property(a => a.CreatedAtUtc).HasColumnName("created_at_utc").IsRequired();

        builder.OwnsOne(a => a.Permissions, perm =>
        {
            perm.Property(p => p.CanPrescribe).HasColumnName("perm_can_prescribe").IsRequired();
            perm.Property(p => p.CanRegisterPatients).HasColumnName("perm_can_register_patients").IsRequired();
            perm.Property(p => p.CanAssignInitialPrimary).HasColumnName("perm_can_assign_initial_primary").IsRequired();
            perm.Property(p => p.CanUploadStudies).HasColumnName("perm_can_upload_studies").IsRequired();
        });

        builder.OwnsOne(a => a.ProfessionalAttribution, attr =>
        {
            attr.Property(p => p.LicenseCode).HasColumnName("attribution_license_code").HasMaxLength(64);
            attr.Property(p => p.Title).HasColumnName("attribution_title").HasMaxLength(160);
            attr.Property(p => p.RegisteredAtGmt6).HasColumnName("attribution_registered_at_gmt6").HasMaxLength(40);
        });

        var linkedConverter = new ValueConverter<List<Guid>, string>(
            list => JsonSerializer.Serialize(list, (JsonSerializerOptions?)null),
            json => string.IsNullOrWhiteSpace(json)
                ? new List<Guid>()
                : JsonSerializer.Deserialize<List<Guid>>(json, (JsonSerializerOptions?)null) ?? new List<Guid>());

        var linkedComparer = new ValueComparer<List<Guid>>(
            (left, right) => (left ?? new List<Guid>()).SequenceEqual(right ?? new List<Guid>()),
            list => list.Aggregate(0, (hash, item) => HashCode.Combine(hash, item.GetHashCode())),
            list => list.ToList());

        builder.Ignore(a => a.LinkedSpecialistIds);
        builder.Property<List<Guid>>("_linkedSpecialistIds")
            .HasColumnName("linked_specialist_ids")
            .HasColumnType("jsonb")
            .HasConversion(linkedConverter, linkedComparer);
    }
}

internal sealed class GlobalIdentityAccountConfiguration : IEntityTypeConfiguration<IdentityAccount>
{
    public void Configure(EntityTypeBuilder<IdentityAccount> builder)
    {
        builder.ToTable(
            "accounts",
            table => table.HasCheckConstraint(
                "ck_global_accounts_tenant_null",
                "tenant_id IS NULL AND role = 'SUPER_ADMIN'"));

        builder.Property(a => a.TenantId).HasColumnName("tenant_id");
        IdentityAccountConfigurationHelper.ConfigureCommon(builder);

        builder.HasIndex(a => a.NormalizedEmail)
            .IsUnique()
            .HasDatabaseName("ux_accounts_platform_email");
    }
}

internal sealed class TenantIdentityAccountConfiguration : IEntityTypeConfiguration<IdentityAccount>
{
    public void Configure(EntityTypeBuilder<IdentityAccount> builder)
    {
        builder.ToTable(
            "accounts",
            table => table.HasCheckConstraint(
                "ck_tenant_accounts_scoped",
                "tenant_id IS NOT NULL AND role <> 'SUPER_ADMIN'"));

        builder.Property(a => a.TenantId).HasColumnName("tenant_id").IsRequired();
        IdentityAccountConfigurationHelper.ConfigureCommon(builder);

        builder.HasIndex(a => new { a.TenantId, a.NormalizedEmail })
            .IsUnique()
            .HasDatabaseName("ux_accounts_tenant_email");
    }
}
