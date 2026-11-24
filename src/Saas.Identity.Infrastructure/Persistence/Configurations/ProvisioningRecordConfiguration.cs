using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Saas.Identity.Domain.Entities;

namespace Saas.Identity.Infrastructure.Persistence.Configurations;

internal sealed class ProvisioningRecordConfiguration : IEntityTypeConfiguration<ProvisioningRecord>
{
    public void Configure(EntityTypeBuilder<ProvisioningRecord> builder)
    {
        builder.ToTable("provisioning_records");
        builder.HasKey(p => p.Id);

        builder.Property(p => p.Id).HasColumnName("id");
        builder.Property(p => p.TenantId).HasColumnName("tenant_id").IsRequired();
        builder.Property(p => p.ProvisioningRequestId).HasColumnName("provisioning_request_id").HasMaxLength(128).IsRequired();
        builder.Property(p => p.ClinicSlug).HasColumnName("clinic_slug").HasMaxLength(120).IsRequired();
        builder.Property(p => p.ClinicName).HasColumnName("clinic_name").HasMaxLength(200).IsRequired();
        builder.Property(p => p.AdminFullName).HasColumnName("admin_full_name").HasMaxLength(160).IsRequired();
        builder.Property(p => p.AdminEmail).HasColumnName("admin_email").HasMaxLength(200).IsRequired();
        builder.Property(p => p.NormalizedAdminEmail).HasColumnName("normalized_admin_email").HasMaxLength(200).IsRequired();
        builder.Property(p => p.InitialAdminAccountId).HasColumnName("initial_admin_account_id");
        builder.Property(p => p.Status).HasColumnName("status").HasConversion<string>().HasMaxLength(32).IsRequired();
        builder.Property(p => p.TemporaryPasswordEmailSent).HasColumnName("temporary_password_email_sent").HasDefaultValue(false).IsRequired();
        builder.Property(p => p.LastErrorCode).HasColumnName("last_error_code").HasMaxLength(64);
        builder.Property(p => p.CreatedAtUtc).HasColumnName("created_at_utc").IsRequired();
        builder.Property(p => p.UpdatedAtUtc).HasColumnName("updated_at_utc").IsRequired();

        builder.HasIndex(p => p.ProvisioningRequestId)
            .IsUnique()
            .HasDatabaseName("ux_provisioning_records_request_id");

        builder.HasIndex(p => p.TenantId)
            .IsUnique()
            .HasDatabaseName("ux_provisioning_records_tenant_id");

        builder.HasOne<IdentityAccount>()
            .WithMany()
            .HasForeignKey(p => p.InitialAdminAccountId)
            .OnDelete(DeleteBehavior.SetNull);
    }
}
