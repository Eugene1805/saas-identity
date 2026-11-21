using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Saas.Identity.Domain.Entities;

namespace Saas.Identity.Infrastructure.Persistence.Configurations;

internal sealed class RoleAuditEntryConfiguration : IEntityTypeConfiguration<RoleAuditEntry>
{
    public void Configure(EntityTypeBuilder<RoleAuditEntry> builder)
    {
        builder.ToTable("role_audit_entries");
        builder.HasKey(r => r.Id);

        builder.Property(r => r.Id).HasColumnName("id");
        builder.Property(r => r.TenantId).HasColumnName("tenant_id").IsRequired();
        builder.Property(r => r.AccountId).HasColumnName("account_id").IsRequired();
        builder.Property(r => r.PreviousRole).HasColumnName("previous_role").HasConversion<string>().HasMaxLength(32).IsRequired();
        builder.Property(r => r.NextRole).HasColumnName("next_role").HasConversion<string>().HasMaxLength(32).IsRequired();
        builder.Property(r => r.PreviousCanPrescribe).HasColumnName("previous_can_prescribe").IsRequired();
        builder.Property(r => r.NextCanPrescribe).HasColumnName("next_can_prescribe").IsRequired();
        builder.Property(r => r.ActorAccountId).HasColumnName("actor_account_id").IsRequired();
        builder.Property(r => r.ActorName).HasColumnName("actor_name").HasMaxLength(160).IsRequired();
        builder.Property(r => r.OccurredAtUtc).HasColumnName("occurred_at_utc").IsRequired();
        builder.Property(r => r.Note).HasColumnName("note").HasMaxLength(500).IsRequired();

        builder.HasIndex(r => new { r.AccountId, r.OccurredAtUtc })
            .HasDatabaseName("ix_role_audit_account_occurred");

        builder.HasIndex(r => r.TenantId)
            .HasDatabaseName("ix_role_audit_tenant");

        builder.HasOne<IdentityAccount>()
            .WithMany()
            .HasForeignKey(r => r.AccountId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}
