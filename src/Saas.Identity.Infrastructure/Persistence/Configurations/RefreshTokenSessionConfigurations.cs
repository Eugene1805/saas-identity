using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Saas.Identity.Domain.Entities;

namespace Saas.Identity.Infrastructure.Persistence.Configurations;

internal static class RefreshTokenConfigurationHelper
{
    public static void ConfigureCommon(EntityTypeBuilder<RefreshTokenSession> builder)
    {
        builder.HasKey(r => r.Id);

        builder.Property(r => r.Id).HasColumnName("id");
        builder.Property(r => r.AccountId).HasColumnName("account_id").IsRequired();
        builder.Property(r => r.TokenHash).HasColumnName("token_hash").HasMaxLength(128).IsRequired();
        builder.Property(r => r.ExpiresAtUtc).HasColumnName("expires_at_utc").IsRequired();
        builder.Property(r => r.CreatedAtUtc).HasColumnName("created_at_utc").IsRequired();
        builder.Property(r => r.RevokedAtUtc).HasColumnName("revoked_at_utc");
        builder.Property(r => r.RevocationReason).HasColumnName("revocation_reason").HasMaxLength(64);
        builder.Property(r => r.ReplacedByTokenId).HasColumnName("replaced_by_token_id");

        builder.HasIndex(r => r.TokenHash)
            .IsUnique()
            .HasDatabaseName("ux_refresh_tokens_hash");

        builder.HasIndex(r => new { r.AccountId, r.RevokedAtUtc })
            .HasDatabaseName("ix_refresh_tokens_account_revoked");

        builder.HasOne<IdentityAccount>()
            .WithMany()
            .HasForeignKey(r => r.AccountId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}

internal sealed class GlobalRefreshTokenSessionConfiguration : IEntityTypeConfiguration<RefreshTokenSession>
{
    public void Configure(EntityTypeBuilder<RefreshTokenSession> builder)
    {
        builder.ToTable(
            "refresh_tokens",
            table => table.HasCheckConstraint(
                "ck_global_refresh_tokens_tenant_null",
                "tenant_id IS NULL"));

        builder.Property(r => r.TenantId).HasColumnName("tenant_id");
        RefreshTokenConfigurationHelper.ConfigureCommon(builder);
    }
}

internal sealed class TenantRefreshTokenSessionConfiguration : IEntityTypeConfiguration<RefreshTokenSession>
{
    public void Configure(EntityTypeBuilder<RefreshTokenSession> builder)
    {
        builder.ToTable(
            "refresh_tokens",
            table => table.HasCheckConstraint(
                "ck_tenant_refresh_tokens_scoped",
                "tenant_id IS NOT NULL"));

        builder.Property(r => r.TenantId).HasColumnName("tenant_id").IsRequired();
        RefreshTokenConfigurationHelper.ConfigureCommon(builder);
    }
}
