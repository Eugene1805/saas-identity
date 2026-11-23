namespace Saas.Identity.Domain.ValueObjects;

public readonly record struct IdentityStoreScope
{
    private IdentityStoreScope(Guid? tenantId)
    {
        TenantId = tenantId;
    }

    public Guid? TenantId { get; }
    public bool IsGlobal => TenantId is null;
    public bool IsTenant => TenantId.HasValue;

    public static IdentityStoreScope Global => new(null);

    public static IdentityStoreScope ForTenant(Guid tenantId)
    {
        if (tenantId == Guid.Empty)
        {
            throw new ArgumentException("El tenantId del almacenamiento de identidad es obligatorio.", nameof(tenantId));
        }

        return new(tenantId);
    }
}
