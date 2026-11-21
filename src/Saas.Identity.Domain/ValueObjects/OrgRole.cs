namespace Saas.Identity.Domain.ValueObjects;

public enum OrgRole
{
    SUPER_ADMIN = 0,
    ADMIN_CLINICA = 1,
    ESPECIALISTA = 2,
    AUXILIAR = 3,
}

public enum TenantOperationalState
{
    PENDIENTE_ADMIN = 0,
    ACTIVA = 1,
    SUSPENDIDA = 2,
}
