using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Saas.Identity.Domain.ValueObjects;

namespace Saas.Identity.Api.Endpoints;

internal readonly record struct AuthenticatedActor(
    Guid AccountId,
    IdentityStoreScope StoreScope,
    OrgRole Role);

internal static class ClaimsPrincipalExtensions
{
    public static bool TryGetActorIdentity(this ClaimsPrincipal user, out AuthenticatedActor actor)
    {
        actor = default;

        var subClaim = user.FindFirstValue(JwtRegisteredClaimNames.Sub)
            ?? user.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!Guid.TryParse(subClaim, out var accountId) || accountId == Guid.Empty)
        {
            return false;
        }

        var roleClaim = user.FindFirstValue("role") ?? user.FindFirstValue(ClaimTypes.Role);
        if (string.IsNullOrWhiteSpace(roleClaim) ||
            !Enum.TryParse<OrgRole>(roleClaim.Trim(), ignoreCase: false, out var role) ||
            !Enum.IsDefined(role))
        {
            return false;
        }

        var tenantClaim = user.FindFirstValue("tenant_id");
        if (role == OrgRole.SUPER_ADMIN)
        {
            if (!string.IsNullOrWhiteSpace(tenantClaim))
            {
                return false;
            }

            actor = new AuthenticatedActor(accountId, IdentityStoreScope.Global, role);
            return true;
        }

        if (!Guid.TryParse(tenantClaim, out var tenantId) || tenantId == Guid.Empty)
        {
            return false;
        }

        actor = new AuthenticatedActor(accountId, IdentityStoreScope.ForTenant(tenantId), role);
        return true;
    }
}
