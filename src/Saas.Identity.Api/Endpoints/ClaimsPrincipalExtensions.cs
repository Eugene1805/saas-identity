using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace Saas.Identity.Api.Endpoints;

internal static class ClaimsPrincipalExtensions
{
    public static bool TryGetAccountId(this ClaimsPrincipal user, out Guid accountId)
    {
        var subClaim = user.FindFirstValue(JwtRegisteredClaimNames.Sub)
            ?? user.FindFirstValue(ClaimTypes.NameIdentifier);

        return Guid.TryParse(subClaim, out accountId);
    }
}
