namespace Saas.Identity.Domain.ValueObjects;

public sealed record TenantAccessState(
    Guid TenantId,
    string Slug,
    string Name,
    TenantOperationalState State,
    bool MayAuthenticate,
    int MaxActiveAccounts,
    string EvaluatedAtGmt6);
