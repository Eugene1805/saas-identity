using Saas.Identity.Domain.ValueObjects;

namespace Saas.Identity.Domain.Entities;

public sealed class RoleAuditEntry
{
    private RoleAuditEntry()
    {
        ActorName = string.Empty;
        Note = string.Empty;
    }

    private RoleAuditEntry(
        Guid id,
        Guid tenantId,
        Guid accountId,
        OrgRole previousRole,
        OrgRole nextRole,
        bool previousCanPrescribe,
        bool nextCanPrescribe,
        Guid actorAccountId,
        string actorName,
        DateTimeOffset occurredAtUtc,
        string note)
    {
        Id = id;
        TenantId = tenantId;
        AccountId = accountId;
        PreviousRole = previousRole;
        NextRole = nextRole;
        PreviousCanPrescribe = previousCanPrescribe;
        NextCanPrescribe = nextCanPrescribe;
        ActorAccountId = actorAccountId;
        ActorName = actorName.Trim();
        OccurredAtUtc = occurredAtUtc.ToUniversalTime();
        Note = note.Trim();
    }

    public Guid Id { get; private set; }
    public Guid TenantId { get; private set; }
    public Guid AccountId { get; private set; }
    public OrgRole PreviousRole { get; private set; }
    public OrgRole NextRole { get; private set; }
    public bool PreviousCanPrescribe { get; private set; }
    public bool NextCanPrescribe { get; private set; }
    public Guid ActorAccountId { get; private set; }
    public string ActorName { get; private set; }
    public DateTimeOffset OccurredAtUtc { get; private set; }
    public string Note { get; private set; }

    public static RoleAuditEntry Create(
        Guid id,
        Guid tenantId,
        Guid accountId,
        OrgRole previousRole,
        OrgRole nextRole,
        bool previousCanPrescribe,
        bool nextCanPrescribe,
        Guid actorAccountId,
        string actorName,
        DateTimeOffset occurredAtUtc,
        string note)
    {
        if (string.IsNullOrWhiteSpace(actorName))
        {
            throw new ArgumentException("El nombre del actor es obligatorio.", nameof(actorName));
        }

        return new RoleAuditEntry(
            id,
            tenantId,
            accountId,
            previousRole,
            nextRole,
            previousCanPrescribe,
            nextCanPrescribe,
            actorAccountId,
            actorName,
            occurredAtUtc,
            string.IsNullOrWhiteSpace(note)
                ? $"Actualización de rol y facultades por {actorName.Trim()}."
                : note);
    }
}
