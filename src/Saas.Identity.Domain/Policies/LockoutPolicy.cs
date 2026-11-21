using Saas.Identity.Domain.Common;

namespace Saas.Identity.Domain.Policies;

public static class LockoutPolicy
{
    public const int MaxAttemptsBeforeLockout = 3;
    public const int BaseLockoutSeconds = 30;
    public const int MaxLockoutSeconds = 1800;

    public static DateTimeOffset? ComputeLockoutUntil(int failedAttempts, DateTimeOffset utcNow)
    {
        if (failedAttempts < MaxAttemptsBeforeLockout)
        {
            return null;
        }

        var exponent = Math.Min(failedAttempts - MaxAttemptsBeforeLockout, 6);
        var seconds = Math.Min(BaseLockoutSeconds * (1 << exponent), MaxLockoutSeconds);
        return utcNow.ToUniversalTime().AddSeconds(seconds);
    }

    public static DomainError CreateLockedOutError(DateTimeOffset lockoutUntilUtc, DateTimeOffset utcNow)
    {
        var remainingSeconds = Math.Max(
            1,
            (int)Math.Ceiling((lockoutUntilUtc.ToUniversalTime() - utcNow.ToUniversalTime()).TotalSeconds));
        var lockoutUntilGmt6 = Gmt6Clock.FormatIsoGmt6(lockoutUntilUtc);

        return new DomainError(
            "ACCOUNT_LOCKED_OUT",
            $"Demasiados intentos fallidos. Intenta nuevamente en {remainingSeconds} segundos.",
            429,
            new Dictionary<string, object?>
            {
                ["retryAfterSeconds"] = remainingSeconds,
                ["lockoutUntilGmt6"] = lockoutUntilGmt6,
            });
    }
}
