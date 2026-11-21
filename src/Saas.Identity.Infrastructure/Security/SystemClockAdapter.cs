using Saas.Identity.Application.Ports;

namespace Saas.Identity.Infrastructure.Security;

internal sealed class SystemClockAdapter : IClockPort
{
    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
}
