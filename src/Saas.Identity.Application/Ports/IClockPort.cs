namespace Saas.Identity.Application.Ports;

public interface IClockPort
{
    DateTimeOffset UtcNow { get; }
}
