using System.Globalization;

namespace Saas.Identity.Domain.Common;

public static class Gmt6Clock
{
    public static readonly TimeSpan FixedOffset = TimeSpan.FromHours(-6);

    public static string FormatIsoGmt6(DateTimeOffset timestamp)
    {
        return timestamp
            .ToOffset(FixedOffset)
            .ToString("yyyy-MM-ddTHH:mm:ss'-06:00'", CultureInfo.InvariantCulture);
    }
}
