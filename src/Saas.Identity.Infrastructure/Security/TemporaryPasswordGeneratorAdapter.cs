using System.Security.Cryptography;
using Saas.Identity.Application.Ports;

namespace Saas.Identity.Infrastructure.Security;

public sealed class TemporaryPasswordGeneratorAdapter : ITemporaryPasswordGeneratorPort
{
    private const string Upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
    private const string Lower = "abcdefghijkmnpqrstuvwxyz";
    private const string Digits = "23456789";
    private const string Symbols = "!@#$%&*?";
    private const string AllChars = Upper + Lower + Digits + Symbols;

    public string Generate()
    {
        Span<char> chars = stackalloc char[12];
        chars[0] = PickChar(Upper);
        chars[1] = PickChar(Lower);
        chars[2] = PickChar(Digits);
        chars[3] = PickChar(Symbols);

        for (var i = 4; i < chars.Length; i++)
        {
            chars[i] = PickChar(AllChars);
        }

        // Fisher-Yates shuffle usando CSPRNG.
        for (var i = chars.Length - 1; i > 0; i--)
        {
            var j = RandomNumberGenerator.GetInt32(i + 1);
            (chars[i], chars[j]) = (chars[j], chars[i]);
        }

        return new string(chars);
    }

    private static char PickChar(string alphabet) =>
        alphabet[RandomNumberGenerator.GetInt32(alphabet.Length)];
}
