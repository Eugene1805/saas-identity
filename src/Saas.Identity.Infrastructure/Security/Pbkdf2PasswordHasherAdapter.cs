using System.Security.Cryptography;
using Saas.Identity.Application.Ports;

namespace Saas.Identity.Infrastructure.Security;

public sealed class Pbkdf2PasswordHasherAdapter : IPasswordHasherPort
{
    private const int SaltSizeBytes = 16;
    private const int KeySizeBytes = 32;
    private const int Iterations = 100_000;
    private const string Prefix = "pbkdf2-sha256";

    public string Hash(string plainPassword)
    {
        if (string.IsNullOrEmpty(plainPassword))
        {
            throw new ArgumentException("La contraseña no puede estar vacía.", nameof(plainPassword));
        }

        var salt = RandomNumberGenerator.GetBytes(SaltSizeBytes);
        var key = Rfc2898DeriveBytes.Pbkdf2(
            plainPassword,
            salt,
            Iterations,
            HashAlgorithmName.SHA256,
            KeySizeBytes);

        return $"{Prefix}${Iterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(key)}";
    }

    public bool Verify(string passwordHash, string plainPassword)
    {
        if (string.IsNullOrWhiteSpace(passwordHash) || string.IsNullOrEmpty(plainPassword))
        {
            return false;
        }

        var parts = passwordHash.Split('$', StringSplitOptions.None);
        if (parts.Length != 4 || parts[0] != Prefix)
        {
            return false;
        }

        if (!int.TryParse(parts[1], out var iterations) || iterations <= 0)
        {
            return false;
        }

        try
        {
            var salt = Convert.FromBase64String(parts[2]);
            var expectedKey = Convert.FromBase64String(parts[3]);
            var actualKey = Rfc2898DeriveBytes.Pbkdf2(
                plainPassword,
                salt,
                iterations,
                HashAlgorithmName.SHA256,
                expectedKey.Length);

            return CryptographicOperations.FixedTimeEquals(actualKey, expectedKey);
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
