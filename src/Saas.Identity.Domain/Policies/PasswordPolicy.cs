using Saas.Identity.Domain.Common;

namespace Saas.Identity.Domain.Policies;

public static class PasswordPolicy
{
    public const int MinLength = 8;
    public const int MaxLength = 40;

    public static readonly DomainError WeakPassword = new(
        "WEAK_PASSWORD",
        "La contraseña debe tener entre 8 y 40 caracteres e incluir al menos una letra, un número y un símbolo.",
        400);

    public static Result Validate(string? password)
    {
        if (string.IsNullOrEmpty(password) ||
            password.Length < MinLength ||
            password.Length > MaxLength)
        {
            return Result.Failure(WeakPassword);
        }

        var hasLetter = false;
        var hasDigit = false;
        var hasSymbol = false;

        foreach (var ch in password)
        {
            if (char.IsControl(ch))
            {
                return Result.Failure(WeakPassword);
            }

            if (char.IsLetter(ch))
            {
                hasLetter = true;
            }
            else if (char.IsDigit(ch))
            {
                hasDigit = true;
            }
            else if (!char.IsWhiteSpace(ch))
            {
                hasSymbol = true;
            }
        }

        return hasLetter && hasDigit && hasSymbol
            ? Result.Success()
            : Result.Failure(WeakPassword);
    }
}
