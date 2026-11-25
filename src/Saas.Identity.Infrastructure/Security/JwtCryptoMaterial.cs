using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace Saas.Identity.Infrastructure.Security;

public sealed class JwtCryptoMaterial
{
    public const int MinimumRsaKeySizeBits = 2048;
    public const int MinimumRefreshHmacKeyBytes = 32;
    public static readonly TimeSpan DefaultClockSkew = TimeSpan.FromSeconds(30);

    private readonly RSAParameters _publicParameters;
    private readonly string _canonicalPublicPem;
    private readonly byte[] _refreshTokenRoutingMacKey;

    private JwtCryptoMaterial(
        string issuer,
        string audience,
        string? keyId,
        int accessTokenMinutes,
        int refreshTokenDays,
        RSAParameters privateParameters,
        RSAParameters publicParameters,
        string canonicalPublicPem,
        byte[] refreshTokenRoutingMacKey)
    {
        Issuer = issuer;
        Audience = audience;
        KeyId = keyId;
        AccessTokenMinutes = accessTokenMinutes;
        RefreshTokenDays = refreshTokenDays;
        _publicParameters = publicParameters;
        _canonicalPublicPem = canonicalPublicPem;
        _refreshTokenRoutingMacKey = refreshTokenRoutingMacKey;

        SigningKey = new RsaSecurityKey(privateParameters);
        ValidationKey = new RsaSecurityKey(publicParameters);
        if (!string.IsNullOrWhiteSpace(keyId))
        {
            SigningKey.KeyId = keyId;
            ValidationKey.KeyId = keyId;
        }

        SigningCredentials = new SigningCredentials(SigningKey, SecurityAlgorithms.RsaSha256);
    }

    public string Issuer { get; }
    public string Audience { get; }
    public string? KeyId { get; }
    public int AccessTokenMinutes { get; }
    public int RefreshTokenDays { get; }
    public RsaSecurityKey SigningKey { get; }
    public RsaSecurityKey ValidationKey { get; }
    public SigningCredentials SigningCredentials { get; }

    internal ReadOnlySpan<byte> RefreshTokenRoutingMacKey => _refreshTokenRoutingMacKey;

    public string ExportPublicKeyPem() => _canonicalPublicPem;

    public TokenValidationParameters CreateTokenValidationParameters() =>
        BuildValidationParameters(new RsaSecurityKey(_publicParameters) { KeyId = KeyId }, Issuer, Audience);

    public static TokenValidationParameters CreatePublicOnlyValidationParameters(
        string publicKeyPem,
        string issuer = "saas-identity",
        string audience = "vital-saas",
        string? keyId = null)
    {
        if (string.IsNullOrWhiteSpace(issuer))
        {
            throw new InvalidOperationException("Jwt:Issuer es obligatorio para validar tokens RS256.");
        }

        if (string.IsNullOrWhiteSpace(audience))
        {
            throw new InvalidOperationException("Jwt:Audience es obligatorio para validar tokens RS256.");
        }

        var normalizedPublicPem = NormalizePem(publicKeyPem);
        if (string.IsNullOrWhiteSpace(normalizedPublicPem))
        {
            throw new InvalidOperationException("La clave pública RSA PEM es obligatoria.");
        }

        if (normalizedPublicPem.Contains("PRIVATE KEY", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("El parámetro de clave pública no debe contener una clave privada RSA.");
        }

        using var rsa = ImportRsaFromPem(normalizedPublicPem, "clave pública RSA");
        EnsureMinimumRsaKeySize(rsa, "clave pública RSA");

        var publicParameters = rsa.ExportParameters(includePrivateParameters: false);
        var validationKey = new RsaSecurityKey(publicParameters);
        if (!string.IsNullOrWhiteSpace(keyId))
        {
            validationKey.KeyId = keyId.Trim();
        }

        return BuildValidationParameters(validationKey, issuer.Trim(), audience.Trim());
    }

    public static JwtCryptoMaterial Create(JwtOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (string.IsNullOrWhiteSpace(options.Issuer))
        {
            throw new InvalidOperationException("Jwt:Issuer es obligatorio.");
        }

        if (string.IsNullOrWhiteSpace(options.Audience))
        {
            throw new InvalidOperationException("Jwt:Audience es obligatorio.");
        }

        if (options.AccessTokenMinutes < 1)
        {
            throw new InvalidOperationException("Jwt:AccessTokenMinutes debe ser mayor o igual a 1.");
        }

        if (options.RefreshTokenDays < 1)
        {
            throw new InvalidOperationException("Jwt:RefreshTokenDays debe ser mayor o igual a 1.");
        }

        var privatePem = LoadPemFromInlineOrPath(
            options.PrivateKeyPem,
            options.PrivateKeyPemPath,
            "Jwt:PrivateKeyPem",
            "Jwt:PrivateKeyPemPath",
            required: true)!;

        if (privatePem.Contains("-----BEGIN PUBLIC KEY-----", StringComparison.OrdinalIgnoreCase) ||
            privatePem.Contains("-----BEGIN RSA PUBLIC KEY-----", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "Jwt:PrivateKeyPem/PrivateKeyPemPath recibió una clave pública; se requiere la clave privada RSA.");
        }

        using var privateRsa = ImportRsaFromPem(privatePem, "Jwt:PrivateKeyPem");
        EnsureMinimumRsaKeySize(privateRsa, "Jwt:PrivateKeyPem");

        RSAParameters privateParameters;
        try
        {
            privateParameters = privateRsa.ExportParameters(includePrivateParameters: true);
        }
        catch (CryptographicException ex)
        {
            throw new InvalidOperationException(
                "La clave configurada en Jwt:PrivateKeyPem/PrivateKeyPemPath no incluye parámetros privados RSA válidos.",
                ex);
        }

        if (privateParameters.D is not { Length: > 0 } ||
            privateParameters.Modulus is not { Length: > 0 } ||
            privateParameters.Exponent is not { Length: > 0 })
        {
            throw new InvalidOperationException(
                "La clave RSA privada configurada está incompleta o carece del exponente privado.");
        }

        var publicParameters = privateRsa.ExportParameters(includePrivateParameters: false);
        var canonicalPublicPem = NormalizePem(privateRsa.ExportSubjectPublicKeyInfoPem());

        var explicitPublicPem = LoadPemFromInlineOrPath(
            options.PublicKeyPem,
            options.PublicKeyPemPath,
            "Jwt:PublicKeyPem",
            "Jwt:PublicKeyPemPath",
            required: false);

        if (explicitPublicPem is not null)
        {
            if (explicitPublicPem.Contains("PRIVATE KEY", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    "Jwt:PublicKeyPem/PublicKeyPemPath no debe contener una clave privada RSA.");
            }

            using var explicitPublicRsa = ImportRsaFromPem(explicitPublicPem, "Jwt:PublicKeyPem");
            EnsureMinimumRsaKeySize(explicitPublicRsa, "Jwt:PublicKeyPem");

            var explicitPublicParameters = explicitPublicRsa.ExportParameters(includePrivateParameters: false);
            var modulusMatches = explicitPublicParameters.Modulus is not null &&
                CryptographicOperations.FixedTimeEquals(explicitPublicParameters.Modulus, publicParameters.Modulus);
            var exponentMatches = explicitPublicParameters.Exponent is not null &&
                CryptographicOperations.FixedTimeEquals(explicitPublicParameters.Exponent, publicParameters.Exponent);

            if (!modulusMatches || !exponentMatches)
            {
                throw new InvalidOperationException(
                    "Jwt:PublicKeyPem/PublicKeyPemPath no corresponde con la clave privada RSA configurada.");
            }
        }

        var refreshHmacKey = options.RefreshTokenHmacKey;
        if (string.IsNullOrWhiteSpace(refreshHmacKey) ||
            Encoding.UTF8.GetByteCount(refreshHmacKey) < MinimumRefreshHmacKeyBytes)
        {
            throw new InvalidOperationException(
                "Configura Jwt:RefreshTokenHmacKey con al menos 32 bytes antes de iniciar saas-identity.");
        }

        var normalizedRefreshHmac = NormalizePem(refreshHmacKey);
        if (normalizedRefreshHmac.Contains("-----BEGIN ", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(normalizedRefreshHmac, canonicalPublicPem, StringComparison.Ordinal) ||
            string.Equals(StripPemFraming(normalizedRefreshHmac), StripPemFraming(canonicalPublicPem), StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "Jwt:RefreshTokenHmacKey debe ser un secreto HMAC independiente y nunca una clave RSA.");
        }

        var derivedMacKey = SHA256.HashData(
            Encoding.UTF8.GetBytes($"vital-identity-rt-route-v1:{refreshHmacKey}"));

        var normalizedKeyId = string.IsNullOrWhiteSpace(options.KeyId)
            ? null
            : options.KeyId.Trim();

        return new JwtCryptoMaterial(
            options.Issuer.Trim(),
            options.Audience.Trim(),
            normalizedKeyId,
            options.AccessTokenMinutes,
            options.RefreshTokenDays,
            privateParameters,
            publicParameters,
            canonicalPublicPem,
            derivedMacKey);
    }

    private static TokenValidationParameters BuildValidationParameters(
        RsaSecurityKey validationKey,
        string issuer,
        string audience) =>
        new()
        {
            ValidateIssuer = true,
            ValidIssuer = issuer,
            ValidateAudience = true,
            ValidAudience = audience,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = validationKey,
            RequireSignedTokens = true,
            ValidAlgorithms = [SecurityAlgorithms.RsaSha256],
            ValidateLifetime = true,
            RequireExpirationTime = true,
            ClockSkew = DefaultClockSkew,
            RoleClaimType = "role",
        };

    private static string? LoadPemFromInlineOrPath(
        string? inlinePem,
        string? pemPath,
        string inlineConfigKey,
        string pathConfigKey,
        bool required)
    {
        var hasInline = !string.IsNullOrWhiteSpace(inlinePem);
        var hasPath = !string.IsNullOrWhiteSpace(pemPath);

        if (hasInline && hasPath)
        {
            throw new InvalidOperationException(
                $"Configura únicamente {inlineConfigKey} o {pathConfigKey}, pero no ambos simultáneamente.");
        }

        if (!hasInline && !hasPath)
        {
            if (required)
            {
                throw new InvalidOperationException(
                    $"Configura {inlineConfigKey} o {pathConfigKey} con una clave RSA de al menos {MinimumRsaKeySizeBits} bits antes de iniciar saas-identity.");
            }

            return null;
        }

        if (hasInline)
        {
            return NormalizePem(inlinePem!);
        }

        var trimmedPath = pemPath!.Trim();
        if (!File.Exists(trimmedPath))
        {
            throw new InvalidOperationException(
                $"El archivo configurado en {pathConfigKey} no existe o no es accesible.");
        }

        string fileContents;
        try
        {
            fileContents = File.ReadAllText(trimmedPath, Encoding.UTF8);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            throw new InvalidOperationException(
                $"No fue posible leer el archivo PEM configurado en {pathConfigKey}.",
                ex);
        }

        var normalized = NormalizePem(fileContents);
        if (string.IsNullOrWhiteSpace(normalized))
        {
            throw new InvalidOperationException($"El archivo PEM configurado en {pathConfigKey} está vacío.");
        }

        return normalized;
    }

    private static RSA ImportRsaFromPem(string normalizedPem, string label)
    {
        var rsa = RSA.Create();
        try
        {
            rsa.ImportFromPem(normalizedPem);
            return rsa;
        }
        catch (Exception ex) when (ex is ArgumentException or CryptographicException)
        {
            rsa.Dispose();
            throw new InvalidOperationException($"{label} no contiene una clave RSA en formato PEM válido.", ex);
        }
    }

    private static void EnsureMinimumRsaKeySize(RSA rsa, string label)
    {
        if (rsa.KeySize < MinimumRsaKeySizeBits)
        {
            throw new InvalidOperationException(
                $"{label} debe usar una clave RSA de al menos {MinimumRsaKeySizeBits} bits (actual: {rsa.KeySize} bits).");
        }
    }

    private static string NormalizePem(string pem) =>
        pem.Trim()
            .Replace("\r\n", "\n", StringComparison.Ordinal)
            .Replace("\\n", "\n", StringComparison.Ordinal);

    private static string StripPemFraming(string pem)
    {
        var lines = pem.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(line => !line.StartsWith("-----BEGIN ", StringComparison.Ordinal) &&
                           !line.StartsWith("-----END ", StringComparison.Ordinal));
        return string.Concat(lines);
    }
}
