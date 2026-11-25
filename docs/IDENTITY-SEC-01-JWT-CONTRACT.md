# IDENTITY-SEC-01 — Contrato Transversal de Access Tokens JWT (RS256)

## 1. Propósito y separación de responsabilidades

`saas-identity` es el **único emisor** autorizado de Access Tokens JWT y el único propietario de:

- La **clave privada RSA** utilizada para firmar access tokens (`RS256`).
- El **secreto HMAC** (`Jwt:RefreshTokenHmacKey`) utilizado exclusivamente para el enrutamiento autenticado y verificación de refresh tokens.

Los microservicios consumidores (**Platform**, **Gateway**, **Clinical** y futuros servicios de Vital) reciben **únicamente la clave pública RSA** para validar localmente la autenticidad e integridad de los JWT Bearer entrantes, sin adquirir capacidad de firmar access tokens ni de generar o enrutar refresh tokens.

---

## 2. Algoritmo y formato de clave pública

| Parámetro | Valor obligatorio |
| --- | --- |
| **Algoritmo de firma** | `RS256` (`RSASSA-PKCS1-v1_5` con `SHA-256`, identificador JOSE `RS256`) |
| **Tamaño mínimo de clave RSA** | `2048` bits |
| **Fallback a algoritmos simétricos (`HS256`, `none`)** | **Prohibido**; debe rechazarse explícitamente |
| **Formato de clave pública distribuida** | PEM `SubjectPublicKeyInfo` (`-----BEGIN PUBLIC KEY----- ... -----END PUBLIC KEY-----`) |
| **Encabezado JWT** | `alg = "RS256"`, `typ = "JWT"` (y `kid` opcional si se configura `Jwt:KeyId`) |

---

## 3. Parámetros de validación estándar

| Parámetro | Valor |
| --- | --- |
| **Issuer (`iss`)** | `saas-identity` |
| **Audience (`aud`)** | `vital-saas` |
| **Duración predeterminada del access token** | `15 minutos` (`900` segundos) |
| **Tolerancia temporal (`ClockSkew`)** | `30 segundos` |
| **Mapeo de claims entrantes** | Deshabilitado (`MapInboundClaims = false`) |
| **Claim de rol (`RoleClaimType`)** | `role` |

---

## 4. Claims del Access Token

### 4.1 Claims estándar y de identidad

| Claim | Tipo JSON | Obligatorio | Significado |
| --- | --- | --- | --- |
| `sub` | `string` (UUID) | Sí | Identificador único de la cuenta (`accountId`) en Identity. |
| `email` | `string` | Sí | Correo electrónico de la cuenta autenticada. |
| `jti` | `string` (UUID) | Sí | Identificador único del JWT emitido. |
| `iat` | `number` (Epoch seconds) | Sí | Instante de emisión UTC en segundos Unix (`Integer64`). |
| `nbf` | `number` (Epoch seconds) | Sí | Instante de inicio de validez UTC (`== iat`). |
| `exp` | `number` (Epoch seconds) | Sí | Instante de expiración UTC (`iat + 900` por defecto). |
| `iss` | `string` | Sí | Emisor: `saas-identity`. |
| `aud` | `string` | Sí | Audiencia: `vital-saas`. |
| `role` | `string` | Sí | Rol cerrado de la cuenta (`SUPER_ADMIN`, `ADMIN_CLINICA`, `ESPECIALISTA`, `AUXILIAR`). |
| `full_name` | `string` | Sí | Nombre completo de la cuenta. |
| `tenant_id` | `string` (UUID) | Condicional | Identificador de la clínica (`Guid`). **Presente** en cuentas clínicas; **ausente** en `SUPER_ADMIN`. |

### 4.2 Diferenciación entre cuentas globales y cuentas clínicas

1. **Cuentas globales (`role = "SUPER_ADMIN"`)**:
   - Se autentican vía `POST /v1/auth/platform/login` contra la base global de Identity.
   - **No contienen** el claim `tenant_id`.
   - Cualquier token con `role == "SUPER_ADMIN"` que incluya `tenant_id` debe considerarse inválido.
   - En servicios exclusivos de clínica (como endpoints `/v1/staff` o módulos clínicos de tenant), un `SUPER_ADMIN` sin contexto clínico debe recibir `403 Forbidden`.

2. **Cuentas clínicas (`ADMIN_CLINICA`, `ESPECIALISTA`, `AUXILIAR`)**:
   - Se autentican vía `POST /v1/auth/login` contra la base aislada de su clínica.
   - **Deben incluir** el claim `tenant_id` con un UUID no vacío.
   - Si falta `tenant_id` o no es un UUID válido distinto de `Guid.Empty`, el consumidor debe rechazar la petición con `401 Unauthorized`.
   - Toda consulta o mutación de negocio debe acotarse estrictamente al `tenant_id` del token validado (nunca confiar en parámetros de ruta/cuerpo sin contrastarlos contra `tenant_id`).

---

## 5. Configuración recomendada para consumidores .NET

Los consumidores .NET (`Platform`, `Gateway`, `Clinical`) deben cargar **únicamente la clave pública PEM** y restringir `ValidAlgorithms` exclusivamente a `SecurityAlgorithms.RsaSha256`:

```csharp
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

JwtSecurityTokenHandler.DefaultMapInboundClaims = false;

var publicKeyPem = builder.Configuration["Jwt:PublicKeyPem"]
    ?? throw new InvalidOperationException("Falta Jwt:PublicKeyPem.");

if (publicKeyPem.Contains("PRIVATE KEY", StringComparison.OrdinalIgnoreCase))
{
    throw new InvalidOperationException("Los consumidores solo deben recibir la clave pública RSA.");
}

var normalizedPem = publicKeyPem.Trim().Replace("\\n", "\n", StringComparison.Ordinal);
using var rsa = RSA.Create();
rsa.ImportFromPem(normalizedPem);
if (rsa.KeySize < 2048)
{
    throw new InvalidOperationException("La clave pública RSA debe ser de al menos 2048 bits.");
}

var validationKey = new RsaSecurityKey(rsa.ExportParameters(includePrivateParameters: false));

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.MapInboundClaims = false;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = "saas-identity",
            ValidateAudience = true,
            ValidAudience = "vital-saas",
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = validationKey,
            RequireSignedTokens = true,
            ValidAlgorithms = [SecurityAlgorithms.RsaSha256],
            ValidateLifetime = true,
            RequireExpirationTime = true,
            ClockSkew = TimeSpan.FromSeconds(30),
            RoleClaimType = "role",
        };
    });
```

> **Importante:** Al exportar `rsa.ExportParameters(includePrivateParameters: false)`, no se debe reutilizar `RSA.Create()` dentro de un `using` si se pasa directamente `new RsaSecurityKey(rsa)` en lugar de `RSAParameters`. Pasar `RSAParameters` desacopla la vida útil del objeto `RsaSecurityKey` del `using var rsa`.

---

## 6. Variables de entorno requeridas

### 6.1 En `saas-identity` (emisor)

| Variable | Obligatoria | Descripción |
| --- | --- | --- |
| `Jwt__Issuer` | No (default `saas-identity`) | Emisor de los JWT emitidos y validados. |
| `Jwt__Audience` | No (default `vital-saas`) | Audiencia de los JWT emitidos y validados. |
| `Jwt__PrivateKeyPem` o `Jwt__PrivateKeyPemPath` | **Sí** (mutuamente excluyentes) | Clave privada RSA (>= 2048 bits) en formato PEM (PKCS#8 o PKCS#1). |
| `Jwt__PublicKeyPem` o `Jwt__PublicKeyPemPath` | Opcional | Si se suministra, Identity verifica al iniciar que coincide con la clave privada. |
| `Jwt__KeyId` | Opcional | Identificador `kid` opcional en la cabecera JWT. |
| `Jwt__RefreshTokenHmacKey` | **Sí** | Secreto HMAC independiente (>= 32 bytes) exclusivo de Identity para enrutamiento de refresh tokens. Nunca usar la clave RSA. |
| `Jwt__AccessTokenMinutes` | No (default `15`) | Vigencia en minutos del access token. |
| `Jwt__RefreshTokenDays` | No (default `7`) | Vigencia en días del refresh token. |

> Si la variable heredada `Jwt__SigningKey` (`HS256`) está presente, `saas-identity` falla el arranque de forma explícita sin fallback silencioso.

### 6.2 En microservicios consumidores (`Platform`, `Gateway`, `Clinical`)

| Variable | Obligatoria | Descripción |
| --- | --- | --- |
| `Jwt__Issuer` | Recomendada (`saas-identity`) | Emisor esperado. |
| `Jwt__Audience` | Recomendada (`vital-saas`) | Audiencia esperada. |
| `Jwt__PublicKeyPem` (o archivo montado) | **Sí** | Clave pública RSA (`BEGIN PUBLIC KEY`) correspondiente a `saas-identity`. |

Los consumidores **nunca** deben recibir `Jwt__PrivateKeyPem`, `Jwt__PrivateKeyPemPath` ni `Jwt__RefreshTokenHmacKey`.

---

## 7. Generación, distribución y sustitución de claves

### 7.1 Generación de par RSA (>= 2048 bits) y secreto HMAC

```bash
# 1. Clave privada RSA PKCS#8 (2048 bits; 3072/4096 también admitidos)
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out jwt-private.pem

# 2. Clave pública SubjectPublicKeyInfo (distribuible a consumidores)
openssl pkey -in jwt-private.pem -pubout -out jwt-public.pem

# 3. Secreto HMAC independiente para refresh tokens (64 hex chars = 32+ bytes)
openssl rand -hex 32
```

### 7.2 Distribución

- **Identity**: recibe `jwt-private.pem` (vía Secret de Kubernetes montado o variable secreta `Jwt__PrivateKeyPem` / `Jwt__PrivateKeyPemPath`) y `Jwt__RefreshTokenHmacKey`.
- **Platform / Gateway / Clinical**: reciben únicamente `jwt-public.pem`.
- Nunca versionar archivos `.pem`, `.key` ni `.env` en Git ni incrustarlos en imágenes Docker.

### 7.3 Sustitución (rotación manual de claves)

1. Generar un nuevo par RSA (`jwt-private-new.pem` / `jwt-public-new.pem`).
2. Mientras no exista infraestructura JWKS automática (excluida en esta fase):
   - Desplegar la nueva clave pública en los consumidores (o habilitar aceptación temporal de la nueva clave durante la ventana de transición si el consumidor soporta múltiples `IssuerSigningKeys`).
   - Actualizar `Jwt__PrivateKeyPem` (y `Jwt__PublicKeyPem` si se especifica) en `saas-identity` y reiniciar sus réplicas.
3. Si la clave privada anterior fue comprometida, reemplazar inmediatamente la clave pública en todos los consumidores para invalidar de forma inmediata los tokens firmados con la clave comprometida.
4. La rotación del par RSA **no invalida** los refresh tokens activos siempre que `Jwt__RefreshTokenHmacKey` se mantenga intacto.

---

## 8. Comportamiento de sesiones emitidas antes del cambio

1. **Access tokens HS256 previos**:
   - Quedan **invalidados inmediatamente** tras el despliegue de `saas-identity` con RS256, porque tanto Identity como los consumidores rechazan `alg: HS256` sin fallback.
2. **Refresh tokens previos (derivados del antiguo `Jwt:SigningKey`)**:
   - Al separarse `Jwt:RefreshTokenHmacKey` de la clave de firma JWT, los refresh tokens emitidos antes del cambio fallarán la verificación del tag HMAC de enrutamiento con `401 INVALID_REFRESH_TOKEN` (en `/v1/auth/refresh`) o serán ignorados de forma idempotente (en `/v1/auth/logout`).
   - Los registros históricos en la tabla `identity.refresh_tokens` permanecen en PostgreSQL hasta su expiración natural (7 días por defecto) sin requerir eliminaciones masivas ni scripts destructivos.
   - Los usuarios deberán iniciar sesión nuevamente (`/v1/auth/login` o `/v1/auth/platform/login`).

---

## 9. Limitaciones actuales respecto a revocación inmediata de Access Tokens

- Los Access Tokens JWT RS256 son **stateless** y tienen una vigencia máxima predeterminada de **15 minutos** (más hasta **30 segundos** de `ClockSkew`).
- Cuando ocurre un evento de revocación (`POST /v1/auth/logout`, detección de reutilización de refresh token, o desactivación de cuenta vía `PATCH /v1/staff/{accountId}/status`), Identity revoca inmediatamente los refresh tokens en PostgreSQL e impide renovaciones futuras; sin embargo, un access token ya emitido puede seguir siendo aceptado localmente por consumidores stateless hasta que expire (`<= 15m 30s`), salvo en endpoints de Identity que revalidan estado en BD (como `/v1/auth/me`).
- Esta fase **no** introduce Redis, listas negras distribuidas ni introspección síncrona transversal. Cualquier mecanismo adicional de revocación inmediata transversal deberá acordarse explícitamente entre ambos desarrolladores antes de su implementación.
