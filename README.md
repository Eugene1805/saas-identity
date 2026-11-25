# saas-identity

Microservicio **Identity** de **Vital** (Plataforma SaaS Gestión Hospitalaria), implementado en **.NET 10** con **Arquitectura Hexagonal (Puertos y Adaptadores)**, persistencia multitenant conforme a **ADR-0002 (Alternativa B: una base PostgreSQL independiente por clínica + base global privada de Identity)**, sesiones con **JWT Bearer + Refresh Tokens rotables autoverificados**, documentación **OpenAPI / Scalar**, servidor **gRPC (`h2c`)** y pruebas **xUnit** + integración multi-PostgreSQL + **Postman / Newman**.

## Arquitectura Hexagonal y Topología Multitenant

```text
protos/
  platform_identity/v1/          # Contrato Protobuf congelado compartido con saas-platform
src/
  Saas.Identity.Domain/          # Entidades, IdentityStoreScope, políticas puras (CU-12, CU-13, CU-14, contraseñas, lockout), reloj GMT-6, Result<T>
  Saas.Identity.Application/     # Puertos con ámbito explícito, ITenantDatabaseMigratorPort y casos de uso Auth, Personal y Provisioning
  Saas.Identity.Infrastructure/  # GlobalIdentityDbContext, TenantIdentityDbContext, migraciones separadas (Global/Tenant), TenantConnectionResolver (CNPG/env), PBKDF2, JWT/HMAC, Email y cliente gRPC Platform
  Saas.Identity.Api/             # Minimal APIs HTTP (:8080), OpenAPI/Scalar, probes K8s y Servidor gRPC fail-closed HTTP/2 (:8082) + Reflection
tests/
  Saas.Identity.UnitTests/       # Pruebas unitarias xUnit de dominio, casos de uso, lockout, resolución de conexiones CNPG, correo y gRPC
  Saas.Identity.IntegrationTests/# Pruebas reales multi-PostgreSQL (Testcontainers / 5 instancias) de aislamiento físico, concurrencia y failover
  postman/                       # Colección y entorno para Postman / Newman
```

Regla de dependencias: `Api -> Application -> Domain` y `Infrastructure -> Application -> Domain`. El núcleo (`Domain` + `Application`) no depende de frameworks HTTP, Entity Framework, SMTP ni PostgreSQL.

## Arranque rápido con Docker Compose (4 instancias PostgreSQL 17)

1. Copia `.env.example` a `.env` (no versionado) y asigna valores locales seguros:
   - Clave privada RSA >= 2048 bits en formato PEM para `JWT_PRIVATE_KEY_PEM` (y opcionalmente `JWT_PUBLIC_KEY_PEM`).
   - Secreto HMAC independiente >= 32 bytes para `JWT_REFRESH_TOKEN_HMAC_KEY`.
   - Credencial >= 16 bytes para `INTERNAL_GRPC_API_KEY` y contraseñas de BD.
   - Consulta el contrato transversal de firma RS256 en [`docs/IDENTITY-SEC-01-JWT-CONTRACT.md`](docs/IDENTITY-SEC-01-JWT-CONTRACT.md).

```powershell
cd saas-identity
cp .env.example .env
docker compose up -d --build
```

- **Base Global privada de Identity:** `127.0.0.1:5433` (`vital_identity_global`, solo `SUPER_ADMIN` y sesiones globales)
- **Bases clínicas independientes:**
  - `clinica-norte` (`10000000-0000-0000-0000-000000000001`): `127.0.0.1:5436` (`vital_identity_norte`)
  - `clinica-valle` (`10000000-0000-0000-0000-000000000002`): `127.0.0.1:5437` (`vital_identity_valle`)
  - `clinica-aurora` (`10000000-0000-0000-0000-000000000003`): `127.0.0.1:5438` (`vital_identity_aurora`)
- **API HTTP Identity:** `http://127.0.0.1:8081`
- **Servidor gRPC (`h2c`):** `http://127.0.0.1:5082` (interno contenedor `http://identity-api:8082`, exige `x-internal-service-key` configurado fail-closed)
- **Health checks:** `GET /health`, `GET /health/live` (liveness `process-only`) y `GET /health/ready` (readiness contra Global DB)
- **OpenAPI / Scalar:** `http://127.0.0.1:8081/openapi/v1.json` y `http://127.0.0.1:8081/scalar/v1`

### Resolución de bases por tenant (Kubernetes / CloudNativePG)

En entornos Kubernetes con CloudNativePG, configurar `TenantDatabases__SecretsDirectory` apuntando al directorio montado donde cada `<tenantId>` tenga `uri` o `{host,port,dbname,username,password,sslmode}` (o `<tenantId>.connection`). En Compose/pruebas también se puede usar `TenantDatabases__Connections__<tenantId>`.

## Endpoints implementados

- `GET /health`, `GET /health/live`, `GET /health/ready`
- `POST /v1/auth/login` (login clínico por `clinicSlug` + bloqueo exponencial `429`)
- `POST /v1/auth/platform/login` (`SUPER_ADMIN` en BD Global privada)
- `POST /v1/auth/refresh` (enrutamiento O(1) firmado con HMAC + rotación + detección de reuso)
- `POST /v1/auth/logout` (idempotente)
- `POST /v1/auth/change-password` (política 8-40 chars: letra, número y símbolo)
- `GET /v1/auth/me`
- `GET /v1/staff`, `POST /v1/staff`, `PUT /v1/staff/{accountId}/role`, `PATCH /v1/staff/{accountId}/status`, `PUT /v1/staff/{accountId}/links`

## Pruebas automatizadas

### 1. Pruebas unitarias xUnit dentro de contenedor .NET 10

```powershell
docker build --target test -t vital-identity-test .
```

### 2. Pruebas de integración reales multi-PostgreSQL (`Testcontainers`)

```powershell
dotnet test tests/Saas.Identity.IntegrationTests/Saas.Identity.IntegrationTests.csproj -c Release
```

### 3. Pruebas Postman con Newman contra el stack levantado

```powershell
docker run --rm --network saas-identity_default `
  -v "${PWD}/tests/postman:/etc/newman" `
  postman/newman:alpine run /etc/newman/Vital.Identity.postman_collection.json `
  --env-var "baseUrl=http://identity-api:8080"
```

## CI y publicación de imagen en GHCR

El workflow [`.github/workflows/ci.yml`](.github/workflows/ci.yml) ejecuta:
- `build-and-test`: `dotnet restore`, `build`, pruebas unitarias (`Saas.Identity.UnitTests`) y pruebas reales multi-PostgreSQL (`Saas.Identity.IntegrationTests` con `Testcontainers`).
- `docker-build`: construye la imagen Docker, levanta **4 instancias PostgreSQL 17 independientes** (`global`, `norte`, `valle`, `aurora`) + `saas-identity` endurecido (`--cap-drop=ALL`, `--security-opt=no-new-privileges:true`, usuario no root `UID 1654`), verifica probes, Newman y aprovisionamiento gRPC idempotente sobre BD vacía.
- `publish-ghcr` (solo `push` a `main`): publica `ghcr.io/eugene1805/saas-identity:<SHA>` registrando el digest inmutable `@sha256:...` en `GITHUB_STEP_SUMMARY`.

Para más detalle de decisiones e historial técnico, consulta `../SEGUIMIENTO_IDENTITY_BACKEND.md`.
