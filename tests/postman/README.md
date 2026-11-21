# Pruebas Postman y Newman (`saas-identity`)

## Importar en Postman Desktop / VS Code

1. Levanta el servicio y PostgreSQL desde `saas-identity/`:

```powershell
docker compose up -d --build
```

2. Importa `Vital.Identity.postman_collection.json` y el entorno `Vital.Identity.local.postman_environment.json`.
3. Ejecuta el **Collection Runner** completo (14 requests secuenciales).

## Ejecutar con Newman en Docker (sin instalar Node/Newman global)

```powershell
docker run --rm --network saas-identity_default `
  -v "${PWD}:/etc/newman" `
  postman/newman:alpine run /etc/newman/Vital.Identity.postman_collection.json `
  --env-var "baseUrl=http://identity-api:8080"
```

Si ejecutaste el comando desde `saas-identity/` en lugar de `tests/postman/`, monta `${PWD}/tests/postman:/etc/newman`.
