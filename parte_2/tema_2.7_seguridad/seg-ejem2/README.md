# seg-ejem2: API REST protegida con OAuth2 y Keycloak

La tienda es un **resource server**: no gestiona usuarios ni contraseñas, solo valida los JWT que emite Keycloak.

* `GET /api/productos`: público
* `POST /api/productos`, `DELETE /api/productos/{id}`: rol `admin`
* `GET /api/me`: cualquier usuario autenticado; muestra lo que la aplicación sabe del token

Usuarios del realm `dad`: `ana`/`ana` (rol `user`) y `admin`/`admin` (roles `user` y `admin`).

```bash
docker compose up --build

# Pedir un token (password grant: SOLO para probar desde la terminal; una aplicación web usa authorization code + PKCE)
TOKEN=$(curl -s -d client_id=tienda-web -d grant_type=password -d username=ana -d password=ana \
  http://localhost:8180/realms/dad/protocol/openid-connect/token | jq -r .access_token)

# Ver lo que lleva dentro (no está cifrado)
echo $TOKEN | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null | jq

curl -i http://localhost:8080/api/productos                                    # 200
curl -i -X POST http://localhost:8080/api/productos -H 'Content-Type: application/json' \
  -d '{"nombre":"Monitor","precio":199}'                                       # 401
curl -i -H "Authorization: Bearer $TOKEN" -X POST http://localhost:8080/api/productos \
  -H 'Content-Type: application/json' -d '{"nombre":"Monitor","precio":199}'   # 403 (ana no es admin)
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/me | jq
```

Los tests (`mvn test`) no necesitan Keycloak: usan `jwt()` de `spring-security-test`.
