# seg-ejem3: comunicación entre servicios con OAuth2 *client credentials*

* `pedidos` (puerto 8080) necesita consultar el stock en `inventario` (8081)
* `inventario` es un resource server que solo acepta tokens con el rol `inventario-lector`
* `pedidos` obtiene su propio token de Keycloak con el flujo *client credentials* (`client_id` + `client_secret`),
  lo guarda mientras es válido y lo añade a cada petición con `OAuth2ClientHttpRequestInterceptor`

```bash
docker compose up --build

curl -i -X POST localhost:8080/api/pedidos -H 'Content-Type: application/json' -d '{"producto":"teclado","unidades":2}'   # 201
curl -i -X POST localhost:8080/api/pedidos -H 'Content-Type: application/json' -d '{"producto":"raton","unidades":1}'     # 409

# El token que obtiene el servicio de pedidos
curl -s -d grant_type=client_credentials -d client_id=pedidos-service -d client_secret=pedidos-secret \
  http://localhost:8180/realms/dad/protocol/openid-connect/token | jq -r .access_token | cut -d. -f2 | base64 -d 2>/dev/null | jq
```

Los tests de los dos proyectos se ejecutan sin Keycloak (`mvn test` en cada carpeta).
