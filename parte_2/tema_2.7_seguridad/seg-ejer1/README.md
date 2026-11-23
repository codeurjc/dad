# seg-ejer1: solución del ejercicio 1 (autorización a nivel de objeto)

El enunciado está en las transparencias del tema. Usuarios del realm: `ana`/`ana` y `luis`/`luis` (rol `user`)
y `soporte`/`soporte` (roles `user` y `soporte`). Al arrancar hay un pedido de ana (id 1) y otro de luis (id 2).

Decisiones de la solución:

* La regla "puede ver" está en un único sitio (`PedidoService.puedeVer`) y se aplica en **todas** las operaciones
* Un pedido ajeno devuelve **404**, igual que uno inexistente: no se revela qué ids existen
* El propietario se toma del **token** (`authentication.getName()`), nunca del cuerpo de la petición
* La entrada es un DTO (`NuevoPedido`) sin `propietario` ni `estado`: no hay asignación masiva
* Los tests prueban explícitamente los accesos que **no** deben funcionar

```bash
mvn test        # no necesita Keycloak

docker compose up --build
TOKEN=$(curl -s -d client_id=pedidos-web -d grant_type=password -d username=ana -d password=ana \
  http://localhost:8180/realms/dad/protocol/openid-connect/token | jq -r .access_token)
curl -s -H "Authorization: Bearer $TOKEN" localhost:8080/api/pedidos | jq
curl -i -H "Authorization: Bearer $TOKEN" localhost:8080/api/pedidos/2      # 404: es de luis
```
