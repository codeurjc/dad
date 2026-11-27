# Tema 3.3: Arquitecturas dirigidas por eventos

## Transparencias

Las transparencias están en [`slides/eventos.qmd`](slides/eventos.qmd) y se generan con [Quarto](https://quarto.org):

```bash
cd slides
quarto render eventos.qmd      # genera eventos.html
quarto preview eventos.qmd     # previsualización con recarga automática
```

Los diagramas de `slides/images` son SVG. Los que tienen un fichero `.mmd` al lado se generan con
[Mermaid CLI](https://github.com/mermaid-js/mermaid-cli):

```bash
cd slides/images
mmdc -i cqrs.mmd -o cqrs.svg -c mermaid-config.json -b white
```

## Ejemplos y ejercicios

| Proyecto | Contenido |
|---|---|
| [eventos-ejem1](eventos-ejem1) | Eventos en memoria con Spring: `@EventListener`, `@TransactionalEventListener` y `@Async`, y qué pasa si la transacción falla |
| [eventos-ejem2](eventos-ejem2) | Publicación/suscripción con un *topic exchange* de RabbitMQ: `pedidos` publica, `inventario` y `notificaciones` se suscriben |
| [eventos-ejem3](eventos-ejem3) | Patrón *transactional outbox* (`pedidos`) y consumidor idempotente (`facturacion`) |
| [eventos-ejem4](eventos-ejem4) | *Event sourcing* y CQRS: cuenta bancaria, *event store* con concurrencia optimista y proyecciones |
| [eventos-ejer1](eventos-ejer1) | Solución del ejercicio 1: saga coreografiada entre `pedidos`, `stock` y `pagos` (el enunciado está en las transparencias) |

Los ejemplos con RabbitMQ incluyen un `docker-compose.yml` para arrancar el broker:

```bash
cd eventos-ejem2
docker compose up -d                   # consola en http://localhost:15672 (guest/guest)
(cd inventario && mvn spring-boot:run)
(cd notificaciones && mvn spring-boot:run)
(cd pedidos && mvn spring-boot:run)
```

Los tests de los proyectos con RabbitMQ usan Testcontainers, así que necesitan Docker.
