# Tema 5.8: Observabilidad en sistemas distribuidos

## Transparencias

Las transparencias están en [`slides/observabilidad.qmd`](slides/observabilidad.qmd) y se generan con [Quarto](https://quarto.org):

```bash
cd slides
quarto render observabilidad.qmd      # genera observabilidad.html
```

Los diagramas de `slides/images` son SVG. Los que tienen un fichero `.mmd` al lado se generan con
[Mermaid CLI](https://github.com/mermaid-js/mermaid-cli)
(`mmdc -i fichero.mmd -o fichero.svg -c mermaid-config.json -b white`).

## Ejemplos y ejercicios

| Proyecto | Contenido |
|---|---|
| [obs-ejem1](obs-ejem1) | Logs estructurados (formato ECS) con pares clave-valor e identificador de correlación en el MDC |
| [obs-ejem2](obs-ejem2) | Métricas de negocio con Micrometer; Prometheus con reglas de alerta y Grafana con un panel aprovisionado |
| [obs-ejem3](obs-ejem3) | Trazas distribuidas con OpenTelemetry entre `tienda` e `inventario`, con spans propios, exportadas a `grafana/otel-lgtm` |
| [obs-ejer1](obs-ejer1) | Solución del ejercicio 1: encontrar por qué los pagos son lentos (el enunciado está en las transparencias) |

```bash
cd obs-ejem1 && mvn spring-boot:run -Dspring-boot.run.profiles=json    # logs en JSON
cd obs-ejem2 && docker compose up --build    # Prometheus :9090, Grafana :3000 (admin/admin)
cd obs-ejem3 && docker compose up --build    # Grafana :3000 -> Explore -> Tempo
```

## Solución del ejercicio: qué se encuentra

Con la carga del `docker-compose.yml` de `obs-ejer1`, el p99 de `/orders` supera los 400 ms aunque
el proveedor VISA responde en 40 ms. En una traza lenta de un pago VISA se ve que
`pagos.provider.call` dura 40 ms, pero antes hay un `pagos.provider.lock-wait` de cientos de
milisegundos: el pago espera a que termine un pago AMEX porque todas las llamadas a proveedores
comparten un cerrojo. Con `PAGOS_FIX_CONTENTION=true docker compose up -d pagos` desaparece la
espera y el p99 de los pagos VISA vuelve a unos 60 ms.

SLI del SLO "el 99 % de los pedidos responde en menos de 300 ms" (con métricas exportadas por OTLP
el nombre puede variar ligeramente según la versión; compruébalo en Grafana → Explore):

```promql
sum(rate(http_server_requests_seconds_bucket{service_name="pedidos", uri="/orders", le="0.3"}[5m]))
  /
sum(rate(http_server_requests_seconds_count{service_name="pedidos", uri="/orders"}[5m]))
```
