# Tema 1.4: Arquitectura de microservicios

## Transparencias

Las transparencias están en [`slides/microservicios.qmd`](slides/microservicios.qmd) y se generan con [Quarto](https://quarto.org):

```bash
cd slides
quarto render microservicios.qmd      # genera microservicios.html
```

Los diagramas de `slides/images` son SVG. Los que tienen un fichero `.mmd` al lado se generan con
[Mermaid CLI](https://github.com/mermaid-js/mermaid-cli)
(`mmdc -i fichero.mmd -o fichero.svg -c mermaid-config.json -b white`).

## Ejemplos y ejercicios

| Proyecto | Contenido |
|---|---|
| [micro-ejem1](micro-ejem1) | `catalogo` y `pedidos`: dos microservicios, cada uno con su base de datos, que se comunican por REST |
| [micro-ejem2](micro-ejem2) | API Gateway con Spring Cloud Gateway delante de los servicios del ejemplo 1 |
| [micro-ejem3](micro-ejem3) | Resiliencia: `pedidos` llama a un `catalogo` al que se le inyectan fallos, con *timeouts*, reintentos, *circuit breaker*, *bulkhead* y *fallback* |
| [micro-ejer1](micro-ejer1) | Solución del ejercicio 1: biblioteca con `libros`, `prestamos` y `gateway` (el enunciado está en las transparencias) |

Cada ejemplo tiene un `docker-compose.yml` que construye y arranca sus servicios:

```bash
cd micro-ejem2
docker compose up --build
curl -i localhost:8080/api/catalogo/products
```
