# Tema 5.5: Balanceo de carga y elasticidad

## Transparencias

Las transparencias están en [`slides/balanceo.qmd`](slides/balanceo.qmd) y se generan con [Quarto](https://quarto.org):

```bash
cd slides
quarto render balanceo.qmd      # genera balanceo.html
```

Los diagramas de `slides/images` son SVG. Los que tienen un fichero `.mmd` al lado se generan con
[Mermaid CLI](https://github.com/mermaid-js/mermaid-cli)
(`mmdc -i fichero.mmd -o fichero.svg -c mermaid-config.json -b white`). La gráfica
`elasticidad-simulacion.svg` sale de la simulación de `balanceo-ejem4`.

## Ejemplos y ejercicios

| Proyecto | Contenido |
|---|---|
| [balanceo-ejem1](balanceo-ejem1) | Tres instancias detrás de HAProxy con *round robin* (`haproxy-roundrobin.cfg`) y con *sticky sessions* por cookie (`haproxy-sticky.cfg`). HAProxy descubre las réplicas por el DNS de Docker |
| [balanceo-ejem2](balanceo-ejem2) | El mismo servicio con la sesión HTTP en Redis (Spring Session): instancias sin estado, sin *sticky sessions* |
| [balanceo-ejem3](balanceo-ejem3) | HTTPS con *SSL passthrough*, terminación SSL y re-cifrado |
| [balanceo-ejem4](balanceo-ejem4) | Elasticidad: algoritmo de autoescalado con tests, simulación y despliegue en Kubernetes con HorizontalPodAutoscaler |
| [balanceo-ejer1](balanceo-ejer1) | Solución del ejercicio 1: un balanceador de carga HTTP en Java (el enunciado está en las transparencias) |

Los ejemplos 1 a 3 se arrancan con Docker Compose (en cada `docker-compose*.yml` se explica cómo):

```bash
cd balanceo-ejem1
docker compose up --build                            # round robin
HAPROXY_CFG=haproxy-sticky.cfg docker compose up     # sticky sessions
docker compose up --scale web=5                      # más réplicas: HAProxy las descubre
```

Aplicación en http://localhost:8080 y estadísticas de HAProxy en http://localhost:8404.
