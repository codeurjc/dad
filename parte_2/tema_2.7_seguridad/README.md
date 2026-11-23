# Tema 2.7: Seguridad en aplicaciones distribuidas

## Transparencias

Las transparencias están en [`slides/seguridad.qmd`](slides/seguridad.qmd) y se generan con [Quarto](https://quarto.org):

```bash
cd slides
quarto render seguridad.qmd      # genera seguridad.html
```

Los diagramas de `slides/images` son SVG. Los que tienen un fichero `.mmd` al lado se generan con
[Mermaid CLI](https://github.com/mermaid-js/mermaid-cli)
(`mmdc -i fichero.mmd -o fichero.svg -c mermaid-config.json -b white`).

## Ejemplos y ejercicios

| Proyecto | Contenido |
|---|---|
| [seg-ejem1](seg-ejem1) | JWT HS256 y hash de contraseñas con PBKDF2 hechos a mano, en Java puro, para entender cómo funcionan |
| [seg-ejem2](seg-ejem2) | API REST como *resource server* OAuth 2 con Keycloak: roles, `@PreAuthorize` y tests con `jwt()` |
| [seg-ejem3](seg-ejem3) | Comunicación entre servicios con *client credentials*: `pedidos` llama a `inventario` con su propio token |
| [seg-ejer1](seg-ejer1) | Solución del ejercicio 1: autorización a nivel de objeto (el enunciado está en las transparencias) |

```bash
cd seg-ejem1 && mvn test && mvn -q compile exec:java -Dexec.mainClass=es.codeurjc.dad.seg.ejem1.Demo
cd seg-ejem2 && docker compose up --build     # Keycloak :8180 (admin/admin), API :8080
cd seg-ejem3 && docker compose up --build     # Keycloak :8180, pedidos :8080
```

Los tests de todos los proyectos se ejecutan sin Keycloak.
