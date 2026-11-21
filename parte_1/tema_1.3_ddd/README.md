# Tema 1.3: Domain-Driven Design

## Transparencias

Las transparencias están en [`slides/ddd.qmd`](slides/ddd.qmd) y se generan con [Quarto](https://quarto.org):

```bash
cd slides
quarto render ddd.qmd      # genera ddd.html
quarto preview ddd.qmd     # previsualización con recarga automática
```

Los diagramas de `slides/images` son SVG. Los que tienen un fichero `.mmd` al lado se generan con
[Mermaid CLI](https://github.com/mermaid-js/mermaid-cli):

```bash
cd slides/images
mmdc -i ciclo-vida-pedido.mmd -o ciclo-vida-pedido.svg -c mermaid-config.json -b white
```

## Ejemplos y ejercicios

| Proyecto | Contenido |
|---|---|
| [ddd-ejem1](ddd-ejem1) | *Value objects* (`Money`, `EmailAddress`, `Address`, `CustomerId`) y la entidad `Customer` |
| [ddd-ejem2](ddd-ejem2) | Agregado `Order` con invariantes y eventos de dominio, repositorio JPA, servicio de aplicación y API REST con arquitectura hexagonal |
| [ddd-ejem3](ddd-ejem3) | Monolito modular con dos *bounded contexts* (Ventas y Logística), lenguaje publicado y *Anti-Corruption Layer* con un transportista externo |
| [ddd-ejer1](ddd-ejer1) | Solución del ejercicio 1: préstamos de una biblioteca (el enunciado está en las transparencias) |

Todos son proyectos Maven con Spring Boot:

```bash
cd ddd-ejem2
mvn test               # pruebas (las del dominio no arrancan Spring)
mvn spring-boot:run    # arranca la aplicación
```
