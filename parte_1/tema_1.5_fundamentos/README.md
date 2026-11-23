# Tema 1.5: Fundamentos de los sistemas distribuidos

## Transparencias

Las transparencias están en [`slides/fundamentos.qmd`](slides/fundamentos.qmd) y se generan con [Quarto](https://quarto.org):

```bash
cd slides
quarto render fundamentos.qmd      # genera fundamentos.html
```

Los diagramas de `slides/images` son SVG. Los que tienen un fichero `.mmd` al lado se generan con
[Mermaid CLI](https://github.com/mermaid-js/mermaid-cli)
(`mmdc -i fichero.mmd -o fichero.svg -c mermaid-config.json -b white`).

## Ejemplos y ejercicios

Son simulaciones en Java puro (sin Spring, sin red y sin Docker): se ejecutan y se prueban con Maven.

| Proyecto | Contenido |
|---|---|
| [fund-ejem1](fund-ejem1) | Relojes de Lamport y vectoriales, con la simulación del diagrama de las transparencias |
| [fund-ejem2](fund-ejem2) | Almacén clave-valor replicado sin líder: quórums W y R, *read repair* y réplicas caídas |
| [fund-ejem3](fund-ejem3) | Raft simplificado sobre una red simulada: elección de líder, replicación del log y particiones |
| [fund-ejer1](fund-ejer1) | Solución del ejercicio 1: chat de grupo con entrega causal (el enunciado está en las transparencias) |

```bash
cd fund-ejem3
mvn test
mvn -q compile exec:java -Dexec.mainClass=es.codeurjc.dad.fund.ejem3.Demo
```
