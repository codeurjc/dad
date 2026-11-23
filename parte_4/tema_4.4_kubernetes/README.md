# Tema 4.4: Kubernetes

## Transparencias

Las transparencias están en [`slides/kubernetes.qmd`](slides/kubernetes.qmd) y se generan con [Quarto](https://quarto.org):

```bash
cd slides
quarto render kubernetes.qmd      # genera kubernetes.html
```

Los diagramas de `slides/images` son SVG. Los que tienen un fichero `.mmd` al lado se generan con
[Mermaid CLI](https://github.com/mermaid-js/mermaid-cli)
(`mmdc -i fichero.mmd -o fichero.svg -c mermaid-config.json -b white`).

## Ejemplos y ejercicios

Para probarlos basta un clúster local: [kind](https://kind.sigs.k8s.io/), [minikube](https://minikube.sigs.k8s.io/)
o el de Docker Desktop. Cada carpeta tiene un README con los comandos.

| Proyecto | Contenido |
|---|---|
| [k8s-ejem1](k8s-ejem1) | Deployment, Service, ConfigMap, Secret, sondas y recursos con una aplicación Spring Boot mínima |
| [k8s-ejem2](k8s-ejem2) | Aplicación con MySQL: StatefulSet, volumen persistente, Service *headless*, Secret e Ingress |
| [k8s-ejem3](k8s-ejem3) | HPA, *rolling update*, PodDisruptionBudget, apagado ordenado, Kustomize (dev/prod) y pipeline de CI/CD |
| [k8s-ejer1](k8s-ejer1) | Solución del ejercicio 1: productor y consumidor con RabbitMQ del tema 4.3 en Kubernetes, con Kustomize |

```bash
kind create cluster
cd k8s-ejem1
docker build -t codeurjc/k8s-ejem1:v1 . && kind load docker-image codeurjc/k8s-ejem1:v1
kubectl apply -f k8s/
```
