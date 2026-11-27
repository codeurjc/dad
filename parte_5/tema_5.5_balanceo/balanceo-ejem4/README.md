# balanceo-ejem4: elasticidad

## Algoritmo de autoescalado (sin Kubernetes)

`ReplicaCalculator` implementa, en Java puro, la idea del HorizontalPodAutoscaler:
`deseadas = ceil(actuales × métrica / objetivo)` con tolerancia, límite de
crecimiento y ventana de estabilización. `ReplicaCalculatorTest` muestra cada regla.

`ElasticitySimulation` simula dos horas de tráfico y escribe un CSV con la demanda
y las réplicas listas (es la gráfica que aparece en las transparencias):

```bash
mvn -q compile exec:java -Dexec.mainClass=es.codeurjc.dad.balanceo.ejem4.autoscaling.ElasticitySimulation
```

## Autoescalado real con Kubernetes

Necesitas un clúster local ([kind](https://kind.sigs.k8s.io) o
[minikube](https://minikube.sigs.k8s.io)) con *metrics-server* (en minikube:
`minikube addons enable metrics-server`). El `preStop` con `sleep` requiere
Kubernetes 1.30 o superior.

```bash
docker build -t dad/balanceo-ejem4:latest .
kind load docker-image dad/balanceo-ejem4:latest     # o: minikube image load dad/balanceo-ejem4:latest

kubectl apply -f k8s/deployment.yaml -f k8s/service.yaml -f k8s/hpa.yaml
kubectl get hpa work --watch                           # en otra terminal

kubectl apply -f k8s/load-generator.yaml               # empieza la carga: el HPA añade réplicas
kubectl delete -f k8s/load-generator.yaml              # termina la carga: tras 2 minutos, las quita
```
