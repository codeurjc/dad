# k8s-ejer1: solución del ejercicio 1

Despliegue en Kubernetes del productor y el consumidor con RabbitMQ del
[ejemplo 1 del tema 4.3](../../tema_4.3/ejemplo-1) (el enunciado está en las transparencias).

```
base/                     # lo común a todos los entornos
  rabbitmq.yaml           # StatefulSet + volumen persistente + Service headless
  producer.yaml           # Deployment (1 réplica)
  consumer.yaml           # Deployment (2 réplicas) + Service
  ingress.yaml            # http://colas.localhost, con afinidad por cookie para el WebSocket
overlays/dev/             # namespace colas-dev, 1 consumidor, credenciales de desarrollo
overlays/prod/            # namespace colas-prod, 3 consumidores, 10 Gi, credenciales fuera del repo
verificar.sh              # despliega dev y comprueba que llegan mensajes
```

```bash
kubectl kustomize overlays/dev          # ver los manifiestos generados
./verificar.sh

kubectl -n colas-dev port-forward service/consumer 8080:80          # http://localhost:8080
kubectl -n colas-dev port-forward service/rabbitmq 15672:15672      # consola de RabbitMQ (dad / dad-dev)
kubectl -n colas-dev scale deployment consumer --replicas=3         # los mensajes se reparten

# Producción
cp overlays/prod/credenciales.env.example overlays/prod/credenciales.env   # y poner valores reales
kubectl apply -k overlays/prod
```

Decisiones:

* **RabbitMQ en un StatefulSet**: nombre de nodo estable y volumen propio; los mensajes persistentes sobreviven a reinicios
* **Credenciales en un Secret** generado por Kustomize, compartido por RabbitMQ, productor y consumidor.
  En producción se leen de un fichero que no se sube al repositorio
* **Sondas TCP** en el consumidor porque la imagen no incluye Actuator; el productor no tiene servidor web
* Con varias réplicas del consumidor, cada mensaje lo procesa **solo una** (consumidores competidores):
  cada página web muestra únicamente los mensajes de su pod. La afinidad por cookie del Ingress hace que un
  navegador no cambie de pod (y de WebSocket) entre peticiones
