# k8s-ejem1: una aplicación en Kubernetes

Aplicación Spring Boot mínima que responde con un mensaje (de un ConfigMap), su versión y el **nombre del pod**
que atiende la petición. Ficheros en [`k8s/`](k8s): `Deployment` con 3 réplicas, sondas y recursos,
`Service`, `ConfigMap` y `Secret`.

Con un clúster local ([kind](https://kind.sigs.k8s.io/), [minikube](https://minikube.sigs.k8s.io/) o el de Docker Desktop):

```bash
# 1. Construir la imagen y hacerla visible al clúster
docker build -t codeurjc/k8s-ejem1:v1 .
kind load docker-image codeurjc/k8s-ejem1:v1         # o: minikube image load codeurjc/k8s-ejem1:v1

# 2. Desplegar (todos los ficheros de la carpeta)
kubectl apply -f k8s/
kubectl get pods -l app=hola -o wide --watch

# 3. Probar: cada petición puede llegar a un pod distinto
kubectl port-forward service/hola 8080:80
for i in $(seq 1 6); do curl -s localhost:8080; echo; done

# 4. Experimentos
kubectl delete pod <un-pod>                           # el Deployment crea otro
kubectl scale deployment hola --replicas=5
kubectl edit configmap hola-config                    # y después:
kubectl rollout restart deployment hola               # las variables de entorno se leen al arrancar
kubectl logs -l app=hola --prefix
kubectl describe pod <un-pod>                         # eventos, sondas, recursos

kubectl delete -f k8s/
```
