# k8s-ejem2: aplicación con base de datos

API de notas (Spring Boot + JPA) con 2 réplicas que comparten una base de datos MySQL:

* [`k8s/mysql.yaml`](k8s/mysql.yaml): `StatefulSet` con un `PersistentVolumeClaim` (los datos sobreviven al pod) y un `Service` *headless*
* [`k8s/mysql-secret.yaml`](k8s/mysql-secret.yaml): credenciales, usadas por MySQL y por la aplicación
* [`k8s/notas.yaml`](k8s/notas.yaml): `Deployment` y `Service` de la aplicación
* [`k8s/ingress.yaml`](k8s/ingress.yaml): entrada HTTP por `http://notas.localhost`

```bash
docker build -t codeurjc/k8s-ejem2:v1 .
kind load docker-image codeurjc/k8s-ejem2:v1      # o: minikube image load codeurjc/k8s-ejem2:v1

kubectl apply -f k8s/
kubectl get pods --watch       # las réplicas de notas se reinician hasta que MySQL está listo

# Con un controlador de Ingress instalado (minikube addons enable ingress, o ingress-nginx en kind):
curl -X POST notas.localhost/api/notas -H 'Content-Type: application/json' -d '{"texto":"hola"}'
curl notas.localhost/api/notas
# Sin Ingress:
kubectl port-forward service/notas 8080:80

# Los datos sobreviven aunque se borre el pod de MySQL
kubectl delete pod mysql-0
kubectl get pvc

kubectl delete -f k8s/        # el PVC NO se borra: kubectl delete pvc datos-mysql-0
```
