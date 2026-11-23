# k8s-ejem3: escalado, actualizaciones sin parada y despliegue continuo

Servicio que cuenta números primos (trabajo de CPU) y responde con su versión y el pod que atiende.

* [`k8s/base`](k8s/base): `Deployment` con *rolling update*, sondas, recursos, `preStop` y apagado ordenado;
  `Service`; `HorizontalPodAutoscaler` (2-10 réplicas al 60 % de CPU) y `PodDisruptionBudget`
* [`k8s/overlays/dev`](k8s/overlays/dev) y [`k8s/overlays/prod`](k8s/overlays/prod): variaciones con **Kustomize**
  (namespace, réplicas, recursos, versión de la imagen, Ingress en producción)
* [`ci/github-actions.yml`](ci/github-actions.yml): pipeline de ejemplo (tests → imagen en GHCR → `kubectl apply -k` → `rollout status`)

```bash
docker build -t codeurjc/k8s-ejem3:v1 . && kind load docker-image codeurjc/k8s-ejem3:v1
kubectl kustomize k8s/overlays/dev            # ver lo que se va a aplicar
kubectl apply -k k8s/overlays/dev

# Autoescalado (necesita metrics-server: minikube addons enable metrics-server)
kubectl -n calculo-dev run carga --image=busybox:1.37 --restart=Never -- \
  /bin/sh -c "while true; do wget -q -O- http://calculo/primos?hasta=300000 > /dev/null; done"
kubectl -n calculo-dev get hpa,pods --watch
kubectl -n calculo-dev delete pod carga

# Actualización sin parada: nueva versión de la imagen
docker build -t codeurjc/k8s-ejem3:v2 . && kind load docker-image codeurjc/k8s-ejem3:v2
kubectl -n calculo-dev set image deployment/calculo calculo=codeurjc/k8s-ejem3:v2
kubectl -n calculo-dev rollout status deployment/calculo
kubectl -n calculo-dev rollout history deployment/calculo
kubectl -n calculo-dev rollout undo deployment/calculo        # volver a la anterior

kubectl delete -k k8s/overlays/dev
```

Mientras se hace el *rolling update*, se puede comprobar que no hay errores lanzando peticiones continuamente
(`kubectl -n calculo-dev port-forward service/calculo 8080:80` y un bucle con `curl -s localhost:8080/version`).

`preStop.sleep` necesita Kubernetes 1.30 o posterior.
