#!/bin/bash
# Despliega el overlay de desarrollo y comprueba que los mensajes fluyen del productor al consumidor
set -euo pipefail
NS=colas-dev

kubectl apply -k "$(dirname "$0")/overlays/dev"
kubectl -n $NS rollout status statefulset/rabbitmq --timeout=180s
kubectl -n $NS rollout status deployment/producer --timeout=180s
kubectl -n $NS rollout status deployment/consumer --timeout=180s

echo "Esperando mensajes..."
sleep 15
if kubectl -n $NS logs deployment/consumer --tail=50 | grep -q "data"; then
  echo "OK: el consumidor está recibiendo mensajes"
else
  echo "ERROR: el consumidor no ha recibido mensajes" >&2
  kubectl -n $NS logs deployment/producer --tail=20 >&2
  exit 1
fi

# La cola sobrevive a un reinicio de RabbitMQ (StatefulSet + volumen persistente)
kubectl -n $NS delete pod rabbitmq-0
kubectl -n $NS rollout status statefulset/rabbitmq --timeout=180s
kubectl -n $NS get pvc
