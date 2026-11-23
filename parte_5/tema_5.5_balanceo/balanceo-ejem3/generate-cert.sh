#!/bin/bash
# Genera el certificado autofirmado del BALANCEADOR (terminación y re-cifrado).
# HAProxy espera un único fichero PEM con el certificado y la clave privada.
set -e
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout certs/lb.key -out certs/lb.crt \
  -subj "/CN=localhost/O=DAD/C=ES" -addext "subjectAltName=DNS:localhost,DNS:app.localhost"
cat certs/lb.crt certs/lb.key > certs/lb.pem
echo "Certificado generado en certs/lb.pem"
