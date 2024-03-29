
# Instalación de k3s en OpenStack de la URJC

Esta es una guía para la instalación de [k3s](https://k3s.io/) (una distribución ligera de Kubernetes) en una única instancia del OpenStack CLEA de la Escuela Técnica Superior de Informática (ETSII) de la Universidad Rey Juan Carlos (URJC).

## Acceso al clúster CLEA

Para acceder al [clúster CLEA](https://clea.etsii.urjc.es/horizon/) de la universidad es necesario cumplir alguno de estos requisitos:
* Estar conectado a la red de la universidad físicamente (mediante Wifi o cable).
* Estar conectado desde cualquier lugar de Internet y tener conectada la [VPN de la URJC](https://www.urjc.es/principal-intranet/documentos/general/82-configuracion-vpn-urjc).
* Usar una máquina virtual de MyApps para [conectarse al clúster](https://tv.urjc.es/video/63ed009ac758c1afe929bf32).


## Creación de una máquina virtual

Para crear una máquina virtual es necesario seguir las instrucciones contenidas en los siguientes vídeos: 

* [Acceso y creación de claves SSH](https://tv.urjc.es/video/63ecff6bc758c1af58537112)
* [Creación de instancias y grupos de seguridad](https://tv.urjc.es/video/63ed0022c758c1afa5794db2)

Para que se pueda usar correctamente k3s en esa máquina, tiene que configurarse adecuadamente:
* Hay que asignar una IP flotante
* Hay que abrir los siguientes puertos:
  * Puerto 22 TCP: Conexión SSH
  * Puerto 80 TCP: Acceso a aplicaciones mediante HTTP
  * Puerto 443 TCP: Acceso a aplicaciones mediante HTTPS
  * Puerto 6443 TCP: Acceso externo mediante `kubectl` (Kube-API)

## Instalación de k3s

Para poder instalar k3s, primero hay que conectarse por SSH a la máquina.

Como el usuario por defecto es `ubuntu`, si asumimos una la IP flotante 10.100.139.50 y un fichero de claves `ssh_key.pem` se ejecutarán los siguientes comandos:

Conexión por SSH (Bash):

`$ chmod 0400 ssh_key.pem`

`$ export FLOAT_IP=10.100.139.50` 

`$ ssh -i ssh_key.pem ubuntu@$FLOAT_IP`

Conexión por SSH (Windows PowerShell (abrir como Administrador)):

`> $sshfile = "ssh_key.pem"`

`> $FLOAT_IP=10.100.139.50` 

`> icacls $sshfile /reset`

`> icacls $sshfile /grant:r "$($env:username):(R)"`

`> ssh -i $sshfile ubuntu@$FLOAT_IP`

Actualización de ubuntu:

`$ sudo apt update && sudo apt upgrade -y`

Instalación de k3s:

`$ export FLOAT_IP=10.100.139.50` 

`$ curl -sfL https://get.k3s.io | sh -s - --node-external-ip $FLOAT_IP`

```
>[INFO]  Finding release for channel stable
>[INFO]  Using v1.28.5+k3s1 as release
>...
>[INFO]  systemd: Starting k3s
```

Verificación que está instalado correctamente:

`$ sudo k3s kubectl get node`

```
>NAME        STATUS   ROLES                  AGE    VERSION
>k3s-test1   Ready    control-plane,master   3m2s   v1.28.5+k3s1
```

Se prepara el fichero `kubeconfig` para permitir la conexión desde la máquina del administrador:

`$ sudo cat /etc/rancher/k3s/k3s.yaml | sed "s/127.0.0.1/$FLOAT_IP/" > ./kubeconfig`

Se cierra la conexión SSH de la máquina:

`$ exit`

Una vez cerrada la conexión SSH con la máquina, se copia el fichero `kubeconfig` a la máquina del administrador (Bash):

`$ scp -i ssh_key.pem ubuntu@$FLOAT_IP:kubeconfig .`

En Windows PowerShell:

`> scp -i $sshfile "ubuntu@$($FLOAT_IP):kubeconfig" .`

## Administración remota de k3s

En la máquina del administrador, si es linux y no se dispone ya del comando `kubectl`, se puede instalar se instalar con:

`$ curl -LO "https://dl.k8s.io/release/1.28.5/bin/linux/amd64/kubectl)"`

`$ chmod +x kubectl`

`$ sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl`

En Windows, si has instalado Docker Desktop este viene con kubectl también instalado. Si no, se pueden seguir [estas instrucciones](https://kubernetes.io/docs/tasks/tools/install-kubectl-windows/).

Para conectar `kubectl` con el clúster k3s recién instalado, se puede configurar la variable de entorno (Bash):

`$ export KUBECONFIG=./kubeconfig`

Windows PowerShell:

`> $KUBECONFIG=./kubeconfig`

Se puede verificar que la conexión es correcta ejecutando un comando de consulta de los nodos:

`$ kubectl get node`

```
>NAME        STATUS   ROLES                  AGE    VERSION
>k3s-test1   Ready    control-plane,master   3m2s   v1.28.5+k3s1
```

## Despliegue de una aplicación en k3s

Para verificar que el clúster k3s funciona correctamente, se puede desplegar una aplicación de ejemplo con los siguientes comandos:

`$ kubectl create deployment webapp --image=mastercloudapps/webapp:v1.0`

```
> deployment.apps/webapp created
```

`$ kubectl expose deployment webapp --port=8080`

```
> service/webapp exposed
```

Una vez desplegada la aplicación mediante `Deployment` y `Service` se puede crear un Ingress usando la línea de comandos:

`$ kubectl create ingress webapp --rule='/=webapp:8080'`

Ahora la aplicación está disponible accediendo a la IP flotante:

`$ curl http://$FLOAT_IP/`

```
{"path":"/","host":"10.42.0.11:8080","from":"10.42.0.8","version":"v1.0"}
```

Una vez verificado el correcto funcionamiento de la aplicación, se puede eliminar del clúster:

`$ kubectl delete service,deployment,ingress --all`

```
service "kubernetes" deleted
service "webapp" deleted
deployment.apps "webapp" deleted
ingress.networking.k8s.io "webapp" deleted
```
