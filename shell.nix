# Entorno para compilar y ejecutar los ejemplos de la asignatura y generar
# las transparencias.
#
#   nix-shell                 # entra en el entorno
#   quarto render             # genera todas las transparencias
#   cd parte_2/tema_2.2_web/web_ejem1 && mvn spring-boot:run
#
# nixpkgs va fijado a una revision concreta (nixos-26.05) para que todos
# tengan las mismas versiones: los proyectos piden Java 25 y Spring Boot 4,
# y los canales anteriores a la 25.11 no traen JDK 25.
#
# Lo que nix no puede dar: el demonio de Docker. Aqui solo van los clientes
# (docker, docker compose, buildx, kind, minikube); el demonio tiene que estar
# instalado y en marcha en el sistema.
{ pkgs ? import (fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/0dc498bfe49baeb18b0f9891e800b53bb2603193.tar.gz";
    sha256 = "09m91kcd36jg2lvvrfy0qwk7frsjn84hfn497bax4rmcrfmj7zdk";
  }) {}
}:

let
  jdk = pkgs.jdk25;

  # El paquete `quarto` de nixpkgs (1.9) arranca con el pandoc de nixpkgs
  # (3.7), y Quarto 1.9 necesita el 3.8.3: sin el, cualquier render falla con
  # `Unknown option "syntax-highlighting"`. Se le da el binario estatico
  # oficial de pandoc 3.8.3 en lugar del de nixpkgs.
  pandocParaQuarto =
    let
      arch = {
        x86_64-linux = { nombre = "amd64"; sha256 = "1d692jwznfwdgv14m8a9r1lwfqy1g087rjqf70ikczc2kywgl962"; };
        aarch64-linux = { nombre = "arm64"; sha256 = "1myq33cx3sxmqqwv0kld3sn5bxzfkc8ahhpjqka0pcby70vmlshn"; };
      }.${pkgs.stdenv.hostPlatform.system};
    in
    pkgs.stdenvNoCC.mkDerivation rec {
      pname = "pandoc-bin";
      version = "3.8.3";
      src = pkgs.fetchurl {
        url = "https://github.com/jgm/pandoc/releases/download/${version}/pandoc-${version}-linux-${arch.nombre}.tar.gz";
        inherit (arch) sha256;
      };
      installPhase = "mkdir -p $out/bin && cp bin/pandoc $out/bin/";
      meta.mainProgram = "pandoc";
    };

  quarto = pkgs.quarto.override { pandoc = pandocParaQuarto; };
in
pkgs.mkShell {
  packages = with pkgs; [
    # Proyectos Spring Boot (131 pom.xml, todos con java.version 25)
    jdk
    (maven.override { jdk_headless = jdk; })

    # Transparencias: quarto (con su pandoc), y mermaid-cli y graphviz para
    # regenerar los diagramas .mmd del tema de Kubernetes y el diagrama de
    # dependencias entre transparencias (docs/dependencias)
    quarto             # el de arriba, con pandoc 3.8.3
    mermaid-cli
    graphviz

    # Contenedores y despliegue (temas 4 y 5)
    docker-client
    docker-compose
    docker-buildx
    kubectl
    kustomize
    kubernetes-helm
    kind
    minikube

    # Pruebas de carga (temas 2.8 y 5): jmeter y k6 vienen de nixpkgs;
    # Artillery no esta empaquetado, se usa con `npx artillery` gracias a node
    jmeter
    k6
    nodejs

    # Clientes y utilidades que usan los README y los scripts
    mariadb.client     # cliente `mysql` para los ejemplos con MySQL
    redis              # `redis-cli` para los ejemplos de cache
    grpcurl            # ejemplos gRPC del tema 3
    websocat           # ejemplos de WebSocket
    curl
    httpie
    jq
    openssl            # certificados autofirmados de HAProxy y balanceo
  ];

  JAVA_HOME = jdk.home;

  shellHook = ''
    echo "DAD: $(java -version 2>&1 | head -1), Maven $(mvn -v 2>/dev/null | head -1 | cut -d' ' -f3), Quarto $(quarto --version)"
  '';
}
