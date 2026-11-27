"""Genera el diagrama de dependencias entre transparencias en Mermaid y Graphviz.

Cada nodo es un mazo (un .qmd) y cada enlace va del mazo que usa un concepto
al mazo que lo define, con el concepto y el numero de diapositiva del origen
donde aparece. Hay un enlace por referencia. Cada mazo tiene su color, y sus
enlaces salientes van en ese mismo color.

Los enlaces estan en enlaces.json, que sale de la revision de conceptos del
README (seccion "Informe: conceptos que se usan antes de definirse").

  python3 docs/dependencias/generar.py         # escribe dependencias.mmd y .dot
  dot -Tpng -Gdpi=90 docs/dependencias/dependencias.dot -o docs/dependencias/dependencias-graphviz.png
  mmdc -i docs/dependencias/dependencias.mmd -o docs/dependencias/dependencias-mermaid.png \
       -c docs/dependencias/mermaid-config.json -b white -w 4000
"""
import colorsys
import json
import re
from collections import Counter
from pathlib import Path

AQUI = Path(__file__).parent
# Agrupar los mazos por parte de la asignatura (subgrafos de Graphviz) y
# atributos de grafo extra para Graphviz (motor y espaciado). Se pueden
# cambiar desde la linea de ordenes para probar otras disposiciones.
# Por defecto, sin grupos y con sfdp: con 27 nodos y mas de 200 enlaces
# etiquetados, dot rompe los grupos y estira el dibujo, y sfdp lo deja
# compacto. `start` fija la semilla para que el dibujo sea reproducible.
GRUPOS = False
EXTRA_DOT = ' layout=sfdp, start=7, sep="+60", K=4, repulsiveforce=1.6,'


def colores(n):
    """n colores distinguibles: tonos repartidos por el circulo, alternando la
    luminosidad para que los vecinos no se confundan. Todos lo bastante
    oscuros para que una linea fina se vea sobre blanco y el texto blanco se
    lea sobre ellos."""
    out = []
    for i in range(n):
        h = (i * 0.618033988749895) % 1.0          # proporcion aurea: tonos bien separados
        l = (0.32, 0.40, 0.27)[i % 3]
        s = (0.75, 0.60, 0.85)[i % 3]
        r, g, b = colorsys.hls_to_rgb(h, l, s)
        out.append("#%02x%02x%02x" % (int(r * 255), int(g * 255), int(b * 255)))
    return out


def corto(concepto, n=34):
    c = re.sub(r"\s*\([^)]*\)", "", concepto).strip() or concepto
    return c if len(c) <= n else c[: n - 1].rstrip() + "…"


def main():
    datos = json.loads((AQUI / "enlaces.json").read_text(encoding="utf-8"))
    mazos, enlaces = datos["mazos"], datos["enlaces"]
    ids = {m["fichero"]: "m%d" % i for i, m in enumerate(mazos)}
    color = dict(zip((m["fichero"] for m in mazos), colores(len(mazos))))
    sal = Counter(e["origen"] for e in enlaces)
    ent = Counter(e["destino"] for e in enlaces)

    def titulo(m):
        return "Tema %s · %s" % (m["tema"], Path(m["fichero"]).name)

    def etiqueta(e):
        return "%s · diap. %s" % (corto(e["concepto"]), e["diapositiva"])

    # El orden de los enlaces: por mazo de origen, en el orden del curso, y
    # dentro de cada uno por numero de diapositiva.
    orden = {m["fichero"]: i for i, m in enumerate(mazos)}
    enlaces = sorted(enlaces, key=lambda e: (orden[e["origen"]], e["diapositiva"] or 0))

    # --- Mermaid -------------------------------------------------------------
    mmd = ["flowchart LR"]
    for m in mazos:
        f = m["fichero"]
        mmd.append('    %s["<b>%s</b><br/>salientes: %d · entrantes: %d"]'
                   % (ids[f], titulo(m), sal[f], ent[f]))
    for e in enlaces:
        txt = etiqueta(e).replace('"', "'")
        mmd.append('    %s -->|"%s"| %s' % (ids[e["origen"]], txt, ids[e["destino"]]))
    for m in mazos:
        f = m["fichero"]
        mmd.append("    style %s fill:%s,stroke:%s,color:#ffffff" % (ids[f], color[f], color[f]))
    for i, e in enumerate(enlaces):
        c = color[e["origen"]]
        mmd.append("    linkStyle %d stroke:%s,color:%s" % (i, c, c))
    (AQUI / "dependencias.mmd").write_text("\n".join(mmd) + "\n", encoding="utf-8")

    # --- Graphviz ------------------------------------------------------------
    # Un grupo por parte de la asignatura, para que el dibujo siga el temario.
    dot = ['digraph dependencias {',
           '  graph [rankdir=LR, newrank=true, fontname="Helvetica", fontsize=22, nodesep=0.5, ranksep=2.2,'
           ' splines=true, overlap=false, labelloc=t,' + EXTRA_DOT +
           ' label="Dependencias entre transparencias: concepto usado en el origen y definido en el destino"];',
           '  node [shape=box, style="rounded,filled", fontname="Helvetica", fontsize=14,'
           ' fontcolor=white, penwidth=0, margin="0.25,0.12"];',
           '  edge [fontname="Helvetica", fontsize=10, arrowsize=0.7, penwidth=1.1];']
    partes = {}
    for m in mazos:
        partes.setdefault(m["tema"].split(".")[0], []).append(m)
    nombres = {"1": "Tema 1 · Patrones arquitectónicos", "2": "Tema 2 · Aplicaciones y servicios web",
               "3": "Tema 3 · Comunicación", "4": "Tema 4 · Despliegue",
               "5": "Tema 5 · Escalabilidad y tolerancia a fallos"}
    for p, ms in sorted(partes.items()):
        if GRUPOS:
            dot.append('  subgraph cluster_%s {' % p)
            dot.append('    label="%s"; fontsize=16; style="rounded,dashed"; color="#999999";' % nombres[p])
        for m in ms:
            f = m["fichero"]
            dot.append('    %s [label=<<b>%s</b><br/>salientes: %d · entrantes: %d>, fillcolor="%s"];'
                       % (ids[f], titulo(m), sal[f], ent[f], color[f]))
        if GRUPOS:
            dot.append('  }')
    for e in enlaces:
        c = color[e["origen"]]
        txt = etiqueta(e).replace('"', '\\"')
        dot.append('  %s -> %s [label="%s", color="%s", fontcolor="%s"];'
                   % (ids[e["origen"]], ids[e["destino"]], txt, c, c))
    dot.append("}")
    (AQUI / "dependencias.dot").write_text("\n".join(dot) + "\n", encoding="utf-8")

    print("%d mazos, %d enlaces" % (len(mazos), len(enlaces)))


if __name__ == "__main__":
    import sys
    args = sys.argv[1:]
    if "--grupos" in args:
        GRUPOS = True
    for a in args:
        if a.startswith("--dot="):
            EXTRA_DOT = " " + a[len("--dot="):] + ","
    main()
