-- code-wrap — parte las lineas largas de los listados en vez de dejar que se
-- salgan por la derecha.
--
-- reveal.js ignora `code-overflow: wrap`, asi que hace falta el CSS de
-- codigo-envuelto.html. Va en un filtro y no como `include-in-header` de la
-- extension para poder quitarlo: un include de la extension no se puede
-- desactivar desde el documento. Y las opciones de formato como
-- `code-overflow` no llegan a los filtros, de ahi la opcion propia:
--
--   wrap-code: true    (por defecto) se parten
--   wrap-code: false   no se parten; conviene volver a poner
--                      `code-line-numbers: true` si se quieren los numeros
function Meta(meta)
  if meta["wrap-code"] == false then return nil end
  quarto.doc.include_file("in-header", "codigo-envuelto.html")
  return nil
end
