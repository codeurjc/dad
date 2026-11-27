-- license — diapositiva de licencia justo despues de la portada.
--
-- Sale de los campos estandar de Quarto `license` y `copyright`, que Quarto
-- normaliza antes de que corran los filtros:
--
--   license: "CC BY-SA"   ->  { type = "creative-commons",
--                               text = "CC BY-SA 4.0",
--                               url  = "https://creativecommons.org/licenses/by-sa/4.0/" }
--   license: { text = "...", url = "..." }
--   copyright: "2025 Ana y Luis"  ->  { statement = "2025 Ana y Luis" }
--   copyright: { holder = "Ana", year = 2025 }
--
-- Sin `copyright`, el titular son los autores y el ano sale de `date`.
-- Sin `license` avisa y no pone nada; con `license-slide: false` no la pone.
-- (`license: false` no vale: Quarto valida la cabecera y exige un objeto.)
-- Si el mazo ya trae su propia diapositiva `.nota-licencia`, no la duplica.

local str = pandoc.utils.stringify

local function warn(message)
  if quarto and quarto.log and quarto.log.warning then
    quarto.log.warning(message)
  else
    io.stderr:write("[WARNING] license: ", message, "\n")
  end
end

-- Nombres oficiales en espanol de las licencias de Creative Commons.
local CC_NAMES = {
  ["by"]       = "Atribución",
  ["by-sa"]    = "Atribución-CompartirIgual",
  ["by-nd"]    = "Atribución-SinDerivadas",
  ["by-nc"]    = "Atribución-NoComercial",
  ["by-nc-sa"] = "Atribución-NoComercial-CompartirIgual",
  ["by-nc-nd"] = "Atribución-NoComercial-SinDerivadas",
}

-- Quarto admite una lista de licencias; aqui se toma cada una por separado.
local function licenses(meta)
  local value = meta.license
  if value == nil then return nil end
  if pandoc.utils.type(value) == "List" then return value end
  return { value }
end

local function field(license, name)
  if type(license) == "table" and license[name] ~= nil then
    local text = str(license[name])
    if text ~= "" then return text end
  end
  return nil
end

-- Lo que dice la diapositiva de una licencia: su nombre y su enlace.
-- Enlace a la version en espanol del resumen de la licencia. Quarto ya lo
-- localiza segun `lang` (`.../4.0/deed.es`), pero no siempre: se normaliza.
local function deed_es(url)
  local base = url:gsub("deed%.[%w%-_]+$", "")
  if not base:match("/$") then base = base .. "/" end
  return base .. "deed.es"
end

-- Quarto pone la URL a los codigos que reconoce ("CC BY-SA"), pero no a todos
-- ("CC0"). Para esos se saca del propio codigo.
local function url_from_code(text)
  local code = text:upper():gsub("%s+", " ")
  if code:match("^CC0") or code:match("^CC ZERO") then
    return "https://creativecommons.org/publicdomain/zero/1.0/"
  end
  local kind, version = code:match("^CC (BY[%-A-Z]*)%s*([%d%.]*)")
  if kind and CC_NAMES[kind:lower()] then
    return "https://creativecommons.org/licenses/" .. kind:lower() .. "/"
      .. (version ~= "" and version or "4.0") .. "/"
  end
  return nil
end

local function describe(license)
  local text = field(license, "text") or str(license)
  local url = field(license, "url") or url_from_code(text)
  local kind, version = nil, nil
  if url then
    kind, version = url:match("creativecommons%.org/licenses/([%a%-]+)/([%d%.]+)")
  end
  if kind and CC_NAMES[kind] then
    local suffix = version == "4.0" and " Internacional" or ""
    return {
      creative_commons = true,
      name = CC_NAMES[kind] .. " " .. version .. suffix,
      url = deed_es(url),
    }
  end
  if url and url:match("creativecommons%.org/publicdomain/zero/") then
    return { public_domain = true, name = "CC0 1.0 Universal", url = deed_es(url) }
  end
  return { name = text, url = url }
end

local function join_names(names)
  if #names <= 1 then return names[1] or "" end
  return table.concat(names, ", ", 1, #names - 1) .. " y " .. names[#names]
end

local function authors(meta)
  local names = {}
  local value = meta.author
  if value == nil then return names end
  if pandoc.utils.type(value) ~= "List" then value = { value } end
  for _, author in ipairs(value) do
    -- Un autor puede ser texto o un mapa con `name` (y `name` puede ser a su
    -- vez un mapa con `literal`, `given`, `family`...).
    local name = author
    if type(author) == "table" and author.name ~= nil then
      name = author.name
      if type(name) == "table" and name.literal ~= nil then name = name.literal end
    end
    local text = str(name)
    if text ~= "" then names[#names + 1] = text end
  end
  return names
end

local function year(meta)
  local date = meta.date and str(meta.date) or ""
  if date ~= "today" and date ~= "now" and date ~= "last-modified" then
    local found = date:match("(%d%d%d%d)")
    if found then return found end
  end
  return os.date("%Y")
end

local function copyright(meta)
  local value = meta.copyright
  local statement = field(value, "statement")
  if statement == nil and value ~= nil and type(value) ~= "table" then
    statement = str(value)
  end
  if statement then
    -- No repetir el simbolo si ya lo trae.
    if statement:match("^©") or statement:lower():match("^copyright") then return statement end
    return "© " .. statement
  end
  local holder = field(value, "holder") or join_names(authors(meta))
  local when = field(value, "year") or year(meta)
  return "© " .. when .. (holder ~= "" and (" " .. holder) or "")
end

-- Nivel de las diapositivas, como lo calcula pandoc: el nivel de cabecera mas
-- alto que va seguido de contenido (y no de otra cabecera).
local function slide_level(blocks)
  local level = nil
  for i, block in ipairs(blocks) do
    if block.t == "Header" then
      local next_block = blocks[i + 1]
      if next_block and next_block.t ~= "Header" and (level == nil or block.level < level) then
        level = block.level
      end
    end
  end
  return level or 2
end

local function has_license_slide(blocks)
  for _, block in ipairs(blocks) do
    if block.t == "Header" and block.classes:includes("nota-licencia") then return true end
  end
  return false
end

local function link(url)
  return pandoc.Link(pandoc.Str(url), url)
end

local function paragraphs(meta, list)
  local described = {}
  local public_domain = false
  for _, license in ipairs(list) do
    local d = describe(license)
    described[#described + 1] = d
    public_domain = public_domain or d.public_domain
  end
  -- Con CC0 se renuncia a los derechos: no hay copyright que poner.
  local out = {}
  if not public_domain then
    out[1] = pandoc.Para({ pandoc.Str(copyright(meta)) })
  end
  for _, d in ipairs(described) do
    if d.creative_commons then
      out[#out + 1] = pandoc.Para(pandoc.Inlines("Algunos derechos reservados. Este documento se distribuye bajo la licencia "
        .. "«" .. d.name .. "» de Creative Commons."))
    elseif d.public_domain then
      out[#out + 1] = pandoc.Para(pandoc.Inlines("Este documento se dedica al dominio público con «" .. d.name
        .. "» de Creative Commons."))
    else
      out[#out + 1] = pandoc.Para(pandoc.Inlines("Este documento se distribuye bajo la licencia «" .. d.name .. "»."))
    end
    if d.url then
      local inlines = pandoc.Inlines("Disponible en ")
      inlines:insert(link(d.url))
      out[#out + 1] = pandoc.Para(inlines)
    end
  end
  return out
end

function Pandoc(doc)
  local enabled = doc.meta["license-slide"]
  if enabled ~= nil and not enabled then return nil end
  if has_license_slide(doc.blocks) then return nil end
  local list = licenses(doc.meta)
  if list == nil then
    warn("no hay `license` en la cabecera: la presentacion sale sin diapositiva de licencia. "
      .. "Ponla (por ejemplo `license: \"CC BY-SA\"`) o quitala con `license-slide: false`.")
    return nil
  end

  local header = pandoc.Header(slide_level(doc.blocks), "Licencia",
    pandoc.Attr("licencia", { "nota-licencia", "unlisted" }, { visibility = "uncounted" }))
  local slide = pandoc.List({ header })
  slide:extend(paragraphs(doc.meta, list))
  slide:extend(doc.blocks)
  doc.blocks = slide
  return doc
end
