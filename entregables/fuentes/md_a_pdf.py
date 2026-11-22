"""
Convierte los entregables Markdown de esta carpeta a PDF con el formato del
documento final del proyecto de grado.

    python entregables/fuentes/md_a_pdf.py [archivo.md ...]

Formato (igual al documento final, 22/11/2026):
  * Portada: marco de 6 pt color #5454E9, logo de la Universidad Icesi y texto
    en Times New Roman 12 pt, negrita, centrado y a doble espacio.
  * Tamaño carta, márgenes de 1 pulgada, Times New Roman 12 pt a doble espacio,
    párrafos justificados con sangría de primera línea de 0,5 pulgadas.
  * Títulos de nivel 1 en mayúsculas, negrita y centrados; de nivel 2 en
    negrita a la izquierda; de nivel 3 en negrita cursiva.
  * «Tabla de contenido» en versalitas, con líneas de puntos y número de página.
  * Tablas con encabezado azul oscuro y filas alternas en azul claro.
  * Número de página centrado al pie desde la segunda página.

Markdown → HTML con python-markdown y HTML → PDF con Chrome/Chromium en modo
headless. La tabla de contenido se arma en dos pasadas: la primera ubica la
página de cada título y la segunda la imprime con esos números.

Cada .md empieza con un bloque de metadatos:

    ---
    titulo: Análisis de eventos de auditoría y necesidades de trazabilidad
    anexo: Anexo 10
    fecha: 2026-11-21
    ---
"""
import base64
import html
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import markdown

CARPETA = Path(__file__).resolve().parents[1]
PROYECTO = "Diseño de un sistema de auditoría de trazabilidad para entornos de ciencia de datos en salud"
AUTORES = ["Valentina Gómez Rivera", "Alexis Delgado Abril", "Juan Pablo Ordoñez"]
TUTORA = "Ingrid Lucia Muñoz"
LOGO = CARPETA / "img" / "logo_icesi.png"
MARCA_INICIO = "INICIODELCONTENIDOAUDITTRACER"
CHROME_CANDIDATOS = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    "google-chrome", "chromium", "chromium-browser",
]

CSS = """
@page { size: Letter; margin: 1in; }
@page portada { margin: 0; }
body { font-family: "Times New Roman", Times, serif; font-size: 12pt; line-height: 2; color: #000; margin: 0; }
p { text-align: justify; text-indent: 0.5in; margin: 0; }
li > p, td p, th p, blockquote p { text-indent: 0; }
ul, ol { margin: 0 0 0 0.5in; padding-left: 0.25in; }
li { text-align: justify; }
h1 { font-size: 12pt; font-weight: bold; text-align: center; text-transform: uppercase; margin: 18pt 0 0;
     line-height: 2; page-break-after: avoid; }
h2 { font-size: 12pt; font-weight: bold; text-align: left; margin: 12pt 0 0; line-height: 2; page-break-after: avoid; }
h3, h4 { font-size: 12pt; font-weight: bold; font-style: italic; text-align: left; margin: 10pt 0 0; line-height: 2;
         page-break-after: avoid; }
strong { font-weight: bold; }
table { border-collapse: collapse; width: 100%; margin: 10pt 0 14pt; font-size: 9.5pt; line-height: 1.25;
        page-break-inside: auto; }
tr { page-break-inside: avoid; }
th { background: #1F3864; color: #fff; font-weight: bold; text-align: left; padding: 5px 6px; vertical-align: middle;
     border: 1px solid #1F3864; }
td { border: 1px solid #9DC3E6; padding: 4px 6px; vertical-align: top; word-break: normal; overflow-wrap: break-word; hyphens: manual; }
tbody tr:nth-child(odd) td { background: #DEEAF6; }
tbody tr:nth-child(even) td { background: #FFFFFF; }
td:first-child { min-width: 18mm; }
thead:has(th:empty) { display: none; }
code { font-family: Consolas, "Courier New", monospace; font-size: 9pt; background: #F2F2F2; padding: 0 2px; }
pre { background: #F2F2F2; color: #000; border: 1px solid #D9D9D9; padding: 8px 10px; font-size: 8.5pt;
      line-height: 1.3; white-space: pre-wrap; word-break: break-word; page-break-inside: auto; margin: 8pt 0 12pt; }
pre code { background: none; padding: 0; font-size: inherit; }
th code { background: transparent; color: #fff; }
td code { word-break: break-all; }
blockquote { border-left: 3px solid #1F3864; margin: 8pt 0; padding: 2pt 12pt; }
img { max-width: 100%; display: block; margin: 8pt auto; }
.pendiente { background: #FFF2CC; }
.marca { color: #fff; font-size: 1pt; line-height: 1pt; text-indent: 0; }
.tabla-contenido { page-break-after: always; }
.tabla-contenido .titulo { text-align: center; font-weight: bold; font-variant: small-caps; text-indent: 0;
                           margin: 0 0 6pt; }
.toc-linea { display: flex; align-items: baseline; line-height: 2; }
.toc-linea .t { flex: 0 1 auto; }
.toc-linea.n2 .t { padding-left: 0.3in; }
.toc-linea .puntos { flex: 1 1 auto; border-bottom: 1.2px dotted #000; margin: 0 3pt; min-width: 12pt;
                     position: relative; top: -4pt; }
.toc-linea .pag { flex: 0 0 auto; }
"""

CSS_PORTADA = """
.portada { page: portada; position: relative; width: 8.5in; height: 10.98in; overflow: hidden;
           break-after: page; page-break-after: always; margin: 0; }
.portada .marco { position: absolute; left: 45.375pt; top: 57.75pt; width: 521.25pt; height: 677.25pt;
                  box-sizing: border-box; border: 6pt solid #5454E9; background: #fff; }
.portada .caja { position: absolute; left: 72pt; right: 72pt; top: 72pt; bottom: 72pt;
                 display: flex; flex-direction: column; align-items: center; text-align: center;
                 font-family: "Times New Roman", Times, serif; font-size: 12pt; font-weight: bold;
                 line-height: 2; color: #000; }
.portada .caja img { width: 199.7pt; height: 74.1pt; margin: 0; }
.portada .caja p { margin: 0; text-indent: 0; text-align: center; }
.portada .esp { flex: 1; }
.portada .esp2 { flex: 0.6; }
"""


def _logo_uri() -> str:
    return "data:image/png;base64," + base64.b64encode(LOGO.read_bytes()).decode()


def portada_html(anexo: str, titulo: str, anio: str = "2026") -> str:
    """Bloque HTML de la portada. `anexo` es solo la etiqueta (p. ej. «Anexo 10»)."""
    e = html.escape
    autores = "".join(f"<p>{e(a)}</p>" for a in AUTORES)
    return f"""
<section class="portada">
  <div class="marco"></div>
  <div class="caja">
    <img src="{_logo_uri()}" alt="Universidad Icesi">
    <div class="esp"></div>
    <p>{e(PROYECTO)}</p>
    <div class="esp2"></div>
    <p>Proyecto de Grado</p>
    <p>{e(anexo)} — {e(titulo)}</p>
    <div class="esp"></div>
    {autores}
    <div class="esp2"></div>
    <p>Tutora</p>
    <p>{e(TUTORA)}</p>
    <div class="esp"></div>
    <p>Facultad Barberi de Ingeniería, Diseño y Ciencias Aplicadas</p>
    <p>Ingeniería de Sistemas</p>
    <p>Santiago de Cali</p>
    <p>{e(anio)}</p>
  </div>
</section>"""


def etiqueta_anexo(meta_anexo: str) -> str:
    """«Anexo 10 · Documento técnico» -> «Anexo 10»."""
    return meta_anexo.split("·")[0].strip()


def _meta(texto: str):
    m = re.match(r"^---\n(.*?)\n---\n", texto, re.S)
    if not m:
        raise ValueError("Falta el bloque de metadatos ---")
    meta = dict(linea.split(":", 1) for linea in m.group(1).splitlines() if ":" in linea)
    return {k.strip(): v.strip() for k, v in meta.items()}, texto[m.end():]


def _chrome() -> str:
    for c in CHROME_CANDIDATOS:
        if os.path.isfile(c) or shutil.which(c):
            return c if os.path.isfile(c) else shutil.which(c)
    sys.exit("No se encontró Chrome/Chromium para imprimir el PDF")


def _titulos(tokens, nivel=1):
    for t in tokens:
        if nivel <= 2:
            yield nivel, html.unescape(re.sub(r"<[^>]+>", "", t["name"]))
        yield from _titulos(t.get("children", []), nivel + 1)


def _tabla_contenido(titulos, paginas) -> str:
    lineas = []
    for (nivel, texto), pag in zip(titulos, paginas):
        lineas.append(f'<div class="toc-linea n{nivel}"><span class="t">{html.escape(texto)}</span>'
                      f'<span class="puntos"></span><span class="pag">{pag}</span></div>')
    return ('<section class="tabla-contenido"><p class="titulo">Tabla de contenido</p>'
            + "".join(lineas) + "</section>")


def _html(meta, contenido, toc) -> str:
    portada = portada_html(etiqueta_anexo(meta.get("anexo", "")), meta["titulo"], meta["fecha"][:4])
    return f"""<!doctype html><html lang="es"><head><meta charset="utf-8">
<title>{html.escape(meta['titulo'])}</title><style>{CSS}{CSS_PORTADA}</style></head>
<body>{portada}{toc}<p class="marca">{MARCA_INICIO}</p>{contenido}</body></html>"""


def _convertir(md_path: Path):
    meta, cuerpo = _meta(md_path.read_text(encoding="utf-8"))
    cuerpo = cuerpo.replace("[TOC]\n", "")
    conv = markdown.Markdown(extensions=["tables", "fenced_code", "toc", "sane_lists", "attr_list"],
                             extension_configs={"toc": {"toc_depth": "1-2"}})
    contenido = conv.convert(cuerpo)
    # En celdas de tabla el pipe se escribe \| ; dentro de `código` markdown deja la barra visible.
    contenido = contenido.replace(r"\|", "|")
    contenido = re.sub(r"(\[PENDIENTE:[^\]]*\])", r'<span class="pendiente">\1</span>', contenido)
    return meta, contenido, list(_titulos(conv.toc_tokens))


def _imprimir(documento: str, pdf: Path, junto_a: Path) -> Path:
    """Imprime `documento` (HTML) a `pdf` con Chrome headless. El HTML temporal se
    escribe en la carpeta `junto_a` para que resuelvan las rutas relativas (img/)."""
    tmp = Path(tempfile.mkdtemp(prefix="md_a_pdf_"))
    html_path = junto_a / f"{pdf.stem}.tmp.html"
    html_path.write_text(documento, encoding="utf-8")
    try:
        subprocess.run([_chrome(), "--headless=new", "--disable-gpu", "--no-pdf-header-footer",
                        f"--user-data-dir={tmp / 'perfil'}", f"--print-to-pdf={pdf}", html_path.as_uri()],
                       check=True, capture_output=True, timeout=240)
    finally:
        html_path.unlink(missing_ok=True)
        shutil.rmtree(tmp, ignore_errors=True)
    return pdf


def _compacto(texto: str) -> str:
    return re.sub(r"\s+", "", texto).upper()


def _paginas_de_titulos(pdf: Path, titulos) -> list:
    import pdfplumber
    with pdfplumber.open(str(pdf)) as doc:
        paginas = [_compacto(p.extract_text() or "") for p in doc.pages]
    inicio = next((i for i, t in enumerate(paginas) if MARCA_INICIO in t), 1)
    resultado, actual = [], inicio
    for _, texto in titulos:
        buscado = _compacto(texto)
        for i in range(actual, len(paginas)):
            if buscado in paginas[i] or (i + 1 < len(paginas) and buscado in paginas[i] + paginas[i + 1]):
                actual = i
                break
        resultado.append(actual + 1)
    return resultado


def _numerar(pdf: Path) -> None:
    """Número de página centrado al pie desde la segunda página, como en el documento final."""
    from pypdf import PdfReader, PdfWriter
    from reportlab.pdfgen import canvas
    lector = PdfReader(str(pdf))
    escritor = PdfWriter()
    for i, pagina in enumerate(lector.pages):
        if i > 0:
            ancho, alto = float(pagina.mediabox.width), float(pagina.mediabox.height)
            buffer = io.BytesIO()
            c = canvas.Canvas(buffer, pagesize=(ancho, alto))
            c.setFont("Times-Roman", 12)
            c.drawCentredString(ancho / 2, 36, str(i + 1))
            c.save()
            buffer.seek(0)
            pagina.merge_page(PdfReader(buffer).pages[0])
        escritor.add_page(pagina)
    escritor.add_metadata({"/Title": lector.metadata.get("/Title", "") if lector.metadata else ""})
    datos = io.BytesIO()
    escritor.write(datos)
    pdf.write_bytes(datos.getvalue())


def a_pdf(md_path: Path) -> Path:
    meta, contenido, titulos = _convertir(md_path)
    pdf = md_path.with_suffix(".pdf")
    # 1.ª pasada: números provisionales del mismo ancho para ubicar cada título.
    _imprimir(_html(meta, contenido, _tabla_contenido(titulos, ["000"] * len(titulos))), pdf, md_path.parent)
    paginas = _paginas_de_titulos(pdf, titulos)
    _imprimir(_html(meta, contenido, _tabla_contenido(titulos, paginas)), pdf, md_path.parent)
    _numerar(pdf)
    return pdf


def portada_pdf(anexo: str, titulo: str, pdf: Path, anio: str = "2026") -> Path:
    """PDF de una sola página con la portada (para anexos que no salen de un .md)."""
    documento = f"""<!doctype html><html lang="es"><head><meta charset="utf-8">
<title>{html.escape(titulo)}</title><style>{CSS}{CSS_PORTADA}</style></head>
<body>{portada_html(anexo, titulo, anio)}</body></html>"""
    return _imprimir(documento, pdf, pdf.parent)


def main():
    archivos = [Path(a) for a in sys.argv[1:]] or sorted(CARPETA.glob("[01]*.md"))
    for md in archivos:
        pdf = a_pdf(md.resolve())
        print(f"{md.name} -> {pdf.name} ({pdf.stat().st_size:,} bytes)")


if __name__ == "__main__":
    main()
