"""
Convierte los entregables Markdown de esta carpeta a PDF con portada.

    python entregables/fuentes/md_a_pdf.py [archivo.md ...]

Markdown → HTML con python-markdown (tablas, bloques de código, índice) y
HTML → PDF con Chrome/Chromium en modo headless (--print-to-pdf). pandoc no
está disponible en el equipo donde se generaron; el resultado es equivalente.

Cada .md empieza con un bloque de metadatos:

    ---
    titulo: Análisis de eventos de auditoría y necesidades de trazabilidad
    anexo: Anexo 10
    fecha: 2026-11-21
    ---
"""
import html
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import markdown

CARPETA = Path(__file__).resolve().parents[1]
PROYECTO = ("Diseño de un sistema de auditoría de trazabilidad para entornos de ciencia de datos en salud "
            "(PDGTRAZDSA)")
AUTORES = ["Valentina Gómez Rivera", "Hector Alexis Delgado Abril", "Juan Pablo Ordoñez"]
CHROME_CANDIDATOS = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    "google-chrome", "chromium", "chromium-browser",
]

CSS = """
@page { size: A4; margin: 18mm 16mm 18mm 16mm; }
body { font-family: "Segoe UI", Arial, sans-serif; font-size: 10.2pt; line-height: 1.45; color: #0f172a; }
h1 { font-size: 18pt; color: #1e3a5f; border-bottom: 2px solid #1e3a5f; padding-bottom: 4px; margin-top: 26px; page-break-after: avoid; }
h2 { font-size: 14pt; color: #1e3a5f; margin-top: 22px; page-break-after: avoid; }
h3 { font-size: 11.5pt; color: #334155; margin-top: 16px; page-break-after: avoid; }
table { border-collapse: collapse; width: 100%; margin: 8px 0 12px; font-size: 8.4pt; page-break-inside: auto; }
tr { page-break-inside: avoid; }
th { background: #1e3a5f; color: #fff; text-align: left; padding: 4px 5px; vertical-align: top; }
td { border: 1px solid #cbd5e1; padding: 3px 5px; vertical-align: top; word-break: break-word; }
tr:nth-child(even) td { background: #f8fafc; }
code { font-family: Consolas, "Courier New", monospace; font-size: 8.6pt; background: #f1f5f9; padding: 0 2px; border-radius: 2px; }
pre { background: #0f172a; color: #e2e8f0; padding: 8px 10px; border-radius: 4px; font-size: 7.8pt; line-height: 1.35; white-space: pre-wrap; word-break: break-word; page-break-inside: auto; }
pre code { background: none; color: inherit; padding: 0; font-size: inherit; }
th code { background: transparent; color: #ffffff; }
td:first-child { min-width: 20mm; }
thead:has(th:empty) { display: none; }
blockquote { border-left: 4px solid #f59e0b; background: #fffbeb; margin: 10px 0; padding: 6px 12px; }
img { max-width: 100%; }
.toc { background: #f8fafc; border: 1px solid #e2e8f0; padding: 6px 14px; font-size: 9pt; }
.toc ul { margin: 2px 0; padding-left: 18px; }
.portada { height: 255mm; display: flex; flex-direction: column; justify-content: space-between; page-break-after: always; }
.portada .univ { font-size: 13pt; letter-spacing: 0.08em; color: #1e3a5f; font-weight: 600; text-transform: uppercase; }
.portada .anexo { font-size: 12pt; color: #64748b; margin-top: 70mm; }
.portada h1.titulo { font-size: 24pt; border: none; color: #0f172a; margin: 6px 0 14px; line-height: 1.2; }
.portada .proyecto { font-size: 11.5pt; color: #334155; }
.portada .pie { font-size: 10.5pt; color: #334155; border-top: 2px solid #1e3a5f; padding-top: 8px; }
.pendiente { background: #fef3c7; }
"""


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


def html_de(md_path: Path) -> str:
    meta, cuerpo = _meta(md_path.read_text(encoding="utf-8"))
    conv = markdown.Markdown(extensions=["tables", "fenced_code", "toc", "sane_lists", "attr_list"],
                             extension_configs={"toc": {"toc_depth": "1-2", "title": "Contenido"}})
    contenido = conv.convert(cuerpo)
    # En celdas de tabla el pipe se escribe \| ; dentro de `código` markdown deja la barra visible.
    contenido = contenido.replace(r"\|", "|")
    contenido = contenido.replace("[PENDIENTE:", '<span class="pendiente">[PENDIENTE:').replace(
        "]</span>", "]</span>")
    contenido = re.sub(r'(<span class="pendiente">\[PENDIENTE:[^\]]*\])', r"\1</span>", contenido)
    autores = "<br>".join(html.escape(a) for a in AUTORES)
    portada = f"""
<section class="portada">
  <div class="univ">Universidad Icesi · Facultad de Ingeniería, Diseño y Ciencias Aplicadas</div>
  <div>
    <div class="anexo">{html.escape(meta.get('anexo', ''))}</div>
    <h1 class="titulo">{html.escape(meta['titulo'])}</h1>
    <div class="proyecto"><b>Proyecto:</b> {html.escape(PROYECTO)}<br>Sistema Audit Tracer (librería <code>audit_tracer</code> y servidor central con dashboard)</div>
  </div>
  <div class="pie"><b>Autores</b><br>{autores}<br><br><b>Fecha:</b> {html.escape(meta['fecha'])} · Cali, Colombia</div>
</section>"""
    return f"""<!doctype html><html lang="es"><head><meta charset="utf-8">
<title>{html.escape(meta['titulo'])}</title><style>{CSS}</style></head>
<body>{portada}{contenido}</body></html>"""


def a_pdf(md_path: Path) -> Path:
    pdf = md_path.with_suffix(".pdf")
    tmp = Path(tempfile.mkdtemp(prefix="md_a_pdf_"))
    html_path = md_path.with_suffix(".tmp.html")  # junto al .md para que resuelva img/ relativas
    html_path.write_text(html_de(md_path), encoding="utf-8")
    try:
        subprocess.run([_chrome(), "--headless=new", "--disable-gpu", "--no-pdf-header-footer",
                        f"--user-data-dir={tmp / 'perfil'}", f"--print-to-pdf={pdf}", html_path.as_uri()],
                       check=True, capture_output=True, timeout=180)
    finally:
        html_path.unlink(missing_ok=True)
        shutil.rmtree(tmp, ignore_errors=True)
    return pdf


def main():
    archivos = [Path(a) for a in sys.argv[1:]] or sorted(CARPETA.glob("0*.md"))
    for md in archivos:
        pdf = a_pdf(md.resolve())
        print(f"{md.name} -> {pdf.name} ({pdf.stat().st_size:,} bytes)")


if __name__ == "__main__":
    main()
