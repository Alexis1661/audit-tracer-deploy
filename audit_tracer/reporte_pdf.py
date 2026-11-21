"""
audit_tracer/reporte_pdf.py
===========================
Exportación del reporte de auditoría en PDF (resultado esperado 3 del
documento: «exportación de reportes en formato PDF»).

Mismo contenido que el CSV de HU-4.5 / HU-7.3: las filas salen de
generate_report() con los mismos filtros y las mismas columnas
(REPORT_CSV_COLUMNS), incluida referencia_normativa. Lo que agrega el PDF es
lo que un documento impreso necesita y un CSV no: título, fecha de
generación, quién lo generó, los filtros aplicados y el total de eventos.

reportlab se importa solo al generar el PDF: el resto de la librería
(captura en el entorno del científico de datos) no lo necesita.
"""

from __future__ import annotations

import io
import os
from typing import Callable, Dict, List, Optional
from xml.sax.saxutils import escape

from .models.audit_log import NO_RESULTS_MESSAGE, REPORT_CSV_COLUMNS

TITULO = "Reporte de auditoría — Audit Tracer"

# Encabezados legibles, en el mismo orden que REPORT_CSV_COLUMNS.
ENCABEZADOS = {
    "event_id": "ID",
    "usuario_id": "Usuario",
    "timestamp": "Fecha y hora",
    "tipo_accion": "Acción",
    "dataset_nombre": "Dataset",
    "columnas_afectadas": "Columnas afectadas",
    "nivel_alerta": "Nivel",
    "sesion_id": "Sesión",
    "contexto_ejecucion": "Origen (contexto de ejecución)",
    "hash_integridad": "Hash SHA-256",
    "referencia_normativa": "Referencia normativa",
}

ETIQUETAS_FILTRO = {
    "reporte_usuario_id": "Usuario",
    "reporte_tipo_accion": "Tipo de acción",
    "reporte_dataset_nombre": "Dataset",
    "reporte_fecha_inicio": "Desde",
    "reporte_fecha_fin": "Hasta",
}

# Fuentes TrueType con cobertura Unicode amplia (§, →, tildes). Si ninguna
# existe se usa Helvetica, que solo cubre Latin-1.
_FUENTES_CANDIDATAS = [
    ("DejaVuSans", "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
     "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"),
    ("Arial", r"C:\Windows\Fonts\arial.ttf", r"C:\Windows\Fonts\arialbd.ttf"),
    ("LiberationSans", "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
     "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf"),
]
_fuente_cache: Optional[tuple] = None


def _fuentes() -> tuple:
    """(normal, negrita, unicode) registradas en reportlab."""
    global _fuente_cache
    if _fuente_cache is not None:
        return _fuente_cache
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    for nombre, normal, negrita in _FUENTES_CANDIDATAS:
        if os.path.isfile(normal) and os.path.isfile(negrita):
            try:
                pdfmetrics.registerFont(TTFont(f"AT-{nombre}", normal))
                pdfmetrics.registerFont(TTFont(f"AT-{nombre}-Bold", negrita))
                _fuente_cache = (f"AT-{nombre}", f"AT-{nombre}-Bold", True)
                return _fuente_cache
            except Exception:
                continue
    _fuente_cache = ("Helvetica", "Helvetica-Bold", False)
    return _fuente_cache


def _texto(valor, unicode_ok: bool) -> str:
    """Texto seguro para un Paragraph de reportlab (escapa el marcado)."""
    if valor is None or valor == "":
        return "—" if unicode_ok else "-"
    texto = str(valor)
    if not unicode_ok:
        texto = texto.encode("latin-1", "replace").decode("latin-1")
    return escape(texto)


def construir_reporte_pdf(
    eventos: List[Dict],
    filtros: Dict[str, Optional[str]],
    generado_por: str,
    generado_en: str,
    formatear_timestamp: Optional[Callable] = None,
) -> bytes:
    """
    Devuelve el PDF del reporte.

    Args:
        eventos: filas de generate_report() (columnas REPORT_CSV_COLUMNS).
        filtros: los parámetros reporte_* de la petición (vacíos = sin filtro).
        generado_por: nombre y rol de quien descarga el reporte.
        generado_en: fecha y hora de generación ya formateada.
        formatear_timestamp: igual que en export_report_to_csv (hora Colombia).
    """
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import LongTable, Paragraph, SimpleDocTemplate, Spacer, TableStyle

    normal, negrita, unicode_ok = _fuentes()
    t = lambda v: _texto(v, unicode_ok)  # noqa: E731

    est_titulo = ParagraphStyle("titulo", fontName=negrita, fontSize=15, leading=19, spaceAfter=4)
    est_meta = ParagraphStyle("meta", fontName=normal, fontSize=9, leading=12)
    est_celda = ParagraphStyle("celda", fontName=normal, fontSize=5.4, leading=6.6)
    est_enc = ParagraphStyle("enc", fontName=negrita, fontSize=5.8, leading=7, textColor=colors.white)
    est_vacio = ParagraphStyle("vacio", fontName=normal, fontSize=10, leading=13, spaceBefore=8)

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=landscape(A4), leftMargin=10 * mm, rightMargin=10 * mm,
        topMargin=12 * mm, bottomMargin=14 * mm, title=TITULO, author="Audit Tracer",
        subject="Reporte de auditoría con mapeo normativo (HIPAA §164.312(b), Ley 1581 de 2012)",
    )

    aplicados = [(ETIQUETAS_FILTRO[k], v) for k, v in filtros.items() if k in ETIQUETAS_FILTRO and v]
    texto_filtros = "; ".join(f"{t(e)}: {t(v)}" for e, v in aplicados) if aplicados else "Sin filtros (todos los eventos)"

    historia = [
        Paragraph(t(TITULO), est_titulo),
        Paragraph(f"<b>Generado:</b> {t(generado_en)} &nbsp;&nbsp; <b>Por:</b> {t(generado_por)}", est_meta),
        Paragraph(f"<b>Filtros aplicados:</b> {texto_filtros}", est_meta),
        Paragraph(f"<b>Total de eventos:</b> {len(eventos)}", est_meta),
        Paragraph("Mismas filas y columnas que «Exportar Reporte (CSV)». La columna Referencia normativa "
                  "indica la cláusula de la HIPAA y el artículo de la Ley 1581 de 2012 que respalda cada evento.",
                  est_meta),
        Spacer(1, 4 * mm),
    ]

    if not eventos:
        historia.append(Paragraph(t(NO_RESULTS_MESSAGE), est_vacio))
    else:
        anchos = [9, 24, 22, 22, 22, 24, 13, 24, 30, 36, 51]  # mm; A4 horizontal (277 mm útiles)
        filas = [[Paragraph(t(ENCABEZADOS[c]), est_enc) for c in REPORT_CSV_COLUMNS]]
        for ev in eventos:
            valores = dict(ev)
            if formatear_timestamp and valores.get("timestamp"):
                valores["timestamp"] = formatear_timestamp(valores["timestamp"])
            filas.append([Paragraph(t(valores.get(c)), est_celda) for c in REPORT_CSV_COLUMNS])
        tabla = LongTable(filas, colWidths=[a * mm for a in anchos], repeatRows=1)
        tabla.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E3A5F")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#94A3B8")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F1F5F9")]),
            ("LEFTPADDING", (0, 0), (-1, -1), 2.5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 2.5),
        ]))
        historia.append(tabla)

    def pie(canvas, documento):
        canvas.saveState()
        canvas.setFont(normal, 7)
        canvas.drawString(10 * mm, 7 * mm, f"Audit Tracer · {generado_en}")
        canvas.drawRightString(documento.pagesize[0] - 10 * mm, 7 * mm, f"Página {documento.page}")
        canvas.restoreState()

    doc.build(historia, onFirstPage=pie, onLaterPages=pie)
    return buffer.getvalue()


__all__ = ["construir_reporte_pdf", "ENCABEZADOS", "TITULO"]
