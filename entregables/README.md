# Entregables del documento final — Audit Tracer (PDGTRAZDSA)

Generados el 21/11/2026 en la rama `entregables-documento-final`. Cada documento está en Markdown (fuente) y en PDF (con portada).

| Archivo | Anexo | Origen |
|---|---|---|
| `01_analisis_eventos_auditoria` | Anexo 10 | Nuevo, escrito a partir del código |
| `02_modelo_datos_auditoria` | Anexo 11 | Nuevo; DDL, columnas y diagramas generados por `fuentes/extraer_esquema.py` y `fuentes/generar_modelo_datos.py` |
| `03_informe_validacion` | Anexo 13 | Nuevo; resultados de `validacion/` (MIMIC-III), de la suite y del benchmark del 21/11/2026 |
| `04_guia_buenas_practicas` | Anexo 14 | Basado en `docs/lineamientos_buenas_practicas_seguridad.md`, corregido (ver su sección 0) |
| `05_modelo_amenazas_stride` | Anexo 15 | `docs/modelo_amenazas_stride.md` + verificación de conteos (`fuentes/generar_anexo15.py`) |
| `06_matriz_trazabilidad_normativa` | Anexo 15 | `docs/matriz_trazabilidad_normativa.md` + verificación de conteos (`fuentes/generar_anexo15.py`) |
| `07_guia_instalacion_despliegue` | Anexo 16 | Basado en `docs/guia_instalacion.md`, verificado y corregido (ver su sección 0) |
| `08_guia_pruebas_validacion_externa` + `08_notebook_validacion_externa.ipynb` | Anexo 13 | Guía y notebook de la sesión del 20/11/2026, sin las hojas de credenciales |

Regenerar:

```powershell
python entregables/fuentes/extraer_esquema.py
python entregables/fuentes/generar_modelo_datos.py
python entregables/fuentes/generar_anexo15.py
python entregables/fuentes/md_a_pdf.py
```

Los textos marcados `[PENDIENTE: …]` son datos que no están en el repositorio.
