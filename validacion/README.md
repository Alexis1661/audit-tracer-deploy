# Validación con MIMIC-III Clinical Database Demo v1.4

Sección 7.4 del documento final: tres casos de uso ejecutados contra el sistema real.

| Archivo | Qué es |
|---|---|
| `descargar_mimic.py` | Descarga el dataset desde PhysioNet y verifica los SHA-256 publicados. Los CSV quedan en `validacion/datos/` (no se versionan). |
| `scripts/` | Código de los analistas: pandas puro con `import audit_tracer` como única línea añadida. |
| `reloj.py` | Corre un script del analista con la hora del día fijada (10:00 o 03:10, hora de Colombia) sobre la fecha real. |
| `entorno.py` | Levanta el servidor central (`app.py`) en su propio proceso, autentica a la científica con código de dispositivo y abre sesiones de dashboard. |
| `casos_mimic.py` | Los tres casos y sus verificaciones (`CUMPLE` / `NO CUMPLE`) con su evidencia. |
| `casos_mimic.ipynb` | Los mismos casos paso a paso, con sus salidas. |
| `evidencia/<fecha>/` | Evidencia de cada ejecución registrada: eventos, CSV del dashboard, correo, anclas Merkle y `RESULTADOS.md`. |

```powershell
python validacion/descargar_mimic.py
python -m pytest tests/test_validacion_mimic.py -v
python -m validacion.casos_mimic --evidencia validacion/evidencia/AAAA-MM-DD
```

Dataset: Johnson, A., Pollard, T., & Mark, R. (2019). *MIMIC-III Clinical Database Demo* (version 1.4).
PhysioNet. https://doi.org/10.13026/C2HM2Q — Open Data Commons Open Database License v1.0.
La evidencia guarda metadatos de auditoría y huellas SHA-256 de los archivos exportados, no las filas clínicas.
