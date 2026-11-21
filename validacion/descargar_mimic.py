"""
validacion/descargar_mimic.py
=============================
Descarga MIMIC-III Clinical Database Demo v1.4 desde PhysioNet (acceso
abierto, licencia ODbL 1.0) y deja en validacion/datos/ las tablas que usa la
validación, verificadas contra el SHA256SUMS.txt que publica PhysioNet.

    python validacion/descargar_mimic.py [--destino CARPETA]

Fuente: https://physionet.org/content/mimiciii-demo/1.4/
Cita: Johnson, A., Pollard, T., & Mark, R. (2019). MIMIC-III Clinical
Database Demo (version 1.4). PhysioNet. https://doi.org/10.13026/C2HM2Q

Los CSV no se versionan (validacion/datos/ está en .gitignore): cada quien
los descarga de la fuente oficial.
"""

import argparse
import hashlib
import io
import sys
import urllib.request
import zipfile
from pathlib import Path

URL = "https://physionet.org/static/published-projects/mimiciii-demo/mimic-iii-clinical-database-demo-1.4.zip"
PREFIJO = "mimic-iii-clinical-database-demo-1.4/"
TABLAS = ("PATIENTS.csv", "ADMISSIONS.csv", "LABEVENTS.csv", "D_LABITEMS.csv")
DESTINO = Path(__file__).resolve().parent / "datos" / "mimic-iii-clinical-database-demo-1.4"


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--destino", default=str(DESTINO))
    destino = Path(p.parse_args().destino)
    destino.mkdir(parents=True, exist_ok=True)

    print(f"Descargando {URL} ...")
    with urllib.request.urlopen(URL, timeout=300) as r:
        contenido = r.read()
    print(f"{len(contenido):,} bytes; SHA-256 del zip: {hashlib.sha256(contenido).hexdigest()}")

    with zipfile.ZipFile(io.BytesIO(contenido)) as z:
        sumas = {}
        for linea in z.read(PREFIJO + "SHA256SUMS.txt").decode("utf-8").splitlines():
            partes = linea.split()
            if len(partes) == 2:
                sumas[partes[1].lstrip("*")] = partes[0]
        for nombre in (*TABLAS, "LICENSE.txt", "SHA256SUMS.txt"):
            datos = z.read(PREFIJO + nombre)
            if nombre in sumas and hashlib.sha256(datos).hexdigest() != sumas[nombre]:
                sys.exit(f"SHA-256 no coincide para {nombre}: descarga corrupta")
            (destino / nombre).write_bytes(datos)
            print(f"  {nombre}: OK" + (" (SHA-256 verificado)" if nombre in sumas else ""))
    print(f"Listo: {destino}")


if __name__ == "__main__":
    main()
