"""
audit_tracer/auth/politica_contrasenas.py
=========================================
B5 / DSH-S1 — Política de contraseñas aplicada en register_user(), así vale
para cualquier origen (formulario del dashboard, SEED_USUARIOS, scripts).

Reglas (HIPAA §164.308(a)(5)(ii)(D), especificación direccionable):
  * Longitud mínima AUDIT_PASSWORD_MIN (8 por defecto) y máxima 128.
  * Al menos tres de cuatro clases: minúsculas, mayúsculas, dígitos, símbolos.
  * No contener la parte local del correo ni estar en la lista de
    contraseñas comunes.

No se fuerza la rotación periódica: NIST SP 800-63B la desaconseja porque
lleva a contraseñas predecibles. Se cambia ante sospecha de compromiso
(protocolo de incidentes del Anexo 14).
"""

import os
import re
from typing import List, Optional

LONGITUD_MAXIMA = 128

# Contraseñas que aparecen en las listas de filtraciones más comunes y
# variantes obvias del dominio del proyecto.
_COMUNES = {
    "password", "password1", "password123", "12345678", "123456789", "1234567890",
    "qwerty123", "qwertyuiop", "11111111", "00000000", "abc12345", "iloveyou",
    "admin123", "administrador", "contrasena", "contraseña", "clave123", "hospital",
    "paciente", "auditoria", "audittracer", "bienvenido", "colombia", "medicina",
}


def longitud_minima() -> int:
    try:
        return max(8, int(os.environ.get("AUDIT_PASSWORD_MIN", "8")))
    except ValueError:
        return 8


def problemas_contrasena(password: str, email: Optional[str] = None) -> List[str]:
    """Lista de incumplimientos (vacía si la contraseña cumple la política)."""
    if not isinstance(password, str):
        return ["La contraseña es obligatoria."]
    problemas = []
    minimo = longitud_minima()
    if len(password) < minimo:
        problemas.append(f"Debe tener al menos {minimo} caracteres.")
    if len(password) > LONGITUD_MAXIMA:
        problemas.append(f"Debe tener como máximo {LONGITUD_MAXIMA} caracteres.")
    clases = sum(bool(re.search(p, password)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
    if clases < 3:
        problemas.append("Debe combinar al menos tres de: minúsculas, mayúsculas, números y símbolos.")
    normalizada = re.sub(r"[^a-z0-9ñ]", "", password.lower())
    if password.lower() in _COMUNES or normalizada in _COMUNES or re.sub(r"\d+$", "", normalizada) in _COMUNES:
        problemas.append("Es una contraseña demasiado común.")
    if email and "@" in email:
        local = email.split("@", 1)[0].lower()
        if len(local) >= 4 and local in password.lower():
            problemas.append("No puede contener el usuario del correo.")
    return problemas


def validar_contrasena(password: str, email: Optional[str] = None) -> None:
    """Lanza ValueError con todos los incumplimientos, o no hace nada si la contraseña cumple."""
    problemas = problemas_contrasena(password, email)
    if problemas:
        raise ValueError("Contraseña no válida: " + " ".join(problemas))
