"""
audit_tracer/utils/limitador.py
===============================
SRV-D1 / DSH-D1 — Límite de peticiones por ventana deslizante, en memoria.

Cada clave (p. ej. "login:<ip>" o "sync:<token_id>") guarda las marcas de
tiempo de sus peticiones recientes; si en `ventana_s` segundos ya hubo
`maximo`, la petición se rechaza y se informa cuántos segundos faltan para
que se libere un cupo (cabecera Retry-After).

El estado vive en el proceso: con varios workers de Gunicorn cada uno
cuenta por su lado. Es una defensa de la aplicación; en producción el proxy
(Nginx `limit_req`) debe aplicar además su propio límite (Anexo 16).
"""

import threading
import time
from collections import deque
from typing import Callable, Dict, Optional, Tuple


class LimitadorPeticiones:
    """Ventana deslizante por clave. Seguro entre hilos."""

    def __init__(self, reloj: Optional[Callable[[], float]] = None, max_claves: int = 50_000):
        self._reloj = reloj or time.monotonic
        self._marcas: Dict[str, deque] = {}
        self._lock = threading.Lock()
        self._max_claves = max_claves

    def permitir(self, clave: str, maximo: int, ventana_s: float) -> Tuple[bool, int]:
        """
        Registra un intento para `clave`.

        Returns:
            (permitido, segundos_para_reintentar). Si se rechaza, el intento
            no se cuenta: un cliente bloqueado no alarga su propio bloqueo.
        """
        if maximo <= 0:
            return True, 0
        ahora = self._reloj()
        with self._lock:
            marcas = self._marcas.get(clave)
            if marcas is None:
                if len(self._marcas) >= self._max_claves:
                    self._purgar(ahora, ventana_s)
                marcas = self._marcas[clave] = deque()
            while marcas and ahora - marcas[0] >= ventana_s:
                marcas.popleft()
            if len(marcas) >= maximo:
                reintentar = max(1, int(ventana_s - (ahora - marcas[0])) + 1)
                return False, reintentar
            marcas.append(ahora)
            return True, 0

    def _purgar(self, ahora: float, ventana_s: float) -> None:
        vencidas = [c for c, m in self._marcas.items() if not m or ahora - m[-1] >= ventana_s]
        for clave in vencidas:
            del self._marcas[clave]
        if len(self._marcas) >= self._max_claves:   # todas activas: se descarta la más antigua
            self._marcas.pop(next(iter(self._marcas)))

    def reiniciar(self) -> None:
        with self._lock:
            self._marcas.clear()
