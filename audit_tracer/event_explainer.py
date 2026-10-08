"""
audit_tracer/event_explainer.py
================================
HU-7.4 — Módulo de Enriquecimiento Explicativo para Eventos de Auditoría.

Proporciona funciones para resolver la identidad completa del usuario,
generar explicaciones en lenguaje natural para auditores clínicos,
evaluar el diagnóstico de severidad e impacto, y sugerir recomendaciones
y guías de mitigación accionables.
"""

import json
import sqlite3
from typing import Dict, Any, Optional, List
from audit_tracer.models.usuarios import get_user_by_id, get_user_by_email


def _format_friendly_name(email: Optional[str], default: str = "Usuario") -> str:
    """Convierte un email corporativo (ej. analista.garcia@audit.com) a un nombre legible."""
    if not email or "@" not in email:
        return default
    local_part = email.split("@")[0]
    # Reemplazar puntos, guiones y números para crear nombre
    parts = [p.capitalize() for p in local_part.replace(".", " ").replace("-", " ").replace("_", " ").split() if not p.isdigit()]
    if not parts:
        return email
    # Mapeo de nombres especiales comunes
    name_map = {
        "admin": "Administrador del Sistema",
        "auditor": "Auditor Clínico",
        "analista": "Analista de Datos",
        "cientifico": "Científico de Datos",
    }
    if len(parts) == 1 and parts[0].lower() in name_map:
        return name_map[parts[0].lower()]
    return " ".join(parts)


def resolve_user_info(conn: sqlite3.Connection, usuario_id: Optional[str]) -> Dict[str, Any]:
    """
    HU-7.4 CA1 — Resuelve la identidad y perfil del usuario a partir de su usuario_id.

    Maneja:
      - IDs de usuarios registrados en la base central (UUIDs).
      - Emails guardados directamente en usuario_id.
      - Usuarios de sistema o servicios internos (SISTEMA, SINCRONIZACION).
      - Usuarios anónimos o desconocidos (DESCONOCIDO).
    """
    if not usuario_id or usuario_id in ("DESCONOCIDO", "anonimo", "ANONIMO", "None"):
        return {
            "usuario_id": usuario_id or "DESCONOCIDO",
            "nombre": "Usuario No Identificado",
            "email": "No disponible (acceso no autenticado)",
            "rol": "DESCONOCIDO",
            "activo": False,
            "es_desconocido": True,
            "es_sistema": False,
            "avatar_letra": "?",
            "rol_badge_class": "badge-normal",
        }

    if usuario_id.upper() in ("SISTEMA", "SINCRONIZACION", "DEVICE_LOGIN"):
        return {
            "usuario_id": usuario_id,
            "nombre": f"Servicio Interno ({usuario_id.title()})",
            "email": f"{usuario_id.lower()}@audit.internal",
            "rol": "SISTEMA",
            "activo": True,
            "es_desconocido": False,
            "es_sistema": True,
            "avatar_letra": "S",
            "rol_badge_class": "badge-normal",
        }

    # Buscar usuario en la base de datos por ID
    user_row = None
    try:
        user_row = get_user_by_id(conn, usuario_id)
        if not user_row:
            # Intentar por email en caso de que usuario_id contenga el correo
            user_row = get_user_by_email(conn, usuario_id)
    except Exception:
        user_row = None

    if user_row:
        email = user_row.get("email", "")
        rol = user_row.get("rol", "ANALISTA")
        nombre = _format_friendly_name(email, default="Usuario Registrado")
        avatar_letra = nombre[0].upper() if nombre else "U"
        rol_badge = {
            "ADMIN": "badge-critico",
            "AUDITOR": "badge-advertencia",
            "CIENTIFICO_DATOS": "badge-normal",
            "ANALISTA": "badge-normal",
        }.get(rol, "badge-normal")

        return {
            "usuario_id": user_row.get("usuario_id", usuario_id),
            "nombre": nombre,
            "email": email,
            "rol": rol,
            "activo": bool(user_row.get("activo", 1)),
            "es_desconocido": False,
            "es_sistema": False,
            "avatar_letra": avatar_letra,
            "rol_badge_class": rol_badge,
        }

    # Si no se encuentra en la base de datos pero tiene formato de email
    if "@" in usuario_id:
        nombre = _format_friendly_name(usuario_id, default="Usuario Externo")
        return {
            "usuario_id": usuario_id,
            "nombre": nombre,
            "email": usuario_id,
            "rol": "NO REGISTRADO",
            "activo": None,
            "es_desconocido": False,
            "es_sistema": False,
            "avatar_letra": nombre[0].upper() if nombre else "U",
            "rol_badge_class": "badge-normal",
        }

    # UUID o ID huérfano no encontrado
    return {
        "usuario_id": usuario_id,
        "nombre": f"Usuario ({usuario_id[:8]}...)" if len(usuario_id) > 8 else f"Usuario {usuario_id}",
        "email": "ID no vinculado a cuenta activa",
        "rol": "NO ASIGNADO",
        "activo": None,
        "es_desconocido": True,
        "es_sistema": False,
        "avatar_letra": "U",
        "rol_badge_class": "badge-normal",
    }


def generate_event_explanation(evento: Dict[str, Any], user_info: Dict[str, Any]) -> Dict[str, Any]:
    """
    HU-7.4 CA2 — Genera una narrativa explicativa en lenguaje claro sobre qué representa el evento.
    """
    tipo = (evento.get("tipo_accion") or "DESCONOCIDO").upper()
    nombre_usuario = user_info.get("nombre", "Un usuario")
    dataset = evento.get("dataset_nombre") or "un conjunto de datos"
    filas = evento.get("filas_exportadas")
    ruta = evento.get("ruta_destino")
    sobrescritura = evento.get("sobrescritura")
    motivo_fallo = evento.get("motivo_fallo")
    contexto = evento.get("contexto_ejecucion") or ""

    # Parsear contexto de ejecución (Jupyter, Script, Host)
    entorno_desc = "Entorno no especificado"
    if "Jupyter" in contexto:
        entorno_desc = "Cuaderno interactivo (Jupyter / Colab Notebook)"
    elif "Script" in contexto or ".py" in contexto:
        entorno_desc = "Script automatizado de Python"
    elif "Dashboard" in contexto or "Web" in contexto:
        entorno_desc = "Interfaz Web del Dashboard"

    # Formatear columnas
    cols_raw = evento.get("columnas_afectadas")
    cols_text = ""
    if cols_raw:
        try:
            cols_list = json.loads(cols_raw) if isinstance(cols_raw, str) and cols_raw.startswith("[") else [cols_raw]
            if isinstance(cols_list, list) and cols_list:
                cols_text = f" sobre las columnas: {', '.join(cols_list[:5])}{' y más...' if len(cols_list) > 5 else ''}"
        except Exception:
            cols_text = f" sobre las columnas {cols_raw}"

    # Generación por tipo de acción
    if tipo == "CARGA":
        titulo = "Carga inicial de datos clínicos"
        descripcion = (
            f"{nombre_usuario} realizó la carga y lectura inicial del archivo clínico "
            f"<strong>{dataset}</strong> en el espacio de trabajo{cols_text}."
        )
        icono = "upload"
    elif tipo == "CONSULTA":
        titulo = "Consulta y exploración de datos"
        descripcion = (
            f"{nombre_usuario} ejecutó una operación de lectura, filtrado o inspección "
            f"sobre el dataset <strong>{dataset}</strong>{cols_text}."
        )
        icono = "search"
    elif tipo == "TRANSFORMACION":
        titulo = "Transformación y procesamiento de datos"
        descripcion = (
            f"{nombre_usuario} aplicó modificaciones, limpieza o transformaciones estructurales "
            f"en los registros del dataset <strong>{dataset}</strong>{cols_text}."
        )
        icono = "shuffle"
    elif tipo == "EXPORTACION":
        titulo = "Exportación de datos a archivo externo"
        sobrescrito_txt = " con sobrescritura del archivo existente" if sobrescritura else ""
        filas_txt = f" conteniendo <strong>{filas} registros</strong>" if filas is not None else ""
        ruta_txt = f" hacia la ruta <code>{ruta}</code>" if ruta else ""
        descripcion = (
            f"{nombre_usuario} exportó información derivada de <strong>{dataset}</strong>"
            f"{filas_txt}{ruta_txt}{sobrescrito_txt}."
        )
        icono = "download"
    elif tipo == "ACCESO_FALLIDO":
        titulo = "Intento fallido de acceso a datos clínicos"
        fallo_txt = f" <em>({motivo_fallo})</em>" if motivo_fallo else ""
        descripcion = (
            f"{nombre_usuario} intentó acceder al recurso clínico <strong>{dataset}</strong>, "
            f"pero la operación no se pudo completar debido a un error o denegación{fallo_txt}."
        )
        icono = "alert-triangle"
    elif tipo == "ACCESO_DENEGADO":
        titulo = "Acceso denegado por política de seguridad (RBAC)"
        fallo_txt = f" <em>({motivo_fallo})</em>" if motivo_fallo else ""
        descripcion = (
            f"El sistema bloqueó el intento de acceso porque el rol <strong>{user_info.get('rol', 'N/A')}</strong> "
            f"no cuenta con los privilegios necesarios para esta acción{fallo_txt}."
        )
        icono = "shield-off"
    elif tipo == "INICIO_SESION":
        titulo = "Inicio de sesión de usuario"
        descripcion = f"{nombre_usuario} inició una sesión autenticada en la plataforma."
        icono = "log-in"
    elif tipo == "CIERRE_SESION":
        titulo = "Cierre de sesión de usuario"
        descripcion = f"{nombre_usuario} finalizó voluntariamente su sesión de trabajo."
        icono = "log-out"
    elif tipo == "SESION_INTERRUMPIDA":
        titulo = "Sesión cerrada o interrumpida"
        descripcion = "La sesión de trabajo fue interrumpida por inactividad o desconexión del cliente."
        icono = "clock"
    elif tipo == "CREACION_USUARIO":
        titulo = "Registro de nueva cuenta de usuario"
        descripcion = f"Acción administrativa de creación de un nuevo usuario en el sistema ({dataset or 'N/A'})."
        icono = "user-plus"
    elif tipo == "MODIFICACION_ROL":
        titulo = "Modificación de permisos y rol de usuario"
        descripcion = f"Acción administrativa de cambio de rol y privilegios para el usuario ({dataset or 'N/A'})."
        icono = "user-check"
    elif tipo == "FIRMA_INVALIDA":
        titulo = "Alerta crítica: Discrepancia en firma digital (No Repudio)"
        descripcion = (
            "Se recibió un evento cuya firma criptográfica Ed25519 no coincide con el payload recibido "
            "o no corresponde a la llave pública registrada del usuario. El evento pudo haber sido manipulado."
        )
        icono = "shield-alert"
    elif tipo == "SINCRONIZACION_RECHAZADA":
        titulo = "Rechazo de sincronización de eventos remotos"
        descripcion = (
            f"El servidor central rechazó la ingesta de un evento sincronizado. "
            f"Motivo: {motivo_fallo or 'Token no válido o expirado'}."
        )
        icono = "wifi-off"
    else:
        titulo = f"Operación registrada: {tipo}"
        descripcion = f"{nombre_usuario} ejecutó la acción '{tipo}' en el sistema de trazabilidad clínica."
        icono = "activity"

    return {
        "titulo": titulo,
        "descripcion": descripcion,
        "entorno_desc": entorno_desc,
        "icono": icono,
    }


def generate_alert_diagnosis(evento: Dict[str, Any]) -> Dict[str, Any]:
    """
    HU-7.4 CA3 — Genera el diagnóstico de severidad y evaluación de impacto de seguridad.
    """
    nivel = (evento.get("nivel_alerta") or "NORMAL").upper()
    motivo = evento.get("motivo_alerta") or ""
    tipo = (evento.get("tipo_accion") or "").upper()

    es_critico = nivel == "CRITICO"
    es_advertencia = nivel == "ADVERTENCIA"

    if es_critico:
        categoria_alerta = "Alerta de Severidad Alta"
        clase_css = "alert-critica"
        if "masiva" in motivo.lower() or (evento.get("filas_exportadas") or 0) > 1000:
            impacto = (
                "Riesgo potencial de fuga o exfiltración masiva de historias clínicas o datos sensibles. "
                "Involucra un volumen de pacientes superior al umbral de seguridad permitido (> 1,000 registros)."
            )
        elif "horario" in motivo.lower():
            impacto = (
                "Acceso atípico fuera de la ventana operativa institucional (08:00 - 18:00 UTC). "
                "Podría indicar credenciales comprometidas o actividad investigativa no programada."
            )
        elif "intentos" in motivo.lower() or tipo == "ACCESO_FALLIDO":
            impacto = (
                "Ráfaga consecutiva de fallos de acceso en corto tiempo. Podría constituir un escaneo "
                "de directorios o intento de fuerza bruta sobre archivos restringidos."
            )
        elif "firma" in motivo.lower() or tipo == "FIRMA_INVALIDA":
            impacto = (
                "Compromiso de integridad o no repudio. El evento no puede ser verificado criptográficamente "
                "con la identidad del emisor."
            )
        elif "no identificado" in motivo.lower():
            impacto = (
                "Operación clínica ejecutada sin credenciales válidas o sesión anónima, "
                "vulnerando el principio de responsabilidad única de acceso a datos de salud."
            )
        else:
            impacto = "Incidente de seguridad crítico que requiere revisión inmediata por el equipo de auditoría."
    elif es_advertencia:
        categoria_alerta = "Advertencia de Seguridad"
        clase_css = "alert-advertencia"
        if evento.get("sobrescritura"):
            impacto = (
                "Sobrescritura de un archivo existente. Podría ocasionar pérdida de datos previos o "
                "destrucción accidental del historial de versiones."
            )
        elif "intentos" in motivo.lower():
            impacto = "Intentos fallidos reiterados que se aproximan al umbral crítico."
        else:
            impacto = "Comportamiento que se desvía levemente de los patrones habituales de consulta."
    else:
        categoria_alerta = "Operación Normal"
        clase_css = "alert-normal"
        impacto = (
            "La acción se ejecutó dentro de los parámetros de seguridad establecidos, "
            "horarios laborales habituales y límites de volumen autorizados."
        )

    return {
        "nivel": nivel,
        "es_alerta": es_critico or es_advertencia,
        "es_critico": es_critico,
        "es_advertencia": es_advertencia,
        "categoria_alerta": categoria_alerta,
        "clase_css": clase_css,
        "motivo": motivo or "Sin anomalías registradas",
        "impacto": impacto,
    }


def generate_recommendations(
    evento: Dict[str, Any], user_info: Dict[str, Any], diagnostico: Dict[str, Any]
) -> List[Dict[str, str]]:
    """
    HU-7.4 CA4 — Sugiere recomendaciones de mitigación y mejores prácticas según el evento y su nivel de riesgo.
    """
    tipo = (evento.get("tipo_accion") or "").upper()
    nivel = diagnostico.get("nivel", "NORMAL")
    dataset = evento.get("dataset_nombre") or "el archivo"
    email = user_info.get("email", "el usuario")
    filas = evento.get("filas_exportadas")
    recs = []

    # 1. Recomendaciones basadas en Severidad Crítica / Advertencia
    if nivel == "CRITICO":
        if "masiva" in (evento.get("motivo_alerta") or "").lower() or (filas or 0) > 1000:
            recs.append({
                "tipo": "urgente",
                "titulo": "Validar autorización de exportación masiva",
                "detalle": f"Solicitar a {email} la justificación ética y el ticket de autorización para la extracción de {filas or 'gran volumen de'} registros clínicos.",
            })
            recs.append({
                "tipo": "seguridad",
                "titulo": "Verificar cifrado en destino",
                "detalle": f"Asegurarse de que el destino ({evento.get('ruta_destino') or 'almacenamiento'}) cuente con controles de acceso restringidos y cifrado en reposo.",
            })
        elif "horario" in (evento.get("motivo_alerta") or "").lower():
            recs.append({
                "tipo": "urgente",
                "titulo": "Confirmar actividad fuera de horario",
                "detalle": f"Contactar a {email} para corroborar si la operación nocturna/fuera de horario fue legítima o corresponde a un inicio de sesión no autorizado.",
            })
        elif tipo == "ACCESO_FALLIDO":
            recs.append({
                "tipo": "urgente",
                "titulo": "Auditar posibles intentos de intrusión",
                "detalle": f"Revisar los logs del entorno de ejecución ({evento.get('contexto_ejecucion') or 'host'}) para descartar scripts automatizados de fuerza bruta.",
            })
            recs.append({
                "tipo": "seguridad",
                "titulo": "Verificar estado de credenciales",
                "detalle": "Si los fallos persisten, considerar la revocación preventiva de tokens de acceso y bloqueo temporal de la sesión.",
            })
        elif tipo == "FIRMA_INVALIDA":
            recs.append({
                "tipo": "urgente",
                "titulo": "Tratar como evento no confiable",
                "detalle": "Aislar el registro. La firma digital Ed25519 falló la validación matemática contra la clave pública del emisor.",
            })
            recs.append({
                "tipo": "seguridad",
                "titulo": "Regenerar par de llaves criptográficas",
                "detalle": "Solicitar al usuario volver a autenticarse con la librería cliente para registrar un nuevo par de llaves públicas.",
            })

    # 2. Recomendaciones basadas en el tipo de acción específico
    if tipo == "ACCESO_FALLIDO" and nivel != "CRITICO":
        recs.append({
            "tipo": "info",
            "titulo": "Verificar existencia y ruta del dataset",
            "detalle": f"Comprobar si el archivo '{dataset}' existe en la ruta esperada o si hubo un error tipográfico en el script de análisis.",
        })
        recs.append({
            "tipo": "seguridad",
            "titulo": "Revisar permisos sobre el archivo",
            "detalle": "Validar si el usuario cuenta con permisos de lectura en el sistema de archivos del servidor/contenedor.",
        })

    elif tipo == "ACCESO_DENEGADO":
        recs.append({
            "tipo": "seguridad",
            "titulo": "Revisar matriz de permisos RBAC",
            "detalle": f"El rol '{user_info.get('rol')}' intentó acceder a una sección restringida. Si requiere el acceso formalmente, solicitar elevación de rol al Administrador.",
        })

    elif tipo == "EXPORTACION" and nivel != "CRITICO":
        recs.append({
            "tipo": "info",
            "titulo": "Registrar en el linaje del dato clínico",
            "detalle": f"El archivo exportado '{dataset}' debe quedar catalogado como dato derivado con su respectivo hash de integridad.",
        })

    elif tipo in ("CARGA", "CONSULTA", "TRANSFORMACION") and nivel == "NORMAL":
        recs.append({
            "tipo": "info",
            "titulo": "Actividad dentro de parámetros normales",
            "detalle": "Operación de rutina sobre datos clínicos. El evento se encuentra debidamente firmado e indexado en la base central inmutable.",
        })
        recs.append({
            "tipo": "mejora",
            "titulo": "Trazabilidad de linaje",
            "detalle": f"Puedes consultar todas las transformaciones previas y posteriores de '{dataset}' usando el filtro por dataset.",
        })

    # Recomendación por defecto si la lista estuviera vacía
    if not recs:
        recs.append({
            "tipo": "info",
            "titulo": "Trazabilidad archivada correctamente",
            "detalle": "El evento cumple con los estándares institucionales de inmutabilidad criptográfica SHA-256.",
        })

    return recs


def generate_copyable_summary(
    evento: Dict[str, Any],
    user_info: Dict[str, Any],
    explicacion: Dict[str, Any],
    diagnostico: Dict[str, Any],
    estado_firma: Optional[Dict[str, Any]] = None,
) -> str:
    """
    HU-7.4 CA5 — Genera un resumen textual formateado para copiar en el portapapeles y pegar en Jira/tickets.
    """
    event_id = evento.get("event_id", "N/A")
    timestamp = str(evento.get("timestamp", "N/A")).replace("T", " ")
    tipo = evento.get("tipo_accion", "N/A")
    nivel = diagnostico.get("nivel", "NORMAL")
    usuario = f"{user_info.get('nombre', 'N/A')} ({user_info.get('email', 'N/A')} | {user_info.get('rol', 'N/A')})"
    dataset = evento.get("dataset_nombre") or "N/A"
    motivo = evento.get("motivo_alerta") or evento.get("motivo_fallo") or "N/A"
    contexto = evento.get("contexto_ejecucion") or "N/A"
    hash_val = evento.get("hash_integridad") or "N/A"

    firma_txt = "No firmado"
    if estado_firma and estado_firma.get("presente"):
        firma_txt = "Válida (Ed25519)" if estado_firma.get("valida") else "Inválida / Corrupta"

    lineas = [
        f"============================================================",
        f" REPORTE DE AUDITORÍA CLÍNICA — EVENTO #{event_id}",
        f"============================================================",
        f"Fecha y Hora (UTC): {timestamp}",
        f"Tipo de Acción:     {tipo}",
        f"Nivel de Alerta:    {nivel}",
        f"Usuario:            {usuario}",
        f"Dataset Afectado:   {dataset}",
        f"Detalle / Motivo:   {motivo}",
        f"Contexto Ejecución: {contexto}",
        f"Hash SHA-256:       {hash_val}",
        f"Firma Digital:      {firma_txt}",
        f"------------------------------------------------------------",
        f"Diagnóstico:        {diagnostico.get('impacto', 'N/A')}",
        f"============================================================",
    ]
    return "\n".join(lineas)


def enrich_event_detail(
    conn: sqlite3.Connection,
    evento: Dict[str, Any],
    estado_firma: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    HU-7.4 — Función principal que consolida todo el contexto explicativo
    del evento para ser consumido por la plantilla de Flask.
    """
    user_info = resolve_user_info(conn, evento.get("usuario_id"))
    explicacion = generate_event_explanation(evento, user_info)
    diagnostico = generate_alert_diagnosis(evento)
    recomendaciones = generate_recommendations(evento, user_info, diagnostico)
    resumen_copiable = generate_copyable_summary(evento, user_info, explicacion, diagnostico, estado_firma)

    return {
        "usuario_info": user_info,
        "explicacion": explicacion,
        "diagnostico": diagnostico,
        "recomendaciones": recomendaciones,
        "resumen_copiable": resumen_copiable,
    }
