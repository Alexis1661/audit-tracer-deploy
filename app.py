"""
app.py — Punto de entrada principal del frontend Flask.
Sistema de Auditoría de Trazabilidad de Datos Clínicos.
"""

import hashlib
import hmac
import io
import json
import os
import secrets
import sqlite3
import time
from collections import Counter
from contextlib import closing
from flask import (
    Flask, abort, render_template, request, redirect, url_for, session, flash, Response, jsonify, g, make_response,
)

# ── Importaciones del backend existente ─────────────────────────────────────
from audit_tracer.db import get_central_connection, get_connection
from audit_tracer.audit_mail import register_audit_mail_command
from audit_tracer.audit_workspace import can_review_alerts, create_audit_blueprint
from audit_tracer.auth.autenticacion import login as auth_login, logout as auth_logout, desbloquear_cuenta
from audit_tracer.auth.politica_contrasenas import problemas_contrasena
from audit_tracer.auth.registro import register_user
from audit_tracer.auth.gestion_roles import assign_role
from audit_tracer.auth.tokens import (
    generar_token,
    validar_token,
    validar_token_sesion,
    revocar_token,
    listar_tokens,
    usuario_de_sesion,
)
from audit_tracer.models.tokens import get_token_by_id
from audit_tracer.auth.device_codes import (
    iniciar_login_dispositivo,
    confirmar_codigo,
    consultar_estado,
    CODIGO_EXPIRACION_MINUTOS,
    INTERVALO_POLLING_SEGUNDOS,
)
from audit_tracer.models.usuarios import get_all_users, get_user_by_id, get_user_by_email, get_user_public_key
from audit_tracer.models.llaves import (  # SRV-S2 / SRV-R2
    listar_llaves, registrar_llave, revocar_llave, usuario_tiene_llaves, verificar_con_historial,
)
from audit_tracer.models.device_codes import get_by_codigo, purgar_codigos_vencidos
from audit_tracer.clasificacion_servidor import (  # SRV-T3
    aplicar_a_evento_sin_firma, clasificar as clasificar_en_servidor, evento_reclasificacion,
    motivos_por_encima_de, rango as rango_nivel, TIPO_EVENTO_RECLASIFICACION,
)
from audit_tracer.utils.limitador import LimitadorPeticiones  # SRV-D1 / DSH-D1
from audit_tracer.utils.session import generate_session_id
from audit_tracer.models.audit_log import (
    get_anomaly_events,       # HU-6.3

    get_events,
    get_event_by_id,
    verify_integrity,
    insert_event,
    get_critical_events,
    export_critical_events_to_csv,
    generate_report,
    export_report_to_csv,
    NO_RESULTS_MESSAGE,
    insert_event_if_new,       # HU-5.8
    get_sync_queue_summary,    # HU-5.8
)
from audit_tracer.anomaly_detector import (  # HU-6.3
    ACCIONES_AUDITABLES_VOLUMEN, TIPO_EVENTO_ANOMALIA, construir_evento_anomalia, evaluar_evento_anomalias,
)
from audit_tracer.merkle import (                                    # HU-6.2
    generate_proof_for_event,
    verify_merkle_proof,
    build_batch_tree,
    publish_batch_root,
    verify_external_anchor,
    verify_all_anchors,
    get_pending_batch_hours,
)
from audit_tracer.event_explainer import enrich_event_detail  # HU-7.4
from audit_tracer.normative_mapping import SIN_REFERENCIA_NORMATIVA  # HU-7.3
from audit_tracer.auth.control_acceso import has_permission  # HU-1.4
from audit_tracer.lineage import build_lineage_graph, list_lineage_datasets  # HU-7.1
from audit_tracer.alerts import (                                    # HU-7.2
    CATALOGO_EVENTOS_CRITICOS,
    ErrorEnvioCorreo,
    configurar_alertas,
    crear_servicio_correo_desde_entorno,
    obtener_despachador,
)
from audit_tracer.models import alertas as alertas_model             # HU-7.2
from audit_tracer.auth.control_acceso import PERMISSION_MATRIX       # HU-7.2
from datetime import datetime, timedelta
from audit_tracer.utils.zona_horaria import (  # hora Colombia en la interfaz
    formatear_fecha, ahora_colombia, inicio_dia_utc, fin_dia_utc,
    lote_a_hora_colombia, ETIQUETA_ZONA,
)


def _categorize_critical_reason(motivo: str) -> str:
    """Agrupa motivo_alerta de eventos CRITICO en categorías legibles para reportes."""
    if not motivo:
        return "Sin motivo registrado"
    m = motivo.lower()
    if "masiva" in m:
        return "Exportación masiva"
    if "horario laboral" in m:
        return "Fuera de horario laboral"
    if "intentos fallidos" in m:
        return "Intentos fallidos de acceso"
    if "no identificado" in m:
        return "Usuario no identificado"
    return "Otro"

# ── Configuración Flask ──────────────────────────────────────────────────────
app = Flask(__name__)
# HU-6.5 — La clave que firma la cookie de sesión no puede estar en el
# código: el repositorio es legible por terceros y con ella cualquiera
# firmaría una cookie con rol=ADMIN. Se toma de SECRET_KEY; si no está
# definida, se genera una aleatoria por proceso (las sesiones se pierden
# al reiniciar, pero nunca quedan falsificables).
app.secret_key = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
app.config.update(
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1),
    SESSION_REFRESH_EACH_REQUEST=False,
    # DSH-S3 (21/11/2026): la cookie solo viaja por HTTPS, JavaScript no la
    # lee y no acompaña peticiones iniciadas desde otro sitio. Para probar por
    # http:// con un navegador que no acepte cookies Secure en localhost:
    # AUDIT_COOKIE_SEGURA=0.
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=os.environ.get('AUDIT_COOKIE_SEGURA', '1') != '0',
    # SRV-D1: ninguna petición legítima (un evento, un formulario) pasa de 2 MB.
    MAX_CONTENT_LENGTH=int(os.environ.get('AUDIT_MAX_PETICION_BYTES', str(2 * 1024 * 1024))),
)
# B1: además del vencimiento absoluto de una hora, la sesión se cierra tras
# AUDIT_SESION_INACTIVIDAD_MIN minutos sin actividad (15 por defecto).
INACTIVIDAD_MAXIMA = timedelta(minutes=int(os.environ.get('AUDIT_SESION_INACTIVIDAD_MIN', '15')))
MENSAJE_SESION_INVALIDA = 'Tu sesión venció o dejó de ser válida. Vuelve a iniciar sesión.'
MENSAJE_SESION_INACTIVA = 'Tu sesión se cerró tras un tiempo sin actividad. Vuelve a iniciar sesión.'

# Hora de Colombia en todas las pantallas. Los timestamps se guardan en UTC
# (hash, firmas y lotes de Merkle dependen de ese valor exacto); solo se
# convierten al mostrarlos.
app.jinja_env.filters['hora_col'] = formatear_fecha

# Opciones del filtro "Acción" en Eventos y Reportes. Además del catálogo
# fijo, se agrega cualquier tipo que ya exista en la base, para que ningún
# evento quede imposible de filtrar desde la interfaz.
TIPOS_ACCION = {
    'CARGA': 'Carga de Datos',
    'CONSULTA': 'Consulta',
    'TRANSFORMACION': 'Transformación',
    'EXPORTACION': 'Exportación de Datos',
    'MODELADO': 'Modelado',
    'MODELADO_FALLIDO': 'Modelado Fallido',
    'ACCESO_FALLIDO': 'Acceso Fallido',
    'ACCESO_DENEGADO': 'Acceso Denegado',
    'INICIO_SESION': 'Inicio Sesión',
    'CIERRE_SESION': 'Cierre Sesión',
    'SESION_INTERRUMPIDA': 'Sesión Interrumpida',
    'ATRIBUCION_SESION': 'Atribución de Sesión',
    'CREACION_USUARIO': 'Creación Usuario',
    'MODIFICACION_ROL': 'Modificación Rol',
    'GENERACION_TOKEN': 'Generación de Token',
    'REVOCACION_TOKEN': 'Revocación de Token',
    'CONFIRMACION_LOGIN_DISPOSITIVO': 'Confirmación Login por Código',
    'SINCRONIZACION_RECHAZADA': 'Sincronización Rechazada',
    'FIRMA_INVALIDA': 'Firma Inválida',
    'ANOMALIA_DETECTADA': 'Anomalía Detectada',
    'AUDITORIA_DESACTIVADA': 'Auditoría Desactivada',
    'CONFIGURACION_ALERTAS': 'Configuración de Alertas',
    'CONSULTA_BITACORA': 'Consulta de la Bitácora',
    'DESCARGA_REPORTE': 'Descarga de Reporte',
    'REGISTRO_LLAVE_PUBLICA': 'Registro de Llave Pública',
    'REVOCACION_LLAVE_PUBLICA': 'Revocación de Llave Pública',
    'DESBLOQUEO_CUENTA': 'Desbloqueo de Cuenta',
    'RECLASIFICACION_SERVIDOR': 'Reclasificación del Servidor',
}


def opciones_tipo_accion():
    """[(valor, etiqueta)] del catálogo más los tipos presentes en la base."""
    opciones = dict(TIPOS_ACCION)
    try:
        with closing(get_db()) as conn:
            for (tipo,) in conn.execute("SELECT DISTINCT tipo_accion FROM audit_log WHERE tipo_accion IS NOT NULL"):
                opciones.setdefault(tipo, tipo.replace('_', ' ').capitalize())
    except Exception:
        pass
    return list(opciones.items())


app.jinja_env.globals['opciones_tipo_accion'] = opciones_tipo_accion
app.jinja_env.filters['hora_col_min'] = lambda v: formatear_fecha(v, segundos=False)
app.jinja_env.filters['lote_col'] = lote_a_hora_colombia
app.jinja_env.globals['ZONA_HORARIA'] = ETIQUETA_ZONA


def _limites_dia_colombia(fecha_inicio, fecha_fin):
    """
    Los <input type="date"> entregan días de Colombia ('YYYY-MM-DD'); la base
    guarda UTC. Devuelve los límites del rango ya convertidos a UTC ISO para
    la comparación lexicográfica sobre timestamp. Una fecha inválida se ignora.
    """
    try:
        inicio = inicio_dia_utc(fecha_inicio)
    except ValueError:
        inicio = None
    try:
        fin = fin_dia_utc(fecha_fin)
    except ValueError:
        fin = None
    return inicio, fin

# HU-5.6/5.7 — Detrás de un proxy inverso real (Railway, Heroku, etc.) Flask
# ve la conexión interna proxy→contenedor, que es HTTP aunque el cliente sí
# haya llegado por HTTPS: sin esto, request.is_secure (usado por
# _peticion_es_segura(), CA5) y url_for(_external=True) (usado para
# url_activacion, CA1) quedan mal — el primero rechaza tráfico HTTPS legítimo,
# el segundo genera URLs http://. Se activa solo con TRUST_PROXY_HEADERS=1
# (puesto en las variables de entorno del despliegue), nunca por defecto: sin
# un proxy real por delante que sobreescriba X-Forwarded-*, confiar en esos
# encabezados dejaría que cualquier cliente los falsifique para saltarse CA5.
if os.environ.get('TRUST_PROXY_HEADERS') == '1':
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_for=1, x_host=1)

# Directorio de trabajo: raíz del proyecto
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# HU-7.2 — Alertas en tiempo real. El despachador se engancha a cada INSERT
# en la base central (models/audit_log.py) y notifica por correo en un hilo
# aparte: el registro del evento nunca espera al envío (CA4). La suite de
# pruebas lo apaga con AUDIT_ALERTAS_DESACTIVADAS=1 (tests/conftest.py) y
# crea sus propios despachadores contra bases temporales.
CENTRAL_DB_PATH = os.path.join(BASE_DIR, 'audit_central.db')
if os.environ.get('AUDIT_ALERTAS_DESACTIVADAS') != '1':
    try:
        configurar_alertas(CENTRAL_DB_PATH, servicio_correo=crear_servicio_correo_desde_entorno())
    except Exception as _exc:  # nunca impedir que el dashboard arranque
        print(f"[AuditTracer] Alertas en tiempo real no disponibles: {_exc}")


@app.before_request
def _recordar_url_dashboard():
    """HU-7.2 CA3 — URL base para el enlace del correo, si no se fijó AUDIT_DASHBOARD_URL."""
    despachador = obtener_despachador()
    if despachador is not None:
        despachador.recordar_url_base(request.url_root)


def get_db():
    """
    Devuelve una conexión a la base de datos CENTRAL consolidada (HU-5.4 CA4).
    El dashboard ya no lee ni escribe contra el SQLite local: local queda
    reservado para la librería de interceptores (data_capture.py,
    export_capture.py, session_tracker.py), que sí puede quedar
    desconectada (ej. una notebook de Colab) y necesita el modelo de
    caché + sincronización posterior.
    """
    os.chdir(BASE_DIR)  # Asegura que db_path sea relativo a la raíz
    return get_central_connection()


# ── LÍMITES DE PETICIONES, CSRF, CABECERAS Y ERRORES (21/11/2026) ────────────

# SRV-D1 / DSH-D1: (máximo, ventana en segundos, criterio). 'ip' cuenta por
# dirección de origen; 'token' por el token Bearer presentado (su hash). El
# proxy (Nginx limit_req) debe aplicar además su propio límite (Anexo 16).
limitador = LimitadorPeticiones()
LIMITES_PETICIONES = {
    'login_post': (int(os.environ.get('AUDIT_LIMITE_LOGIN_MIN', '10')), 60, 'ip'),
    # Por token y también por IP: variar el token no sirve para inundar la bitácora de rechazos.
    'api_sincronizar_evento': [(int(os.environ.get('AUDIT_LIMITE_SYNC_MIN', '1200')), 60, 'token'),
                               (int(os.environ.get('AUDIT_LIMITE_SYNC_IP_MIN', '3000')), 60, 'ip')],
    'api_registrar_llave_publica': (30, 60, 'token'),
    'api_iniciar_login_dispositivo': (10, 60, 'ip'),
    'api_estado_login_dispositivo': (120, 60, 'ip'),
    'api_validar_token': (60, 60, 'ip'),
}


def _clave_limite(criterio: str) -> str:
    if criterio == 'token':
        autorizacion = request.headers.get('Authorization', '')
        if autorizacion:
            return 'tk:' + hashlib.sha256(autorizacion.encode('utf-8')).hexdigest()[:24]
    return 'ip:' + (request.remote_addr or 'desconocida')


@app.before_request
def _aplicar_limites():
    limites = LIMITES_PETICIONES.get(request.endpoint)
    if not limites:
        return None
    for maximo, ventana, criterio in (limites if isinstance(limites, list) else [limites]):
        permitido, reintentar = limitador.permitir(
            f"{request.endpoint}|{criterio}|{_clave_limite(criterio)}", maximo, ventana)
        if not permitido:
            break
    else:
        return None
    if request.endpoint == 'login_post':
        respuesta = make_response(render_template(
            'auth/login.html', error='Demasiados intentos de inicio de sesión. Espera un minuto e intenta de nuevo.',
            next=request.form.get('next', ''), email=request.form.get('email', '')), 429)
    else:
        respuesta = jsonify({'status': 'error', 'mensaje': 'Demasiadas peticiones. Reintenta más tarde.',
                             'reintentar_en_segundos': reintentar})
        respuesta.status_code = 429
    respuesta.headers['Retry-After'] = str(reintentar)
    return respuesta


# DSH-T1 / DSH-E3: todo POST hecho con la cookie del dashboard debe traer el
# token CSRF de esa sesión (campo oculto csrf_token o cabecera X-CSRF-Token).
# Las rutas de la API que se autentican con token Bearer, o que todavía no
# tienen sesión (inicio y polling del login por código), no usan la cookie.
_ENDPOINTS_SIN_CSRF = frozenset({
    'api_sincronizar_evento', 'api_registrar_llave_publica', 'api_validar_token',
    'api_iniciar_login_dispositivo', 'api_estado_login_dispositivo', 'static',
})
_METODOS_SEGUROS = frozenset({'GET', 'HEAD', 'OPTIONS', 'TRACE'})


def csrf_token() -> str:
    """Token CSRF de la sesión actual (se crea la primera vez que se pide)."""
    token = session.get('_csrf')
    if not token:
        token = secrets.token_urlsafe(32)
        session['_csrf'] = token
    return token


app.jinja_env.globals['csrf_token'] = csrf_token


def _es_peticion_api() -> bool:
    return request.path.startswith('/api/') or request.is_json


@app.before_request
def _verificar_csrf():
    if request.method in _METODOS_SEGUROS or request.endpoint in _ENDPOINTS_SIN_CSRF:
        return None
    if not app.config.get('CSRF_ACTIVO', True):
        return None
    enviado = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token') or ''
    esperado = session.get('_csrf') or ''
    if esperado and enviado and hmac.compare_digest(enviado, esperado):
        return None
    if session.get('usuario_id'):
        _registrar_acceso_denegado(
            'csrf', request.endpoint or request.path,
            motivo='Petición sin token CSRF válido (posible formulario de otro sitio)')
    if request.endpoint == 'login_post':
        return render_template('auth/login.html', error='La página de inicio de sesión venció. Intenta de nuevo.',
                               next=request.form.get('next', ''), email=request.form.get('email', '')), 400
    if _es_peticion_api():
        return jsonify({'status': 'error', 'mensaje': 'Token CSRF ausente o inválido.'}), 400
    return render_template('error.html', codigo=400,
                           mensaje='El formulario venció o no es válido. Vuelve a la página e intenta de nuevo.'), 400


# DSH-E3: CSP. Las plantillas usan estilos y scripts en línea, así que se
# permiten, pero ningún script de otro origen salvo cdnjs, ninguna conexión
# (fetch) ni envío de formularios fuera del propio servidor y nada de marcos.
_CSP = (
    "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; "
    "img-src 'self' data: blob:; connect-src 'self'; object-src 'none'; base-uri 'self'; "
    "form-action 'self'; frame-ancestors 'none'"
)


@app.after_request
def _cabeceras_de_seguridad(response):
    response.headers.setdefault('Content-Security-Policy', _CSP)
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('X-Frame-Options', 'DENY')
    response.headers.setdefault('Referrer-Policy', 'same-origin')
    if request.is_secure:
        response.headers.setdefault('Strict-Transport-Security', 'max-age=31536000')
    return response


# SRV-I2: el usuario nunca ve el texto de una excepción ni un traceback; el
# detalle queda en el log del servidor (app.logger).
_MENSAJES_ERROR = {
    400: 'La solicitud no es válida.',
    403: 'No tienes permiso para realizar esta acción.',
    404: 'La página que buscas no existe.',
    405: 'Método no permitido.',
    413: 'La solicitud supera el tamaño máximo permitido.',
    500: 'Ocurrió un error interno. El detalle quedó en el registro del servidor.',
    503: 'El servicio no está disponible en este momento. Intenta de nuevo.',
}


def _respuesta_error(codigo: int):
    mensaje = _MENSAJES_ERROR.get(codigo, 'Ocurrió un error.')
    if _es_peticion_api():
        return jsonify({'status': 'error', 'mensaje': mensaje}), codigo
    return render_template('error.html', codigo=codigo, mensaje=mensaje), codigo


for _codigo in (400, 403, 404, 405, 413, 503):
    app.register_error_handler(_codigo, lambda e, c=_codigo: _respuesta_error(c))


@app.errorhandler(500)
def _error_interno(e):
    app.logger.error('Error interno no controlado: %s', getattr(e, 'original_exception', e))
    return _respuesta_error(500)


# DSH-R1: las consultas y descargas de la bitácora también quedan registradas.
# Una misma vista con los mismos filtros se registra una vez por minuto para
# no llenar la bitácora con recargas de página.
_VENTANA_CONSULTAS_S = 60
_ultimas_consultas: dict = {}


def _auditar_acceso_bitacora(tipo: str, vista: str, filtros: dict = None, filas: int = None,
                             sha256: str = None, agrupar: bool = True) -> None:
    usuario_id = session.get('usuario_id')
    if not usuario_id:
        return
    filtros_txt = json.dumps({k: v for k, v in (filtros or {}).items() if v}, ensure_ascii=False, sort_keys=True)
    if agrupar:
        clave = (usuario_id, vista, filtros_txt)
        ahora = time.monotonic()
        if ahora - _ultimas_consultas.get(clave, -1e9) < _VENTANA_CONSULTAS_S:
            return
        if len(_ultimas_consultas) > 5000:
            _ultimas_consultas.clear()
        _ultimas_consultas[clave] = ahora
    partes = [f"Vista: {vista}", f"Rol: {session.get('rol', '')}"]
    if filtros_txt != '{}':
        partes.append(f"Filtros: {filtros_txt}")
    if filas is not None:
        partes.append(f"Filas: {filas}")
    if sha256:
        partes.append(f"SHA-256: {sha256}")
    try:
        with closing(get_db()) as conn:
            insert_event(conn, {
                'usuario_id': usuario_id,
                'sesion_id': session.get('sesion_id', 'N/A'),
                'timestamp': datetime.utcnow().isoformat(),
                'tipo_accion': tipo,
                'contexto_ejecucion': ' | '.join(partes),
                'filas_exportadas': filas if tipo == 'DESCARGA_REPORTE' else None,
                'nivel_alerta': 'NORMAL',
            })
    except Exception:
        app.logger.exception('No se pudo registrar el acceso a la bitácora.')


# ── Decorador de protección de rutas ────────────────────────────────────────
def _sesion_web_activa():
    """
    True si la cookie corresponde a una sesión vigente. DSH-E2: el rol se
    relee de la base en cada petición (degradar un rol o bloquear una cuenta
    surte efecto de inmediato). B1: la sesión se cierra tras
    INACTIVIDAD_MAXIMA sin peticiones, además del vencimiento absoluto.
    """
    if not session.get('usuario_id') or not session.get('token_id'):
        return False
    try:
        with closing(get_db()) as conn:
            usuario = usuario_de_sesion(conn, session['token_id'], session['usuario_id'])
            if usuario is None:
                return False
            ahora = datetime.utcnow()
            ultima = session.get('ultima_actividad')
            if ultima:
                try:
                    inactiva = ahora - datetime.fromisoformat(ultima) > INACTIVIDAD_MAXIMA
                except (TypeError, ValueError):
                    inactiva = True
                if inactiva:
                    _cerrar_sesion_por_inactividad(conn)
                    g.sesion_inactiva = True
                    return False
            if usuario['rol'] != session.get('rol'):
                session['rol'] = usuario['rol']
            session['ultima_actividad'] = ahora.isoformat()
            return True
    except sqlite3.Error:
        app.logger.exception('No se pudo validar la sesión web.')
        abort(503)


def _cerrar_sesion_por_inactividad(conn) -> None:
    """Revoca el token de la sesión y deja CIERRE_SESION con el motivo."""
    try:
        sesion_id = session.get('sesion_id', 'N/A')
        revocar_token(conn, session['token_id'], session['usuario_id'], sesion_id, 'Cierre de sesión por inactividad')
        auth_logout(conn, session['usuario_id'], sesion_id, session.get('login_time'))
    except Exception:
        app.logger.exception('No se pudo cerrar la sesión inactiva.')


def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        g.respuesta_privada = True
        if not _sesion_web_activa():
            sesion_anterior = bool(session.get('usuario_id'))
            if sesion_anterior:
                session.clear()
            if g.get('sesion_inactiva'):
                flash(MENSAJE_SESION_INACTIVA, 'warning')
            else:
                flash(MENSAJE_SESION_INVALIDA if sesion_anterior else 'Debes iniciar sesión para acceder a esta página.', 'warning')
            # HU-5.7 CA2: conserva a dónde iba (ej. /auth/dispositivo?codigo=...)
            # para volver ahí mismo después de un login exitoso.
            if request.method in ('GET', 'HEAD'):
                destino = request.full_path if request.query_string else request.path
            elif request.endpoint == 'confirmar_dispositivo_post':
                codigo = request.form.get('codigo', '').strip().upper()
                destino = url_for('confirmar_dispositivo', codigo=codigo) if codigo else url_for('confirmar_dispositivo')
            else:
                destino = None
            return redirect(url_for('login', next=destino))
        return f(*args, **kwargs)
    return decorated


@app.after_request
def impedir_cache_sesion(response):
    if g.get('respuesta_privada') or request.endpoint in ('login', 'login_post', 'logout'):
        response.headers['Cache-Control'] = 'no-store'
    return response

def _registrar_acceso_denegado(modulo: str, ruta: str, motivo: str = None) -> None:
    """HU-1.4 / HU-6.5 CA2 — Deja constancia en audit_log de un acceso bloqueado por rol."""
    rol = session.get('rol', '')
    try:
        conn = get_db()
        insert_event(conn, {
            'usuario_id': session.get('usuario_id', 'DESCONOCIDO'),
            'sesion_id': session.get('sesion_id', 'N/A'),
            'timestamp': datetime.utcnow().isoformat(),
            'tipo_accion': 'ACCESO_DENEGADO',
            'contexto_ejecucion': (
                f"Rol: {rol} | Módulo: {modulo} | Ruta: {ruta} | Método: {request.method}"
            ),
            'motivo_fallo': motivo or f"Acceso denegado: rol '{rol}' no tiene permiso sobre '{modulo}'",
            'nivel_alerta': 'ADVERTENCIA',
        })
        conn.close()
    except Exception:
        pass  # No bloquear la respuesta si falla el log


def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get('rol') != 'ADMIN':
            # HU-6.5 CA2: antes este bloqueo no quedaba en audit_log, así que
            # un intento de escalar privilegios (p. ej. un ANALISTA haciendo
            # POST a /admin/usuarios/nuevo) no dejaba rastro.
            _registrar_acceso_denegado('administracion', f.__name__)
            flash('No tienes permisos para acceder a esta sección.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated


def modulo_required(modulo: str):
    """
    HU-1.4 — Decorador Flask que valida permisos por módulo en tiempo de
    ejecución usando la PERMISSION_MATRIX.
    Si el rol de la sesión no tiene acceso:
      - Registra ACCESO_DENEGADO en audit_log.
      - Muestra la página de acceso denegado (403).
    """
    from functools import wraps
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            rol = session.get('rol', '')

            if not has_permission(rol, modulo):
                # Registrar el rechazo en audit_log
                _registrar_acceso_denegado(modulo, f.__name__)

                return render_template(
                    'acceso_denegado.html',
                    modulo=modulo,
                    rol=rol,
                    nombre=session.get('nombre', 'Usuario'),
                ), 403

            return f(*args, **kwargs)
        return decorated
    return decorator


app.register_blueprint(create_audit_blueprint(lambda: get_db(), login_required, modulo_required))
register_audit_mail_command(app, lambda: get_db())


# ── B7: política de retención (comandos de administración) ───────────────────
import click  # noqa: E402  (Flask ya depende de click)


@app.cli.command('retencion-resumen')
def _cli_retencion_resumen():
    """Muestra el plazo de retención y cuántos eventos ya lo cumplieron."""
    from audit_tracer.retencion import resumen
    with closing(get_db()) as conn:
        click.echo(json.dumps(resumen(conn), ensure_ascii=False, indent=2))


@app.cli.command('retencion-archivar')
@click.option('--destino', required=True, help='Carpeta donde se escribe el archivo de conservación.')
@click.option('--hasta', default=None, help='Archiva eventos anteriores a esta fecha ISO (por defecto, el límite).')
def _cli_retencion_archivar(destino, hasta):
    """Escribe el archivo verificable (JSONL + manifiesto) de los eventos que cumplieron el plazo. No borra nada."""
    from audit_tracer.merkle import _DEFAULT_ANCHORS_DIR
    from audit_tracer.retencion import archivar
    with closing(get_db()) as conn:
        manifiesto = archivar(conn, destino, hasta=hasta, anchors_dir=_DEFAULT_ANCHORS_DIR)
    click.echo(json.dumps(manifiesto, ensure_ascii=False, indent=2))


@app.cli.command('retencion-verificar')
@click.option('--destino', required=True, help='Carpeta de un archivo generado con retencion-archivar.')
def _cli_retencion_verificar(destino):
    """Comprueba, sin la base, que un archivo de conservación no cambió."""
    from audit_tracer.retencion import verificar_archivo
    resultado = verificar_archivo(destino)
    click.echo(json.dumps(resultado, ensure_ascii=False, indent=2))
    raise SystemExit(0 if resultado['valido'] else 1)


@app.context_processor
def audit_navigation():
    role = session.get("rol", "") if session.get("usuario_id") else ""
    return {
        "audit_available": has_permission(role, "consulta_reportes"),
        "audit_alert_available": can_review_alerts(role),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# RUTAS PÚBLICAS
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/')
def landing():
    """Landing page del sistema."""
    return render_template('landing.html')


# ── LOGIN ────────────────────────────────────────────────────────────────────

def _next_es_seguro(next_url: str) -> bool:
    """Solo redirige a rutas relativas propias — nunca a una URL externa."""
    return (
        next_url.startswith('/') and not next_url.startswith('//')
        and '\\' not in next_url and not any(ord(char) < 32 for char in next_url)
    )


@app.route('/login', methods=['GET'])
def login():
    """Muestra el formulario de login."""
    next_url = request.args.get('next', '')
    if session.get('usuario_id'):
        if _sesion_web_activa():
            return redirect(next_url if _next_es_seguro(next_url) else url_for('dashboard'))
        session.clear()
        flash(MENSAJE_SESION_INVALIDA, 'warning')
    return render_template('auth/login.html', next=next_url)


@app.route('/login', methods=['POST'])
def login_post():
    """Procesa el formulario de login."""
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '').strip()
    next_url = request.form.get('next', '')

    if not email or not password:
        return render_template('auth/login.html', error='Ingresa el correo y la contraseña.', next=next_url, email=email)

    try:
        with closing(get_db()) as conn:
            result = auth_login(
                conn, email, password, generate_session_id(),
                token_lifetime=app.permanent_session_lifetime,
            )
    except Exception:
        app.logger.exception('No se pudo iniciar la sesión web.')
        return render_template(
            'auth/login.html', error='El servicio de inicio de sesión no está disponible. Intenta de nuevo.',
            next=next_url, email=email,
        ), 503

    if result.get('success'):
        session.clear()
        session['usuario_id'] = result['usuario_id']
        session['rol'] = result['rol']
        session['nombre'] = email
        session['sesion_id'] = result['sesion_id']
        session['token_id'] = result['token_id']
        session['login_time'] = datetime.utcnow().isoformat()
        session['ultima_actividad'] = session['login_time']
        return redirect(next_url if _next_es_seguro(next_url) else url_for('dashboard'))
    else:
        return render_template('auth/login.html', error=result['message'], next=next_url, email=email)


# ── ADMINISTRACIÓN DE USUARIOS (Solo ADMIN) ─────────────────────────────────

@app.route('/admin/usuarios/nuevo', methods=['GET'])
@login_required
@admin_required
def nuevo_usuario():
    """Muestra el formulario de creación de usuario para el admin."""
    return render_template('admin/nuevo_usuario.html', 
                           nombre=session.get('nombre'), 
                           rol=session.get('rol'))


@app.route('/admin/usuarios/nuevo', methods=['POST'])
@login_required
@admin_required
def nuevo_usuario_post():
    """Procesa la creación de un nuevo usuario por parte del admin."""
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '').strip()
    confirmar = request.form.get('confirmar_password', '').strip()
    rol = request.form.get('rol', '').strip()

    if not email or not password or not confirmar or not rol:
        return render_template('admin/nuevo_usuario.html', error='Todos los campos son requeridos.')

    if password != confirmar:
        return render_template('admin/nuevo_usuario.html', error='Las contraseñas no coinciden.')

    problemas = problemas_contrasena(password, email)  # B5: la misma política que register_user()
    if problemas:
        return render_template('admin/nuevo_usuario.html', error=' '.join(problemas))

    roles_permitidos = ['ANALISTA', 'AUDITOR', 'CIENTIFICO_DATOS', 'ADMIN']
    if rol not in roles_permitidos:
        return render_template('admin/nuevo_usuario.html', error='Rol inválido.')

    try:
        with closing(get_db()) as conn:
            # Se usa el ID del administrador logueado para el registro de auditoría
            register_user(conn, email, password, rol, admin_id=session['usuario_id'])
    except ValueError as e:
        return render_template('admin/nuevo_usuario.html', error=str(e))
    except Exception:
        app.logger.exception('No se pudo crear el usuario.')
        return render_template('admin/nuevo_usuario.html',
                               error='No se pudo crear el usuario. El detalle quedó en el registro del servidor.')

    flash('Usuario creado correctamente.', 'success')
    return redirect(url_for('lista_usuarios'))

@app.route('/admin/usuarios')
@login_required
@modulo_required('gestion_usuarios')  # HU-1.4
def lista_usuarios():
    """Lista todos los usuarios del sistema."""
    conn = get_db()
    usuarios = get_all_users(conn)
    conn.close()
    return render_template('admin/usuarios.html',
                           usuarios=usuarios,
                           nombre=session.get('nombre'),
                           rol=session.get('rol'))


@app.route('/admin/usuarios/editar/<usuario_id>', methods=['GET'])
@login_required
@admin_required
def editar_usuario(usuario_id):
    """Muestra el formulario para editar el rol de un usuario."""
    conn = get_db()
    usuario = get_user_by_id(conn, usuario_id)
    llaves = listar_llaves(conn, usuario_id) if usuario else []
    conn.close()
    
    if not usuario:
        flash('Usuario no encontrado.', 'error')
        return redirect(url_for('lista_usuarios'))
        
    return render_template('admin/editar_usuario.html', 
                           usuario=usuario,
                           llaves=llaves,
                           nombre=session.get('nombre'), 
                           rol=session.get('rol'))


@app.route('/admin/usuarios/editar/<usuario_id>', methods=['POST'])
@login_required
@admin_required
def editar_usuario_post(usuario_id):
    """Procesa la modificación de rol de un usuario."""
    nuevo_rol = request.form.get('rol')
    
    try:
        conn = get_db()
        assign_role(conn, session['usuario_id'], usuario_id, nuevo_rol)
        conn.close()
        flash('Rol actualizado correctamente.', 'success')
        return redirect(url_for('lista_usuarios'))
    except ValueError as e:
        flash(str(e), 'error')
        return redirect(url_for('editar_usuario', usuario_id=usuario_id))
    except Exception:
        app.logger.exception('No se pudo cambiar el rol.')
        flash('No se pudo cambiar el rol. El detalle quedó en el registro del servidor.', 'error')
        return redirect(url_for('lista_usuarios'))


@app.route('/admin/usuarios/<usuario_id>/desbloquear', methods=['POST'])
@login_required
@admin_required
def desbloquear_usuario_post(usuario_id):
    """B6 / DSH-D1 — Un ADMIN reactiva una cuenta bloqueada; queda DESBLOQUEO_CUENTA en audit_log."""
    with closing(get_db()) as conn:
        exito = desbloquear_cuenta(conn, usuario_id, session['usuario_id'], session.get('sesion_id'))
    flash('Cuenta desbloqueada.' if exito else 'Usuario no encontrado.', 'success' if exito else 'error')
    return redirect(url_for('editar_usuario', usuario_id=usuario_id))


@app.route('/admin/usuarios/<usuario_id>/llaves/<int:llave_id>/revocar', methods=['POST'])
@login_required
@admin_required
def revocar_llave_post(usuario_id, llave_id):
    """
    SRV-S2 — Revoca una llave pública (p. ej. registrada con un token robado o
    de un equipo perdido). La llave deja de aceptar eventos nuevos; los que
    llegaron antes siguen verificándose.
    """
    with closing(get_db()) as conn:
        fila = revocar_llave(conn, llave_id, session['usuario_id'])
        if fila is not None and fila['usuario_id'] == usuario_id:
            insert_event(conn, {
                'usuario_id': session['usuario_id'],
                'sesion_id': session.get('sesion_id', 'N/A'),
                'timestamp': datetime.utcnow().isoformat(),
                'tipo_accion': 'REVOCACION_LLAVE_PUBLICA',
                'contexto_ejecucion': f"Usuario: {usuario_id} | Huella: {fila['huella']}",
                'nivel_alerta': 'ADVERTENCIA',
            })
            flash(f"Llave {fila['huella']} revocada.", 'success')
        else:
            flash('La llave no existe o ya estaba revocada.', 'error')
    return redirect(url_for('editar_usuario', usuario_id=usuario_id))


# ── ADMINISTRACIÓN DE TOKENS PERSONALES (HU-5.5) ───────────────────────────

@app.route('/admin/tokens', methods=['GET'])
@login_required
@admin_required
def lista_tokens():
    """
    HU-5.5 CA3 — Lista de tokens personales activos y filtrables por usuario/estado.
    """
    return _pagina_tokens()


def _pagina_tokens(token_nuevo: str = None):
    """
    B3: la base solo guarda el SHA-256 de cada token, así que el valor en
    claro se muestra una única vez, en la respuesta que lo genera.
    """
    usuario_id = request.args.get('usuario_id') or None
    estado = request.args.get('estado') or None

    conn = get_db()
    tokens = listar_tokens(conn, usuario_id=usuario_id, estado=estado)
    usuarios = get_all_users(conn)

    # Calcular métricas para el dashboard de tokens
    all_tokens = listar_tokens(conn)
    total_tokens = len(all_tokens)
    tokens_activos = len([t for t in all_tokens if t['estado'] == 'ACTIVO'])
    tokens_revocados = len([t for t in all_tokens if t['estado'] == 'REVOCADO'])
    tokens_expirados = len([t for t in all_tokens if t['estado'] == 'EXPIRADO'])

    conn.close()

    return render_template(
        'admin/tokens.html',
        tokens=tokens,
        usuarios=usuarios,
        filtros={'usuario_id': usuario_id, 'estado': estado},
        total_tokens=total_tokens,
        tokens_activos=tokens_activos,
        tokens_revocados=tokens_revocados,
        tokens_expirados=tokens_expirados,
        token_nuevo=token_nuevo,
        nombre=session.get('nombre'),
        rol=session.get('rol')
    )


@app.route('/admin/tokens/nuevo', methods=['POST'])
@login_required
@admin_required
def nuevo_token_post():
    """
    HU-5.5 CA1 & CA2 — Generación manual de tokens para un usuario por el administrador.
    """
    usuario_id = request.form.get('usuario_id', '').strip()
    dias_exp = request.form.get('dias_expiracion', '30').strip()

    try:
        dias_expiracion = int(dias_exp)
    except ValueError:
        dias_expiracion = 30

    if not usuario_id:
        flash('Debes seleccionar un usuario para generar el token.', 'error')
        return redirect(url_for('lista_tokens'))

    dias_expiracion = min(max(dias_expiracion, 1), 365)
    try:
        with closing(get_db()) as conn:
            token_info = generar_token(
                conn,
                usuario_id=usuario_id,
                dias_expiracion=dias_expiracion,
                creado_por='ADMIN',
                sesion_id=session.get('sesion_id', 'N/A'),
                admin_id=session.get('usuario_id')
            )
    except ValueError as e:
        flash(str(e), 'error')
        return redirect(url_for('lista_tokens'))
    except Exception:
        app.logger.exception('No se pudo generar el token.')
        flash('No se pudo generar el token. El detalle quedó en el registro del servidor.', 'error')
        return redirect(url_for('lista_tokens'))

    flash(f'Token generado con vigencia de {dias_expiracion} días. Cópialo ahora: no se volverá a mostrar.', 'success')
    return _pagina_tokens(token_nuevo=token_info['token'])


@app.route('/admin/tokens/revocar/<token_id>', methods=['POST'])
@login_required
@admin_required
def revocar_token_post(token_id):
    """
    HU-5.5 CA4 — Revocación manual de un token desde el dashboard.
    """
    try:
        conn = get_db()
        exito, mensaje = revocar_token(
            conn,
            token_id_o_str=token_id,
            admin_id=session.get('usuario_id'),
            sesion_id=session.get('sesion_id', 'N/A'),
            motivo='Revocación manual desde dashboard de administración'
        )
        conn.close()

        if exito:
            flash('Token revocado exitosamente. Ha dejado de ser válido de inmediato.', 'success')
        else:
            flash('Token no encontrado.', 'error')
    except Exception:
        app.logger.exception('No se pudo revocar el token.')
        flash('No se pudo revocar el token. El detalle quedó en el registro del servidor.', 'error')

    return redirect(url_for('lista_tokens'))


# ── DIAGNÓSTICO DE SINCRONIZACIÓN (HU-5.8 Sub-tarea 6) ─────────────────────────

@app.route('/admin/sincronizacion')
@login_required
@admin_required
def admin_sincronizacion():
    """
    HU-5.8 Sub-tarea 6 — Panel de diagnóstico de sincronización.

    Combina dos fuentes con alcance distinto:
      - Cola local de ESTA instancia (audit_trail.db, si existe en este
        filesystem): pendientes / fallidos / sincronizados / último intento
        / último error — leído directamente de audit_sync_queue.
      - Rechazos de autenticación que el servidor central sí observó de
        verdad (tipo_accion = SINCRONIZACION_RECHAZADA), sin exponer tokens.

    En un despliegue distribuido real, un Colab remoto corre en otra
    máquina: el servidor central NO puede ver la cola local de un cliente
    que nunca llegó a conectarse (eso requeriría que el cliente reporte su
    propio estado, protocolo fuera del alcance de esta HU). El panel de
    cola local, por eso, se etiqueta explícitamente como "esta instancia".
    """
    cola_local = None
    try:
        conn_local = get_connection()
        cola_local = get_sync_queue_summary(conn_local)
        conn_local.close()
    except Exception:
        cola_local = None

    from audit_tracer.monitoreo_sesiones import sesiones_sin_cierre
    conn = get_db()
    rechazos = get_events(conn, tipo_accion='SINCRONIZACION_RECHAZADA', orden_desc=True)
    # LIB-D2 / CAN-D1: sesiones de la librería que dejaron de reportar.
    sesiones_abiertas = sesiones_sin_cierre(conn, horas=float(os.environ.get('AUDIT_HORAS_SESION_SIN_CIERRE', '24')))
    conn.close()

    return render_template(
        'admin/sincronizacion.html',
        nombre=session.get('nombre', 'Usuario'),
        rol=session.get('rol', 'N/A'),
        cola_local=cola_local,
        total_rechazos=len(rechazos),
        rechazos_recientes=rechazos[:10],
        sesiones_abiertas=sesiones_abiertas,
    )


# ── ALERTAS EN TIEMPO REAL (HU-7.2 Sub-tarea 4) ────────────────────────────────

import re as _re
_EMAIL_RE = _re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')


def _auditar_config_alertas(conn, detalle: str) -> None:
    """Deja constancia en audit_log de cada cambio en la configuración de alertas."""
    try:
        insert_event(conn, {
            'usuario_id': session.get('usuario_id', 'DESCONOCIDO'),
            'sesion_id': session.get('sesion_id', 'N/A'),
            'timestamp': datetime.utcnow().isoformat(),
            'tipo_accion': 'CONFIGURACION_ALERTAS',
            'contexto_ejecucion': detalle,
            'nivel_alerta': 'NORMAL',
        })
    except Exception:
        pass


def _tipos_evento_del_form() -> list:
    return [t for t in request.form.getlist('tipos_evento') if t in CATALOGO_EVENTOS_CRITICOS]


@app.route('/admin/alertas')
@login_required
@admin_required
def admin_alertas():
    """
    HU-7.2 — Configuración de alertas: catálogo de eventos críticos (CA1),
    a quién se notifica y con qué severidad (Sub-tarea 4), estado del
    servicio de correo e historial de notificaciones enviadas.
    """
    conn = get_db()
    destinatarios = alertas_model.listar_destinatarios(conn)
    for d in destinatarios:
        if d['tipo_destino'] == 'ROL':
            d['correos'] = [r[0] for r in conn.execute(
                "SELECT email FROM usuarios WHERE rol = ? AND activo = 1 ORDER BY email",
                (d['valor'],),
            ).fetchall()]
    notificaciones = alertas_model.listar_notificaciones(conn, limite=50)
    resumen = alertas_model.resumen_notificaciones(conn, horas=24)
    conn.close()

    despachador = obtener_despachador()
    servicio = despachador.servicio_correo if despachador else None
    return render_template(
        'admin/alertas.html',
        nombre=session.get('nombre', 'Usuario'),
        rol=session.get('rol', 'N/A'),
        catalogo=list(CATALOGO_EVENTOS_CRITICOS.values()),
        catalogo_nombres={c: t.nombre for c, t in CATALOGO_EVENTOS_CRITICOS.items()},
        severidades=alertas_model.SEVERIDADES,
        roles=sorted(PERMISSION_MATRIX.keys()),
        destinatarios=destinatarios,
        notificaciones=notificaciones,
        resumen=resumen,
        despachador_activo=bool(despachador and despachador.activo),
        servicio_descripcion=servicio.descripcion() if servicio else None,
        remitente=servicio.remitente if servicio else None,
        url_base=despachador.url_base if despachador else None,
    )


@app.route('/admin/alertas/destinatarios', methods=['POST'])
@login_required
@admin_required
def admin_alertas_crear_destinatario():
    tipo = request.form.get('tipo_destino', '').upper()
    valor = request.form.get('valor_rol') if tipo == 'ROL' else request.form.get('valor_email')
    valor = (valor or '').strip()
    severidad = request.form.get('severidad_minima', 'MEDIA').upper()
    tipos = _tipos_evento_del_form()

    if tipo not in alertas_model.TIPOS_DESTINO:
        flash('Tipo de destinatario inválido.', 'error')
    elif severidad not in alertas_model.SEVERIDADES:
        flash('Severidad inválida.', 'error')
    elif tipo == 'ROL' and valor.upper() not in PERMISSION_MATRIX:
        flash('Rol inválido.', 'error')
    elif tipo == 'EMAIL' and not _EMAIL_RE.match(valor):
        flash('Correo electrónico inválido.', 'error')
    else:
        conn = get_db()
        try:
            alertas_model.crear_destinatario(
                conn, tipo, valor, severidad, tipos, creado_por=session.get('usuario_id', 'SISTEMA')
            )
            _auditar_config_alertas(
                conn, f"Alta destinatario {tipo}={valor} | severidad>={severidad} | "
                      f"tipos={','.join(tipos) or 'TODOS'}"
            )
            flash(f'Destinatario {valor} agregado.', 'success')
        except sqlite3.IntegrityError:
            flash(f'El destinatario {valor} ya existe.', 'error')
        finally:
            conn.close()
    return redirect(url_for('admin_alertas'))


@app.route('/admin/alertas/destinatarios/<int:destinatario_id>', methods=['POST'])
@login_required
@admin_required
def admin_alertas_actualizar_destinatario(destinatario_id):
    accion = request.form.get('accion', 'actualizar')
    conn = get_db()
    try:
        dest = alertas_model.obtener_destinatario(conn, destinatario_id)
        if dest is None:
            flash('Destinatario no encontrado.', 'error')
        elif accion == 'eliminar':
            alertas_model.eliminar_destinatario(conn, destinatario_id)
            _auditar_config_alertas(conn, f"Baja destinatario {dest['tipo_destino']}={dest['valor']}")
            flash(f"Destinatario {dest['valor']} eliminado.", 'success')
        elif accion == 'alternar':
            alertas_model.actualizar_destinatario(conn, destinatario_id, activo=not dest['activo'])
            _auditar_config_alertas(
                conn, f"{'Desactivado' if dest['activo'] else 'Activado'} destinatario "
                      f"{dest['tipo_destino']}={dest['valor']}"
            )
            flash(f"Destinatario {dest['valor']} {'desactivado' if dest['activo'] else 'activado'}.", 'success')
        else:
            severidad = request.form.get('severidad_minima', '').upper()
            if severidad not in alertas_model.SEVERIDADES:
                flash('Severidad inválida.', 'error')
            else:
                tipos = _tipos_evento_del_form()
                alertas_model.actualizar_destinatario(
                    conn, destinatario_id, severidad_minima=severidad, tipos_evento=tipos
                )
                _auditar_config_alertas(
                    conn, f"Cambio destinatario {dest['tipo_destino']}={dest['valor']} | "
                          f"severidad>={severidad} | tipos={','.join(tipos) or 'TODOS'}"
                )
                flash(f"Destinatario {dest['valor']} actualizado.", 'success')
    finally:
        conn.close()
    return redirect(url_for('admin_alertas'))


@app.route('/admin/alertas/prueba', methods=['POST'])
@login_required
@admin_required
def admin_alertas_prueba():
    """Envía un correo de prueba para validar el servicio de envío configurado."""
    destino = (request.form.get('destino') or '').strip()
    despachador = obtener_despachador()
    if not _EMAIL_RE.match(destino):
        flash('Correo electrónico inválido.', 'error')
    elif despachador is None:
        flash('Las alertas en tiempo real están desactivadas en este servidor.', 'error')
    else:
        try:
            despachador.enviar_prueba(destino)
            flash(f'Correo de prueba enviado a {destino}.', 'success')
        except ErrorEnvioCorreo as exc:
            flash(f'No se pudo enviar el correo de prueba: {exc}', 'error')
    return redirect(url_for('admin_alertas'))


# ── API ENDPOINTS DE TOKENS (HU-5.5 CA5 / HU-6.1 ready) ───────────────────────

@app.route('/api/tokens/validar', methods=['POST'])
def api_validar_token():
    """
    HU-5.5 CA5 — Endpoint API para validar un token de acceso (vigente / revocado / expirado).
    """
    data = request.get_json(silent=True) or {}
    token_str = data.get('token')

    # Soporte también para Header 'Authorization: Bearer <token>'
    if not token_str and 'Authorization' in request.headers:
        auth_header = request.headers['Authorization']
        if auth_header.startswith('Bearer '):
            token_str = auth_header.split(' ', 1)[1]

    if not token_str:
        return jsonify({
            'valido': False,
            'mensaje': 'Token no proporcionado',
            'estado': 'NO_PROPORCIONADO'
        }), 400

    conn = get_db()
    valido, mensaje, token_data = validar_token(conn, token_str)
    conn.close()

    if not valido:
        estado = token_data.get('estado', 'INVALIDO') if token_data else 'INEXISTENTE'
        return jsonify({
            'valido': False,
            'mensaje': mensaje,
            'estado': estado
        }), 401

    return jsonify({
        'valido': True,
        'mensaje': mensaje,
        'estado': token_data.get('estado', 'ACTIVO'),
        'usuario_id': token_data.get('usuario_id'),
        'fecha_expiracion': token_data.get('fecha_expiracion')
    }), 200


@app.route('/api/tokens/revocar', methods=['POST'])
@login_required
@admin_required
def api_revocar_token():
    """
    HU-5.5 CA4 — Endpoint API para revocar un token.
    """
    data = request.get_json(silent=True) or {}
    token_target = data.get('token_id') or data.get('token')

    if not token_target:
        return jsonify({'success': False, 'message': 'Se requiere token_id o token'}), 400

    conn = get_db()
    exito, mensaje = revocar_token(
        conn,
        token_id_o_str=token_target,
        admin_id=session.get('usuario_id'),
        sesion_id=session.get('sesion_id', 'N/A'),
        motivo=data.get('motivo', 'Revocación solicitada vía API')
    )
    conn.close()

    status_code = 200 if exito else 404
    return jsonify({'success': exito, 'message': mensaje if exito else 'Token no encontrado.'}), status_code


# ── LOGIN POR CÓDIGO DE DISPOSITIVO (HU-5.7) ──────────────────────────────────

@app.route('/api/auth/dispositivo/iniciar', methods=['POST'])
def api_iniciar_login_dispositivo():
    """
    HU-5.7 CA1 — Genera un código corto + URL de activación para que la
    librería (notebook/script) los muestre. Sin autenticación: es el
    primer paso del flujo, antes de que exista ningún token.
    """
    cuerpo = request.get_json(silent=True) or {}
    origen = {  # CAN-S2: se muestra en la página de confirmación
        'ip': request.remote_addr,
        'agente': request.headers.get('User-Agent'),
        'host': cuerpo.get('host') if isinstance(cuerpo.get('host'), str) else None,
    }
    with closing(get_db()) as conn:
        purgar_codigos_vencidos(conn)  # SRV-D1: los códigos vencidos no se acumulan
        datos = iniciar_login_dispositivo(conn, origen=origen)

    url_activacion = url_for('confirmar_dispositivo', codigo=datos['codigo'], _external=True)
    return jsonify({
        'codigo': datos['codigo'],
        'device_code': datos['device_code'],
        'url_activacion': url_activacion,
        'expira_en_segundos': CODIGO_EXPIRACION_MINUTOS * 60,
        'intervalo_polling': INTERVALO_POLLING_SEGUNDOS,
    }), 201


@app.route('/auth/dispositivo', methods=['GET'])
@login_required
def confirmar_dispositivo():
    """HU-5.7 CA2 — Página del dashboard para confirmar un código de login por dispositivo."""
    codigo = request.args.get('codigo', '').strip().upper()
    return render_template('auth/confirmar_dispositivo.html', codigo=codigo, origen=_origen_codigo(codigo))


def _origen_codigo(codigo: str):
    """CAN-S2 — Quién pidió el código (IP, equipo, hora), para que el usuario reconozca su propio pedido."""
    if not codigo:
        return None
    try:
        with closing(get_db()) as conn:
            registro = get_by_codigo(conn, codigo)
    except sqlite3.Error:
        return None
    if not registro or registro.get('estado') != 'PENDIENTE':
        return None
    return {
        'ip': registro.get('ip_origen'),
        'host': registro.get('host_origen'),
        'agente': registro.get('agente_origen'),
        'creado': formatear_fecha(registro.get('fecha_creacion')),
    }


@app.route('/auth/dispositivo', methods=['POST'])
@login_required
def confirmar_dispositivo_post():
    """HU-5.7 CA2 — Procesa la confirmación del código, ya autenticado en el dashboard."""
    codigo = request.form.get('codigo', '').strip().upper()

    if not codigo:
        return render_template('auth/confirmar_dispositivo.html', error='Ingresa el código.', codigo='')

    conn = get_db()
    exito, mensaje = confirmar_codigo(
        conn, codigo, session['usuario_id'], sesion_id=session.get('sesion_id', 'DEVICE_LOGIN')
    )
    conn.close()

    if exito:
        return render_template('auth/confirmar_dispositivo.html', success=mensaje, codigo='')
    return render_template('auth/confirmar_dispositivo.html', error=mensaje, codigo=codigo,
                           origen=_origen_codigo(codigo))


@app.route('/api/auth/dispositivo/estado', methods=['GET', 'POST'])
def api_estado_login_dispositivo():
    """
    HU-5.7 CA3 — Polling del estado de un device_code. Sin autenticación
    por token: el device_code largo y secreto ES la credencial (nunca se
    muestra al usuario, solo lo conoce el proceso que llamó a /iniciar).

    CAN-I2: la librería consulta por POST con el device_code en el cuerpo
    JSON (no queda en logs de acceso ni en el historial del proxy). GET con
    ?device_code= se mantiene por compatibilidad con versiones anteriores.
    """
    if request.method == 'POST':
        cuerpo = request.get_json(silent=True) or {}
        device_code = cuerpo.get('device_code') if isinstance(cuerpo.get('device_code'), str) else ''
    else:
        device_code = request.args.get('device_code', '')
    if not device_code:
        return jsonify({'estado': 'INVALIDO'}), 400

    conn = get_db()
    resultado = consultar_estado(conn, device_code)
    conn.close()

    codigos_estado_http = {'INVALIDO': 404, 'CONSUMIDO': 410}
    return jsonify(resultado), codigos_estado_http.get(resultado['estado'], 200)


# ── ENDPOINT RECEPTOR DE EVENTOS (HU-5.6, construido inicialmente dentro ──────
# ── de HU-5.8 porque su cliente no tenía a dónde sincronizar sin él) ──────────

# Campos NOT NULL en audit_log/audit_log_central: sin ellos el INSERT
# fallaría con un error de esquema, así que se validan antes de tocar la BD.
_CAMPOS_EVENTO_REQUERIDOS = ('evento_uuid', 'usuario_id', 'sesion_id', 'timestamp', 'tipo_accion')

# Mismos nombres de columna que audit_tracer/schema/audit_log.sql / audit_log_central.sql —
# el payload JSON usa exactamente estos campos (ver README HU-5.8).
_CAMPOS_EVENTO_ACEPTADOS = _CAMPOS_EVENTO_REQUERIDOS + (
    'dataset_nombre', 'columnas_afectadas', 'ruta_destino', 'filas_exportadas',
    'sobrescritura', 'contexto_ejecucion', 'motivo_fallo', 'nivel_alerta', 'motivo_alerta',
    'firma_digital',  # HU-6.1 CA2/CA4 — la firma viaja y se persiste junto al evento
)


def _peticion_es_segura() -> bool:
    """
    HU-5.6 CA5 — Exige HTTPS para el endpoint de sincronización, con la
    misma excepción que ya aplica sync_client.py del lado del cliente
    (audit_tracer/sync_client.py::_validar_https()): localhost/127.0.0.1
    se permite sin TLS, únicamente para pruebas y desarrollo local.
    """
    if request.is_secure:
        return True
    host = (request.host or '').split(':')[0]
    return host in ('localhost', '127.0.0.1')


def _registrar_anomalia_de_evento_firmado(conn, registro, motivos) -> None:
    """HU-6.3 — Agrega ANOMALIA_DETECTADA para un evento firmado (una por sesión y conjunto de reglas)."""
    evento_anomalia = construir_evento_anomalia(registro, motivos, registro.get('event_id'))
    existe = conn.execute(
        "SELECT 1 FROM audit_log WHERE tipo_accion = ? AND sesion_id = ? AND usuario_id = ? AND motivo_fallo = ?",
        (TIPO_EVENTO_ANOMALIA, evento_anomalia['sesion_id'], evento_anomalia['usuario_id'],
         evento_anomalia['motivo_fallo'])).fetchone()
    if not existe:
        insert_event(conn, evento_anomalia)


def _token_bearer():
    autorizacion = request.headers.get('Authorization', '')
    if autorizacion.startswith('Bearer '):
        return autorizacion.split(' ', 1)[1].strip()
    return None


def firma_obligatoria() -> bool:
    """
    CAN-T2: con AUDIT_EXIGIR_FIRMA=1 el servidor rechaza todo evento sin firma,
    también de usuarios que aún no registraron llave (la librería actual
    firma siempre). Sin la variable, se exige firma solo a quien ya tiene llave.
    """
    return os.environ.get('AUDIT_EXIGIR_FIRMA') == '1'


def _rechazo_firma(conn, usuario_id, motivo, recibido_en):
    try:
        insert_event(conn, {
            'usuario_id': usuario_id,
            'sesion_id': 'SINCRONIZACION',
            'timestamp': recibido_en.isoformat(),
            'tipo_accion': 'FIRMA_INVALIDA',
            'motivo_fallo': motivo,
            'nivel_alerta': 'CRITICO',
        })
    except Exception:
        app.logger.exception('No se pudo registrar FIRMA_INVALIDA.')


def _registrar_reclasificacion(conn, registro, nivel_servidor, motivos, recibido_en) -> None:
    """SRV-T3 — Evento del servidor para un evento firmado con nivel declarado menor al calculado."""
    evento = evento_reclasificacion(registro, nivel_servidor, motivos, recibido_en)
    solo_desfase = all(m.startswith(('Evento recibido', 'Timestamp del cliente')) for m in motivos)
    if solo_desfase:
        # Un lote sincronizado tarde: un aviso por sesión, no uno por evento.
        existe = conn.execute(
            "SELECT 1 FROM audit_log WHERE tipo_accion = ? AND sesion_id = ? AND usuario_id = ? AND motivo_fallo = ?",
            (TIPO_EVENTO_RECLASIFICACION, evento['sesion_id'], evento['usuario_id'], evento['motivo_fallo'])
        ).fetchone()
        if existe:
            return
    insert_event(conn, evento)


@app.route('/api/eventos/sincronizar', methods=['POST'])
def api_sincronizar_evento():
    """
    HU-5.6 CA1-CA5 — Endpoint receptor de eventos sincronizados desde la
    librería (Colab u otro entorno).

    1. CA5: exige HTTPS (excepto localhost, para pruebas/dev).
    2. CA2: autentica al emisor con un token personal (HU-5.5/HU-6.2).
    3. CA1: valida que el payload traiga los campos NOT NULL del esquema.
    4. SRV-S1 (21/11/2026): el usuario del evento debe ser el dueño del token
       (o DESCONOCIDO, para eventos capturados antes del login); si no, 403 y
       un SINCRONIZACION_RECHAZADA CRITICO.
    5. HU-6.1 / SRV-R2: la firma se verifica con las llaves del dueño del
       token vigentes al recibir el evento (historial de llaves).
    6. SRV-T3: el servidor recalcula la criticidad y guarda la fecha de
       recepción con su propio reloj.
    7. CA3/CA4: inserta de forma idempotente por evento_uuid.
    """
    if not _peticion_es_segura():
        return jsonify({
            'status': 'error',
            'mensaje': 'Esta operación requiere HTTPS (excepto en localhost, para pruebas/dev).',
        }), 426  # 426 Upgrade Required — el código HTTP pensado para exigir un cambio de protocolo

    token_str = _token_bearer()
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({'status': 'error', 'mensaje': 'Se esperaba un cuerpo JSON con los campos del evento'}), 400

    recibido_en = datetime.utcnow()
    conn = get_db()
    try:
        # CA4: validar el token del emisor ANTES de aceptar el evento.
        valido, mensaje, token_data = validar_token(conn, token_str)
        if not valido:
            # Deja constancia del rechazo en auditoría sin exponer el valor del token.
            try:
                insert_event(conn, {
                    'usuario_id': (token_data or {}).get('usuario_id', 'DESCONOCIDO'),
                    'sesion_id': 'SINCRONIZACION',
                    'timestamp': recibido_en.isoformat(),
                    'tipo_accion': 'SINCRONIZACION_RECHAZADA',
                    'motivo_fallo': mensaje,
                    'nivel_alerta': 'ADVERTENCIA',
                })
            except Exception:
                app.logger.exception('No se pudo registrar SINCRONIZACION_RECHAZADA.')
            return jsonify({'status': 'error', 'mensaje': mensaje}), 401

        evento = {campo: data.get(campo) for campo in _CAMPOS_EVENTO_ACEPTADOS if campo in data}
        faltantes = [c for c in _CAMPOS_EVENTO_REQUERIDOS if not evento.get(c)]
        if faltantes:
            return jsonify({
                'status': 'error',
                'mensaje': f"Campos requeridos faltantes: {', '.join(faltantes)}",
            }), 400

        dueno = token_data['usuario_id']

        # SRV-S1 / LIB-S1 — nadie sincroniza eventos a nombre de otro usuario.
        if evento['usuario_id'] not in (dueno, 'DESCONOCIDO'):
            insert_event(conn, {
                'usuario_id': dueno,
                'sesion_id': 'SINCRONIZACION',
                'timestamp': recibido_en.isoformat(),
                'tipo_accion': 'SINCRONIZACION_RECHAZADA',
                'motivo_fallo': (
                    f"El evento {evento.get('evento_uuid')} dice ser del usuario {evento['usuario_id']}, "
                    f"pero el token pertenece a {dueno}"
                ),
                'nivel_alerta': 'CRITICO',
                'motivo_alerta': 'Posible suplantación: el usuario del evento no es el dueño del token',
            })
            return jsonify({
                'status': 'error', 'motivo': 'USUARIO_NO_COINCIDE',
                'mensaje': 'El usuario del evento no corresponde al dueño del token.',
            }), 403

        # HU-6.1 CA3 / HU-6.5 CA4 / CAN-T2 — firma digital.
        firmado = bool(evento.get('firma_digital'))
        tiene_llaves = usuario_tiene_llaves(conn, dueno)
        if not firmado and (tiene_llaves or firma_obligatoria()):
            # Ataque de degradación: quitarle la firma a un evento manipulado no
            # puede ser la forma de saltarse la verificación.
            _rechazo_firma(conn, dueno, (
                f"Evento sin firma de un usuario {'con llave registrada' if tiene_llaves else 'sin llave registrada'} "
                f"(evento_uuid={evento.get('evento_uuid')})"), recibido_en)
            return jsonify({
                'status': 'error',
                'mensaje': (
                    'Evento sin firma digital: el usuario tiene una llave pública registrada, '
                    'así que todos sus eventos deben venir firmados.' if tiene_llaves else
                    'Evento sin firma digital: este servidor exige que todos los eventos vengan firmados.'
                ),
            }), 422
        if firmado:
            if not tiene_llaves:
                return jsonify({
                    'status': 'error',
                    'mensaje': (
                        'El usuario no tiene llave pública registrada en el servidor. '
                        'La librería debe registrar la llave al autenticarse (HU-6.1 CA1).'
                    ),
                }), 422
            firma_valida, _ = verificar_con_historial(conn, evento, recibido_en.isoformat(), usuario_id=dueno)
            if not firma_valida:
                _rechazo_firma(conn, dueno, f"Firma inválida para evento_uuid={evento.get('evento_uuid')}", recibido_en)
                return jsonify({
                    'status': 'error',
                    'mensaje': (
                        'Firma digital inválida: el evento fue manipulado tras la firma '
                        'o la firma no corresponde a una llave vigente del usuario.'
                    ),
                }), 422

        # SRV-T3 — clasificación del servidor y fecha de recepción.
        evento['recibido_en'] = recibido_en.isoformat()
        nivel_servidor, motivos_servidor = clasificar_en_servidor(evento, recibido_en)
        motivos_reclasificacion = []
        motivos_anomalia = []
        if not firmado:
            # Sin firma, el evento se guarda ya reclasificado y el detector de
            # anomalías (HU-6.3) puede marcarlo ANOMALIA o conservar CRITICO.
            evento = aplicar_a_evento_sin_firma(evento, recibido_en)
            try:
                _, evento, _ = evaluar_evento_anomalias(conn, evento)
            except Exception:
                app.logger.exception('El detector de anomalías falló; el evento se guarda igual.')
        else:
            # Con firma, nivel y motivo están firmados: el evento se guarda tal
            # como llegó y el servidor agrega sus propios eventos que lo referencian.
            nuevos = motivos_por_encima_de(evento, nivel_servidor, motivos_servidor)
            if rango_nivel(nivel_servidor) > rango_nivel(evento.get('nivel_alerta')) and nuevos:
                motivos_reclasificacion = nuevos
            if evento.get('tipo_accion') in ACCIONES_AUDITABLES_VOLUMEN:
                try:
                    _, _, motivos_anomalia = evaluar_evento_anomalias(conn, evento)
                except Exception:
                    motivos_anomalia = []

        try:
            registro, creado = insert_event_if_new(conn, evento)
        except sqlite3.IntegrityError:
            app.logger.exception('Evento rechazado por el esquema de la base central.')
            return jsonify({'status': 'error', 'mensaje': 'Evento inválido.'}), 400
        if creado and motivos_reclasificacion:
            try:
                _registrar_reclasificacion(conn, registro, nivel_servidor, motivos_reclasificacion, recibido_en)
            except Exception:
                app.logger.exception('No se pudo registrar RECLASIFICACION_SERVIDOR.')
        if creado and motivos_anomalia:
            try:
                _registrar_anomalia_de_evento_firmado(conn, registro, motivos_anomalia)
            except Exception:
                app.logger.exception('No se pudo registrar el evento ANOMALIA_DETECTADA.')
    finally:
        conn.close()

    return jsonify({
        'status': 'creado' if creado else 'duplicado',
        'event_id': registro['event_id'],
        'evento_uuid': registro['evento_uuid'],
    }), 201 if creado else 200


# ── REGISTRO DE LLAVE PÚBLICA (HU-6.1 CA1 / SRV-S2) ─────────────────────────

@app.route('/api/usuarios/llave-publica', methods=['POST'])
def api_registrar_llave_publica():
    """
    HU-6.1 CA1 — La librería llama a este endpoint justo después de
    autenticarse para registrar su llave pública Ed25519 en el servidor.

    SRV-S2 / SRV-R2 (21/11/2026): las llaves se acumulan en un historial
    (una por equipo) en lugar de reemplazarse en silencio:
      * la misma llave otra vez -> 200, sin cambios ni eventos;
      * una llave nueva -> 200 y REGISTRO_LLAVE_PUBLICA (ADVERTENCIA si el
        usuario ya tenía otra activa: alerta de "equipo nuevo");
      * una llave revocada por un ADMIN -> 409 y evento CRITICO.

    Autenticación: Bearer token. Cuerpo JSON: { "llave_publica": "<PEM Ed25519>" }
    """
    if not _peticion_es_segura():
        return jsonify({
            'status': 'error',
            'mensaje': 'Esta operación requiere HTTPS (excepto en localhost, para pruebas/dev).',
        }), 426

    conn = get_db()
    try:
        valido, mensaje, token_data = validar_token(conn, _token_bearer())
        if not valido:
            return jsonify({'status': 'error', 'mensaje': mensaje}), 401

        data = request.get_json(silent=True)
        if not isinstance(data, dict) or not isinstance(data.get('llave_publica'), str) or not data['llave_publica']:
            return jsonify({
                'status': 'error',
                'mensaje': 'Se esperaba un cuerpo JSON con el campo llave_publica (PEM Ed25519).',
            }), 400

        llave_publica_pem = data['llave_publica']
        try:
            from audit_tracer.digital_signatures import public_key_from_pem
            from cryptography.hazmat.primitives.asymmetric import ed25519
            if not isinstance(public_key_from_pem(llave_publica_pem), ed25519.Ed25519PublicKey):
                raise ValueError('no es Ed25519')
        except Exception:
            return jsonify({
                'status': 'error',
                'mensaje': 'El campo llave_publica no es un PEM Ed25519 válido.',
            }), 400

        dueno = token_data['usuario_id']
        resultado = registrar_llave(conn, dueno, llave_publica_pem, token_id=token_data.get('token_id'))
        contexto = (f"Huella: {resultado['huella']} | Llaves activas antes: {resultado['activas_previas']} | "
                    f"Token: {token_data.get('token_id')} | IP: {request.remote_addr}")
        if resultado['estado'] == 'REVOCADA':
            insert_event(conn, {
                'usuario_id': dueno, 'sesion_id': 'REGISTRO_LLAVE',
                'timestamp': datetime.utcnow().isoformat(), 'tipo_accion': 'REGISTRO_LLAVE_PUBLICA',
                'contexto_ejecucion': contexto, 'motivo_fallo': 'Intento de volver a registrar una llave revocada',
                'nivel_alerta': 'CRITICO',
            })
            return jsonify({
                'status': 'error', 'motivo': 'LLAVE_REVOCADA',
                'mensaje': 'Esa llave fue revocada por un administrador y no puede volver a usarse.',
            }), 409
        if resultado['estado'] == 'NUEVA':
            otra_activa = resultado['activas_previas'] > 0
            insert_event(conn, {
                'usuario_id': dueno, 'sesion_id': 'REGISTRO_LLAVE',
                'timestamp': datetime.utcnow().isoformat(), 'tipo_accion': 'REGISTRO_LLAVE_PUBLICA',
                'contexto_ejecucion': contexto,
                'nivel_alerta': 'ADVERTENCIA' if otra_activa else 'NORMAL',
                'motivo_alerta': ('Llave nueva para un usuario que ya tenía otra activa (equipo nuevo o token robado)'
                                  if otra_activa else None),
            })
    finally:
        conn.close()

    return jsonify({
        'status': 'ok',
        'mensaje': 'Llave pública registrada correctamente.' if resultado['estado'] == 'NUEVA'
                   else 'La llave ya estaba registrada.',
        'usuario_id': dueno,
        'huella': resultado['huella'],
        'nueva': resultado['estado'] == 'NUEVA',
    }), 200


# ═══════════════════════════════════════════════════════════════════════════════
# RUTAS PROTEGIDAS
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/dashboard')
@login_required
def dashboard():
    """Dashboard principal con métricas reales."""
    conn = get_db()

    # Obtener todos los eventos para métricas
    all_events = get_events(conn)

    # Integridad de los registros (recalcula y compara hash_integridad)
    registros_corruptos = len(verify_integrity(conn))

    # Eventos hoy
    hoy_inicio, hoy_fin = _limites_dia_colombia(
        ahora_colombia().date().isoformat(), ahora_colombia().date().isoformat())
    events_today = [e for e in all_events if hoy_inicio <= e['timestamp'] <= hoy_fin]
    
    # Alertas críticas y anomalías (HU-6.3)
    critical_alerts = [e for e in all_events if e['nivel_alerta'] == 'CRITICO']
    anomalias_detectadas = [e for e in all_events if e['nivel_alerta'] == 'ANOMALIA']

    # Usuarios únicos (basado en el log)
    unique_users = len(set(e['usuario_id'] for e in all_events))

    # Exportaciones de datos (HU-2.3 — PDGTRAZDSA-101)
    export_events = [e for e in all_events if e['tipo_accion'] == 'EXPORTACION']
    total_exportaciones = len(export_events)
    filas_exportadas_total = sum(e['filas_exportadas'] or 0 for e in export_events)
    exportaciones_criticas = len([e for e in export_events if e['nivel_alerta'] == 'CRITICO'])

    # Intentos fallidos de acceso — HU-2.4 (CA3: accesos fallidos del día)
    accesos_fallidos_hoy = len([
        e for e in events_today if e['tipo_accion'] == 'ACCESO_FALLIDO'
    ])
    accesos_fallidos_criticos_hoy = len([
        e for e in events_today
        if e['tipo_accion'] == 'ACCESO_FALLIDO' and e['nivel_alerta'] == 'CRITICO'
    ])

    # Distribución de eventos por tipo de acción (HU-4.2/4.4)
    top_tipos = Counter(e['tipo_accion'] for e in all_events).most_common(6)
    max_tipo_count = top_tipos[0][1] if top_tipos else 1
    eventos_por_tipo = [
        {'tipo': tipo, 'count': count, 'pct': round(count / max_tipo_count * 100)}
        for tipo, count in top_tipos
    ]

    # Distribución por nivel de alerta (HU-4.4)
    nivel_counts = Counter(e['nivel_alerta'] or 'NORMAL' for e in all_events)
    max_nivel_count = max(nivel_counts.values()) if nivel_counts else 1
    alertas_por_nivel = [
        {'nivel': nivel, 'count': nivel_counts.get(nivel, 0), 'pct': round(nivel_counts.get(nivel, 0) / max_nivel_count * 100)}
        for nivel in ('NORMAL', 'ADVERTENCIA', 'ANOMALIA', 'CRITICO')
    ]

    # Eventos críticos agrupados por causa (HU-4.4 CA1)
    criticos_por_causa = Counter(
        _categorize_critical_reason(e['motivo_alerta']) for e in critical_alerts
    ).most_common(5)

    conn.close()

    return render_template(
        'dashboard/index.html',
        nombre=session.get('nombre', 'Usuario'),
        rol=session.get('rol', 'N/A'),
        total_eventos=len(all_events),
        eventos_hoy=len(events_today),
        usuarios_activos=unique_users,
        alertas_criticas=len(critical_alerts),
        total_anomalias=len(anomalias_detectadas),  # HU-6.3
        registros_corruptos=registros_corruptos,
        total_exportaciones=total_exportaciones,
        filas_exportadas_total=filas_exportadas_total,
        exportaciones_criticas=exportaciones_criticas,
        accesos_fallidos_hoy=accesos_fallidos_hoy,                    # HU-2.4
        accesos_fallidos_criticos_hoy=accesos_fallidos_criticos_hoy,  # HU-2.4
        eventos_por_tipo=eventos_por_tipo,
        alertas_por_nivel=alertas_por_nivel,
        criticos_por_causa=criticos_por_causa,
        now_date=ahora_colombia().strftime('%Y-%m-%d %H:%M')
    )


def _usuario_id_desde_filtro(conn, valor):
    """
    Los filtros de usuario aceptan el ID o el correo. Si el valor parece un correo se
    traduce al usuario_id de esa cuenta (sin distinguir mayúsculas); si no existe,
    se devuelve tal cual y el filtro no encuentra eventos.
    """
    valor = (valor or '').strip() or None
    if valor and '@' in valor:
        fila = conn.execute(
            "SELECT usuario_id FROM usuarios WHERE lower(email) = lower(?)", (valor,)).fetchone()
        if fila:
            return fila[0]
    return valor


@app.route('/reportes')
@login_required
@modulo_required('consulta_reportes')  # HU-1.4
def reportes():
    """Reportes de auditoría: distribución de eventos y eventos críticos recientes."""
    conn = get_db()
    all_events = get_events(conn)
    critical_events = get_critical_events(conn)
    conn.close()

    top_tipos = Counter(e['tipo_accion'] for e in all_events).most_common(8)
    max_tipo_count = top_tipos[0][1] if top_tipos else 1
    eventos_por_tipo = [
        {'tipo': tipo, 'count': count, 'pct': round(count / max_tipo_count * 100)}
        for tipo, count in top_tipos
    ]

    criticos_por_causa = Counter(
        _categorize_critical_reason(e['motivo_alerta']) for e in critical_events
    ).most_common()

    ultimos_criticos = list(reversed(critical_events))[:10]

    # HU-4.5 CA1 — Reporte de auditoría filtrable por usuario/fecha/acción/dataset.
    reporte_usuario_id = request.args.get('reporte_usuario_id')
    reporte_tipo_accion = request.args.get('reporte_tipo_accion')
    reporte_dataset_nombre = request.args.get('reporte_dataset_nombre')
    reporte_fecha_inicio = request.args.get('reporte_fecha_inicio')
    reporte_fecha_fin = request.args.get('reporte_fecha_fin')

    # Mismo criterio que /eventos: ampliar 'YYYY-MM-DD' a los límites del día
    # para que la comparación lexicográfica sobre el timestamp ISO 8601 cubra
    # el día completo.
    reporte_fecha_inicio_query, reporte_fecha_fin_query = _limites_dia_colombia(
        reporte_fecha_inicio, reporte_fecha_fin)

    conn = get_db()
    reporte_eventos = generate_report(
        conn,
        usuario_id=_usuario_id_desde_filtro(conn, reporte_usuario_id),
        fecha_inicio=reporte_fecha_inicio_query,
        fecha_fin=reporte_fecha_fin_query,
        tipo_accion=reporte_tipo_accion,
        dataset_nombre=reporte_dataset_nombre,
    )
    conn.close()

    reporte_filtros = {
        'reporte_usuario_id': reporte_usuario_id,
        'reporte_tipo_accion': reporte_tipo_accion,
        'reporte_dataset_nombre': reporte_dataset_nombre,
        'reporte_fecha_inicio': reporte_fecha_inicio,
        'reporte_fecha_fin': reporte_fecha_fin,
    }
    _auditar_acceso_bitacora('CONSULTA_BITACORA', '/reportes', reporte_filtros, filas=len(reporte_eventos))

    return render_template(
        'dashboard/reportes.html',
        nombre=session.get('nombre', 'Usuario'),
        rol=session.get('rol', 'N/A'),
        total_eventos=len(all_events),
        total_criticos=len(critical_events),
        eventos_por_tipo=eventos_por_tipo,
        criticos_por_causa=criticos_por_causa,
        ultimos_criticos=ultimos_criticos,
        reporte_eventos=reporte_eventos,
        reporte_filtros=reporte_filtros,
        reporte_mensaje_vacio=NO_RESULTS_MESSAGE if not reporte_eventos else None,
        sin_referencia_normativa=SIN_REFERENCIA_NORMATIVA,  # HU-7.3 CA3
    )


@app.route('/reportes/exportar')
@login_required
@modulo_required('consulta_reportes')  # HU-1.4
def exportar_reporte():
    """
    HU-4.5 CA3 — Exporta a CSV el reporte de auditoría filtrado por
    usuario/fecha/tipo_accion/dataset, con la cabecera estandarizada
    de REPORT_CSV_COLUMNS. HU-7.3 CA2 — incluye la columna
    referencia_normativa con la cláusula HIPAA / Ley 1581 de cada evento.
    """
    usuario_id = request.args.get('reporte_usuario_id')
    tipo_accion = request.args.get('reporte_tipo_accion')
    dataset_nombre = request.args.get('reporte_dataset_nombre')
    fecha_inicio = request.args.get('reporte_fecha_inicio')
    fecha_fin = request.args.get('reporte_fecha_fin')

    fecha_inicio_query, fecha_fin_query = _limites_dia_colombia(fecha_inicio, fecha_fin)

    conn = get_db()
    buffer = io.StringIO()
    filas_reporte = export_report_to_csv(
        conn, buffer,
        usuario_id=_usuario_id_desde_filtro(conn, usuario_id),
        fecha_inicio=fecha_inicio_query,
        fecha_fin=fecha_fin_query,
        tipo_accion=tipo_accion,
        dataset_nombre=dataset_nombre,
        formatear_timestamp=formatear_fecha,
    )
    conn.close()
    return _descarga('reporte_auditoria.csv', 'text/csv', buffer.getvalue().encode('utf-8'), '/reportes/exportar',
                     {'usuario': usuario_id, 'tipo_accion': tipo_accion, 'dataset': dataset_nombre,
                      'desde': fecha_inicio, 'hasta': fecha_fin}, filas=filas_reporte)


def _descarga(nombre: str, tipo_mime: str, contenido: bytes, vista: str, filtros: dict, filas: int = None):
    """
    DSH-R1 / DSH-T2 — Entrega un archivo descargado de la bitácora: queda un
    evento DESCARGA_REPORTE con quién, qué filtros, cuántas filas y el SHA-256
    del archivo, que también viaja en la cabecera X-Contenido-SHA256. Con ese
    hash, un auditor comprueba que el archivo que recibió es el que salió.
    """
    huella = hashlib.sha256(contenido).hexdigest()
    _auditar_acceso_bitacora('DESCARGA_REPORTE', vista, filtros, filas=filas, sha256=huella, agrupar=False)
    return Response(contenido, mimetype=tipo_mime, headers={
        'Content-Disposition': f'attachment; filename={nombre}',
        'X-Contenido-SHA256': huella,
    })


@app.route('/reportes/exportar/pdf')
@login_required
@modulo_required('consulta_reportes')  # HU-1.4 — mismo módulo que el CSV
def exportar_reporte_pdf():
    """
    Resultado esperado 3 — Exporta en PDF el mismo reporte de auditoría que
    /reportes/exportar: mismos filtros, mismas filas (generate_report) y
    mismas columnas, incluida referencia_normativa (HU-7.3). Agrega título,
    fecha de generación, quién lo generó y los filtros aplicados.
    """
    from audit_tracer.reporte_pdf import construir_reporte_pdf

    filtros = {clave: request.args.get(clave) for clave in (
        'reporte_usuario_id', 'reporte_tipo_accion', 'reporte_dataset_nombre',
        'reporte_fecha_inicio', 'reporte_fecha_fin')}
    fecha_inicio_query, fecha_fin_query = _limites_dia_colombia(
        filtros['reporte_fecha_inicio'], filtros['reporte_fecha_fin'])

    conn = get_db()
    eventos = generate_report(
        conn,
        usuario_id=_usuario_id_desde_filtro(conn, filtros['reporte_usuario_id']),
        fecha_inicio=fecha_inicio_query,
        fecha_fin=fecha_fin_query,
        tipo_accion=filtros['reporte_tipo_accion'],
        dataset_nombre=filtros['reporte_dataset_nombre'],
    )
    conn.close()

    pdf = construir_reporte_pdf(
        eventos,
        filtros,
        generado_por=f"{session.get('nombre', 'Usuario')} ({session.get('rol', 'N/A')})",
        generado_en=formatear_fecha(datetime.utcnow().isoformat()),
        formatear_timestamp=formatear_fecha,
    )
    return _descarga('reporte_auditoria.pdf', 'application/pdf', pdf, '/reportes/exportar/pdf',
                     {clave.replace('reporte_', ''): valor for clave, valor in filtros.items()}, filas=len(eventos))


@app.route('/eventos')
@login_required
@modulo_required('consulta_reportes')  # HU-1.4
def eventos():
    """
    Vista de consulta de registros de auditoría con paginación.
    HU-4.2 — Permite filtrar por usuario, rango de fechas, tipo de acción
    y dataset, de forma individual o combinada (CA1-CA5).
    """
    usuario_id = request.args.get('usuario_id')
    tipo_accion = request.args.get('tipo_accion')
    nivel_alerta = request.args.get('nivel_alerta')
    # La paginación reenvía los filtros en la URL: un valor como 'False' o
    # vacío no debe activar el filtro de anomalías.
    solo_anomalias = request.args.get('solo_anomalias', '').strip().lower() in ('1', 'true', 'on')
    if solo_anomalias and not nivel_alerta:
        nivel_alerta = 'ANOMALIA'
    dataset_nombre = request.args.get('dataset_nombre')
    fecha_inicio = request.args.get('fecha_inicio')
    fecha_fin = request.args.get('fecha_fin')

    # Los campos <input type="date"> entregan 'YYYY-MM-DD'; se amplían a los
    # límites del día para que la comparación lexicográfica sobre el
    # timestamp ISO 8601 cubra el día completo (CA2).
    fecha_inicio_query, fecha_fin_query = _limites_dia_colombia(fecha_inicio, fecha_fin)

    # Paginación
    page = request.args.get('page', 1, type=int)
    per_page = 10
    offset = (page - 1) * per_page

    conn = get_db()

    # Obtener eventos filtrados en orden cronológico descendente (HU-4.1 CA1-CA4)
    eventos_list = get_events(
        conn,
        usuario_id=_usuario_id_desde_filtro(conn, usuario_id),
        fecha_inicio=fecha_inicio_query,
        fecha_fin=fecha_fin_query,
        tipo_accion=tipo_accion,
        dataset_nombre=dataset_nombre,
        nivel_alerta=nivel_alerta,
        orden_desc=True
    )

    total = len(eventos_list)
    paginated_eventos = eventos_list[offset : offset + per_page]

    conn.close()

    total_pages = (total + per_page - 1) // per_page
    _auditar_acceso_bitacora('CONSULTA_BITACORA', '/eventos', {
        'usuario': usuario_id, 'tipo_accion': tipo_accion, 'nivel_alerta': nivel_alerta,
        'dataset': dataset_nombre, 'desde': fecha_inicio, 'hasta': fecha_fin,
    }, filas=total)

    return render_template(
        'dashboard/eventos.html',
        nombre=session.get('nombre', 'Usuario'),
        rol=session.get('rol', 'N/A'),
        eventos=paginated_eventos,
        page=page,
        total_pages=total_pages,
        filtros={
            'usuario_id': usuario_id,
            'tipo_accion': tipo_accion,
            'nivel_alerta': nivel_alerta,
            'solo_anomalias': '1' if (solo_anomalias or nivel_alerta == 'ANOMALIA') else '',
            'dataset_nombre': dataset_nombre,
            'fecha_inicio': fecha_inicio,
            'fecha_fin': fecha_fin,
        }
    )


@app.route('/eventos/<int:event_id>')
@login_required
@modulo_required('consulta_reportes')  # HU-1.4
def detalle_evento(event_id):
    """
    HU-4.3 — Visualización de detalle de evento (CA1-CA4).
    Muestra todos los datos asociados a un evento específico por su event_id.
    HU-6.1 CA5 — Incluye validación de la firma digital (PDGTRAZDSA-144).
    """
    conn = get_db()
    evento = get_event_by_id(conn, event_id)
    
    if not evento:
        conn.close()
        flash(f'Evento #{event_id} no encontrado.', 'error')
        return redirect(url_for('eventos'))
        
    # HU-6.1 CA5 / SRV-R2 — la firma se verifica con las llaves del usuario
    # vigentes cuando el servidor recibió el evento (historial de llaves): una
    # llave nueva no invalida las firmas anteriores.
    if evento.get('firma_digital'):
        llave_disponible = usuario_tiene_llaves(conn, evento['usuario_id'])
        if llave_disponible:
            es_valida, huella_llave = verificar_con_historial(conn, evento, evento.get('recibido_en'))
            estado_firma = {
                'presente': True,
                'valida': es_valida,
                'mensaje': (f'Firma válida y verificada (llave {huella_llave}).' if es_valida
                            else 'Firma inválida o corrupta.'),
                'llave_disponible': True,
            }
        else:
            estado_firma = {
                'presente': True,
                'valida': False,
                'mensaje': 'El usuario no tiene llave pública registrada.',
                'llave_disponible': False
            }
    else:
        estado_firma = {
            'presente': False,
            'valida': False,
            'mensaje': 'El evento no tiene firma digital.',
            'llave_disponible': False
        }

    # HU-7.4 — Enriquecimiento contextual, identidad de usuario y recomendaciones
    contexto_enriquecido = enrich_event_detail(conn, evento, estado_firma)

    conn.close()
    _auditar_acceso_bitacora('CONSULTA_BITACORA', f'/eventos/{event_id}', filtros=None)

    return render_template(
        'dashboard/detalle_evento.html',
        nombre=session.get('nombre', 'Usuario'),
        rol=session.get('rol', 'N/A'),
        evento=evento,
        estado_firma=estado_firma,
        usuario_info=contexto_enriquecido['usuario_info'],
        explicacion=contexto_enriquecido['explicacion'],
        diagnostico=contexto_enriquecido['diagnostico'],
        recomendaciones=contexto_enriquecido['recomendaciones'],
        resumen_copiable=contexto_enriquecido['resumen_copiable'],
    )


def _grafo_linaje_desde_request():
    """
    HU-7.1 — Lee el alcance (?event_id= o ?dataset=) y construye el grafo.
    Cada nodo asociado a un evento lleva detalle_url hacia el detalle de
    HU-4.3 (/eventos/<event_id>): el grafo no tiene un detalle propio (CA4).
    """
    event_id = request.args.get('event_id', type=int)
    dataset_nombre = request.args.get('dataset') or None

    conn = get_db()
    grafo = build_lineage_graph(conn, dataset_nombre=dataset_nombre, event_id=event_id)
    datasets = list_lineage_datasets(conn)
    conn.close()
    _auditar_acceso_bitacora('CONSULTA_BITACORA', '/linaje', {'dataset': dataset_nombre, 'evento': event_id})

    for nodo in grafo['nodes']:
        if nodo.get('event_id') is not None:
            nodo['detalle_url'] = url_for('detalle_evento', event_id=nodo['event_id'])
    return grafo, datasets


@app.route('/linaje')
@login_required
@modulo_required('consulta_reportes')  # HU-1.4 — mismo módulo que /eventos
def linaje():
    """HU-7.1 CA2 — Grafo de linaje de un dataset o de un evento."""
    grafo, datasets = _grafo_linaje_desde_request()
    return render_template(
        'dashboard/linaje.html',
        nombre=session.get('nombre', 'Usuario'),
        rol=session.get('rol', 'N/A'),
        grafo=grafo,
        datasets=datasets,
    )


@app.route('/api/linaje')
@login_required
@modulo_required('consulta_reportes')
def api_linaje():
    """HU-7.1 — Mismo grafo que /linaje, en JSON."""
    grafo, _ = _grafo_linaje_desde_request()
    return jsonify(grafo)


@app.route('/eventos/criticos/exportar')
@login_required
@modulo_required('consulta_reportes')  # HU-1.4
def exportar_eventos_criticos():
    """
    HU-4.4 CA5 — Exporta a CSV los eventos con nivel_alerta = CRITICO,
    respetando los filtros de usuario y tipo de acción activos en la vista.
    """
    usuario_id = request.args.get('usuario_id')
    tipo_accion = request.args.get('tipo_accion')

    conn = get_db()
    buffer = io.StringIO()
    filas = export_critical_events_to_csv(
        conn, buffer,
        usuario_id=_usuario_id_desde_filtro(conn, usuario_id),
        tipo_accion=tipo_accion,
        formatear_timestamp=formatear_fecha,
    )
    conn.close()
    return _descarga('eventos_criticos.csv', 'text/csv', buffer.getvalue().encode('utf-8'),
                     '/eventos/criticos/exportar', {'usuario': usuario_id, 'tipo_accion': tipo_accion}, filas=filas)


@app.route('/verificar-integridad', methods=['POST'])
@login_required
def verificar_integridad():
    """
    Ejecuta la prueba de integridad de los registros. DSH-D2: recorre toda la
    bitácora, así que solo la pueden lanzar ADMIN y AUDITOR.
    """
    if session.get('rol') not in ('ADMIN', 'AUDITOR'):
        _registrar_acceso_denegado('verificacion_integridad', 'verificar_integridad')
        flash('Solo ADMIN y AUDITOR pueden ejecutar la verificación completa de integridad.', 'error')
        return redirect(url_for('eventos'))
    conn = get_db()
    corruptos = verify_integrity(conn)
    conn.close()
    
    if not corruptos:
        flash('Verificación completada: Todos los registros son íntegros (SHA-256 coincide).', 'success')
    else:
        flash(f'¡ALERTA DE INTEGRIDAD! Se detectaron {len(corruptos)} registros alterados.', 'danger')
        
    return redirect(url_for('eventos'))



# ═══════════════════════════════════════════════════════════════════════════════
# HU-6.2 — Merkle tree y ancla externa de integridad
# PDGTRAZDSA-146 / 147 / 148 / 149 / 150
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/merkle/verificar/<int:event_id>')
@login_required
@modulo_required('consulta_reportes')
def merkle_verificar_evento(event_id):
    """
    PDGTRAZDSA-147 / 150 — Genera la prueba de Merkle para un evento puntual
    y la verifica inmediatamente, sin recorrer todo el historial.

    Usado por el botón «Verificar integridad Merkle» en detalle_evento.html.
    """
    conn = get_db()
    evento = get_event_by_id(conn, event_id)
    if not evento:
        conn.close()
        return jsonify({'error': f'Evento #{event_id} no encontrado.'}), 404

    proof = generate_proof_for_event(conn, event_id)
    conn.close()

    if proof is None:
        return jsonify({
            'event_id': event_id,
            'integrity_ok': False,
            'details': 'No se pudo generar la prueba de Merkle (el evento puede no tener hash_integridad).',
        }), 422

    integrity_ok = verify_merkle_proof(proof)
    return jsonify({
        'event_id': event_id,
        'evento_uuid': proof.get('evento_uuid'),
        'timestamp': proof.get('timestamp'),
        'batch_hour': proof.get('batch_hour'),
        'leaf_hash': proof.get('leaf_hash'),
        'merkle_root': proof.get('root'),
        'proof_steps': len(proof.get('proof', [])),
        'integrity_ok': integrity_ok,
        'details': (
            'Prueba de Merkle válida: el evento forma parte íntegra del lote.'
            if integrity_ok else
            'Prueba de Merkle INVÁLIDA: el evento o algún registro del lote puede haber sido alterado.'
        ),
        'proof': proof.get('proof', []),
    })


@app.route('/merkle/lote/<batch_hour>')
@login_required
@modulo_required('consulta_reportes')
def merkle_lote(batch_hour):
    """
    PDGTRAZDSA-146 — Devuelve la raíz del árbol de Merkle para el lote horario
    indicado (formato YYYY-MM-DDTHH), junto con el número de hojas.
    No expone todos los hashes por razones de tamaño.
    """
    conn = get_db()
    try:
        tree = build_batch_tree(conn, batch_hour)
    except Exception:
        conn.close()
        app.logger.exception('No se pudo construir el lote de Merkle %s.', batch_hour)
        return jsonify({'error': 'Lote horario inválido. Usa el formato AAAA-MM-DDTHH.'}), 400
    conn.close()

    return jsonify({
        'batch_hour': batch_hour,
        'root': tree['root'],
        'leaf_count': tree['leaf_count'],
    })


@app.route('/merkle/publicar', methods=['POST'])
@login_required
def merkle_publicar():
    """
    PDGTRAZDSA-148 — Publica manualmente el anclaje externo para un lote
    horario. Body JSON: {"batch_hour": "YYYY-MM-DDTHH"}.
    Si no se provee batch_hour, publica todos los lotes pendientes.
    Solo accesible por ADMIN o AUDITOR.
    """
    rol = session.get('rol', '')
    if rol not in ('ADMIN', 'AUDITOR'):
        _registrar_acceso_denegado('merkle_publicacion', 'merkle_publicar')  # SRV-R3
        return jsonify({'error': 'Acceso denegado. Se requiere rol ADMIN o AUDITOR.'}), 403

    data = request.get_json(silent=True) or {}
    batch_hour = data.get('batch_hour')

    conn = get_db()
    try:
        if batch_hour:
            anchor = publish_batch_root(conn, batch_hour)
            results = [anchor]
        else:
            from audit_tracer.merkle import publish_all_pending
            results = publish_all_pending(conn)
    except Exception:
        conn.close()
        app.logger.exception('No se pudo publicar el anclaje de Merkle.')
        return jsonify({'error': 'No se pudo publicar el anclaje. El detalle quedó en el registro del servidor.'}), 500
    conn.close()

    return jsonify({
        'published': len(results),
        'anchors': [
            {
                'batch_hour': a.get('batch_hour'),
                'root': a.get('root'),
                'leaf_count': a.get('leaf_count'),
                'published_at': a.get('published_at'),
                'file_path': a.get('_file_path'),
                'signed': bool(a.get('signature')),
                'sello_tiempo': bool((a.get('rfc3161') or {}).get('token')),
            }
            for a in results
        ],
    })


@app.route('/merkle/verificar-ancla', methods=['GET', 'POST'])
@login_required
@modulo_required('consulta_reportes')
def merkle_verificar_ancla():
    """
    PDGTRAZDSA-149 / 150 — Verifica la raíz publicada en el anclaje externo
    contra la raíz recalculada desde la base de datos.

    GET  → pantalla de verificación de anclas.
    POST → verifica el lote batch_hour recibido en el formulario y muestra resultado.
    """
    conn = get_db()

    if request.method == 'POST':
        batch_hour = request.form.get('batch_hour', '').strip()
        if not batch_hour:
            flash('Debes indicar el lote horario a verificar.', 'warning')
            conn.close()
            return redirect(url_for('merkle_verificar_ancla'))

        resultado = verify_external_anchor(conn, batch_hour)
        pendientes = get_pending_batch_hours(conn)
        conn.close()

        return render_template(
            'dashboard/merkle_integridad.html',
            nombre=session.get('nombre', 'Usuario'),
            rol=session.get('rol', 'N/A'),
            resultado=resultado,
            pendientes=pendientes,
            batch_hour_verificado=batch_hour,
        )

    # GET — mostrar todos los anclajes disponibles
    todos = verify_all_anchors(conn)
    pendientes = get_pending_batch_hours(conn)
    conn.close()

    return render_template(
        'dashboard/merkle_integridad.html',
        nombre=session.get('nombre', 'Usuario'),
        rol=session.get('rol', 'N/A'),
        resultado=None,
        pendientes=pendientes,
        todos_anchors=todos,
        batch_hour_verificado=None,
    )


@app.route('/logout')
def logout():
    """Revoca el token de la sesión web antes de borrar la cookie."""
    usuario_id = session.get('usuario_id')
    token_id = session.get('token_id')
    if usuario_id and token_id:
        try:
            with closing(get_db()) as conn:
                token = get_token_by_id(conn, token_id)
                if (
                    token and token['usuario_id'] == usuario_id
                    and token['creado_por'] == 'LOGIN' and token['estado'] == 'ACTIVO'
                ):
                    sesion_id = session.get('sesion_id', 'N/A')
                    revocar_token(conn, token_id, usuario_id, sesion_id, 'Cierre de sesión web')
                    auth_logout(conn, usuario_id, sesion_id, session.get('login_time'))
        except sqlite3.Error:
            app.logger.exception('No se pudo revocar el token de la sesión web.')
            abort(503, 'No pudimos cerrar tu sesión. Inténtalo de nuevo.')

    session.clear()
    flash('Sesión cerrada correctamente.', 'info')
    return redirect(url_for('login'))


# ═══════════════════════════════════════════════════════════════════════════════
# ARRANQUE
# ═══════════════════════════════════════════════════════════════════════════════

def _seed_demo_data_if_requested():
    """
    Siembra un admin + usuarios de demo (analista, científico, auditor) en la
    base central, solo si SEED_DEMO_DATA=1. Pensado para un despliegue de
    prueba (ej. Render) donde no hay acceso de shell a la base. No hace nada
    si ya existe admin@audit.com.

    B10 (21/11/2026): las contraseñas ya no están escritas en el código. Se
    toman de SEED_DEMO_PASSWORD (la misma para las cuatro cuentas) o, si no
    está, se genera una aleatoria por cuenta y se imprime una sola vez en el
    log del servidor, que solo ve quien administra el despliegue.
    """
    if os.environ.get('SEED_DEMO_DATA') != '1':
        return

    conn = get_db()
    try:
        if get_user_by_email(conn, 'admin@audit.com'):
            return  # ya sembrado en un arranque anterior

        fija = os.environ.get('SEED_DEMO_PASSWORD', '').strip()

        def contrasena():
            return fija or f"Demo-{secrets.token_urlsafe(9)}-9"

        cuentas = [('admin@audit.com', 'ADMIN'), ('analista.garcia@audit.com', 'ANALISTA'),
                   ('cientifico.lopez@audit.com', 'CIENTIFICO_DATOS'), ('auditor.perez@audit.com', 'AUDITOR')]
        admin_id = 'SISTEMA'
        for email, rol in cuentas:
            clave = contrasena()
            try:
                nuevo = register_user(conn, email, clave, rol, admin_id=admin_id)
            except ValueError as exc:
                print(f'[AuditTracer] SEED_DEMO_DATA: se omitió {email}: {exc}')
                continue
            if rol == 'ADMIN':
                admin_id = nuevo
            if not fija:
                print(f'[AuditTracer] SEED_DEMO_DATA: {email} / {clave}')
        print('[AuditTracer] SEED_DEMO_DATA=1: usuarios de demo sembrados. No usar con datos reales.')
    finally:
        conn.close()


def _seed_usuarios_desde_entorno():
    """
    Crea al arrancar las cuentas listadas en la variable de entorno
    SEED_USUARIOS, un JSON con la forma
    [{"email": "...", "password": "...", "rol": "ANALISTA"}, ...].

    Sirve para despliegues con disco efímero (ej. el plan gratuito de Render),
    donde cada reinicio recrea la base vacía: las cuentas vuelven a existir con
    las mismas contraseñas, que viven solo en el panel del proveedor y nunca en
    el repositorio. Es idempotente: una cuenta que ya existe no se toca, así que
    no cambia contraseñas ni duplica eventos. Nunca imprime una contraseña.
    """
    import json

    crudo = os.environ.get('SEED_USUARIOS', '').strip()
    if not crudo:
        return
    try:
        cuentas = json.loads(crudo)
        if not isinstance(cuentas, list):
            raise ValueError('se esperaba una lista')
    except ValueError as exc:
        print(f'[AuditTracer] SEED_USUARIOS ignorada: JSON inválido ({exc}).')
        return

    creadas = existentes = rechazadas = 0
    with closing(get_db()) as conn:
        for cuenta in cuentas:
            try:
                email, password, rol = cuenta['email'], cuenta['password'], cuenta['rol']
            except (KeyError, TypeError):
                rechazadas += 1
                continue
            try:
                register_user(conn, email, password, rol, admin_id='SISTEMA')
                creadas += 1
            except ValueError as exc:
                # correo repetido o rol inválido; el mensaje no incluye la contraseña
                if 'ya se encuentra registrado' in str(exc):
                    existentes += 1
                else:
                    rechazadas += 1
                    print(f'[AuditTracer] SEED_USUARIOS: se omitió {email}: {exc}')
    print(f'[AuditTracer] SEED_USUARIOS: {creadas} creadas, {existentes} ya existían, {rechazadas} omitidas.')


def inicializar_servidor() -> None:
    """
    Tareas de arranque del servidor central, comunes a `python app.py` y a
    Gunicorn (wsgi.py): cuentas sembradas, limpieza de códigos de
    dispositivo vencidos y publicador horario de raíces de Merkle.
    """
    _seed_demo_data_if_requested()
    _seed_usuarios_desde_entorno()
    try:
        with closing(get_db()) as conn:
            purgar_codigos_vencidos(conn)
    except Exception as exc:
        print(f"[AuditTracer] No se pudieron purgar los códigos de dispositivo vencidos: {exc}")
    if os.environ.get('START_MERKLE_SCHEDULER', '1') == '1':
        try:
            from audit_tracer.merkle_scheduler import start_scheduler
            start_scheduler(interval_hours=1)
        except Exception as e:
            print(f"[AuditTracer] Info Merkle Scheduler: {e}")


if __name__ == '__main__':
    inicializar_servidor()
    port = int(os.environ.get('PORT', 5000))
    # SRV-I2: el modo de depuración (traceback y consola de Werkzeug en el
    # navegador) solo se activa pidiéndolo explícitamente con FLASK_DEBUG=1.
    debug_mode = os.environ.get('FLASK_DEBUG', '0') == '1'
    app.run(debug=debug_mode, host='0.0.0.0', port=port)
