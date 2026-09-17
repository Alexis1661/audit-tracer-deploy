"""
app.py — Punto de entrada principal del frontend Flask.
Sistema de Auditoría de Trazabilidad de Datos Clínicos.
"""

import io
import os
import sqlite3
from collections import Counter
from flask import Flask, render_template, request, redirect, url_for, session, flash, Response, jsonify

# ── Importaciones del backend existente ─────────────────────────────────────
from audit_tracer.db import get_central_connection, get_connection
from audit_tracer.auth.autenticacion import login as auth_login, logout as auth_logout
from audit_tracer.auth.registro import register_user
from audit_tracer.auth.gestion_roles import assign_role
from audit_tracer.auth.tokens import (
    generar_token,
    validar_token,
    revocar_token,
    listar_tokens,
)
from audit_tracer.auth.device_codes import (
    iniciar_login_dispositivo,
    confirmar_codigo,
    consultar_estado,
    CODIGO_EXPIRACION_MINUTOS,
    INTERVALO_POLLING_SEGUNDOS,
)
from audit_tracer.models.usuarios import get_all_users, get_user_by_id
from audit_tracer.utils.session import generate_session_id
from audit_tracer.models.audit_log import (
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
from audit_tracer.auth.control_acceso import has_permission  # HU-1.4
from datetime import datetime, timedelta


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
app.secret_key = 'audit_tracer_dev_key_2026'

# Directorio de trabajo: raíz del proyecto
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


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


# ── Decorador de protección de rutas ────────────────────────────────────────
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'usuario_id' not in session:
            flash('Debes iniciar sesión para acceder a esta página.', 'warning')
            # HU-5.7 CA2: conserva a dónde iba (ej. /auth/dispositivo?codigo=...)
            # para volver ahí mismo después de un login exitoso.
            destino = request.full_path if request.query_string else request.path
            return redirect(url_for('login', next=destino))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get('rol') != 'ADMIN':
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
            rol        = session.get('rol', '')
            usuario_id = session.get('usuario_id', 'DESCONOCIDO')
            sesion_id  = session.get('sesion_id', 'N/A')

            if not has_permission(rol, modulo):
                # Registrar el rechazo en audit_log
                try:
                    conn = get_db()
                    insert_event(conn, {
                        'usuario_id': usuario_id,
                        'sesion_id': sesion_id,
                        'timestamp': datetime.utcnow().isoformat(),
                        'tipo_accion': 'ACCESO_DENEGADO',
                        'contexto_ejecucion': (
                            f"Rol: {rol} | Módulo: {modulo} | Ruta: {f.__name__}"
                        ),
                        'motivo_fallo': (
                            f"Acceso denegado: rol '{rol}' no tiene permiso sobre '{modulo}'"
                        ),
                        'nivel_alerta': 'ADVERTENCIA',
                    })
                    conn.close()
                except Exception:
                    pass  # No bloquear la respuesta si falla el log

                return render_template(
                    'acceso_denegado.html',
                    modulo=modulo,
                    rol=rol,
                    nombre=session.get('nombre', 'Usuario'),
                ), 403

            return f(*args, **kwargs)
        return decorated
    return decorator


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
    return bool(next_url) and next_url.startswith('/') and not next_url.startswith('//')


@app.route('/login', methods=['GET'])
def login():
    """Muestra el formulario de login."""
    next_url = request.args.get('next', '')
    if 'usuario_id' in session:
        return redirect(next_url if _next_es_seguro(next_url) else url_for('dashboard'))
    return render_template('auth/login.html', next=next_url)


@app.route('/login', methods=['POST'])
def login_post():
    """Procesa el formulario de login."""
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '').strip()
    next_url = request.form.get('next', '')

    if not email or not password:
        return render_template('auth/login.html', error='Todos los campos son requeridos.', next=next_url)

    try:
        conn = get_db()
        sesion_id = generate_session_id()
        result = auth_login(conn, email, password, sesion_id)
        conn.close()
    except Exception as e:
        return render_template('auth/login.html', error=f'Error del sistema: {str(e)}', next=next_url)

    if result.get('success'):
        session.clear()
        session['usuario_id'] = result['usuario_id']
        session['rol'] = result['rol']
        session['nombre'] = email
        session['sesion_id'] = result['sesion_id']
        session['token'] = result.get('token')
        session['token_expiracion'] = result.get('token_expiracion')
        session['login_time'] = datetime.utcnow().isoformat()
        return redirect(next_url if _next_es_seguro(next_url) else url_for('dashboard'))
    else:
        return render_template('auth/login.html', error=result.get('message', 'Error desconocido.'), next=next_url)


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

    if len(password) < 8:
        return render_template('admin/nuevo_usuario.html', error='La contraseña debe tener al menos 8 caracteres.')

    roles_permitidos = ['ANALISTA', 'AUDITOR', 'CIENTIFICO_DATOS', 'ADMIN']
    if rol not in roles_permitidos:
        return render_template('admin/nuevo_usuario.html', error='Rol inválido.')

    try:
        conn = get_db()
        # Se usa el ID del administrador logueado para el registro de auditoría
        new_user_id = register_user(conn, email, password, rol, admin_id=session['usuario_id'])
        conn.close()
    except ValueError as e:
        return render_template('admin/nuevo_usuario.html', error=str(e))
    except Exception as e:
        return render_template('admin/nuevo_usuario.html', error=f'Error del sistema: {str(e)}')

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
    conn.close()
    
    if not usuario:
        flash('Usuario no encontrado.', 'error')
        return redirect(url_for('lista_usuarios'))
        
    return render_template('admin/editar_usuario.html', 
                           usuario=usuario,
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
    except Exception as e:
        flash(f'Error del sistema: {str(e)}', 'error')
        return redirect(url_for('lista_usuarios'))


# ── ADMINISTRACIÓN DE TOKENS PERSONALES (HU-5.5) ───────────────────────────

@app.route('/admin/tokens', methods=['GET'])
@login_required
@admin_required
def lista_tokens():
    """
    HU-5.5 CA3 — Lista de tokens personales activos y filtrables por usuario/estado.
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

    try:
        conn = get_db()
        token_info = generar_token(
            conn,
            usuario_id=usuario_id,
            dias_expiracion=dias_expiracion,
            creado_por='ADMIN',
            sesion_id=session.get('sesion_id', 'N/A'),
            admin_id=session.get('usuario_id')
        )
        conn.close()
        flash(f'Token generado exitosamente con vigencia de {dias_expiracion} días.', 'success')
    except Exception as e:
        flash(f'Error al generar token: {str(e)}', 'error')

    return redirect(url_for('lista_tokens'))


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
            flash(mensaje, 'error')
    except Exception as e:
        flash(f'Error al revocar token: {str(e)}', 'error')

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

    conn = get_db()
    rechazos = get_events(conn, tipo_accion='SINCRONIZACION_RECHAZADA', orden_desc=True)
    conn.close()

    return render_template(
        'admin/sincronizacion.html',
        nombre=session.get('nombre', 'Usuario'),
        rol=session.get('rol', 'N/A'),
        cola_local=cola_local,
        total_rechazos=len(rechazos),
        rechazos_recientes=rechazos[:10],
    )


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
    return jsonify({'success': exito, 'message': mensaje}), status_code


# ── LOGIN POR CÓDIGO DE DISPOSITIVO (HU-5.7) ──────────────────────────────────

@app.route('/api/auth/dispositivo/iniciar', methods=['POST'])
def api_iniciar_login_dispositivo():
    """
    HU-5.7 CA1 — Genera un código corto + URL de activación para que la
    librería (notebook/script) los muestre. Sin autenticación: es el
    primer paso del flujo, antes de que exista ningún token.
    """
    conn = get_db()
    datos = iniciar_login_dispositivo(conn)
    conn.close()

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
    return render_template('auth/confirmar_dispositivo.html', codigo=request.args.get('codigo', ''))


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
    return render_template('auth/confirmar_dispositivo.html', error=mensaje, codigo=codigo)


@app.route('/api/auth/dispositivo/estado', methods=['GET'])
def api_estado_login_dispositivo():
    """
    HU-5.7 CA3 — Polling del estado de un device_code. Sin autenticación
    por token: el device_code largo y secreto ES la credencial (nunca se
    muestra al usuario, solo lo conoce el proceso que llamó a /iniciar).
    """
    device_code = request.args.get('device_code', '')
    if not device_code:
        return jsonify({'estado': 'INVALIDO'}), 400

    conn = get_db()
    resultado = consultar_estado(conn, device_code)
    conn.close()

    codigos_estado_http = {'INVALIDO': 404, 'CONSUMIDO': 410}
    return jsonify(resultado), codigos_estado_http.get(resultado['estado'], 200)


# ── ENDPOINT RECEPTOR DE EVENTOS (HU-5.8, cierra el hueco de HU-5.6) ───────────

# Campos NOT NULL en audit_log/audit_log_central: sin ellos el INSERT
# fallaría con un error de esquema, así que se validan antes de tocar la BD.
_CAMPOS_EVENTO_REQUERIDOS = ('evento_uuid', 'usuario_id', 'sesion_id', 'timestamp', 'tipo_accion')

# Mismos nombres de columna que schema/audit_log.sql / audit_log_central.sql —
# el payload JSON usa exactamente estos campos (ver README HU-5.8).
_CAMPOS_EVENTO_ACEPTADOS = _CAMPOS_EVENTO_REQUERIDOS + (
    'dataset_nombre', 'columnas_afectadas', 'ruta_destino', 'filas_exportadas',
    'sobrescritura', 'contexto_ejecucion', 'motivo_fallo', 'nivel_alerta', 'motivo_alerta',
)


@app.route('/api/eventos/sincronizar', methods=['POST'])
def api_sincronizar_evento():
    """
    HU-5.8 CA1-CA5 — Endpoint receptor de eventos sincronizados desde la
    librería (Colab u otro entorno). No existía ningún endpoint de
    ingesta en el repositorio (HU-5.6 estaba pendiente); se implementa
    aquí porque HU-5.8 no tiene a dónde sincronizar sin él.

    1. Autentica al emisor con un token personal (HU-5.5, sin tocar
       validar_token()).
    2. Valida que el payload traiga los campos NOT NULL del esquema.
    3. Inserta de forma idempotente por evento_uuid (CA5): reintentar el
       mismo evento nunca crea una segunda fila.
    """
    token_str = None
    auth_header = request.headers.get('Authorization', '')
    if auth_header.startswith('Bearer '):
        token_str = auth_header.split(' ', 1)[1].strip()

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({'status': 'error', 'mensaje': 'Se esperaba un cuerpo JSON con los campos del evento'}), 400

    conn = get_db()

    # CA4: validar el token del emisor ANTES de aceptar el evento.
    valido, mensaje, token_data = validar_token(conn, token_str)
    if not valido:
        # Deja constancia del rechazo en auditoría sin exponer el valor del token.
        try:
            insert_event(conn, {
                'usuario_id': (token_data or {}).get('usuario_id', 'DESCONOCIDO'),
                'sesion_id': 'SINCRONIZACION',
                'timestamp': datetime.utcnow().isoformat(),
                'tipo_accion': 'SINCRONIZACION_RECHAZADA',
                'motivo_fallo': mensaje,
                'nivel_alerta': 'ADVERTENCIA',
            })
        except Exception:
            pass
        conn.close()
        return jsonify({'status': 'error', 'mensaje': mensaje}), 401

    evento = {campo: data.get(campo) for campo in _CAMPOS_EVENTO_ACEPTADOS if campo in data}
    faltantes = [c for c in _CAMPOS_EVENTO_REQUERIDOS if not evento.get(c)]
    if faltantes:
        conn.close()
        return jsonify({
            'status': 'error',
            'mensaje': f"Campos requeridos faltantes: {', '.join(faltantes)}",
        }), 400

    try:
        registro, creado = insert_event_if_new(conn, evento)
    except sqlite3.IntegrityError as exc:
        conn.close()
        return jsonify({'status': 'error', 'mensaje': f'Evento inválido: {exc}'}), 400
    conn.close()

    return jsonify({
        'status': 'creado' if creado else 'duplicado',
        'event_id': registro['event_id'],
        'evento_uuid': registro['evento_uuid'],
    }), 201 if creado else 200


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
    today = datetime.utcnow().strftime('%Y-%m-%d')
    events_today = [e for e in all_events if e['timestamp'].startswith(today)]
    
    # Alertas críticas
    critical_alerts = [e for e in all_events if e['nivel_alerta'] == 'CRITICO']

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
        for nivel in ('NORMAL', 'ADVERTENCIA', 'CRITICO')
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
        registros_corruptos=registros_corruptos,
        total_exportaciones=total_exportaciones,
        filas_exportadas_total=filas_exportadas_total,
        exportaciones_criticas=exportaciones_criticas,
        accesos_fallidos_hoy=accesos_fallidos_hoy,                    # HU-2.4
        accesos_fallidos_criticos_hoy=accesos_fallidos_criticos_hoy,  # HU-2.4
        eventos_por_tipo=eventos_por_tipo,
        alertas_por_nivel=alertas_por_nivel,
        criticos_por_causa=criticos_por_causa,
        now_date=today
    )


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
    reporte_fecha_inicio_query = f"{reporte_fecha_inicio}T00:00:00" if reporte_fecha_inicio else None
    reporte_fecha_fin_query = f"{reporte_fecha_fin}T23:59:59.999999" if reporte_fecha_fin else None

    conn = get_db()
    reporte_eventos = generate_report(
        conn,
        usuario_id=reporte_usuario_id,
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
    )


@app.route('/reportes/exportar')
@login_required
@modulo_required('consulta_reportes')  # HU-1.4
def exportar_reporte():
    """
    HU-4.5 CA3 — Exporta a CSV el reporte de auditoría filtrado por
    usuario/fecha/tipo_accion/dataset, con la cabecera estandarizada
    de REPORT_CSV_COLUMNS.
    """
    usuario_id = request.args.get('reporte_usuario_id')
    tipo_accion = request.args.get('reporte_tipo_accion')
    dataset_nombre = request.args.get('reporte_dataset_nombre')
    fecha_inicio = request.args.get('reporte_fecha_inicio')
    fecha_fin = request.args.get('reporte_fecha_fin')

    fecha_inicio_query = f"{fecha_inicio}T00:00:00" if fecha_inicio else None
    fecha_fin_query = f"{fecha_fin}T23:59:59.999999" if fecha_fin else None

    conn = get_db()
    buffer = io.StringIO()
    export_report_to_csv(
        conn, buffer,
        usuario_id=usuario_id,
        fecha_inicio=fecha_inicio_query,
        fecha_fin=fecha_fin_query,
        tipo_accion=tipo_accion,
        dataset_nombre=dataset_nombre,
    )
    conn.close()

    return Response(
        buffer.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=reporte_auditoria.csv'}
    )


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
    dataset_nombre = request.args.get('dataset_nombre')
    fecha_inicio = request.args.get('fecha_inicio')
    fecha_fin = request.args.get('fecha_fin')

    # Los campos <input type="date"> entregan 'YYYY-MM-DD'; se amplían a los
    # límites del día para que la comparación lexicográfica sobre el
    # timestamp ISO 8601 cubra el día completo (CA2).
    fecha_inicio_query = f"{fecha_inicio}T00:00:00" if fecha_inicio else None
    fecha_fin_query = f"{fecha_fin}T23:59:59.999999" if fecha_fin else None

    # Paginación
    page = request.args.get('page', 1, type=int)
    per_page = 10
    offset = (page - 1) * per_page

    conn = get_db()

    # Obtener eventos filtrados en orden cronológico descendente (HU-4.1 CA1-CA4)
    eventos_list = get_events(
        conn,
        usuario_id=usuario_id,
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
    """
    conn = get_db()
    evento = get_event_by_id(conn, event_id)
    conn.close()

    if not evento:
        flash(f'Evento #{event_id} no encontrado.', 'error')
        return redirect(url_for('eventos'))

    return render_template(
        'dashboard/detalle_evento.html',
        nombre=session.get('nombre', 'Usuario'),
        rol=session.get('rol', 'N/A'),
        evento=evento,
    )


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
    export_critical_events_to_csv(
        conn, buffer,
        usuario_id=usuario_id,
        tipo_accion=tipo_accion,
    )
    conn.close()

    return Response(
        buffer.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=eventos_criticos.csv'}
    )


@app.route('/verificar-integridad', methods=['POST'])
@login_required
def verificar_integridad():
    """Ejecuta la prueba de integridad de los registros."""
    conn = get_db()
    corruptos = verify_integrity(conn)
    conn.close()
    
    if not corruptos:
        flash('Verificación completada: Todos los registros son íntegros (SHA-256 coincide).', 'success')
    else:
        flash(f'¡ALERTA DE INTEGRIDAD! Se detectaron {len(corruptos)} registros alterados.', 'danger')
        
    return redirect(url_for('eventos'))


@app.route('/logout')
def logout():
    """Cierra la sesión y registra el evento en auditoría."""
    if 'usuario_id' in session:
        try:
            conn = get_db()
            auth_logout(
                conn, 
                session['usuario_id'], 
                session['sesion_id'], 
                session.get('login_time')
            )
            conn.close()
        except:
            pass

    session.clear()
    flash('Sesión cerrada correctamente.', 'info')
    return redirect(url_for('login'))


# ═══════════════════════════════════════════════════════════════════════════════
# ARRANQUE
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
