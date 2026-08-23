"""
app.py — Punto de entrada principal del frontend Flask.
Sistema de Auditoría de Trazabilidad de Datos Clínicos.
"""

import io
import os
from collections import Counter
from flask import Flask, render_template, request, redirect, url_for, session, flash, Response

# ── Importaciones del backend existente ─────────────────────────────────────
from audit_tracer.db import get_connection
from audit_tracer.auth.autenticacion import login as auth_login, logout as auth_logout
from audit_tracer.auth.registro import register_user
from audit_tracer.auth.gestion_roles import assign_role
from audit_tracer.models.usuarios import get_all_users, get_user_by_id
from audit_tracer.utils.session import generate_session_id
from audit_tracer.models.audit_log import (
    get_events,
    verify_integrity,
    insert_event,
    get_critical_events,
    export_critical_events_to_csv,
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
    """Devuelve una conexión a la base de datos SQLite."""
    os.chdir(BASE_DIR)  # Asegura que db_path sea relativo a la raíz
    return get_connection()


# ── Decorador de protección de rutas ────────────────────────────────────────
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'usuario_id' not in session:
            flash('Debes iniciar sesión para acceder a esta página.', 'warning')
            return redirect(url_for('login'))
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

@app.route('/login', methods=['GET'])
def login():
    """Muestra el formulario de login."""
    if 'usuario_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('auth/login.html')


@app.route('/login', methods=['POST'])
def login_post():
    """Procesa el formulario de login."""
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '').strip()

    if not email or not password:
        return render_template('auth/login.html', error='Todos los campos son requeridos.')

    try:
        conn = get_db()
        sesion_id = generate_session_id()
        result = auth_login(conn, email, password, sesion_id)
        conn.close()
    except Exception as e:
        return render_template('auth/login.html', error=f'Error del sistema: {str(e)}')

    if result.get('success'):
        session.clear()
        session['usuario_id'] = result['usuario_id']
        session['rol'] = result['rol']
        session['nombre'] = email
        session['sesion_id'] = result['sesion_id']
        session['login_time'] = datetime.utcnow().isoformat()
        return redirect(url_for('dashboard'))
    else:
        return render_template('auth/login.html', error=result.get('message', 'Error desconocido.'))


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

    return render_template(
        'dashboard/reportes.html',
        nombre=session.get('nombre', 'Usuario'),
        rol=session.get('rol', 'N/A'),
        total_eventos=len(all_events),
        total_criticos=len(critical_events),
        eventos_por_tipo=eventos_por_tipo,
        criticos_por_causa=criticos_por_causa,
        ultimos_criticos=ultimos_criticos,
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
