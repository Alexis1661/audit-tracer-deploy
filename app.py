"""
app.py — Punto de entrada principal del frontend Flask.
Sistema de Auditoría de Trazabilidad de Datos Clínicos.
"""

import os
from flask import Flask, render_template, request, redirect, url_for, session, flash

# ── Importaciones del backend existente ─────────────────────────────────────
from audit_tracer.db import get_connection
from audit_tracer.auth.autenticacion import login as auth_login, logout as auth_logout
from audit_tracer.auth.registro import register_user
from audit_tracer.auth.gestion_roles import assign_role
from audit_tracer.models.usuarios import get_all_users, get_user_by_id
from audit_tracer.utils.session import generate_session_id
from audit_tracer.models.audit_log import get_events, verify_integrity
from datetime import datetime, timedelta

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
@admin_required
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
    
    # Eventos hoy
    today = datetime.utcnow().strftime('%Y-%m-%d')
    events_today = [e for e in all_events if e['timestamp'].startswith(today)]
    
    # Alertas críticas
    critical_alerts = [e for e in all_events if e['nivel_alerta'] == 'CRITICO']
    
    # Usuarios únicos (basado en el log)
    unique_users = len(set(e['usuario_id'] for e in all_events))
    
    conn.close()
    
    return render_template(
        'dashboard/index.html',
        nombre=session.get('nombre', 'Usuario'),
        rol=session.get('rol', 'N/A'),
        total_eventos=len(all_events),
        eventos_hoy=len(events_today),
        usuarios_activos=unique_users,
        alertas_criticas=len(critical_alerts),
        now_date=today
    )

@app.route('/eventos')
@login_required
def eventos():
    """Vista de consulta de registros de auditoría con paginación."""
    usuario_id = request.args.get('usuario_id')
    tipo_accion = request.args.get('tipo_accion')
    nivel_alerta = request.args.get('nivel_alerta')
    
    # Paginación
    page = request.args.get('page', 1, type=int)
    per_page = 10
    offset = (page - 1) * per_page
    
    conn = get_db()
    
    # Obtener eventos filtrados
    eventos_list = get_events(
        conn, 
        usuario_id=usuario_id, 
        tipo_accion=tipo_accion, 
        nivel_alerta=nivel_alerta
    )
    
    # Invertir para ver lo más reciente primero si no se filtró por fecha
    eventos_list = list(reversed(eventos_list))
    
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
            'nivel_alerta': nivel_alerta
        }
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
