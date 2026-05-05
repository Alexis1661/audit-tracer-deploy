"""
app.py — Punto de entrada principal del frontend Flask.
Sistema de Auditoría de Trazabilidad de Datos Clínicos.
"""

import os
from flask import Flask, render_template, request, redirect, url_for, session, flash

# ── Importaciones del backend existente ─────────────────────────────────────
from audit_tracer.db import get_connection
from audit_tracer.auth.autenticacion import login as auth_login
from audit_tracer.auth.registro import register_user
from audit_tracer.utils.session import generate_session_id

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
        return redirect(url_for('dashboard'))
    else:
        return render_template('auth/login.html', error=result.get('message', 'Error desconocido.'))


# ── REGISTRO ─────────────────────────────────────────────────────────────────

@app.route('/registro', methods=['GET'])
def registro():
    """Muestra el formulario de registro."""
    if 'usuario_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('auth/registro.html')


@app.route('/registro', methods=['POST'])
def registro_post():
    """Procesa el formulario de registro."""
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '').strip()
    confirmar = request.form.get('confirmar_password', '').strip()
    rol = request.form.get('rol', '').strip()

    # Validaciones del servidor
    if not email or not password or not confirmar or not rol:
        return render_template('auth/registro.html', error='Todos los campos son requeridos.')

    if password != confirmar:
        return render_template('auth/registro.html', error='Las contraseñas no coinciden.')

    if len(password) < 8:
        return render_template('auth/registro.html', error='La contraseña debe tener al menos 8 caracteres.')

    roles_permitidos = ['ANALISTA', 'AUDITOR', 'CIENTIFICO_DATOS']
    if rol not in roles_permitidos:
        return render_template('auth/registro.html', error='Rol inválido.')

    try:
        conn = get_db()
        # Se usa 'SISTEMA' como admin_id para registro público
        new_user_id = register_user(conn, email, password, rol, admin_id='SISTEMA')
        conn.close()
    except ValueError as e:
        return render_template('auth/registro.html', error=str(e))
    except Exception as e:
        return render_template('auth/registro.html', error=f'Error del sistema: {str(e)}')

    flash('Cuenta creada exitosamente. Ahora puedes iniciar sesión.', 'success')
    return redirect(url_for('login'))


# ═══════════════════════════════════════════════════════════════════════════════
# RUTAS PROTEGIDAS
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/dashboard')
@login_required
def dashboard():
    """Dashboard principal — requiere sesión activa."""
    return render_template(
        'dashboard/index.html',
        nombre=session.get('nombre', 'Usuario'),
        rol=session.get('rol', 'N/A')
    )


@app.route('/logout')
def logout():
    """Cierra la sesión y redirige al login."""
    session.clear()
    flash('Sesión cerrada correctamente.', 'info')
    return redirect(url_for('login'))


# ═══════════════════════════════════════════════════════════════════════════════
# ARRANQUE
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
