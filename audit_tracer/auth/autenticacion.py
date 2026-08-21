import sqlite3
from typing import Dict
from ..models.usuarios import get_user_by_email, increment_failed_attempts, reset_failed_attempts, block_user
from ..models.audit_log import insert_event, contar_intentos_fallidos_recientes
from ..utils.hashing import verify_password
from ..utils.session import get_hostname, detect_environment
from datetime import datetime

# HU-4.4 CA1-a: más de este número de intentos fallidos del mismo usuario en
# menos de VENTANA_INTENTOS_FALLIDOS_MIN minutos se clasifica como CRITICO.
UMBRAL_INTENTOS_FALLIDOS = 3
VENTANA_INTENTOS_FALLIDOS_MIN = 5

def login(conn: sqlite3.Connection, email: str, password: str, sesion_id: str) -> Dict:
    """
    Authenticates a user and manages session login attempts.

    Args:
        conn (sqlite3.Connection): Database connection.
        email (str): User email.
        password (str): User password.
        sesion_id (str): Session ID for the login attempt.

    Returns:
        Dict: Authentication result.
    """
    user = get_user_by_email(conn, email)
    
    # Generic error message for both cases (user not found or invalid pwd)
    invalid_credentials = {'success': False, 'message': 'Credenciales inválidas'}

    if not user:
        # We still log the attempt but with a generic ID or 'DESCONOCIDO'
        insert_event(conn, {
            'usuario_id': 'DESCONOCIDO',
            'sesion_id': sesion_id,
            'timestamp': datetime.utcnow().isoformat(),
            'tipo_accion': 'ACCESO_FALLIDO',
            'motivo_fallo': 'Credenciales inválidas',
            'nivel_alerta': 'NORMAL'
        })
        return invalid_credentials

    user_id = user['usuario_id']
    
    # Check if user is active
    if user['activo'] == 0:
        return {'success': False, 'message': 'Cuenta bloqueada. Contacte al administrador.'}

    # Verify password
    if verify_password(password, user['password_hash']):
        # Login successful
        reset_failed_attempts(conn, user_id)
        
        insert_event(conn, {
            'usuario_id': user_id,
            'sesion_id': sesion_id,
            'timestamp': datetime.utcnow().isoformat(),
            'tipo_accion': 'INICIO_SESION',
            'contexto_ejecucion': f"Env: {detect_environment()} | Host: {get_hostname()}",
            'nivel_alerta': 'NORMAL'
        })
        
        return {
            'success': True, 
            'usuario_id': user_id, 
            'rol': user['rol'], 
            'sesion_id': sesion_id
        }
    else:
        # Login failed
        attempts = increment_failed_attempts(conn, user_id)
        ahora = datetime.utcnow()

        # HU-4.4 CA1-a: intentos fallidos recientes del usuario (ventana de tiempo),
        # independiente del contador acumulado usado para el bloqueo de cuenta.
        intentos_recientes = contar_intentos_fallidos_recientes(
            conn, user_id, ahora, ventana_minutos=VENTANA_INTENTOS_FALLIDOS_MIN
        ) + 1  # +1: incluye el intento actual, que todavía no está insertado

        nivel_alerta = 'NORMAL'
        motivo_alerta = None

        if attempts >= 5:
            nivel_alerta = 'CRITICO'
            motivo_alerta = '5 intentos fallidos consecutivos'
            block_user(conn, user_id)
            message = 'Cuenta bloqueada por seguridad tras 5 intentos fallidos.'
        elif intentos_recientes > UMBRAL_INTENTOS_FALLIDOS:
            nivel_alerta = 'CRITICO'
            motivo_alerta = (
                f'{intentos_recientes} intentos fallidos en menos de '
                f'{VENTANA_INTENTOS_FALLIDOS_MIN} minutos'
            )
            message = 'Credenciales inválidas'
        elif attempts >= 3:
            nivel_alerta = 'ADVERTENCIA'
            motivo_alerta = f'{attempts} intentos fallidos'
            message = 'Credenciales inválidas'
        else:
            message = 'Credenciales inválidas'

        insert_event(conn, {
            'usuario_id': user_id,
            'sesion_id': sesion_id,
            'timestamp': ahora.isoformat(),
            'tipo_accion': 'ACCESO_FALLIDO',
            'motivo_fallo': 'Credenciales inválidas',
            'nivel_alerta': nivel_alerta,
            'motivo_alerta': motivo_alerta
        })

        return {'success': False, 'message': message}

def logout(conn: sqlite3.Connection, usuario_id: str, sesion_id: str, start_time_iso: str = None):
    """
    Logs the logout event and calculates session duration.
    """
    now = datetime.utcnow()
    duration_secs = 0
    
    if start_time_iso:
        try:
            start_time = datetime.fromisoformat(start_time_iso)
            duration_secs = int((now - start_time).total_seconds())
        except:
            pass

    insert_event(conn, {
        'usuario_id': usuario_id,
        'sesion_id': sesion_id,
        'timestamp': now.isoformat(),
        'tipo_accion': 'CIERRE_SESION',
        'contexto_ejecucion': f"Duración: {duration_secs}s",
        'nivel_alerta': 'NORMAL'
    })
    
    return True
