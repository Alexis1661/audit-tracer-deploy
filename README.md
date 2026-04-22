# Audit Tracer

Sistema de auditoría de trazabilidad para entornos de ciencia de datos en salud.

## Descripción
Este sistema registra, almacena y reporta automáticamente todas las operaciones que un usuario realiza sobre datos clínicos sensibles dentro de Jupyter Notebooks y scripts Python. 
Cumple con normativas como HIPAA §164.312(b) y §164.312(c)(1), Ley 1581 de 2012 e ISO/IEC 27001:2022.

## Instalación
```bash
pip install -r requirements.txt
```

## Pruebas
Para correr las pruebas:
```bash
python -m pytest tests/
```

## Módulos
- `db.py`: Conexión a SQLite e inicialización de la BD.
- `models/audit_log.py`: Operaciones en la tabla `audit_log` para registrar eventos y recuperarlos.
- `models/usuarios.py`: Gestión de usuarios (creación, obtención, bloqueo).
- `auth/registro.py`: Registro de nuevos usuarios y hashing de contraseñas.
- `auth/autenticacion.py`: Inicio de sesión y manejo de accesos fallidos.
- `utils/hashing.py`: Utilidades para hashing de contraseñas y cálculo de hashes de integridad SHA-256.
- `utils/session.py`: Generación de UUIDs de sesión.
