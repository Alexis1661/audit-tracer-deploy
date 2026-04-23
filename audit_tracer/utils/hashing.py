import bcrypt
import hashlib
import json
import sqlite3
from typing import List

def hash_password(password: str) -> str:
    """
    Hashes a password using bcrypt.

    Args:
        password (str): The plain text password.

    Returns:
        str: The hashed password.
    """
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    """
    Verifies a password against its bcrypt hash.

    Args:
        password (str): The plain text password.
        hashed (str): The hashed password.

    Returns:
        bool: True if it matches, False otherwise.
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def hash_event(event_data: dict) -> str:
    """
    Calculates a SHA-256 hash over the event fields.
    Keys are sorted to ensure consistent results.

    Args:
        event_data (dict): Dictionary containing event data.

    Returns:
        str: SHA-256 hash.
    """
    # Remove hash_integridad if present to avoid circular reference or hashing an old hash
    data_to_hash = {k: v for k, v in event_data.items() if k != 'hash_integridad' and k != 'event_id'}
    # Sort keys for consistency
    encoded_data = json.dumps(data_to_hash, sort_keys=True).encode('utf-8')
    return hashlib.sha256(encoded_data).hexdigest()

# TODO: HU-3.3 — Juan Pablo Ordoñez
# Implementar: verify_integrity(conn) -> list
# Ver criterios de aceptación en Jira: PDGTRAZDSA
