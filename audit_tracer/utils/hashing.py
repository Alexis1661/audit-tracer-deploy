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

def verify_integrity(conn: sqlite3.Connection) -> List[int]:
    """
    Recalculates hashes for all events in the audit_log table and
    returns a list of event_ids that have been altered.

    Args:
        conn (sqlite3.Connection): Database connection.

    Returns:
        List[int]: List of altered event IDs.
    """
    altered_ids = []
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM audit_log")
    rows = cursor.fetchall()
    
    for row in rows:
        event_dict = dict(row)
        stored_hash = event_dict.get('hash_integridad')
        # Recalculate hash excluding hash_integridad and event_id
        calculated_hash = hash_event(event_dict)
        
        if stored_hash != calculated_hash:
            altered_ids.append(event_dict['event_id'])
            
    return altered_ids
