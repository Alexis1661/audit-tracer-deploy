import uuid

def generate_session_id() -> str:
    """
    Generates a unique session ID using UUID4.

    Returns:
        str: A unique session ID.
    """
    return str(uuid.uuid4())
