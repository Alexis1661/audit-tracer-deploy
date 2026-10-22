import uuid

def generate_session_id() -> str:
    """
    Generates a unique session ID using UUID4.

    Returns:
        str: A unique session ID.
    """
    return str(uuid.uuid4())

def get_hostname() -> str:
    """Returns the hostname of the current machine."""
    from .contexto import get_hostname as _cached_hostname
    return _cached_hostname()

def detect_environment() -> str:
    """
    Detects the execution environment.
    Returns 'Google Colab', 'Jupyter' or 'Script (.py)'.
    """
    from .contexto import detect_environment as _detect
    return _detect()
