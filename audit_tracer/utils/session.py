import uuid
import socket
import sys

def generate_session_id() -> str:
    """
    Generates a unique session ID using UUID4.

    Returns:
        str: A unique session ID.
    """
    return str(uuid.uuid4())

def get_hostname() -> str:
    """Returns the hostname of the current machine."""
    return socket.gethostname()

def detect_environment() -> str:
    """
    Detects the execution environment.
    Returns 'Jupyter' or 'Script (.py)'.
    """
    if 'ipykernel' in sys.modules:
        return 'Jupyter'
    return 'Script (.py)'
