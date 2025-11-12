import base64
import charset_normalizer
from hashlib import sha512


def make_bytes(val):
    """
    :param str val: The supplied value (string-like)
    """
    if isinstance(val, str):
        return val.encode("utf-8")
    if isinstance(val, int):
        return str(val).encode("utf-8")

    return val


def hexdigest(val):
    return sha512(make_bytes(val)).hexdigest()


def base64_encode(signature):
    return base64.b64encode(signature).decode("US-ASCII").replace("\n", "")


def decode(byte_string: bytes) -> str:
    """
    Attempt to decode a byte string with utf and fallback to charset_normalizer.
    """
    try:
        return byte_string.decode("utf-8")
    except UnicodeDecodeError:
        encoding = charset_normalizer.detect(byte_string)["encoding"]
        return byte_string.decode(encoding)


def is_exempt_request_path(path: str, exempt: set) -> bool:
    """
    Check if a request path should be exempt from authentication based on prefix matching.

    This function performs prefix matching with path separator boundary checking to prevent
    false positives. A path matches an exempt prefix only if it starts with the exempt path
    followed by a path separator ('/').

    :param str path: The request path to check (e.g., '/health/live', '/api/users')
    :param set exempt: Set of exempt path prefixes (e.g., {'/health', '/metrics'})
    :return: True if the path matches any exempt prefix, False otherwise
    :rtype: bool

    Examples:
        Matching cases (returns True):
        - path='/health/live', exempt={'/health'} -> True
        - path='/health/ready', exempt={'/health'} -> True
        - path='/metrics/prometheus', exempt={'/metrics'} -> True

        Non-matching cases (returns False):
        - path='/health', exempt={'/health'} -> False (exact match without trailing slash)
        - path='/api-admin', exempt={'/api'} -> False (not a path separator boundary)
        - path='/app_status_admin', exempt={'/app_status'} -> False (underscore, not separator)
        - path='/healthcare', exempt={'/health'} -> False (different path)
    """
    for exempt_path in exempt:
        # Exact match or prefix match with path separator
        # For instance this prevents /api matching /api-admin or /app_status matching /app_status_admin
        if path.startswith(exempt_path.rstrip('/') + '/'):
            return True
    return False
