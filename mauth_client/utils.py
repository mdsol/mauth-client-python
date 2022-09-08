import base64
import cchardet
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
    Attempt to decode a byte string with utf and fallback to cchardet.
    """
    try:
        return byte_string.decode("utf-8")
    except UnicodeDecodeError:
        encoding = cchardet.detect(byte_string)["encoding"]
        return byte_string.decode(encoding)
