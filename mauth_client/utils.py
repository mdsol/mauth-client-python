import base64
import charset_normalizer
import re
from hashlib import sha512

HEADER = '-----BEGIN RSA PRIVATE KEY-----'
FOOTER = '-----END RSA PRIVATE KEY-----'


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


def to_rsa_format(key: str) -> str:
    """Convert a private key to RSA format with proper newlines."""

    if "\n" in key and HEADER in key and FOOTER in key:
        return key

    body = key.strip()
    body = body.replace(HEADER, "").replace(FOOTER, "").strip()

    # Replace whitespace with newlines or chunk into 64-char lines
    if " " in body or "\t" in body:
        body = re.sub(r'\s+', '\n', body)
    else:
        # PEM-encoded keys are typically split into lines of 64 characters as per RFC 7468 (section 2)
        body = '\n'.join(body[i:i + 64] for i in range(0, len(body), 64))

    return f"{HEADER}\n{body}\n{FOOTER}"
