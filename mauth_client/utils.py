import base64
import charset_normalizer
import re
from hashlib import sha512

PEM_BOUNDARY_RE = re.compile(r"^-----(?:BEGIN|END) ([A-Za-z0-9 -]+)-----$", re.MULTILINE)


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
    """Convert a private key to PEM format with proper newlines (RFC 7468)."""
    stripped = key.strip()
    labels = PEM_BOUNDARY_RE.findall(stripped)

    # Already well-formed if we have at least a BEGIN and END boundary with newlines
    if len(labels) >= 2 and "\n" in stripped:
        return stripped

    if labels:
        label = labels[0]
        header = f"-----BEGIN {label}-----"
        footer = f"-----END {label}-----"
    else:
        # Fallback: treat as a bare RSA private key body
        header = "-----BEGIN RSA PRIVATE KEY-----"
        footer = "-----END RSA PRIVATE KEY-----"

    body = PEM_BOUNDARY_RE.sub("", stripped).strip()

    # Replace whitespace with newlines or chunk into 64-char lines
    if " " in body or "\t" in body:
        body = re.sub(r"\s+", "\n", body)
    else:
        # PEM-encoded keys are typically split into lines of 64 characters as per RFC 7468 (section 2)
        body = "\n".join(body[i : i + 64] for i in range(0, len(body), 64))

    return f"{header}\n{body}\n{footer}"
