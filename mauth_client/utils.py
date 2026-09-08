import base64
import charset_normalizer
import re
from hashlib import sha512

HEADER = '-----BEGIN RSA PRIVATE KEY-----'
FOOTER = '-----END RSA PRIVATE KEY-----'
PKCS8_HEADER = '-----BEGIN PRIVATE KEY-----'
PKCS8_FOOTER = '-----END PRIVATE KEY-----'
SUPPORTED_PRIVATE_KEY_FORMATS = (
    (HEADER, FOOTER),
    (PKCS8_HEADER, PKCS8_FOOTER),
)
# Keys stored in environment variables or secret stores are often one-liners in which the
# newlines have been escaped, e.g. "-----BEGIN RSA PRIVATE KEY-----\\nMIIE...".
ESCAPED_NEWLINES = re.compile(r"\\r\\n|\\n|\\r")


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
    """Normalize a private key PEM string with proper newlines.

    Supports both PKCS#1 (``-----BEGIN RSA PRIVATE KEY-----``) and
    PKCS#8 (``-----BEGIN PRIVATE KEY-----``) PEM formats, preserving
    the original header and footer markers.

    Literal ``\\n`` escape sequences are converted to real newlines first, otherwise they
    would be treated as part of the base64 body and corrupt the decoded key.

    Values that do not carry a supported PEM header/footer pair are returned unchanged:
    they are not PEM keys (for example a KMS-encrypted, base64-encoded key), and wrapping
    them in PEM markers would make them look like a valid key while producing garbage.
    """

    markers = next(
        ((hdr, ftr) for hdr, ftr in SUPPORTED_PRIVATE_KEY_FORMATS if hdr in key and ftr in key),
        None,
    )
    if markers is None:
        return key

    header, footer = markers
    key = ESCAPED_NEWLINES.sub("\n", key)

    if "\n" in key:
        return key

    body = key.strip()
    body = body.replace(header, "").replace(footer, "").strip()

    # Replace whitespace with newlines or chunk into 64-char lines
    if " " in body or "\t" in body:
        body = re.sub(r'\s+', '\n', body)
    else:
        # PEM-encoded keys are typically split into lines of 64 characters as per RFC 7468 (section 2)
        body = '\n'.join(body[i:i + 64] for i in range(0, len(body), 64))

    return f"{header}\n{body}\n{footer}"
