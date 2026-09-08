import base64
import unittest

import rsa
from pyasn1.error import PyAsn1Error

from .common import load_key
from mauth_client.rsa_signer import RSASigner

LOAD_ERROR_MESSAGE = "Unable to load private key as PKCS#1 or PKCS#8 PEM"

# Valid base64, but the decoded bytes are not a DER structure. This is what a PEM block looks
# like when the body has been corrupted, e.g. by escaped "\n" sequences being left in the body
# or by a still-encrypted (KMS ciphertext) value being wrapped in PEM markers.
GARBAGE_BODY = base64.b64encode(b"this is not DER at all" * 20).decode("ascii")
GARBAGE_BODY = "\n".join(GARBAGE_BODY[i:i + 64] for i in range(0, len(GARBAGE_BODY), 64))

PKCS1_WITH_GARBAGE_BODY = f"-----BEGIN RSA PRIVATE KEY-----\n{GARBAGE_BODY}\n-----END RSA PRIVATE KEY-----"
PKCS8_WITH_GARBAGE_BODY = f"-----BEGIN PRIVATE KEY-----\n{GARBAGE_BODY}\n-----END PRIVATE KEY-----"


class LoadPrivateKeyTest(unittest.TestCase):
    def test_loads_pkcs1_key(self):
        self.assertIsInstance(RSASigner(load_key("priv")).private_key, rsa.PrivateKey)

    def test_loads_pkcs8_key(self):
        self.assertIsInstance(RSASigner(load_key("pkcs8")).private_key, rsa.PrivateKey)

    def test_pyasn1_error_is_not_a_value_error(self):
        # Guards the assumption behind KEY_LOAD_ERRORS: catching only ValueError is not enough,
        # because pyasn1 decode failures would escape as PyAsn1Error.
        self.assertFalse(issubclass(PyAsn1Error, ValueError))

    def test_rsa_raises_pyasn1_error_for_malformed_pkcs1_body(self):
        # Documents the underlying failure the wrapper has to translate: the PEM markers parse,
        # so rsa base64-decodes the body and a PyAsn1Error is triggered in decoder.decode.
        with self.assertRaises(PyAsn1Error):
            rsa.PrivateKey.load_pkcs1(PKCS1_WITH_GARBAGE_BODY.encode("utf-8"), "PEM")

    def test_malformed_pkcs1_body_raises_value_error(self):
        # Regression: the PKCS#1 attempt raises PyAsn1Error, which must be caught so the
        # PKCS#8 fallback runs and a clear ValueError is raised instead of a pyasn1 error.
        with self.assertRaises(ValueError) as ctx:
            RSASigner(PKCS1_WITH_GARBAGE_BODY)
        self.assertEqual(str(ctx.exception), LOAD_ERROR_MESSAGE)

    def test_malformed_pkcs8_body_raises_value_error(self):
        # Regression: here it is the PKCS#8 fallback itself that raises PyAsn1Error.
        with self.assertRaises(ValueError) as ctx:
            RSASigner(PKCS8_WITH_GARBAGE_BODY)
        self.assertEqual(str(ctx.exception), LOAD_ERROR_MESSAGE)
        self.assertIsInstance(ctx.exception.__cause__, PyAsn1Error)

    def test_encrypted_key_wrapped_in_pem_markers_raises_value_error(self):
        # The reported failure mode: a KMS-encrypted key that reached the loader still encrypted.
        ciphertext = base64.b64encode(b"encrypted-key-blob" * 30).decode("ascii")
        pem = f"-----BEGIN RSA PRIVATE KEY-----\n{ciphertext}\n-----END RSA PRIVATE KEY-----"
        with self.assertRaises(ValueError) as ctx:
            RSASigner(pem)
        self.assertEqual(str(ctx.exception), LOAD_ERROR_MESSAGE)

    def test_value_is_not_pem_at_all(self):
        with self.assertRaises(ValueError) as ctx:
            RSASigner("not a key")
        self.assertEqual(str(ctx.exception), LOAD_ERROR_MESSAGE)

    def test_original_error_is_chained(self):
        with self.assertRaises(ValueError) as ctx:
            RSASigner(PKCS1_WITH_GARBAGE_BODY)
        self.assertIsNotNone(ctx.exception.__cause__)
