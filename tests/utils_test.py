import base64
import unittest

from .common import load_key
from mauth_client.utils import FOOTER, to_rsa_format

PRIVATE_KEY = load_key("priv").strip()
PRIVATE_KEY_PKCS8 = load_key("pkcs8").strip()


class TestToRsaFormat(unittest.TestCase):
    def test_proper_format(self):
        key = to_rsa_format(PRIVATE_KEY)
        self.assertEqual(key, PRIVATE_KEY)

    def test_newlines_replaced_with_spaces(self):
        key_no_newlines = PRIVATE_KEY.replace("\n", " ")
        key = to_rsa_format(key_no_newlines)
        self.assertEqual(key, PRIVATE_KEY)

    def test_newlines_removed(self):
        key_no_newlines = PRIVATE_KEY.replace("\n", "")
        key = to_rsa_format(key_no_newlines)
        self.assertEqual(key, PRIVATE_KEY)

    def test_escaped_newlines(self):
        key_escaped_newlines = PRIVATE_KEY.replace("\n", "\\n")
        key = to_rsa_format(key_escaped_newlines)
        self.assertEqual(key, PRIVATE_KEY)

    def test_escaped_carriage_returns(self):
        key_escaped_newlines = PRIVATE_KEY.replace("\n", "\\r\\n")
        key = to_rsa_format(key_escaped_newlines)
        self.assertEqual(key, PRIVATE_KEY)

    def test_proper_format_pkcs8(self):
        key = to_rsa_format(PRIVATE_KEY_PKCS8)
        self.assertEqual(key, PRIVATE_KEY_PKCS8)

    def test_newlines_replaced_with_spaces_pkcs8(self):
        key_no_newlines = PRIVATE_KEY_PKCS8.replace("\n", " ")
        key = to_rsa_format(key_no_newlines)
        self.assertEqual(key, PRIVATE_KEY_PKCS8)

    def test_escaped_newlines_pkcs8(self):
        key_escaped_newlines = PRIVATE_KEY_PKCS8.replace("\n", "\\n")
        key = to_rsa_format(key_escaped_newlines)
        self.assertEqual(key, PRIVATE_KEY_PKCS8)

    def test_non_pem_value_is_untouched(self):
        # e.g. a KMS-encrypted, base64-encoded key: it must not be wrapped in PEM markers
        ciphertext = base64.b64encode(b"not a pem key" * 40).decode("ascii")
        self.assertEqual(to_rsa_format(ciphertext), ciphertext)

    def test_key_without_footer_is_untouched(self):
        truncated = PRIVATE_KEY.replace(FOOTER, "")
        self.assertEqual(to_rsa_format(truncated), truncated)
