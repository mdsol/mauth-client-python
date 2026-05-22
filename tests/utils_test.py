import unittest

from .common import load_key
from mauth_client.utils import to_rsa_format

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

    def test_proper_format_pkcs8(self):
        key = to_rsa_format(PRIVATE_KEY_PKCS8)
        self.assertEqual(key, PRIVATE_KEY_PKCS8)

    def test_newlines_replaced_with_spaces_pkcs8(self):
        key_no_newlines = PRIVATE_KEY_PKCS8.replace("\n", " ")
        key = to_rsa_format(key_no_newlines)
        self.assertEqual(key, PRIVATE_KEY_PKCS8)
