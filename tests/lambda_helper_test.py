import base64
import sys
import unittest
from unittest.mock import MagicMock, patch

from .common import load_key
from mauth_client.lambda_helper import _get_private_key

PRIVATE_KEY = load_key("priv").strip()
PRIVATE_KEY_PKCS8 = load_key("pkcs8").strip()


class TestGetPrivateKey(unittest.TestCase):
    def _get_key(self, configured_key):
        with patch("mauth_client.lambda_helper.Config") as config:
            config.PRIVATE_KEY = configured_key
            return _get_private_key()

    def test_returns_key_unchanged(self):
        self.assertEqual(self._get_key(PRIVATE_KEY), PRIVATE_KEY)

    def test_normalizes_one_liner_with_spaces(self):
        self.assertEqual(self._get_key(PRIVATE_KEY.replace("\n", " ")), PRIVATE_KEY)

    def test_normalizes_one_liner_with_escaped_newlines(self):
        self.assertEqual(self._get_key(PRIVATE_KEY.replace("\n", "\\n")), PRIVATE_KEY)

    def test_returns_pkcs8_key_unchanged(self):
        self.assertEqual(self._get_key(PRIVATE_KEY_PKCS8), PRIVATE_KEY_PKCS8)

    def test_normalizes_pkcs8_one_liner_with_spaces(self):
        self.assertEqual(self._get_key(PRIVATE_KEY_PKCS8.replace("\n", " ")), PRIVATE_KEY_PKCS8)

    def test_normalizes_pkcs8_one_liner_with_escaped_newlines(self):
        self.assertEqual(self._get_key(PRIVATE_KEY_PKCS8.replace("\n", "\\n")), PRIVATE_KEY_PKCS8)

    def test_missing_key(self):
        self.assertIsNone(self._get_key(None))

    def test_encrypted_key_is_decrypted_with_kms(self):
        ciphertext = base64.b64encode(b"encrypted-key-blob").decode("ascii")
        kms_client = MagicMock()
        kms_client.decrypt.return_value = {"Plaintext": PRIVATE_KEY.replace("\n", "\\n").encode("ascii")}
        boto3 = MagicMock()
        boto3.client.return_value = kms_client

        with patch.dict(sys.modules, {"boto3": boto3}):
            key = self._get_key(ciphertext)

        kms_client.decrypt.assert_called_once_with(CiphertextBlob=b"encrypted-key-blob")
        self.assertEqual(key, PRIVATE_KEY)
