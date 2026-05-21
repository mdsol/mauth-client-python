import unittest

from .common import load_key
from mauth_client.utils import to_rsa_format

PRIVATE_KEY = load_key("priv").strip()


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

    def test_non_rsa_label_well_formed(self):
        """A well-formed PRIVATE KEY (non-RSA label) PEM should be returned unchanged."""
        non_rsa_key = PRIVATE_KEY.replace("RSA PRIVATE KEY", "PRIVATE KEY")
        self.assertEqual(to_rsa_format(non_rsa_key), non_rsa_key)

    def test_boundary_less_body_with_embedded_newlines(self):
        """A bare body with embedded newlines is wrapped in RSA PRIVATE KEY boundaries."""
        lines = PRIVATE_KEY.splitlines()
        body_with_newlines = "\n".join(lines[1:-1])
        header = "-----BEGIN RSA PRIVATE KEY-----"
        footer = "-----END RSA PRIVATE KEY-----"
        result = to_rsa_format(body_with_newlines)
        self.assertTrue(result.startswith(header + "\n"))
        self.assertTrue(result.endswith("\n" + footer))
        # Verify the base64 content is preserved
        result_body = result[len(header) + 1 : -(len(footer) + 1)]
        self.assertEqual(result_body.replace("\n", ""), body_with_newlines.replace("\n", ""))
