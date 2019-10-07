import unittest
from unittest.mock import MagicMock

from mauth_client.signed import Signed

APP_UUID = "f5af50b2-bf7d-4c29-81db-76d086d4808a"
URL = "https://api_gateway.com/sandbox/path"
EPOCH = "1500854400"  # 2017-07-24 09:00:00 UTC

X_MWS_SIGNATURE = "p0SNltF6B4G5z+nVNbLv2XCEdouimo/ECQ/Sum6YM+QgE1/LZLXY+hAcwe/TkaC/2d8I3Zot37Xgob3cftgSf9S1fPAi3euN0Fm"\
            "v/OEkfUmsYvmqyOXawEWGpevoEX6KNpEAUrt48hFGomsWRgbEEjuUtN4iiPe9y3HlIjumUmDrM499RZxgZdyOhqtLVOv5ngNShDbFv2Ll"\
            "jITl4sO0f7zU8wAYGfxLEPXvp8qgnzQ6usZwrD2ujSmXbZtksqgG1R0Vmb7LAd6P+uvtRkw8kGLz/wWwxRweSGliX/IwovGi/bMIIClDD"\
            "faUAY9QDjcU1x7i0Yy1IEyQYyCWcnL1rA=="
X_MWS_AUTHENTICATION = "MWS {}:{}".format(APP_UUID, X_MWS_SIGNATURE)
X_MWS_HEADERS = { "X-MWS-Time": EPOCH, "X-MWS-Authentication": X_MWS_AUTHENTICATION }

MWSV2_SIGNATURE = "Ub8CWA4rIWsG62PbzKeP33pBDXDk+yY5l3XdI35NSrS7LlwJMQ78C5y+yIAsDAZL3RqZTAd8zQJKdh3s1JXdd3ccc/hoJfs3B31"\
            "qCzZffx685QoVpl+Az2AJHvGzOUcZi55ZsvArvdlTikNH7dVz3+K5y5Q5/c2i2D5CBiqD+76zRy6R43BoxxD9flVwhy6PCdgfygegyZo2"\
            "g5F7MEgAH/Qvpc6omoVxkbGUmMdWbu00CkfVYh511L4RYss9lLMdd84/2OhV/uG/JtObSJuf5dObvAwKNwqxcmuuAVOE7Bo/qtUL5XBIl"\
            "Kmst1b9CjoRn2sZzd/alvZtTdFqdC7DeQ=="
MWSV2_AUTHENTICATION = "MWSV2 {}:{};".format(APP_UUID, MWSV2_SIGNATURE)
MWSV2_HEADERS = { "MCC-Time": EPOCH, "MCC-Authentication": MWSV2_AUTHENTICATION }


class TestSigned(unittest.TestCase):
    def test_from_headers_v1(self):
        signed = Signed.from_headers(X_MWS_HEADERS)

        self.assertEqual(signed.protocol_version, 1)
        self.assertEqual(signed.signature_time, EPOCH)
        self.assertEqual(signed.token, "MWS")
        self.assertEqual(signed.app_uuid, APP_UUID)
        self.assertEqual(signed.signature, X_MWS_SIGNATURE)

    def test_from_headers_v2(self):
        signed = Signed.from_headers(MWSV2_HEADERS)

        self.assertEqual(signed.protocol_version, 2)
        self.assertEqual(signed.signature_time, EPOCH)
        self.assertEqual(signed.token, "MWSV2")
        self.assertEqual(signed.app_uuid, APP_UUID)
        self.assertEqual(signed.signature, MWSV2_SIGNATURE)

    def test_from_headers_missing_header(self):
        signed = Signed.from_headers({})

        self.assertEqual(signed.protocol_version, None)
        self.assertEqual(signed.signature_time, "")
        self.assertEqual(signed.token, "")
        self.assertEqual(signed.app_uuid, "")
        self.assertEqual(signed.signature, "")

    def test_from_headers_bad_header(self):
        bad_header = { "MCC-Time": EPOCH, "MCC-Authentication": X_MWS_AUTHENTICATION }
        signed = Signed.from_headers(bad_header)

        self.assertEqual(signed.protocol_version, None)
        self.assertEqual(signed.signature_time, "")
        self.assertEqual(signed.token, "")
        self.assertEqual(signed.app_uuid, "")
        self.assertEqual(signed.signature, "")
