from datetime import datetime, timedelta
import unittest
import copy
from unittest.mock import MagicMock
from freezegun import freeze_time

from mauth_client.authenticator import Authenticator
from mauth_client.signable import RequestSignable
from mauth_client.signed import Signed
from mauth_client.key_holder import KeyHolder
from mauth_client.exceptions import InauthenticError, UnableToAuthenticateError, MAuthNotPresent, MissingV2Error

from tests.common import load_key

APP_UUID = "f5af50b2-bf7d-4c29-81db-76d086d4808a"
URL = "https://api_gateway.com/sandbox/path"
EPOCH = "1500854400"  # 2017-07-24 09:00:00 UTC
EPOCH_DATETIME = datetime.fromtimestamp(float(EPOCH))
BODY = "こんにちはÆ"

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


class MockAuthenticator(Authenticator):
    def __init__(self, headers, v2_only_authenticate=False, method="POST"):
        signable = RequestSignable(method=method, url=URL, body=BODY)
        super().__init__(signable, Signed(headers), v2_only_authenticate)


class TestAuthenticator(unittest.TestCase):
    def setUp(self):
        self.__get_public_key__ = KeyHolder.get_public_key
        KeyHolder.get_public_key = MagicMock(return_value=load_key("rsapub"))

        self.v1_headers = copy.deepcopy(X_MWS_HEADERS)
        self.v2_headers = copy.deepcopy(MWSV2_HEADERS)

    def tearDown(self):
        # reset the KeyHolder.get_public_key method
        KeyHolder.get_public_key = self.__get_public_key__

    def test_authenticate_v2_only_with_v1_headers(self):
        with self.assertRaises(MissingV2Error) as exc:
            MockAuthenticator(self.v1_headers, True).authenticate()
        self.assertEqual(str(exc.exception),
                         "This service requires mAuth v2 mcc-authentication header "
                         "but only v1 x-mws-authentication is present")

    def test_authenticate_signature_missing(self):
        with self.assertRaises(MAuthNotPresent) as exc:
            MockAuthenticator({}).authenticate()
        self.assertEqual(str(exc.exception),
                         "Authentication Failed. No mAuth signature present; "
                         "X-MWS-Authentication header is blank, MCC-Authentication header is blank.")

    def test_authenticate_bad_token_in_mcc(self):
        self.v2_headers["MCC-Authentication"] = "RWS {}:{};".format(APP_UUID, MWSV2_SIGNATURE)
        with self.assertRaises(MAuthNotPresent) as exc:
            MockAuthenticator(self.v2_headers).authenticate()
        self.assertEqual(str(exc.exception),
                         "Authentication Failed. No mAuth signature present; "
                         "X-MWS-Authentication header is blank, MCC-Authentication header is blank.")

    @freeze_time(EPOCH_DATETIME)
    def test_authentication_v1_happy_path(self):
        self.assertTrue(MockAuthenticator(self.v1_headers).authenticate())

    @freeze_time(EPOCH_DATETIME)
    def test_authentication_v1_happy_path_pub_key(self):
        KeyHolder.get_public_key = MagicMock(return_value=load_key("pub"))
        self.assertTrue(MockAuthenticator(self.v1_headers).authenticate())

    @freeze_time(EPOCH_DATETIME)
    def test_fail_to_retrieve_public_key_v1(self):
        KeyHolder.get_public_key = MagicMock(return_value="")
        with self.assertRaises(UnableToAuthenticateError) as exc:
            MockAuthenticator(self.v1_headers).authenticate()
        self.assertEqual(str(exc.exception),
                         "Unable to identify Public Key type from Signature.")

    def test_time_valid_v1_missing_header(self):
        del self.v1_headers["X-MWS-Time"]
        with self.assertRaises(InauthenticError) as exc:
            MockAuthenticator(self.v1_headers).authenticate()
        self.assertEqual(str(exc.exception),
                         "Time verification failed. No X-MWS-Time present.")

    def test_time_valid_v1_bad_header(self):
        self.v1_headers["X-MWS-Time"] = "apple"
        with self.assertRaises(InauthenticError) as exc:
            MockAuthenticator(self.v1_headers).authenticate()
        self.assertEqual(str(exc.exception),
                         "Time verification failed. X-MWS-Time Header format incorrect.")

    @freeze_time(EPOCH_DATETIME)
    def test_token_valid_v1_bad_token(self):
        self.v1_headers["X-MWS-Authentication"] = "RWS {}:{}".format(APP_UUID, X_MWS_SIGNATURE)
        with self.assertRaises(InauthenticError) as exc:
            MockAuthenticator(self.v1_headers).authenticate()
        self.assertEqual(str(exc.exception),
                         "Token verification failed. Expected MWS; token was RWS.")

    @freeze_time(EPOCH_DATETIME + timedelta(minutes=5, seconds=1))
    def test_time_valid_v1_expired_header(self):
        with self.assertRaises(InauthenticError) as exc:
            MockAuthenticator(self.v1_headers).authenticate()
        self.assertEqual(str(exc.exception),
                         "Time verification failed. %s "
                         "not within %ss of %s" % (datetime.fromtimestamp(int(EPOCH)),
                                                   MockAuthenticator.ALLOWED_DRIFT_SECONDS,
                                                   datetime.now()))

    @freeze_time(EPOCH_DATETIME)
    def test_authentication_v1_does_not_authenticate_a_false_message(self):
        with self.assertRaises(InauthenticError) as exc:
            MockAuthenticator(self.v1_headers, False, "GET").authenticate()
        self.assertEqual(str(exc.exception),
                         "Signature verification failed for request.")

    @freeze_time(EPOCH_DATETIME)
    def test_authentication_v2_happy_path(self):
        self.assertTrue(MockAuthenticator(self.v2_headers).authenticate())

    @freeze_time(EPOCH_DATETIME)
    def test_authentication_v2_happy_path_pub_key(self):
        KeyHolder.get_public_key = MagicMock(return_value=load_key("pub"))
        self.assertTrue(MockAuthenticator(self.v2_headers).authenticate())

    @freeze_time(EPOCH_DATETIME)
    def test_authentication_v2_happy_path_multiple_versions(self):
        self.v2_headers["MCC-Authentication"] = "RWS {app_uuid}:ABC;{mwsv2_authentication};MWSV3 {app_uuid}:DEF" \
                                                .format(app_uuid=APP_UUID, mwsv2_authentication=MWSV2_AUTHENTICATION)
        self.assertTrue(MockAuthenticator(self.v2_headers).authenticate())

    @freeze_time(EPOCH_DATETIME)
    def test_fail_to_retrieve_public_key_v2(self):
        KeyHolder.get_public_key = MagicMock(return_value="")
        with self.assertRaises(UnableToAuthenticateError) as exc:
            MockAuthenticator(self.v2_headers).authenticate()
        self.assertEqual(str(exc.exception),
                         "Unable to identify Public Key type from Signature.")

    def test_time_valid_v2_missing_header(self):
        del self.v2_headers["MCC-Time"]
        with self.assertRaises(InauthenticError) as exc:
            MockAuthenticator(self.v2_headers).authenticate()
        self.assertEqual(str(exc.exception),
                         "Time verification failed. No MCC-Time present.")

    def test_time_valid_v2_bad_header(self):
        self.v2_headers["MCC-Time"] = "apple"
        with self.assertRaises(InauthenticError) as exc:
            MockAuthenticator(self.v2_headers).authenticate()
        self.assertEqual(str(exc.exception),
                         "Time verification failed. MCC-Time Header format incorrect.")

    @freeze_time(EPOCH_DATETIME + timedelta(minutes=5, seconds=1))
    def test_time_valid_v2_expired_header(self):
        with self.assertRaises(InauthenticError) as exc:
            MockAuthenticator(self.v2_headers).authenticate()
        self.assertEqual(str(exc.exception),
                         "Time verification failed. %s "
                         "not within %ss of %s" % (datetime.fromtimestamp(int(EPOCH)),
                                                   MockAuthenticator.ALLOWED_DRIFT_SECONDS,
                                                   datetime.now()))

    @freeze_time(EPOCH_DATETIME)
    def test_authentication_v2_does_not_authenticate_a_false_message(self):
        with self.assertRaises(InauthenticError) as exc:
            MockAuthenticator(self.v2_headers, False, "GET").authenticate()
        self.assertEqual(str(exc.exception),
                         "Signature verification failed for request.")
