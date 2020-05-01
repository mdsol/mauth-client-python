from datetime import datetime, timedelta
import unittest
import copy
import logging
from unittest.mock import MagicMock
from io import StringIO
import pytest
import dateutil
import requests_mock

from mauth_client.authenticator import AbstractAuthenticator, LocalAuthenticator, RemoteAuthenticator
from mauth_client.config import Config
from mauth_client.signable import RequestSignable
from mauth_client.signed import Signed
from mauth_client.key_holder import KeyHolder
from mauth_client.exceptions import InauthenticError, UnableToAuthenticateError, MAuthNotPresent

from tests.common import load_key

AUTHENTICATOR_APP_UUID = "2f746447-c212-483c-9eec-d9b0216f7613"
APP_UUID = "f5af50b2-bf7d-4c29-81db-76d086d4808a"
URL = "https://api_gateway.com/sandbox/path"
UTC = dateutil.tz.tzutc()
EPOCH = "1500854400"  # 2017-07-24 09:00:00 UTC
EPOCH_DATETIME = datetime.fromtimestamp(float(EPOCH), tz=UTC)
BODY = "こんにちはÆ"

X_MWS_SIGNATURE = (
    "p0SNltF6B4G5z+nVNbLv2XCEdouimo/ECQ/Sum6YM+QgE1/LZLXY+hAcwe/TkaC/2d8I3Zot37Xgob3cftgSf9S1fPAi3euN0Fm"
    "v/OEkfUmsYvmqyOXawEWGpevoEX6KNpEAUrt48hFGomsWRgbEEjuUtN4iiPe9y3HlIjumUmDrM499RZxgZdyOhqtLVOv5ngNShDbFv2Ll"
    "jITl4sO0f7zU8wAYGfxLEPXvp8qgnzQ6usZwrD2ujSmXbZtksqgG1R0Vmb7LAd6P+uvtRkw8kGLz/wWwxRweSGliX/IwovGi/bMIIClDD"
    "faUAY9QDjcU1x7i0Yy1IEyQYyCWcnL1rA=="
)
X_MWS_AUTHENTICATION = "MWS {}:{}".format(APP_UUID, X_MWS_SIGNATURE)
X_MWS_HEADERS = {"X-MWS-Time": EPOCH, "X-MWS-Authentication": X_MWS_AUTHENTICATION}

MWSV2_SIGNATURE = (
    "Ub8CWA4rIWsG62PbzKeP33pBDXDk+yY5l3XdI35NSrS7LlwJMQ78C5y+yIAsDAZL3RqZTAd8zQJKdh3s1JXdd3ccc/hoJfs3B31"
    "qCzZffx685QoVpl+Az2AJHvGzOUcZi55ZsvArvdlTikNH7dVz3+K5y5Q5/c2i2D5CBiqD+76zRy6R43BoxxD9flVwhy6PCdgfygegyZo2"
    "g5F7MEgAH/Qvpc6omoVxkbGUmMdWbu00CkfVYh511L4RYss9lLMdd84/2OhV/uG/JtObSJuf5dObvAwKNwqxcmuuAVOE7Bo/qtUL5XBIl"
    "Kmst1b9CjoRn2sZzd/alvZtTdFqdC7DeQ=="
)
MWSV2_AUTHENTICATION = "MWSV2 {}:{};".format(APP_UUID, MWSV2_SIGNATURE)
MWSV2_HEADERS = {"MCC-Time": EPOCH, "MCC-Authentication": MWSV2_AUTHENTICATION}

MAUTH_AUTHENTICATION_URL = "https://mauth.com/mauth/v1/security_tokens/authentication_tickets.json"


class MockAuthenticator(AbstractAuthenticator):
    def __init__(self, headers, v2_only_authenticate=False, method="POST"):
        Config.V2_ONLY_AUTHENTICATE = v2_only_authenticate
        signable = RequestSignable(method=method, url=URL, body=BODY)
        super().__init__(signable, Signed.from_headers(headers), logging.getLogger())

    def _signature_valid_v1(self):
        return True

    def _signature_valid_v2(self):
        return True


class TestAuthenticator(unittest.TestCase):
    def setUp(self):
        Config.APP_UUID = AUTHENTICATOR_APP_UUID

        # redirect the output of stdout to self.captor
        self.captor = StringIO()
        self.logger = logging.getLogger()
        self.logger_handlers = self.logger.handlers
        self.logger.handlers = [logging.StreamHandler(self.captor)]

        self.v1_headers = copy.deepcopy(X_MWS_HEADERS)
        self.v2_headers = copy.deepcopy(MWSV2_HEADERS)

        self.mock_authenticator = None

    def test_is_authentic(self):
        self.logger.setLevel(logging.INFO)
        self.mock_authenticator = MockAuthenticator(self.v1_headers)
        self.mock_authenticator._authenticate = MagicMock(return_value=True)
        authentic, status, message = self.mock_authenticator.is_authentic()

        self.assertTrue(authentic)
        self.assertEqual(status, 200)
        self.assertEqual(message, "")

        self.assertEqual(
            self.captor.getvalue(),
            "Mauth-client attempting to authenticate request from app with mauth"
            " app uuid {} to app with mauth app uuid {}"
            " using version MWS.\n".format(APP_UUID, AUTHENTICATOR_APP_UUID),
        )

    def test_is_authentic_mauth_not_present(self):
        self.logger.setLevel(logging.ERROR)
        self.mock_authenticator = MockAuthenticator({})
        authentic, status, message = self.mock_authenticator.is_authentic()
        expected = (
            "Authentication Failed. No mAuth signature present; "
            "X-MWS-Authentication header is blank, MCC-Authentication header is blank."
        )

        self.assertFalse(authentic)
        self.assertEqual(status, 401)
        self.assertEqual(message, expected)
        self.assertEqual(
            self.captor.getvalue(), "mAuth signature not present on request. Exception: {}\n".format(expected)
        )

    def test_is_authentic_v2_only_with_v1_headers(self):
        self.logger.setLevel(logging.ERROR)
        self.mock_authenticator = MockAuthenticator(self.v1_headers, True)
        authentic, status, message = self.mock_authenticator.is_authentic()
        expected = (
            "This service requires mAuth v2 mcc-authentication header " "but only v1 x-mws-authentication is present"
        )

        self.assertFalse(authentic)
        self.assertEqual(status, 401)
        self.assertEqual(message, expected)
        self.assertEqual(
            self.captor.getvalue(), "mAuth signature not present on request. Exception: {}\n".format(expected)
        )

    def test_is_authentic_inauthentic_error(self):
        self.logger.setLevel(logging.ERROR)
        self.mock_authenticator = MockAuthenticator(self.v1_headers)
        self.mock_authenticator._authenticate = MagicMock(side_effect=InauthenticError("Boom!"))
        authentic, status, message = self.mock_authenticator.is_authentic()

        self.assertFalse(authentic)
        self.assertEqual(status, 401)
        self.assertEqual(message, "Boom!")

        self.assertEqual(
            self.captor.getvalue(), "mAuth signature authentication failed for request. Exception: Boom!\n"
        )

    def test_is_authentic_unable_to_authenticate_error(self):
        self.logger.setLevel(logging.ERROR)
        self.mock_authenticator = MockAuthenticator(self.v1_headers)
        self.mock_authenticator._authenticate = MagicMock(side_effect=UnableToAuthenticateError("Boom!"))
        authentic, status, message = self.mock_authenticator.is_authentic()

        self.assertFalse(authentic)
        self.assertEqual(status, 500)
        self.assertEqual(message, "Boom!")

        self.assertEqual(self.captor.getvalue(), "Boom!\n")

    def test_authenticate_signature_missing(self):
        with self.assertRaises(MAuthNotPresent) as exc:
            MockAuthenticator({})._authenticate()
        self.assertEqual(
            str(exc.exception),
            "Authentication Failed. No mAuth signature present; "
            "X-MWS-Authentication header is blank, MCC-Authentication header is blank.",
        )

    def test_time_valid_v1_missing_header(self):
        del self.v1_headers["X-MWS-Time"]
        with self.assertRaises(InauthenticError) as exc:
            MockAuthenticator(self.v1_headers)._authenticate()
        self.assertEqual(str(exc.exception), "Time verification failed. No X-MWS-Time present.")

    def test_time_valid_v1_bad_header(self):
        self.v1_headers["X-MWS-Time"] = "apple"
        with self.assertRaises(InauthenticError) as exc:
            MockAuthenticator(self.v1_headers)._authenticate()
        self.assertEqual(str(exc.exception), "Time verification failed. X-MWS-Time header format incorrect.")

    @pytest.mark.freeze_time(EPOCH_DATETIME)
    def test_token_valid_v1_bad_token(self):
        self.v1_headers["X-MWS-Authentication"] = "RWS {}:{}".format(APP_UUID, X_MWS_SIGNATURE)
        with self.assertRaises(InauthenticError) as exc:
            MockAuthenticator(self.v1_headers)._authenticate()
        self.assertEqual(str(exc.exception), "Token verification failed. Expected MWS; token was RWS.")

    @pytest.mark.freeze_time(EPOCH_DATETIME + timedelta(minutes=5, seconds=1))
    def test_time_valid_v1_expired_header(self):
        with self.assertRaises(InauthenticError) as exc:
            MockAuthenticator(self.v1_headers)._authenticate()
        self.assertEqual(
            str(exc.exception),
            "Time verification failed. {} "
            "not within {}s of {}".format(
                datetime.fromtimestamp(int(EPOCH)), MockAuthenticator.ALLOWED_DRIFT_SECONDS, datetime.now()
            ),
        )

    def test_time_valid_v2_missing_header(self):
        del self.v2_headers["MCC-Time"]
        with self.assertRaises(InauthenticError) as exc:
            MockAuthenticator(self.v2_headers)._authenticate()
        self.assertEqual(str(exc.exception), "Time verification failed. No MCC-Time present.")

    def test_time_valid_v2_bad_header(self):
        self.v2_headers["MCC-Time"] = "apple"
        with self.assertRaises(InauthenticError) as exc:
            MockAuthenticator(self.v2_headers)._authenticate()
        self.assertEqual(str(exc.exception), "Time verification failed. MCC-Time header format incorrect.")

    @pytest.mark.freeze_time(EPOCH_DATETIME)
    def test_token_valid_v2_bad_token(self):
        self.v2_headers["MCC-Authentication"] = "RWS {}:{}".format(APP_UUID, X_MWS_SIGNATURE)
        with self.assertRaises(InauthenticError) as exc:
            MockAuthenticator(self.v2_headers)._authenticate()
        self.assertEqual(str(exc.exception), "Token verification failed. Expected MWSV2.")

    @pytest.mark.freeze_time(EPOCH_DATETIME + timedelta(minutes=50, seconds=1))
    def test_time_valid_v2_expired_header(self):
        with self.assertRaises(InauthenticError) as exc:
            MockAuthenticator(self.v2_headers)._authenticate()
        self.assertEqual(
            str(exc.exception),
            "Time verification failed. {} "
            "not within {}s of {}".format(
                datetime.fromtimestamp(int(EPOCH)), MockAuthenticator.ALLOWED_DRIFT_SECONDS, datetime.now()
            ),
        )

    @pytest.mark.freeze_time(EPOCH_DATETIME)
    def test_fallback_to_v1_when_v2_fails(self):
        self.logger.setLevel(logging.INFO)
        self.mock_authenticator = MockAuthenticator({**self.v2_headers, **self.v1_headers})
        self.mock_authenticator._signature_valid_v2 = MagicMock(side_effect=InauthenticError("Boom!"))
        authentic, status, message = self.mock_authenticator.is_authentic()

        self.assertTrue(authentic)
        self.assertEqual(status, 200)
        self.assertEqual(message, "")

        self.assertEqual(
            self.captor.getvalue(),
            "Mauth-client attempting to authenticate request from app with mauth"
            " app uuid {app_uuid} to app with mauth app uuid {auth_app_uuid}"
            " using version MWSV2.\n"
            "Mauth-client attempting to authenticate request from app with mauth"
            " app uuid {app_uuid} to app with mauth app uuid {auth_app_uuid}"
            " using version MWS.\n"
            "Completed successful authentication attempt after fallback to v1\n".format(
                app_uuid=APP_UUID, auth_app_uuid=AUTHENTICATOR_APP_UUID
            ),
        )

    @pytest.mark.freeze_time(EPOCH_DATETIME)
    def test_does_not_fallback_to_v1_when_v2_only_flag_is_true(self):
        self.logger.setLevel(logging.INFO)
        self.mock_authenticator = MockAuthenticator({**self.v2_headers, **self.v1_headers}, True)
        self.mock_authenticator._signature_valid_v2 = MagicMock(side_effect=InauthenticError("Boom!"))
        authentic, status, message = self.mock_authenticator.is_authentic()

        self.assertFalse(authentic)
        self.assertEqual(status, 401)
        self.assertEqual(message, "Boom!")

        self.assertEqual(
            self.captor.getvalue(),
            "Mauth-client attempting to authenticate request from app with mauth"
            " app uuid {app_uuid} to app with mauth app uuid {auth_app_uuid}"
            " using version MWSV2.\n"
            "mAuth signature authentication failed for request. Exception: Boom!\n".format(
                app_uuid=APP_UUID, auth_app_uuid=AUTHENTICATOR_APP_UUID
            ),
        )

    @pytest.mark.freeze_time(EPOCH_DATETIME)
    def test_does_not_fallback_to_v1_when_v1_signature_is_missing(self):
        self.logger.setLevel(logging.INFO)
        del self.v1_headers["X-MWS-Authentication"]
        self.mock_authenticator = MockAuthenticator({**self.v2_headers, **self.v1_headers})
        self.mock_authenticator._signature_valid_v2 = MagicMock(side_effect=InauthenticError("Boom!"))
        authentic, status, message = self.mock_authenticator.is_authentic()

        self.assertFalse(authentic)
        self.assertEqual(status, 401)
        self.assertEqual(message, "Boom!")

        self.assertEqual(
            self.captor.getvalue(),
            "Mauth-client attempting to authenticate request from app with mauth"
            " app uuid {app_uuid} to app with mauth app uuid {auth_app_uuid}"
            " using version MWSV2.\n"
            "mAuth signature authentication failed for request. Exception: Boom!\n".format(
                app_uuid=APP_UUID, auth_app_uuid=AUTHENTICATOR_APP_UUID
            ),
        )


class TestLocalAuthenticator(unittest.TestCase):
    def setUp(self):
        self.__get_public_key__ = KeyHolder.get_public_key
        KeyHolder.get_public_key = MagicMock(return_value=load_key("rsapub"))

        Config.V2_ONLY_AUTHENTICATE = False
        self.logger = logging.getLogger()

        self.v1_headers = copy.deepcopy(X_MWS_HEADERS)
        self.v2_headers = copy.deepcopy(MWSV2_HEADERS)
        self.signable = RequestSignable(method="POST", url=URL, body=BODY)

        self.authenticator = LocalAuthenticator(self.signable, Signed.from_headers(self.v1_headers), self.logger)

    def tearDown(self):
        # reset the KeyHolder.get_public_key method
        KeyHolder.get_public_key = self.__get_public_key__

    def test_authenticator_type(self):
        self.assertEqual(self.authenticator.authenticator_type, "LOCAL")

    @pytest.mark.freeze_time(EPOCH_DATETIME)
    def test_authentication_v1_happy_path(self):
        self.assertTrue(self.authenticator._authenticate())

    @pytest.mark.freeze_time(EPOCH_DATETIME)
    def test_authentication_v1_happy_path_pub_key(self):
        KeyHolder.get_public_key = MagicMock(return_value=load_key("pub"))
        self.assertTrue(self.authenticator._authenticate())

    @pytest.mark.freeze_time(EPOCH_DATETIME)
    def test_fail_to_retrieve_public_key_v1(self):
        KeyHolder.get_public_key = MagicMock(return_value="")
        with self.assertRaises(UnableToAuthenticateError) as exc:
            self.authenticator._authenticate()
        self.assertEqual(str(exc.exception), "Unable to identify Public Key type from Signature.")

    @pytest.mark.freeze_time(EPOCH_DATETIME)
    def test_authentication_v1_does_not_authenticate_a_false_message(self):
        self.authenticator.signable = RequestSignable(method="GET", url=URL, body=BODY)
        with self.assertRaises(InauthenticError) as exc:
            self.authenticator._authenticate()
        self.assertEqual(str(exc.exception), "Signature verification failed for request.")

    @pytest.mark.freeze_time(EPOCH_DATETIME)
    def test_authentication_v2_happy_path(self):
        self.authenticator.signed = Signed.from_headers(self.v2_headers)
        self.assertTrue(self.authenticator._authenticate())

    @pytest.mark.freeze_time(EPOCH_DATETIME)
    def test_authentication_v2_happy_path_pub_key(self):
        self.authenticator.signed = Signed.from_headers(self.v2_headers)
        KeyHolder.get_public_key = MagicMock(return_value=load_key("pub"))
        self.assertTrue(self.authenticator._authenticate())

    @pytest.mark.freeze_time(EPOCH_DATETIME)
    def test_authentication_v2_happy_path_multiple_versions(self):
        self.v2_headers["MCC-Authentication"] = "RWS {app_uuid}:ABC;{mwsv2_authentication};MWSV3 {app_uuid}:DEF".format(
            app_uuid=APP_UUID, mwsv2_authentication=MWSV2_AUTHENTICATION
        )
        self.authenticator.signed = Signed.from_headers(self.v2_headers)
        self.assertTrue(self.authenticator._authenticate())

    @pytest.mark.freeze_time(EPOCH_DATETIME)
    def test_fail_to_retrieve_public_key_v2(self):
        KeyHolder.get_public_key = MagicMock(return_value="")
        self.authenticator.signed = Signed.from_headers(self.v2_headers)
        with self.assertRaises(UnableToAuthenticateError) as exc:
            self.authenticator._authenticate()
        self.assertEqual(str(exc.exception), "Unable to identify Public Key type from Signature.")

    @pytest.mark.freeze_time(EPOCH_DATETIME)
    def test_authentication_v2_does_not_authenticate_a_false_message(self):
        self.authenticator.signed = Signed.from_headers(self.v2_headers)
        self.authenticator.signable = RequestSignable(method="GET", url=URL, body=BODY)
        with self.assertRaises(InauthenticError) as exc:
            self.authenticator._authenticate()
        self.assertEqual(str(exc.exception), "Signature verification failed for request.")


class TestRemoteAuthenticator(unittest.TestCase):
    def setUp(self):
        Config.V2_ONLY_AUTHENTICATE = False
        RemoteAuthenticator._MAUTH = {"auth": MagicMock(), "url": MAUTH_AUTHENTICATION_URL}

        self.logger = logging.getLogger()

        self.v1_headers = copy.deepcopy(X_MWS_HEADERS)
        self.v2_headers = copy.deepcopy(MWSV2_HEADERS)
        self.signable = RequestSignable(method="POST", url=URL, body=BODY)
        self.signed = Signed.from_headers(self.v1_headers)

        self.authenticator = RemoteAuthenticator(self.signable, self.signed, self.logger)

    def test_authenticator_type(self):
        self.assertEqual(self.authenticator.authenticator_type, "REMOTE")

    @pytest.mark.freeze_time(EPOCH_DATETIME)
    def test_authentication_v1_happy_path(self):
        expected_ticket_v1 = {
            "authentication_ticket": {
                "verb": "POST",
                "app_uuid": APP_UUID,
                "client_signature": X_MWS_SIGNATURE,
                "request_url": "/sandbox/path",
                "request_time": EPOCH,
                "b64encoded_body": "44GT44KT44Gr44Gh44Gvw4Y=",
            }
        }

        with requests_mock.mock() as requests:
            requests.post(MAUTH_AUTHENTICATION_URL, status_code=200)
            result = self.authenticator._authenticate()

        self.assertTrue(result)
        self.assertEqual(requests.last_request.json(), expected_ticket_v1)

    @pytest.mark.freeze_time(EPOCH_DATETIME)
    def test_authentication_v1_does_not_authenticate_404(self):
        with requests_mock.mock() as requests:
            requests.post(MAUTH_AUTHENTICATION_URL, status_code=404)
            with self.assertRaises(InauthenticError) as exc:
                self.authenticator._authenticate()
            self.assertEqual(str(exc.exception), "The mAuth service responded with 404: ")

    @pytest.mark.freeze_time(EPOCH_DATETIME)
    def test_authentication_v1_does_not_authenticate_412(self):
        with requests_mock.mock() as requests:
            requests.post(MAUTH_AUTHENTICATION_URL, status_code=412)
            with self.assertRaises(InauthenticError) as exc:
                self.authenticator._authenticate()
            self.assertEqual(str(exc.exception), "The mAuth service responded with 412: ")

    @pytest.mark.freeze_time(EPOCH_DATETIME)
    def test_authentication_v1_does_not_authenticate_500(self):
        with requests_mock.mock() as requests:
            requests.post(MAUTH_AUTHENTICATION_URL, status_code=500)
            with self.assertRaises(UnableToAuthenticateError) as exc:
                self.authenticator._authenticate()
            self.assertEqual(str(exc.exception), "The mAuth service responded with 500: ")

    @pytest.mark.freeze_time(EPOCH_DATETIME)
    def test_authentication_v2_happy_path(self):
        expected_ticket_v2 = {
            "authentication_ticket": {
                "verb": "POST",
                "app_uuid": APP_UUID,
                "client_signature": MWSV2_SIGNATURE,
                "request_url": "/sandbox/path",
                "request_time": EPOCH,
                "b64encoded_body": "44GT44KT44Gr44Gh44Gvw4Y=",
                "query_string": "",
                "token": "MWSV2",
            }
        }
        self.authenticator.signed = Signed.from_headers(self.v2_headers)

        with requests_mock.mock() as requests:
            requests.post(MAUTH_AUTHENTICATION_URL, status_code=200)
            result = self.authenticator._authenticate()

        self.assertTrue(result)
        self.assertEqual(requests.last_request.json(), expected_ticket_v2)

    @pytest.mark.freeze_time(EPOCH_DATETIME)
    def test_authentication_v2_does_not_authenticate_404(self):
        self.authenticator.signed = Signed.from_headers(self.v2_headers)
        with requests_mock.mock() as requests:
            requests.post(MAUTH_AUTHENTICATION_URL, status_code=404)
            with self.assertRaises(InauthenticError) as exc:
                self.authenticator._authenticate()
            self.assertEqual(str(exc.exception), "The mAuth service responded with 404: ")

    @pytest.mark.freeze_time(EPOCH_DATETIME)
    def test_authentication_v2_does_not_authenticate_412(self):
        self.authenticator.signed = Signed.from_headers(self.v2_headers)
        with requests_mock.mock() as requests:
            requests.post(MAUTH_AUTHENTICATION_URL, status_code=412)
            with self.assertRaises(InauthenticError) as exc:
                self.authenticator._authenticate()
            self.assertEqual(str(exc.exception), "The mAuth service responded with 412: ")

    @pytest.mark.freeze_time(EPOCH_DATETIME)
    def test_authentication_v2_does_not_authenticate_500(self):
        self.authenticator.signed = Signed.from_headers(self.v2_headers)
        with requests_mock.mock() as requests:
            requests.post(MAUTH_AUTHENTICATION_URL, status_code=500)
            with self.assertRaises(UnableToAuthenticateError) as exc:
                self.authenticator._authenticate()
            self.assertEqual(str(exc.exception), "The mAuth service responded with 500: ")
