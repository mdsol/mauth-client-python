import sys
import unittest
from unittest.mock import MagicMock
from io import StringIO
import logging
from mauth_client.config import Config
from mauth_client.lambda_authenticator import LambdaAuthenticator
from mauth_client.exceptions import InauthenticError, UnableToAuthenticateError, MAuthNotPresent, MissingV2Error
from mauth_client.rsa_verifier import RSAVerifier

LAMBDA_APP_UUID = "2f746447-c212-483c-9eec-d9b0216f7613"
CLIENT_APP_UUID = "f5af50b2-bf7d-4c29-81db-76d086d4808a"
URL = "https://api_gateway.com/sandbox/path"
X_MWS_TIME = "1500854400"  # 2017-07-24 09:00:00 UTC

SIGNATURE = "p0SNltF6B4G5z+nVNbLv2XCEdouimo/ECQ/Sum6YM+QgE1/LZLXY+hAcwe/TkaC/2d8I3Zot37Xgob3cftgSf9S1fPAi3euN0Fmv/OE" \
            "kfUmsYvmqyOXawEWGpevoEX6KNpEAUrt48hFGomsWRgbEEjuUtN4iiPe9y3HlIjumUmDrM499RZxgZdyOhqtLVOv5ngNShDbFv2LljI" \
            "Tl4sO0f7zU8wAYGfxLEPXvp8qgnzQ6usZwrD2ujSmXbZtksqgG1R0Vmb7LAd6P+uvtRkw8kGLz/wWwxRweSGliX/IwovGi/bMIIClDD" \
            "faUAY9QDjcU1x7i0Yy1IEyQYyCWcnL1rA=="

X_MWS_AUTHENTICATION = "MWS {}:{}".format(CLIENT_APP_UUID, SIGNATURE)
HEADERS = {"X-Mws-Time": X_MWS_TIME, "X-Mws-Authentication": X_MWS_AUTHENTICATION}
BODY = "こんにちはÆ"


class TestLambdaAuthenticator(unittest.TestCase):
    def setUp(self):
        Config.APP_UUID = LAMBDA_APP_UUID
        self.lambda_authenticator = LambdaAuthenticator("POST", URL, HEADERS, BODY)

        # redirect the output of stdout to self.captor
        self.captor = StringIO()
        self.logger = logging.getLogger()
        self.logger_handlers = self.logger.handlers
        self.logger.handlers = [logging.StreamHandler(self.captor)]

    def tearDown(self):
        # reset the output of stdout to console
        sys.stdout = sys.__stdout__
        self.logger.handlers = self.logger_handlers

    def test_get_app_uuid(self):
        self.assertEqual(self.lambda_authenticator.get_app_uuid(), CLIENT_APP_UUID)

    def test_is_authentic(self):
        self.logger.setLevel(logging.INFO)
        self.lambda_authenticator.authenticate = MagicMock(return_value=True)
        authentic, status = self.lambda_authenticator.is_authentic()

        self.assertTrue(authentic)
        self.assertEqual(status, 200)

        self.assertEqual(self.captor.getvalue(),
                         "Mauth-client attempting to authenticate request from app with mauth" \
                         " app uuid {} to app with mauth app uuid {}" \
                         " using version MWS.\n".format(CLIENT_APP_UUID, LAMBDA_APP_UUID))

    def test_is_authentic_v2_only_with_v1_headers(self):
        self.logger.setLevel(logging.ERROR)
        Config.V2_ONLY_AUTHENTICATE = True
        authentic, status, message = LambdaAuthenticator("POST", URL, HEADERS, BODY).is_authentic()

        self.assertFalse(authentic)
        self.assertEqual(status, 401)
        self.assertEqual(
            message,
            "This service requires mAuth v2 mcc-authentication header but only v1 x-mws-authentication is present"
        )

    def test_is_authentic_mauth_not_present(self):
        self.logger.setLevel(logging.ERROR)
        self.lambda_authenticator.authenticate = MagicMock(side_effect=MAuthNotPresent("Boom!"))
        authentic, status, message = self.lambda_authenticator.is_authentic()

        self.assertFalse(authentic)
        self.assertEqual(status, 401)
        self.assertEqual(message, "Boom!")

        self.assertEqual(self.captor.getvalue(), "mAuth signature not present on request. Exception: Boom!\n")

    def test_is_authentic_missing_v2_error(self):
        self.logger.setLevel(logging.ERROR)
        self.lambda_authenticator.authenticate = MagicMock(side_effect=MissingV2Error("Boom!"))
        authentic, status, message = self.lambda_authenticator.is_authentic()

        self.assertFalse(authentic)
        self.assertEqual(status, 401)
        self.assertEqual(message, "Boom!")

        self.assertEqual(self.captor.getvalue(), "mAuth signature not present on request. Exception: Boom!\n")

    def test_is_authentic_inauthentic_error(self):
        self.logger.setLevel(logging.ERROR)
        self.lambda_authenticator.authenticate = MagicMock(side_effect=InauthenticError("Boom!"))
        authentic, status, message = self.lambda_authenticator.is_authentic()

        self.assertFalse(authentic)
        self.assertEqual(status, 401)
        self.assertEqual(message, "Boom!")

        self.assertEqual(self.captor.getvalue(),
                         "mAuth signature authentication failed for request. Exception: Boom!\n")

    def test_is_authentic_unable_to_authenticate_error(self):
        self.logger.setLevel(logging.ERROR)
        self.lambda_authenticator.authenticate = MagicMock(side_effect=UnableToAuthenticateError("Boom!"))
        authentic, status, message = self.lambda_authenticator.is_authentic()

        self.assertFalse(authentic)
        self.assertEqual(status, 500)
        self.assertEqual(message, "Boom!")

        self.assertEqual(self.captor.getvalue(), "Boom!\n")
