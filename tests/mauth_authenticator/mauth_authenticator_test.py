from datetime import datetime, timedelta
import sys
import unittest
from unittest.mock import MagicMock
from io import StringIO
from freezegun import freeze_time

from mauth_client.mauth_authenticator import MAuthAuthenticator
from mauth_client.mauth_authenticator.key_holder import KeyHolder
from mauth_client.mauth_authenticator.exceptions import InauthenticError, UnableToAuthenticateError

from tests.mauth_authenticator.common import load_key

APP_UUID = 'f5af50b2-bf7d-4c29-81db-76d086d4808a'
TRACE_ID = '0b99e6a00834848b'
URL = 'https://api_gateway.com/sandbox/path'
X_MWS_TIME = '1500854400'  # 2017-07-24 09:00:00 UTC
MWS_DATETIME = datetime.fromtimestamp(float(X_MWS_TIME))

SIGNATURE = 'p0SNltF6B4G5z+nVNbLv2XCEdouimo/ECQ/Sum6YM+QgE1/LZLXY+hAcwe/TkaC/2d8I3Zot37Xgob3cftgSf9S1fPAi3euN0Fmv/OE' \
            'kfUmsYvmqyOXawEWGpevoEX6KNpEAUrt48hFGomsWRgbEEjuUtN4iiPe9y3HlIjumUmDrM499RZxgZdyOhqtLVOv5ngNShDbFv2LljI' \
            'Tl4sO0f7zU8wAYGfxLEPXvp8qgnzQ6usZwrD2ujSmXbZtksqgG1R0Vmb7LAd6P+uvtRkw8kGLz/wWwxRweSGliX/IwovGi/bMIIClDD' \
            'faUAY9QDjcU1x7i0Yy1IEyQYyCWcnL1rA=='

X_MWS_AUTHENTICATION = "MWS {}:{}".format(APP_UUID, SIGNATURE)
HEADERS = {'X-Mws-Time': X_MWS_TIME, 'X-Mws-Authentication': X_MWS_AUTHENTICATION}
BODY = "こんにちはÆ"


class TestMauthAuthenticator(unittest.TestCase):
    def setUp(self):
        self.__get_public_key__ = KeyHolder.get_public_key
        KeyHolder.get_public_key = MagicMock(return_value=load_key('rsapub'))

        # redirect the output of stdout to self.captor
        self.captor = StringIO()
        sys.stdout = self.captor

        self.mauth_authenticator = MAuthAuthenticator(TRACE_ID, 'POST', URL, HEADERS, BODY)
        self.mauth_authenticator_with_empty_headers = MAuthAuthenticator(TRACE_ID, 'POST', URL, {})

    def tearDown(self):
        # reset the KeyHolder.get_public_key method
        KeyHolder.get_public_key = self.__get_public_key__

        # reset the output of stdout to console
        sys.stdout = sys.__stdout__

    def test_init(self):
        self.assertEqual(self.mauth_authenticator.method, 'POST')
        self.assertEqual(self.mauth_authenticator.url, 'https://api_gateway.com/sandbox/path')
        self.assertEqual(self.mauth_authenticator.path, '/sandbox/path')
        self.assertEqual(self.mauth_authenticator.body, BODY)
        self.assertEqual(self.mauth_authenticator.x_mws_time, '1500854400')
        self.assertEqual(self.mauth_authenticator.x_mws_authentication, X_MWS_AUTHENTICATION)
        self.assertEqual(self.mauth_authenticator.token, 'MWS')
        self.assertEqual(self.mauth_authenticator.app_uuid, 'f5af50b2-bf7d-4c29-81db-76d086d4808a')
        self.assertEqual(self.mauth_authenticator.signature, SIGNATURE)

    def test_init_with_empty_headers(self):
        self.assertEqual(self.mauth_authenticator_with_empty_headers.method, 'POST')
        self.assertEqual(self.mauth_authenticator_with_empty_headers.url, 'https://api_gateway.com/sandbox/path')
        self.assertEqual(self.mauth_authenticator_with_empty_headers.path, '/sandbox/path')
        self.assertEqual(self.mauth_authenticator_with_empty_headers.body, '')
        self.assertEqual(self.mauth_authenticator_with_empty_headers.x_mws_time, '')
        self.assertEqual(self.mauth_authenticator_with_empty_headers.x_mws_authentication, '')
        self.assertEqual(self.mauth_authenticator_with_empty_headers.token, '')
        self.assertEqual(self.mauth_authenticator_with_empty_headers.app_uuid, '')
        self.assertEqual(self.mauth_authenticator_with_empty_headers.signature, '')

    def test_authentication_present_happy_path(self):
        self.assertTrue(self.mauth_authenticator._authentication_present())

    def test_authentication_present_missing(self):
        with self.assertRaises(InauthenticError) as exc:
            self.mauth_authenticator_with_empty_headers._authentication_present()
        self.assertEqual(str(exc.exception),
                         "Authentication Failed. No mAuth signature present; X-MWS-Authentication header is blank.")

    def test_authentication_present_blank(self):
        self.mauth_authenticator.x_mws_authentication = ''
        with self.assertRaises(InauthenticError) as exc:
            self.mauth_authenticator._authentication_present()
        self.assertEqual(str(exc.exception),
                         "Authentication Failed. No mAuth signature present; X-MWS-Authentication header is blank.")

    @freeze_time(MWS_DATETIME)
    def test_time_valid_happy_path(self):
        self.assertTrue(self.mauth_authenticator._time_valid())

    def test_time_valid_missing_header(self):
        with self.assertRaises(InauthenticError) as exc:
            self.mauth_authenticator_with_empty_headers._time_valid()
        self.assertEqual(str(exc.exception), "Time verification failed. No x-mws-time present.")

    def test_time_valid_bad_header(self):
        self.mauth_authenticator.x_mws_time = 'apple'
        with self.assertRaises(InauthenticError) as exc:
            self.mauth_authenticator._time_valid()
        self.assertEqual(str(exc.exception), "Time verification failed. X-MWS-Time Header format incorrect.")

    @freeze_time(MWS_DATETIME + timedelta(minutes=5,seconds=1))
    def test_time_valid_expired_header(self):
        with self.assertRaises(InauthenticError) as exc:
            self.mauth_authenticator._time_valid()
        self.assertEqual(str(exc.exception),
                         "Time verification failed. %s "
                         "not within %ss of %s" % (datetime.fromtimestamp(int(X_MWS_TIME)),
                                                   MAuthAuthenticator.ALLOWED_DRIFT_SECONDS,
                                                   datetime.now()))

    def test_token_valid_happy_path(self):
        self.assertTrue(self.mauth_authenticator._token_valid())

    def test_token_valid_missing_token(self):
        self.mauth_authenticator.token = ''
        with self.assertRaises(InauthenticError) as exc:
            self.mauth_authenticator._token_valid()
        self.assertEqual(str(exc.exception), "Token verification failed. Misformatted signature.")

    def test_token_valid_bad_token(self):
        self.mauth_authenticator.token = 'RWS'
        with self.assertRaises(InauthenticError) as exc:
            self.mauth_authenticator._token_valid()
        self.assertEqual(str(exc.exception), "Token verification failed. Expected MWS; token was RWS")

    def test_authenticates_a_genuine_message(self):
        self.assertTrue(self.mauth_authenticator._signature_valid())

    def test_authenticates_a_genuine_message_v1(self):
        KeyHolder.get_public_key = MagicMock(return_value=load_key('pub'))
        self.assertTrue(self.mauth_authenticator._signature_valid())

    def test_does_not_authenticate_a_false_message(self):
        self.mauth_authenticator.method = 'GET'
        with self.assertRaises(InauthenticError) as exc:
            self.mauth_authenticator._signature_valid()
        self.assertEqual("Signature verification failed", str(exc.exception))

    @freeze_time(MWS_DATETIME)
    def test_is_authentic_happy_path(self):
        authentic, status, _message = self.mauth_authenticator.is_authentic()
        self.assertTrue(authentic)
        self.assertEqual(200, status)

    @freeze_time(MWS_DATETIME)
    def test_is_authentic_fails(self):
        self.mauth_authenticator._authenticate = MagicMock(return_value=False)
        authentic, _status, _message = self.mauth_authenticator.is_authentic()
        self.assertFalse(authentic)

    @freeze_time(MWS_DATETIME)
    def test_is_authentic_some_token_invalid(self):
        self.mauth_authenticator._token_valid = MagicMock(side_effect=InauthenticError())
        authentic, _status, _message = self.mauth_authenticator.is_authentic()
        self.assertFalse(authentic)

    @freeze_time(MWS_DATETIME)
    def test_is_authentic_some_time_invalid(self):
        self.mauth_authenticator._time_valid = MagicMock(side_effect=InauthenticError())
        authentic, _status, _message = self.mauth_authenticator.is_authentic()
        self.assertFalse(authentic)

    @freeze_time(MWS_DATETIME)
    def test_is_authentic_some_authentication_missing(self):
        self.mauth_authenticator._authentication_present = MagicMock(side_effect=InauthenticError())
        authentic, _status, _message = self.mauth_authenticator.is_authentic()
        self.assertFalse(authentic)

    @freeze_time(MWS_DATETIME)
    def test_is_authentic_some_signature_invalid(self):
        self.mauth_authenticator._signature_valid = MagicMock(side_effect=InauthenticError())
        authentic, _status, _message = self.mauth_authenticator.is_authentic()
        self.assertFalse(authentic)

    @freeze_time(MWS_DATETIME)
    def test_is_authenticate_error_conditions_inauthentic(self):
        self.mauth_authenticator._authenticate = MagicMock(side_effect=InauthenticError())
        authentic, status, message = self.mauth_authenticator.is_authentic()
        self.assertFalse(authentic)
        self.assertEqual(401, status)
        self.assertEqual("", message)

    @freeze_time(MWS_DATETIME)
    def test_is_authenticate_error_conditions_unable(self):
        self.mauth_authenticator._authenticate = MagicMock(side_effect=UnableToAuthenticateError(''))
        authentic, status, message = self.mauth_authenticator.is_authentic()
        self.assertFalse(authentic)
        self.assertEqual(500, status)
        self.assertEqual("", message)

    @freeze_time(MWS_DATETIME)
    def test_authenticate_happy_path(self):
        authentic = self.mauth_authenticator._authenticate()
        self.assertTrue(authentic)

    @freeze_time(MWS_DATETIME)
    def test_authenticate_happy_path_lowercase_headers(self):
        headers = {'x-mws-time': X_MWS_TIME, 'x-mws-authentication': X_MWS_AUTHENTICATION}
        authentic = MAuthAuthenticator(TRACE_ID, 'POST', URL, headers, BODY)._authenticate()
        self.assertTrue(authentic)

    @freeze_time(MWS_DATETIME)
    def test_authenticate_fails(self):
        self.mauth_authenticator._signature_valid = MagicMock(return_value=False)
        authentic = self.mauth_authenticator._authenticate()
        self.assertFalse(authentic)

    def test_log_inauthentic_error(self):
        self.mauth_authenticator._log_authentication_error("X-MWS-Time too old")
        self.assertEqual(
            self.captor.getvalue().rstrip('\n'),
            'MAuth Authentication Error: App UUID: {}; URL: {}; Error: X-MWS-Time too old'.format(APP_UUID, URL)
        )

    def test_log_inauthentic_error_missing_app_uuid(self):
        self.mauth_authenticator.app_uuid = ''
        self.mauth_authenticator._log_authentication_error("X-MWS-Time too old")
        self.assertEqual(
            self.captor.getvalue().rstrip('\n'),
            'MAuth Authentication Error: App UUID: MISSING; URL: {}; Error: X-MWS-Time too old'.format(URL)
        )

    def test_log_authentication_request_info(self):
        self.mauth_authenticator._log_authentication_request()
        self.assertEqual(self.captor.getvalue().rstrip('\n'),
                         'MAuth Request: App UUID: {}; URL: {}'.format(APP_UUID, URL))

    def test_log_authentication_request_missing_app_uuid(self):
        self.mauth_authenticator.app_uuid = ''
        self.mauth_authenticator._log_authentication_request()
        self.assertEqual(self.captor.getvalue().rstrip('\n'),
                         'MAuth Request: App UUID: MISSING; URL: {}'.format(URL))
