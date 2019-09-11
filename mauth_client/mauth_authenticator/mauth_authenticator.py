import datetime
import re
from hashlib import sha512

import six
from six.moves.urllib.parse import urlparse

from .exceptions import InauthenticError, UnableToAuthenticateError
from .key_holder import KeyHolder
from .rsa_decrypt import RSAPublicKey


class MAuthAuthenticator(object):
    ALLOWED_DRIFT_SECONDS = 300
    MWS_TOKEN = "MWS"

    # Parser for Signature
    SIGNATURE_INFO = re.compile(r'\A([^ ]+) *([^:]+):([^:]+)\Z')

    X_MWS_TIME = "x-mws-time"
    X_MWS_AUTHENTICATION = "x-mws-authentication"

    def __init__(self, method, url, headers, body=''):
        lowercased_headers = { k.lower(): v for k, v in headers.items() }
        self.method = method
        self.url = url
        self.path = urlparse(url).path
        self.body = body or ''
        self.x_mws_time = lowercased_headers.get(self.X_MWS_TIME, '')
        self.x_mws_authentication = lowercased_headers.get(self.X_MWS_AUTHENTICATION, '')
        self.token, self.app_uuid, self.signature = '', '', ''
        if self.x_mws_authentication:
            match = self.SIGNATURE_INFO.match(self.x_mws_authentication)
            if match:
                self.token, self.app_uuid, self.signature = match.groups()

    def get_app_uuid(self):
        return self.app_uuid

    def is_authentic(self):
        self._log_authentication_request()
        authentic = False
        try:
            authentic = self._authenticate()
        except InauthenticError as exc:
            self._log_authentication_error(str(exc))
            return False, 401, str(exc)
        except UnableToAuthenticateError as exc:
            self._log_authentication_error(str(exc))
            return False, 500, str(exc)
        return authentic, 200 if authentic else 401, ''

    def _authenticate(self):
        return self._authentication_present() and self._time_valid() and self._token_valid() and self._signature_valid()

    def _authentication_present(self):
        """
        Is the mauth header present (assuming request has a headers attribute) that can be treated like a dict?
        """
        if not self.x_mws_authentication:
            raise InauthenticError(
                "Authentication Failed. No mAuth signature present; X-MWS-Authentication header is blank.")
        return True

    def _time_valid(self):
        """
        Is the time of the request within the allowed drift?
        """
        if not self.x_mws_time:
            raise InauthenticError("Time verification failed. No x-mws-time present.")
        if not str(self.x_mws_time).isdigit():
            raise InauthenticError("Time verification failed. X-MWS-Time Header format incorrect.")
        now = datetime.datetime.now()
        # this needs a float
        signature_time = datetime.datetime.fromtimestamp(float(self.x_mws_time))
        if now > signature_time + datetime.timedelta(seconds=self.ALLOWED_DRIFT_SECONDS):
            raise InauthenticError("Time verification failed. {} "
                                   "not within {}s of {}".format(signature_time,
                                                                 self.ALLOWED_DRIFT_SECONDS,
                                                                 now.strftime("%Y-%m-%d %H:%M:%S")))
        return True

    def _token_valid(self):
        """
        Is the message signed correctly?
        """
        if not self.token:
            raise InauthenticError("Token verification failed. Misformatted signature.")
        if self.token != self.MWS_TOKEN:
            raise InauthenticError("Token verification failed. "
                                   "Expected {}; token was {}".format(self.MWS_TOKEN, self.token))
        return True

    def _signature_valid(self):
        """
        Is the signature valid?
        """
        try:
            if not self._expected_hash() == self._signature_hash():
                raise InauthenticError("Signature verification failed")
        except ValueError as exc:
            raise InauthenticError("Public key decryption of signature failed!: {}".format(exc))

        return True

    def _string_for_signing(self):
        return '\n'.join([self.method, self.path, self.body, self.app_uuid, self.x_mws_time]).encode('utf-8')

    def _expected_hash(self):
        return six.b(sha512(self._string_for_signing()).hexdigest())

    def _signature_hash(self):
        key_text = KeyHolder.get_public_key(self.app_uuid)
        if "BEGIN PUBLIC KEY" in key_text:
            # Load a PKCS#1 PEM-encoded public key
            rsakey = RSAPublicKey.load_pkcs1_openssl_pem(keyfile=key_text)
        elif "BEGIN RSA PUBLIC KEY" in key_text:
            # Loads a PKCS#1.5 PEM-encoded public key
            rsakey = RSAPublicKey.load_pkcs1(keyfile=key_text, format='PEM')
        else:
            # Unable to identify the key type
            raise UnableToAuthenticateError("Unable to identify Public Key type from Signature")
        padded = rsakey.public_decrypt(self.signature)
        return rsakey.unpad_message(padded)

    def _log_authentication_error(self, message=""):
        app_uuid = self.app_uuid if self.app_uuid else "MISSING"
        print("MAuth Authentication Error: App UUID: {}; URL: {}; Error: {}".format(app_uuid, self.url, message))

    def _log_authentication_request(self):
        app_uuid = self.app_uuid if self.app_uuid else "MISSING"
        print("MAuth Request: App UUID: {}; URL: {}".format(app_uuid, self.url))
