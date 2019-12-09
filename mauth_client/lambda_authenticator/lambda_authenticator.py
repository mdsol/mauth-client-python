import logging
from mauth_client.authenticator import LocalAuthenticator, RemoteAuthenticator
from mauth_client.config import Config
from mauth_client.signable import RequestSignable
from mauth_client.signed import Signed


class LambdaAuthenticator:
    def __init__(self, method, url, headers, body):
        logger = logging.getLogger()
        signable = RequestSignable(method=method, url=url, body=body)
        authenticator = LocalAuthenticator if Config.MAUTH_MODE == "local" else RemoteAuthenticator
        self._authenticator = authenticator(signable, Signed.from_headers(headers), logger)

    def get_app_uuid(self):
        return self._authenticator.signed.app_uuid

    def is_authentic(self):
        return self._authenticator.is_authentic()
