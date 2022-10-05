import json
import logging

from mauth_client.authenticator import LocalAuthenticator
from mauth_client.config import Config
from mauth_client.consts import (
    ENV_APP_UUID,
    ENV_AUTHENTIC,
    ENV_PROTOCOL_VERSION,
)

from mauth_client.signable import RequestSignable
from mauth_client.signed import Signed

logger = logging.getLogger("mauth_wsgi")


class MAuthWSGIMiddleware:
    def __init__(self, app, exempt=None):
        self._validate_configs()
        self.app = app
        self.exempt = exempt.copy() if exempt else set()

    def __call__(self, environ, start_response):
        req = environ["werkzeug.request"]

        if req.path in self.exempt:
            return self.app(environ, start_response)

        signable = RequestSignable(
            method=req.method,
            url=req.url,
            body=self._read_body(environ),
        )
        signed = Signed.from_headers(dict(req.headers))
        authenticator = LocalAuthenticator(signable, signed, logger)
        is_authentic, status, message = authenticator.is_authentic()

        if is_authentic:
            environ[ENV_APP_UUID] = signed.app_uuid
            environ[ENV_AUTHENTIC] = True
            environ[ENV_PROTOCOL_VERSION] = signed.protocol_version()
            return self.app(environ, start_response)

        start_response(status, [("content-type", "application/json")])
        body = {"errors": {"mauth": [message]}}
        return [json.dumps(body).encode("utf-8")]

    def _validate_configs(self):
        # Validate the client settings (APP_UUID, PRIVATE_KEY)
        if not all([Config.APP_UUID, Config.PRIVATE_KEY]):
            raise TypeError("MAuthWSGIMiddleware requires APP_UUID and PRIVATE_KEY")
        # Validate the mauth settings (MAUTH_BASE_URL, MAUTH_API_VERSION)
        if not all([Config.MAUTH_URL, Config.MAUTH_API_VERSION]):
            raise TypeError("MAuthWSGIMiddleware requires MAUTH_URL and MAUTH_API_VERSION")

    def _read_body(self, environ):
        input = environ["wsgi.input"]
        input.seek(0)
        body = input.read()
        input.seek(0)
        return body
