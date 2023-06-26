import io
import json
import logging

from urllib.parse import quote

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
        path = environ.get("PATH_INFO", "")

        if path in self.exempt:
            return self.app(environ, start_response)

        signable = RequestSignable(
            method=environ["REQUEST_METHOD"],
            url=self._extract_url(environ),
            body=self._read_body(environ),
        )
        signed = Signed.from_headers(self._extract_headers(environ))
        authenticator = LocalAuthenticator(signable, signed, logger)
        is_authentic, code, message = authenticator.is_authentic()

        if is_authentic:
            environ[ENV_APP_UUID] = signed.app_uuid
            environ[ENV_AUTHENTIC] = True
            environ[ENV_PROTOCOL_VERSION] = signed.protocol_version()
            return self.app(environ, start_response)

        return self._send_response(code, message, start_response)

    def _validate_configs(self):
        # Validate the client settings (APP_UUID, PRIVATE_KEY)
        if not all([Config.APP_UUID, Config.PRIVATE_KEY]):
            raise TypeError("MAuthWSGIMiddleware requires APP_UUID and PRIVATE_KEY")
        # Validate the mauth settings (MAUTH_BASE_URL, MAUTH_API_VERSION)
        if not all([Config.MAUTH_URL, Config.MAUTH_API_VERSION]):
            raise TypeError("MAuthWSGIMiddleware requires MAUTH_URL and MAUTH_API_VERSION")

    def _read_body(self, environ):
        try:
            size = int(environ.get("CONTENT_LENGTH", 0))
        except ValueError:
            size = 0

        if not size:
            return b""

        body = environ["wsgi.input"].read(size)

        # hack way of "rewinding" body so that downstream can reuse
        #
        # seek() will not work because production Flask and gunicorn give
        # objects without a seek() function and blow up...
        # yet humorously Flask in our tests gives a normal BytesIO object
        # that does have seek()
        #
        # NOTE:
        # this will not play well with large bodies where this may result in
        # blowing out memory, but tbh MAuth is not adequately designed for and
        # thus should not be used with large bodies.
        environ["wsgi.input"] = io.BytesIO(body)

        return body

    def _extract_headers(self, environ):
        """
        Adapted from werkzeug package: https://github.com/pallets/werkzeug
        """
        headers = {}

        # don't care to titleize the header keys since
        # the Signed class is just going to lowercase them
        for k, v in environ.items():
            if k.startswith("HTTP_") and k not in {
                "HTTP_CONTENT_TYPE",
                "HTTP_CONTENT_LENGTH",
            }:
                key = k[5:].replace("_", "-")
                headers[key] = v
            elif k in {"CONTENT_TYPE", "CONTENT_LENGTH"}:
                key = k.replace("_", "-")
                headers[key] = v

        return headers

    SAFE_CHARS = "!$&'()*+,/:;=@%"

    def _extract_url(self, environ):
        """
        Adapted from https://peps.python.org/pep-0333/#url-reconstruction
        """
        scheme = environ["wsgi.url_scheme"]
        url_parts = [scheme, "://"]
        http_host = environ.get("HTTP_HOST")

        if http_host:
            url_parts.append(http_host)
        else:
            url_parts.append(environ["SERVER_NAME"])
            port = environ["SERVER_PORT"]

            if (scheme == "https" and port != 443) or (scheme != "https" and port != 80):
                url_parts.append(f":{port}")

        url_parts.append(
            quote(environ.get("SCRIPT_NAME", ""), safe=self.SAFE_CHARS)
        )
        url_parts.append(
            quote(environ.get("PATH_INFO", ""), safe=self.SAFE_CHARS)
        )

        qs = environ.get("QUERY_STRING")
        if qs:
            url_parts.append(f"?{quote(qs, safe=self.SAFE_CHARS)}")

        return "".join(url_parts)

    _STATUS_STRS = {
        401: "401 Unauthorized",
        500: "500 Internal Server Error",
    }

    def _send_response(self, code, msg, start_response):
        status = self._STATUS_STRS[code]
        body = {"errors": {"mauth": [msg]}}
        body_bytes = json.dumps(body).encode("utf-8")

        headers = [
            ("Content-Type", "application/json"),
            ("Content-Length", str(len(body_bytes))),
        ]
        start_response(status, headers)

        return [body_bytes]
