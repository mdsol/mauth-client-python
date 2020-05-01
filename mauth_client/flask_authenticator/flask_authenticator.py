import json
import logging
from functools import wraps

from flask import Response, current_app, request
from mauth_client.authenticator import LocalAuthenticator, RemoteAuthenticator
from mauth_client.config import Config
from mauth_client.signable import RequestSignable
from mauth_client.signed import Signed

logger = logging.getLogger("flask_mauth")


class FlaskAuthenticator:
    """
    The MAuth Authenticator instance
    """

    state_key = "flask_mauth.client"

    def __init__(self, app=None):
        # backwards compatibility support
        self._app = app
        self._authenticator = None
        if app:
            self.init_app(app)

    def init_app(self, app):
        """
        Init app with Flask instance.

        :param app: Flask Application instance
        """
        self._app = app
        app.authenticator = self
        app.extensions = getattr(app, "extensions", {})
        app.extensions[self.state_key] = self

        self._authenticator = self._get_authenticator()

    def _get_authenticator(self):
        # Validate the client settings (APP_UUID, PRIVATE_KEY)
        if None in (Config.APP_UUID, Config.PRIVATE_KEY) or "" in (Config.APP_UUID, Config.PRIVATE_KEY):
            raise TypeError("FlaskAuthenticator requires APP_UUID and PRIVATE_KEY")
        # Validate the mauth settings (MAUTH_BASE_URL, MAUTH_API_VERSION)
        if None in (Config.MAUTH_URL, Config.MAUTH_API_VERSION) or "" in (Config.MAUTH_URL, Config.MAUTH_API_VERSION):
            raise TypeError("FlaskAuthenticator requires MAUTH_URL and MAUTH_API_VERSION")
        # Validate MAUTH_MODE
        if Config.MAUTH_MODE not in ("local", "remote"):
            raise TypeError("FlaskAuthenticator MAUTH_MODE must be one of local or remote")

        return LocalAuthenticator if Config.MAUTH_MODE == "local" else RemoteAuthenticator

    def authenticate(self, signed_request):
        """
        Authenticates a request

        :param signed_request: Request object
        :type request: werkzeug.wrappers.BaseRequest
        :return: Is the request authentic, Status Code, Message
        :rtype: bool, int, str
        """
        signable = RequestSignable(method=signed_request.method, url=signed_request.path, body=signed_request.data)
        return self._authenticator(signable, Signed.from_headers(signed_request.headers), logger).is_authentic()


def requires_authentication(func):
    """
    A Decorator for routes requiring mauth authentication
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        authenticator = current_app.authenticator
        authentic, status, message = authenticator.authenticate(request)
        if not authentic:
            _message = json.dumps(dict(errors=dict(mauth=[message])))
            return Response(response=_message, status=status, mimetype="application/json")
        return func(*args, **kwargs)

    return wrapper
