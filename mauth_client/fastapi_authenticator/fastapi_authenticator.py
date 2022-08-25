import logging

from fastapi import FastAPI, HTTPException, Request
from mauth_client.authenticator import LocalAuthenticator, RemoteAuthenticator
from mauth_client.config import Config
from mauth_client.signable import RequestSignable
from mauth_client.signed import Signed
from typing import Tuple, Union

logger = logging.getLogger("fastapi_mauth")
MAuthAuthenticator = LocalAuthenticator if Config.MAUTH_MODE == "local" else RemoteAuthenticator
state_key = 'fastapi_mauth.client'


class MAuthAuthenticationError(HTTPException):
    pass


class FastAPIAuthenticator:
    """
    The MAuth Authenticator instance
    """

    def __init__(self, app: FastAPI = None) -> None:
        self._app = app
        self._authenticator = None
        if app:
            self.init_app(app)

    def init_app(self, app: FastAPI) -> None:
        """
        Attach authenticator to FastAPI app instance
        """
        self._app = app
        self._authenticator = self
        setattr(app.state, self.state_key, self)

        self._authenticator = self._get_authenticator()

    def _get_authenticator(self) -> Union[LocalAuthenticator, RemoteAuthenticator]:
        # Validate the client settings (APP_UUID, PRIVATE_KEY)
        if not all([Config.APP_UUID, Config.PRIVATE_KEY]):
            raise TypeError("FastAPIAuthenticator requires APP_UUID and PRIVATE_KEY")
        # Validate the mauth settings (MAUTH_BASE_URL, MAUTH_API_VERSION)
        if not all([Config.MAUTH_URL, Config.MAUTH_API_VERSION]):
            raise TypeError("FastAPIAuthenticator requires MAUTH_URL and MAUTH_API_VERSION")
        # Validate MAUTH_MODE
        if Config.MAUTH_MODE not in ("local", "remote"):
            raise TypeError("FastAPIAuthenticator MAUTH_MODE must be one of local or remote")

        return LocalAuthenticator if Config.MAUTH_MODE == "local" else RemoteAuthenticator

    async def authenticate(self, request: Request) -> Tuple[bool, int, str]:
        """
        Authenticate given FastAPI request
        """
        body = await request.body()
        signable = RequestSignable(
            method=request.method,
            url=request.url.path,
            body=body,
        )
        return self._authenticator(
            signable, Signed.from_headers(request.headers), logger
        ).is_authentic()


async def requires_authentication(request: Request) -> None:
    """
    FastAPI Dependecy function for routes requiring MAuth authentication
    """
    authenticator = getattr(request.app.state, state_key)
    is_authentic, status, msg = await authenticator.authenticate(request)
    if not is_authentic:
        raise MAuthAuthenticationError(status_code=status, detail=msg)
