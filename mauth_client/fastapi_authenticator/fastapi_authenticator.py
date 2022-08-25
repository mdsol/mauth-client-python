import logging

from fastapi import HTTPException, Request
from mauth_client.authenticator import LocalAuthenticator, RemoteAuthenticator
from mauth_client.config import Config
from mauth_client.signable import RequestSignable
from mauth_client.signed import Signed

logger = logging.getLogger("fastapi_mauth")
MAuthAuthenticator = LocalAuthenticator if Config.MAUTH_MODE == "local" else RemoteAuthenticator


class MAuthAuthenticationError(HTTPException):
    pass


async def authenticate(request: Request) -> list:
    """
    Authenticate given FastAPI request
    """
    body = await request.body()
    signable = RequestSignable(
        method=request.method,
        url=request.url.path,
        body=body,
    )
    return MAuthAuthenticator(
        signable, Signed.from_headers(request.headers), logger
    ).is_authentic()


async def requires_authentication(request: Request) -> None:
    """
    FastAPI Dependecy function for routes requiring MAuth authentication
    """
    is_authentic, status, msg = await authenticate(request)
    if not is_authentic:
        raise MAuthAuthenticationError(status_code=status, detail=msg)
