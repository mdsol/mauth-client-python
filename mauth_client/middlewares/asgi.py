import json
import logging

from asgiref.typing import (
    ASGI3Application,
    ASGIReceiveCallable,
    ASGISendCallable,
    Scope,
)

from mauth_client.authenticator import LocalAuthenticator
from mauth_client.config import Config
from mauth_client.signable import RequestSignable
from mauth_client.signed import Signed

from copy import deepcopy

logger = logging.getLogger("mauth_asgi")


class MAuthASGIMiddleware:
    def __init__(self, app: ASGI3Application) -> None:
        # self._validate_configs()
        self.app = app

    async def __call__(
        self, scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable
    ) -> None:
        url = "?".join(scope["path"], scope["query_string"].decode("utf-8"))
        headers = self._get_headers(scope)
        body = await self._get_body(receive)

        signable = RequestSignable(
            method=scope["method"],
            url=url,
            body=body,
        )
        authenticator = LocalAuthenticator(
            signable,
            Signed.from_headers(headers),
            logger,
        )

        is_authentic, status, message = authenticator.is_authentic()

        if is_authentic:
            # asgi spec calls for passing a copy of the scope rather than mutating it
            scope_copy = deepcopy(scope)
            scope_copy["mauth"] = {"app_uuid": authenticator.signed.app_uuid}
            await self.app(scope_copy, receive, send)
        else:
            await self._send_response(send, status, message)


    def _validate_configs(self) -> None:
        # Validate the client settings (APP_UUID, PRIVATE_KEY)
        if not all([Config.APP_UUID, Config.PRIVATE_KEY]):
            raise TypeError("FastAPIAuthenticator requires APP_UUID and PRIVATE_KEY")
        # Validate the mauth settings (MAUTH_BASE_URL, MAUTH_API_VERSION)
        if not all([Config.MAUTH_URL, Config.MAUTH_API_VERSION]):
            raise TypeError("FastAPIAuthenticator requires MAUTH_URL and MAUTH_API_VERSION")

    def _get_headers(scope: Scope) -> dict:
        return {
            k.decode("utf-8"): v.decode("utf-8")
            for k, v in scope["headers"]
        }

    async def _get_body(receive: ASGIReceiveCallable) -> str:
        body = b""
        more_body = True
        while more_body:
            msg = await receive()
            body += msg.get("body", b"")
            more_body = msg.get("more_body", False)
        return body.decode("utf-8")

    async def _send_response(self, send: ASGISendCallable, status: int, msg: str) -> None:
        await send({
            "type": "http.response.start",
            "status": status,
            "headers": [(b"content-type", b"application/json")],
        })
        body = {"errors": {"mauth": msg}}
        await({
            "type": "http.response.body",
            "body": json.dumps(body).encode("utf-8")
        })
