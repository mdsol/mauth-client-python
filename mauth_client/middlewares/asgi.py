import json
import logging

from asgiref.typing import (
    ASGI3Application,
    ASGIReceiveCallable,
    ASGIReceiveEvent,
    ASGISendCallable,
    Scope,
)
from typing import List, Tuple, Optional

from mauth_client.authenticator import LocalAuthenticator
from mauth_client.config import Config
from mauth_client.consts import (
    ENV_APP_UUID,
    ENV_AUTHENTIC,
    ENV_PROTOCOL_VERSION,
)
from mauth_client.signable import RequestSignable
from mauth_client.signed import Signed
from mauth_client.utils import decode, is_exempt_request_path

logger = logging.getLogger("mauth_asgi")


class MAuthASGIMiddleware:
    def __init__(self, app: ASGI3Application, exempt: Optional[set] = None, exempt_prefix_match: bool = False) -> None:
        self._validate_configs()
        self.app = app
        self.exempt = exempt.copy() if exempt else set()
        self.exempt_prefix_match = exempt_prefix_match

    async def __call__(
        self, scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable
    ) -> None:
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        path = scope["path"]
        if path in self.exempt:
            return await self.app(scope, receive, send)

        if self.exempt_prefix_match and is_exempt_request_path(path, self.exempt):
            return await self.app(scope, receive, send)

        query_string = scope["query_string"]
        url = f"{path}?{decode(query_string)}" if query_string else path
        headers = {decode(k): decode(v) for k, v in scope["headers"]}

        events, body = await self._get_body(receive)

        signable = RequestSignable(
            method=scope["method"],
            url=url,
            body=body,
        )
        signed = Signed.from_headers(headers)
        authenticator = LocalAuthenticator(signable, signed, logger)
        is_authentic, status, message = authenticator.is_authentic()

        if is_authentic:
            # asgi spec calls for passing a copy of the scope rather than mutating it
            # note: deepcopy will blow up with infi recursion due to objects in some values
            scope_copy = scope.copy()
            scope_copy[ENV_APP_UUID] = signed.app_uuid
            scope_copy[ENV_AUTHENTIC] = True
            scope_copy[ENV_PROTOCOL_VERSION] = signed.protocol_version()
            await self.app(scope_copy, self._fake_receive(events, receive), send)
        else:
            await self._send_response(send, status, message)

    def _validate_configs(self) -> None:
        # Validate the client settings (APP_UUID, PRIVATE_KEY)
        if not all([Config.APP_UUID, Config.PRIVATE_KEY]):
            raise TypeError("MAuthASGIMiddleware requires APP_UUID and PRIVATE_KEY")
        # Validate the mauth settings (MAUTH_BASE_URL, MAUTH_API_VERSION)
        if not all([Config.MAUTH_URL, Config.MAUTH_API_VERSION]):
            raise TypeError("MAuthASGIMiddleware requires MAUTH_URL and MAUTH_API_VERSION")

    async def _get_body(
        self, receive: ASGIReceiveCallable
    ) -> Tuple[List[ASGIReceiveEvent], bytes]:
        body = b""
        more_body = True
        events = []

        while more_body:
            event = await receive()
            body += event.get("body", b"")
            more_body = event.get("more_body", False)
            events.append(event)
        return (events, body)

    async def _send_response(self, send: ASGISendCallable, status: int, msg: str) -> None:
        await send({
            "type": "http.response.start",
            "status": status,
            "headers": [(b"content-type", b"application/json")],
        })
        body = {"errors": {"mauth": [msg]}}
        await send({
            "type": "http.response.body",
            "body": json.dumps(body).encode("utf-8"),
        })

    def _fake_receive(self, events: List[ASGIReceiveEvent],
                      original_receive: ASGIReceiveCallable) -> ASGIReceiveCallable:
        """
        Create a fake receive function that replays cached body events.

        After the middleware consumes request body events for authentication,
        this allows downstream apps to also "receive" those events. Once all
        cached events are exhausted, delegates to the original receive to
        properly forward lifecycle events (like http.disconnect).

        This is essential for long-lived connections (SSE, streaming responses)
        that need to detect client disconnects.
        """
        events_iter = iter(events)

        async def _receive() -> ASGIReceiveEvent:
            try:
                return next(events_iter)
            except StopIteration:
                # After body events are consumed, delegate to original receive
                # This allows proper handling of disconnects for SSE connections
                return await original_receive()
        return _receive
