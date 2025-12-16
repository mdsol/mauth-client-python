import httpx
from mauth_client.config import Config
from mauth_client.signable import RequestSignable
from mauth_client.signer import Signer


class MAuthHttpx(httpx.Auth):
    """
    HTTPX authentication for MAuth.
    Adds MAuth headers based on method, URL, and body bytes.
    """

    # We need the body bytes to sign the request
    requires_request_body = True

    def __init__(
        self,
        app_uuid: str = Config.APP_UUID,
        private_key_data: str = Config.PRIVATE_KEY,
        sign_versions: str = Config.SIGN_VERSIONS,
    ):
        self.signer = Signer(app_uuid, private_key_data, sign_versions)

    def _make_headers(self, request: httpx.Request) -> dict[str, str]:
        # With requires_request_body=True, httpx ensures the content is buffered.
        body = request.content or b""
        req_signable = RequestSignable(
            method=request.method,
            url=str(request.url),
            body=body,
        )
        return self.signer.signed_headers(req_signable)

    def auth_flow(self, request: httpx.Request):
        # Body is already read due to requires_request_body=True.
        request.headers.update(self._make_headers(request))
        yield request
