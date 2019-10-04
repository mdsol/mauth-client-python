import requests
from mauth_client.config import Config
from mauth_client.signable import RequestSignable
from mauth_client.signer import Signer


class MAuth(requests.auth.AuthBase):
    """
    Custom requests authorizer for MAuth
    """
    def __init__(self, app_uuid, private_key_data, v2_only_sign_requests=Config.V2_ONLY_SIGN_REQUESTS):
        """
        Create a new MAuth Instance

        :param str app_uuid: The Application UUID (or APP_UUID) for the application
        :param str private_key_data: Content of the Private Key File
        :param bool v2_only_sign_requests: Flag to sign requests with only V2
        """
        self.signer = Signer(app_uuid, private_key_data, v2_only_sign_requests)

    def __call__(self, request):
        """Call override, the entry point for a custom auth object

        :param requests.models.PreparedRequest request: the Request object
        """
        request.headers.update(self.make_headers(request))
        return request

    def make_headers(self, request):
        """Make headers for the request.

        :param requests.models.PreparedRequest request: the Request object
        """
        request_signable = RequestSignable(method=request.method, url=request.url, body=request.body)
        return { **self.signer.signed_headers(request_signable), "Content-Type": "application/json;charset=utf-8" }
