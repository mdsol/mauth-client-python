import requests
from mauth_client.config import Config
from mauth_client.signable import RequestSignable
from mauth_client.signer import Signer


class MAuth(requests.auth.AuthBase):
    """
    Custom requests authorizer for MAuth
    """

    def __init__(self, app_uuid, private_key_data, sign_versions=Config.SIGN_VERSIONS):
        """
        Create a new MAuth Instance

        :param str app_uuid: The Application UUID (or APP_UUID) for the application
        :param str private_key_data: Content of the Private Key File
        :param str sign_versions: Comma-separated protocol versions to sign requests
        """
        self.signer = Signer(app_uuid, private_key_data, sign_versions)

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
        return {**self.signer.signed_headers(request_signable)}
