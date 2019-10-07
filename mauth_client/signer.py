import time
from .rsa_signer import RSASigner
from .consts import AUTH_HEADER_DELIMITER, MWS_TOKEN, X_MWS_AUTH, X_MWS_TIME, MWSV2_TOKEN, MCC_AUTH, MCC_TIME
from .utils import base64_encode

class Signer:
    """
    methods to sign requests.
    """

    def __init__(self, app_uuid, private_key_data, v2_only_sign_requests=False):
        """
        Create a new Signer Instance

        :param str app_uuid: The Application UUID (or APP_UUID) for the application
        :param str private_key_data: Content of the Private Key File
        :param bool v2_only_sign_requests: Flag to sign with only V2
        """
        self.app_uuid = app_uuid
        self.rsa_signer = RSASigner(private_key_data)
        self.v2_only_sign_requests = v2_only_sign_requests

    def signed_headers(self, signable, attributes=None):
        """
        Takes a signable object and returns a hash of headers to be applied to the object which comprises its signature.
        """
        if self.v2_only_sign_requests:
            return self.signed_headers_v2(signable, attributes)

        # by default sign with both the v1 and v2 protocol
        return { **self.signed_headers_v1(signable, attributes), **self.signed_headers_v2(signable, attributes) }

    def signed_headers_v1(self, signable, attributes=None):
        override_attributes = self._build_override_attributes(attributes)
        signature = self.signature_v1(signable.string_to_sign_v1(override_attributes))

        return {
            X_MWS_AUTH: "{} {}:{}".format(MWS_TOKEN, self.app_uuid, signature),
            X_MWS_TIME: override_attributes.get("time")
        }

    def signed_headers_v2(self, signable, attributes=None):
        override_attributes = self._build_override_attributes(attributes)
        signature = self.signature_v2(signable.string_to_sign_v2(override_attributes))

        return {
            MCC_AUTH: "{} {}:{}{}".format(MWSV2_TOKEN, self.app_uuid, signature, AUTH_HEADER_DELIMITER),
            MCC_TIME: override_attributes.get("time")
        }

    def signature_v1(self, string_to_sign):
        return base64_encode(self.rsa_signer.sign_v1(string_to_sign))

    def signature_v2(self, string_to_sign):
        return base64_encode(self.rsa_signer.sign_v2(string_to_sign))

    def _build_override_attributes(self, attributes):
        if not attributes:
            attributes = {}

        return { "time": str(int(time.time())), "app_uuid": self.app_uuid, **attributes }
