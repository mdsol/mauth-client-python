import time
import re
from .rsa_signer import RSASigner
from .consts import AUTH_HEADER_DELIMITER, MWS_TOKEN, X_MWS_AUTH, X_MWS_TIME, MWSV2_TOKEN, MCC_AUTH, MCC_TIME
from .utils import base64_encode


class Signer:
    """
    methods to sign requests.
    """

    def __init__(self, app_uuid, private_key_data, sign_versions):
        """
        Create a new Signer Instance

        :param str app_uuid: The Application UUID (or APP_UUID) for the application
        :param str private_key_data: Content of the Private Key File
        :param str sign_versions: Comma-separated protocol versions to sign requests
        """
        self.app_uuid = app_uuid
        self.rsa_signer = RSASigner(private_key_data)
        self.sign_versions = self._list_sign_versions(sign_versions)

    def signed_headers(self, signable, attributes=None):
        """
        Takes a signable object and returns a hash of headers to be applied to the object which comprises its signature.
        """
        headers = {}
        if "v1" in self.sign_versions:
            headers.update(self.signed_headers_v1(signable, attributes))

        if "v2" in self.sign_versions:
            headers.update(self.signed_headers_v2(signable, attributes))

        return headers

    def signed_headers_v1(self, signable, attributes=None):
        override_attributes = self._build_override_attributes(attributes)
        signature = self.signature_v1(signable.string_to_sign_v1(override_attributes))

        return {
            X_MWS_AUTH: "{} {}:{}".format(MWS_TOKEN, self.app_uuid, signature),
            X_MWS_TIME: override_attributes.get("time"),
        }

    def signed_headers_v2(self, signable, attributes=None):
        override_attributes = self._build_override_attributes(attributes)
        signature = self.signature_v2(signable.string_to_sign_v2(override_attributes))

        return {
            MCC_AUTH: "{} {}:{}{}".format(MWSV2_TOKEN, self.app_uuid, signature, AUTH_HEADER_DELIMITER),
            MCC_TIME: override_attributes.get("time"),
        }

    def signature_v1(self, string_to_sign):
        return base64_encode(self.rsa_signer.sign_v1(string_to_sign))

    def signature_v2(self, string_to_sign):
        return base64_encode(self.rsa_signer.sign_v2(string_to_sign))

    def _build_override_attributes(self, attributes):
        if not attributes:
            attributes = {}

        return {"time": str(int(time.time())), "app_uuid": self.app_uuid, **attributes}

    @staticmethod
    def _list_sign_versions(sign_versions):
        sign_versions = sign_versions.lower().replace(" ", "").split(",")
        if not all(re.match(r"^v\d+$", sign_version) for sign_version in sign_versions):
            raise ValueError("SIGN_VERSIONS must be comma-separated MAuth protocol versions (e.g. 'v1,v2')")

        return sign_versions
