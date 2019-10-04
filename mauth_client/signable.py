from abc import ABC, abstractmethod
from urllib.parse import quote, urlparse
from .utils import hexdigest
from .exceptions import UnableToSignError


class Signable(ABC):
    """
    Makes a signature string to sign
    """
    def __init__(self, **kwargs):
        """
        Create a new Signable instance

        :param dict attributes_for_signing: Attributes to generate a signature string
        """
        self.name = self. __class__.__name__.replace("Signable", "").lower()
        self.attributes_for_signing = self.build_attributes(**kwargs)

    def string_to_sign_v1(self, override_attributes):
        """
        Composes a string suitable for private-key signing from the SIGNATURE_COMPONENTS keys of
        attributes for signing, which are themselves taken from attributes_for_signing and
        the given argument override_attributes.

        The string to sign for V1 protocol will be (where LF is line feed character) for requests::

            string_to_sign =
                http_verb + <LF> +
                resource_url_path (no host, port or query string; first "/" is included) + <LF> +
                request_body + <LF> +
                app_uuid + <LF> +
                current_seconds_since_epoch

        :param dict override_attributes: Additional attributes to generate a signature string
        """
        attributes_for_signing = { **self.attributes_for_signing, **override_attributes }
        missing_attributes = [
            k for k in self.SIGNATURE_COMPONENTS if (not attributes_for_signing.get(k) and k != "body")
        ]

        if missing_attributes:
            raise UnableToSignError("Missing required attributes to sign: {}".format(missing_attributes))

        return "\n".join([str(attributes_for_signing.get(k, "")) for k in self.SIGNATURE_COMPONENTS])

    def string_to_sign_v2(self, override_attributes):
        """
        Composes a string suitable for private-key signing from the SIGNATURE_COMPONENTS_V2 keys of
        attributes for signing, which are themselves taken from attributes_for_signing and
        the given argument override_attributes

        The string to sign for V2 protocol will be (where LF is line feed character) for requests::

            string_to_sign =
                http_verb + <LF> +
                resource_url_path (no host, port or query string; first "/" is included) + <LF> +
                request_body_digest + <LF> +
                app_uuid + <LF> +
                current_seconds_since_epoch + <LF> +
                encoded_query_params

        :param dict override_attributes: Additional attributes to generate a signature string
        """

        # memoization of body_digest
        # note that if :body is None we hash an empty string ("")
        if "body_digest" not in self.attributes_for_signing:
            body_digest = hexdigest(str(self.attributes_for_signing.get("body", "")))
            self.attributes_for_signing["body_digest"] = body_digest

        attrs_with_overrides = { **self.attributes_for_signing, **override_attributes }
        encoded_query_params = self.encode_query_string(attrs_with_overrides.get("query_string"))
        attrs_with_overrides["encoded_query_params"] = encoded_query_params

        missing_attributes = [
            k for k in self.SIGNATURE_COMPONENTS_V2 if (not attrs_with_overrides.get(k) and k != "encoded_query_params")
        ]

        if missing_attributes:
            raise UnableToSignError("Missing required attributes to sign: {}".format(missing_attributes))

        return "\n".join([str(attrs_with_overrides.get(k, "")) for k in self.SIGNATURE_COMPONENTS_V2])

    def encode_query_string(self, query_string):
        """
        Sorts query string parameters by codepoint, uri encodes keys and values,
        and rejoins parameters into a query string
        """
        if query_string:
            return "&".join([self.encode_query_parameter(param) for param in sorted(query_string.split("&"))])

        return ""

    @classmethod
    def encode_query_parameter(cls, param):
        part = param.partition("=")
        return "{}={}".format(cls.quote_unescape_tilde(part[0]), cls.quote_unescape_tilde(part[2]))

    @staticmethod
    def quote_unescape_tilde(string):
        """
        The urllib.parse.quote method changed in 3.7 to not escape tildes.
        We replace tilde encoding back to tildes to account for older Pythons.
        (See: https://docs.python.org/3/library/urllib.parse.html#url-quoting)
        """
        return quote(string).replace("%7E", "~")

    @abstractmethod
    def build_attributes(self, **kwargs):
        pass


class RequestSignable(Signable):
    """
    Makes a signature string for signing a request
    """
    SIGNATURE_COMPONENTS = ["verb", "request_url", "body", "app_uuid", "time"]
    SIGNATURE_COMPONENTS_V2 = ["verb", "request_url", "body_digest", "app_uuid", "time", "encoded_query_params"]

    def build_attributes(self, **kwargs):
        body = kwargs.get("body") or ""
        parsed = urlparse(kwargs.get("url"))
        return {
            "verb": kwargs.get("method"),
            "request_url": parsed.path,
            "query_string": parsed.query,
            "body": body.decode("utf-8") if isinstance(body, bytes) else body
        }
