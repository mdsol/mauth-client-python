from abc import ABC, abstractmethod
import base64
import datetime
import requests
from .config import Config
from .consts import MWS_TOKEN, MWSV2_TOKEN
from .exceptions import InauthenticError, MAuthNotPresent, MissingV2Error, UnableToAuthenticateError
from .lambda_helper import generate_mauth
from .rsa_verifier import RSAVerifier
from .utils import make_bytes


class AbstractAuthenticator(ABC):
    ALLOWED_DRIFT_SECONDS = 300
    AUTHENTICATION_TYPE = None

    @abstractmethod
    def __init__(self, signable, signed, logger):
        self.signable = signable
        self.signed = signed
        self.logger = logger
        self.rsa_verifier = None  # Lazy loading

    def is_authentic(self):
        self._log_authentication_request()
        try:
            self._authenticate()
        except (MAuthNotPresent, MissingV2Error) as exc:
            self.logger.error("mAuth signature not present on %s. Exception: %s", self.signable.name, str(exc))
            return False, 401, str(exc)
        except InauthenticError as exc:
            self.logger.error(
                "mAuth signature authentication failed for %s. " "Exception: %s", self.signable.name, str(exc)
            )
            return False, 401, str(exc)
        except UnableToAuthenticateError as exc:
            self.logger.error(str(exc))
            return False, 500, str(exc)
        return True, 200, ""

    def _log_authentication_request(self):
        signed_app_uuid = self.signed.app_uuid if self.signed.app_uuid else "[none provided]"
        signed_token = self.signed.token if self.signed.token else "[none provided]"
        self.logger.info(
            "Mauth-client attempting to authenticate request from app with mauth"
            " app uuid %s to app with mauth app uuid %s"
            " using version %s.",
            signed_app_uuid,
            Config.APP_UUID,
            signed_token,
        )

    # raises InauthenticError unless the given object is authentic. Will only
    # authenticate with v2 if the environment variable V2_ONLY_AUTHENTICATE
    # is set. Otherwise will fallback to v1 when v2 authentication fails
    def _authenticate(self):
        if self.signed.protocol_version() == 2:
            try:
                self._authenticate_v2()
            except InauthenticError:
                if Config.V2_ONLY_AUTHENTICATE:
                    raise

                self.signed.fall_back_to_mws_signature_info()
                if not self.signed.signature:
                    raise

                self._log_authentication_request()
                self._authenticate_v1()
                self.logger.warning("Completed successful authentication attempt after fallback to v1")

        elif self.signed.protocol_version() == 1:
            if Config.V2_ONLY_AUTHENTICATE:
                # If v2 is required but not present and v1 is present we raise MissingV2Error
                msg = (
                    "This service requires mAuth v2 mcc-authentication header "
                    "but only v1 x-mws-authentication is present"
                )
                raise MissingV2Error(msg)

            self._authenticate_v1()

        else:
            sub_str = "" if Config.V2_ONLY_AUTHENTICATE else "X-MWS-Authentication header is blank, "
            msg = "Authentication Failed. No mAuth signature present; " "{}MCC-Authentication header is blank.".format(
                sub_str
            )
            raise MAuthNotPresent(msg)

        return True

    # V1 helpers
    def _authenticate_v1(self):
        self._time_valid_v1()
        self._token_valid_v1()
        self._signature_valid_v1()

    def _time_valid_v1(self):
        if not self.signed.x_mws_time:
            raise InauthenticError("Time verification failed. No X-MWS-Time present.")

        if not str(self.signed.x_mws_time).isdigit():
            raise InauthenticError("Time verification failed. X-MWS-Time header format incorrect.")

        self._time_within_valid_range(self.signed.x_mws_time)

    def _token_valid_v1(self):
        if not self.signed.token == MWS_TOKEN:
            msg = "Token verification failed. Expected {}; token was {}.".format(MWS_TOKEN, self.signed.token)
            raise InauthenticError(msg)

    @abstractmethod
    def _signature_valid_v1(self):
        pass

    # V2 helpers
    def _authenticate_v2(self):
        self._time_valid_v2()
        self._token_valid_v2()
        self._signature_valid_v2()

    def _time_valid_v2(self):
        if not self.signed.mcc_time:
            raise InauthenticError("Time verification failed. No MCC-Time present.")

        if not str(self.signed.mcc_time).isdigit():
            raise InauthenticError("Time verification failed. MCC-Time header format incorrect.")

        self._time_within_valid_range(self.signed.mcc_time)

    def _token_valid_v2(self):
        if not self.signed.token == MWSV2_TOKEN:
            msg = "Token verification failed. Expected {}.".format(MWSV2_TOKEN)
            raise InauthenticError(msg)

    @abstractmethod
    def _signature_valid_v2(self):
        pass

    def _time_within_valid_range(self, signature_timestamp):
        """
        Is the time of the request within the allowed drift?
        """
        now = datetime.datetime.now()
        # this needs a float
        signature_time = datetime.datetime.fromtimestamp(float(signature_timestamp))
        if now > signature_time + datetime.timedelta(seconds=self.ALLOWED_DRIFT_SECONDS):
            msg = "Time verification failed. {} not within {}s of {}".format(
                signature_time, self.ALLOWED_DRIFT_SECONDS, now.strftime("%Y-%m-%d %H:%M:%S")
            )
            raise InauthenticError(msg)

    @property
    def authenticator_type(self):
        return self.AUTHENTICATION_TYPE


class LocalAuthenticator(AbstractAuthenticator):
    """
    Local Authentication object, authenticates the request locally, retrieving the necessary credentials from the
    upstream MAuth Server
    """

    AUTHENTICATION_TYPE = "LOCAL"

    def __init__(self, signable, signed, logger):
        super().__init__(signable, signed, logger)

    def _signature_valid_v1(self):
        if not self.rsa_verifier:
            self.rsa_verifier = RSAVerifier(self.signed.app_uuid)

        expected = self.signable.string_to_sign_v1({"time": self.signed.x_mws_time, "app_uuid": self.signed.app_uuid})
        if not self.rsa_verifier.verify_v1(expected, self.signed.signature):
            msg = "Signature verification failed for {}.".format(self.signable.name)
            raise InauthenticError(msg)

    def _signature_valid_v2(self):
        if not self.rsa_verifier:
            self.rsa_verifier = RSAVerifier(self.signed.app_uuid)

        expected = self.signable.string_to_sign_v2({"time": self.signed.mcc_time, "app_uuid": self.signed.app_uuid})
        if not self.rsa_verifier.verify_v2(expected, self.signed.signature):
            msg = "Signature verification failed for {}.".format(self.signable.name)
            raise InauthenticError(msg)


class RemoteAuthenticator(AbstractAuthenticator):
    """
    Remote Authentication object, passes through the authentication to the upstream MAuth Server
    """

    AUTHENTICATION_TYPE = "REMOTE"
    _MAUTH = None

    def __init__(self, signable, signed, logger):
        if not self._MAUTH:
            self._MAUTH = {
                "auth": generate_mauth(),
                "url": "{}/mauth/{}/authentication_tickets.json".format(Config.MAUTH_URL, Config.MAUTH_API_VERSION),
            }

        super().__init__(signable, signed, logger)

    def _signature_valid_v1(self):
        self._make_mauth_request(self._build_authentication_ticket(self.signed.x_mws_time))

    def _signature_valid_v2(self):
        self._make_mauth_request(
            self._build_authentication_ticket(
                self.signed.mcc_time,
                {"query_string": self.signable.attributes_for_signing["query_string"], "token": self.signed.token},
            )
        )

    def _build_authentication_ticket(self, request_time, additional_attributes=None):
        if not additional_attributes:
            additional_attributes = {}

        binary_body = make_bytes(self.signable.attributes_for_signing.get("body", ""))
        return {
            "verb": self.signable.attributes_for_signing["verb"],
            "app_uuid": self.signed.app_uuid,
            "client_signature": self.signed.signature,
            "request_url": self.signable.attributes_for_signing["request_url"],
            "request_time": request_time,
            "b64encoded_body": base64.b64encode(binary_body).decode("utf-8"),
            **additional_attributes,
        }

    def _make_mauth_request(self, authentication_ticket):
        response = requests.post(
            self._MAUTH["url"], json=dict(authentication_ticket=authentication_ticket), auth=self._MAUTH["auth"]
        )

        if 200 <= response.status_code <= 299:
            return True

        # the mAuth service responds with 412 when the given request is not authentically signed.
        # older versions of the mAuth service respond with 404 when the given app_uuid
        # does not exist, which is also considered to not be authentically signed. newer
        # versions of the service respond 412 in all cases, so the 404 check may be removed
        # when the old version of the mAuth service is out of service.
        error_class = InauthenticError if response.status_code in (412, 404) else UnableToAuthenticateError
        raise error_class("The mAuth service responded with {}: {}".format(response.status_code, response.text))
