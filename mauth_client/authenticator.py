from abc import ABC, abstractmethod
import base64
import datetime
from .consts import MWS_TOKEN
from .exceptions import InauthenticError, MAuthNotPresent, MissingV2Error
from .rsa_verifier import RSAVerifier

class Authenticator(ABC):
    ALLOWED_DRIFT_SECONDS = 300

    @abstractmethod
    def __init__(self, signable, signed, v2_only_authenticate):
        self.signable = signable
        self.signed = signed
        self.v2_only_authenticate = v2_only_authenticate
        self.rsa_verifier = None # Lazy loading

    # raises InauthenticError unless the given object is authentic. Will only
    # authenticate with v2 if the environment variable V2_ONLY_AUTHENTICATE
    # is set. Otherwise will authenticate with only the highest protocol version present
    def authenticate(self):
        if self.signed.protocol_version == 2:
            self._authenticate_v2()

        elif self.signed.protocol_version == 1:
            if self.v2_only_authenticate:
                # If v2 is required but not present and v1 is present we raise MissingV2Error
                msg = "This service requires mAuth v2 mcc-authentication header "\
                      "but only v1 x-mws-authentication is present"
                raise MissingV2Error(msg)

            self._authenticate_v1()

        else:
            sub_str = "" if self.v2_only_authenticate else "X-MWS-Authentication header is blank, "
            msg = "Authentication Failed. No mAuth signature present; "\
                    "{}MCC-Authentication header is blank.".format(sub_str)
            raise MAuthNotPresent(msg)

        return True

    # V1 helpers
    def _authenticate_v1(self):
        self._time_valid_v1()
        self._token_valid_v1()
        self._signature_valid_v1()

    def _time_valid_v1(self):
        if not self.signed.time:
            raise InauthenticError("Time verification failed. No X-MWS-Time present.")

        if not str(self.signed.time).isdigit():
            raise InauthenticError("Time verification failed. X-MWS-Time Header format incorrect.")

        self._time_within_valid_range()

    def _token_valid_v1(self):
        if not self.signed.token == MWS_TOKEN:
            msg = "Token verification failed. Expected {}; token was {}.".format(MWS_TOKEN, self.signed.token)
            raise InauthenticError(msg)

    def _signature_valid_v1(self):
        if not self.rsa_verifier:
            self.rsa_verifier = RSAVerifier(self.signed.app_uuid)

        expected = self.signable.string_to_sign_v1({ "time": self.signed.time, "app_uuid": self.signed.app_uuid })
        if not self.rsa_verifier.verify_v1(expected, self.signed.signature):
            msg = "Signature verification failed for {}.".format(self.signable.name)
            raise InauthenticError(msg)

    # V2 helpers
    def _authenticate_v2(self):
        # Since the V2 token is already verified in the Signed class (MWSV2_AUTH_PATTERN),
        # "_token_valid_v2()" is not defined in this class.
        self._time_valid_v2()
        self._signature_valid_v2()

    def _time_valid_v2(self):
        if not self.signed.time:
            raise InauthenticError("Time verification failed. No MCC-Time present.")

        if not str(self.signed.time).isdigit():
            raise InauthenticError("Time verification failed. MCC-Time Header format incorrect.")

        self._time_within_valid_range()

    def _signature_valid_v2(self):
        if not self.rsa_verifier:
            self.rsa_verifier = RSAVerifier(self.signed.app_uuid)

        expected = self.signable.string_to_sign_v2({ "time": self.signed.time, "app_uuid": self.signed.app_uuid })
        if not self.rsa_verifier.verify_v2(expected, self.signed.signature):
            msg = "Signature verification failed for {}.".format(self.signable.name)
            raise InauthenticError(msg)

    def _time_within_valid_range(self):
        """
        Is the time of the request within the allowed drift?
        """
        now = datetime.datetime.now()
        # this needs a float
        signature_time = datetime.datetime.fromtimestamp(float(self.signed.time))
        if now > signature_time + datetime.timedelta(seconds=self.ALLOWED_DRIFT_SECONDS):
            msg = "Time verification failed. {} not within {}s of {}".format(signature_time,
                                                                             self.ALLOWED_DRIFT_SECONDS,
                                                                             now.strftime("%Y-%m-%d %H:%M:%S"))
            raise InauthenticError(msg)
