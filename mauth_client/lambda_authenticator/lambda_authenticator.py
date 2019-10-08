import logging
from mauth_client.authenticator import Authenticator
from mauth_client.config import Config
from mauth_client.exceptions import InauthenticError, MAuthNotPresent, MissingV2Error, UnableToAuthenticateError
from mauth_client.signable import RequestSignable
from mauth_client.signed import Signed


class LambdaAuthenticator(Authenticator):
    def __init__(self, method, url, headers, body):
        self.logger = logging.getLogger()
        signable = RequestSignable(method=method, url=url, body=body)
        super().__init__(signable, Signed.from_headers(headers), Config.V2_ONLY_AUTHENTICATE)

    def get_app_uuid(self):
        return self.signed.app_uuid

    def is_authentic(self):
        self._log_authentication_request()
        try:
            self.authenticate()
        except (MAuthNotPresent, MissingV2Error) as exc:
            self.logger.error("mAuth signature not present on %s. Exception: %s", self.signable.name, str(exc))
            return False, 401, str(exc)
        except InauthenticError as exc:
            self.logger.error("mAuth signature authentication failed for %s. "\
                                "Exception: %s", self.signable.name, str(exc))
            return False, 401, str(exc)
        except UnableToAuthenticateError as exc:
            self.logger.error(str(exc))
            return False, 500, str(exc)
        return True, 200, ""

    def _log_authentication_request(self):
        signed_app_uuid = self.signed.app_uuid if self.signed.app_uuid else "[none provided]"
        signed_token = self.signed.token if self.signed.token else "[none provided]"
        self.logger.info("Mauth-client attempting to authenticate request from app with mauth" \
                        " app uuid %s to app with mauth app uuid %s" \
                        " using version %s.", signed_app_uuid, Config.APP_UUID, signed_token)
