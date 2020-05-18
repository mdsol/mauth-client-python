from .consts import X_MWS_AUTH, X_MWS_TIME, MCC_AUTH, MCC_TIME, X_MWS_AUTH_PATTERN, MWSV2_AUTH_PATTERN


class Signed:
    """
    Extracts signature information from an incoming object.

    mauth_client will authenticate with the highest protocol version present and if authentication fails,
    will fallback to lower protocol versions (if provided).
    """

    def __init__(self, x_mws_authentication, x_mws_time, mcc_authentication, mcc_time):
        self.x_mws_authentication = x_mws_authentication
        self.x_mws_time = x_mws_time
        self.mcc_authentication = mcc_authentication
        self.mcc_time = mcc_time

        if self.mcc_authentication:
            self.build_signature_info(self.mcc_data())
        elif self.x_mws_authentication:
            self.build_signature_info(self.x_mws_data())
        else:
            self.build_signature_info()

    def build_signature_info(self, match_data=None):
        self.token, self.app_uuid, self.signature = match_data.groups() if match_data else ("", "", "")

    def fall_back_to_mws_signature_info(self):
        self.build_signature_info(self.x_mws_data())

    def x_mws_data(self):
        return X_MWS_AUTH_PATTERN.search(self.x_mws_authentication)

    def mcc_data(self):
        return MWSV2_AUTH_PATTERN.search(self.mcc_authentication)

    def protocol_version(self):
        if self.mcc_authentication:
            return 2

        if self.x_mws_authentication:
            return 1

        return None

    @classmethod
    def from_headers(cls, headers):
        lowercased_headers = {k.lower(): v for k, v in headers.items()}
        return cls(*(lowercased_headers.get(k.lower(), "") for k in [X_MWS_AUTH, X_MWS_TIME, MCC_AUTH, MCC_TIME]))
