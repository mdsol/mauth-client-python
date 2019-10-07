from .consts import X_MWS_AUTH, X_MWS_TIME, MCC_AUTH, MCC_TIME, X_MWS_AUTH_PATTERN, MWSV2_AUTH_PATTERN

class Signed:
    """
    Extracts signature information from an incoming object.

    mauth_client will authenticate with the highest protocol version present and ignore other protocol versions.
    """
    def __init__(self, protocol_version=None, signature_time="", token="", app_uuid="", signature=""):
        self.protocol_version = protocol_version
        self.signature_time = signature_time
        self.token = token
        self.app_uuid = app_uuid
        self.signature = signature

    @classmethod
    def from_headers(cls, headers):
        lowercased_headers = { k.lower(): v for k, v in headers.items() }
        x_mws_authentication, x_mws_time, mcc_authentication, mcc_time = [
            lowercased_headers.get(k.lower(), "") for k in [X_MWS_AUTH, X_MWS_TIME, MCC_AUTH, MCC_TIME]
        ]
        match_v2 = MWSV2_AUTH_PATTERN.search(mcc_authentication)
        if match_v2:
            return cls(2, mcc_time, *match_v2.groups())
        match_v1 = X_MWS_AUTH_PATTERN.search(x_mws_authentication)
        if match_v1:
            return cls(1, x_mws_time, *match_v1.groups())

        return cls()
