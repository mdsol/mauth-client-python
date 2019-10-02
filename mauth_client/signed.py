from .consts import X_MWS_AUTH, X_MWS_TIME, MCC_AUTH, MCC_TIME, X_MWS_AUTH_PATTERN, MWSV2_AUTH_PATTERN

class Signed:
    """
    Extracts signature information from an incoming object.

    mauth_client will authenticate with the highest protocol version present and ignore other protocol versions.
    """
    def __init__(self, headers):
        lowercased_headers = { k.lower(): v for k, v in headers.items() }
        x_mws_authentication, x_mws_time, mcc_authentication, mcc_time = [
            lowercased_headers.get(k.lower(), "") for k in [X_MWS_AUTH, X_MWS_TIME, MCC_AUTH, MCC_TIME]
        ]

        self.protocol_version = None

        match_v2 = MWSV2_AUTH_PATTERN.search(mcc_authentication)
        if match_v2:
            self.protocol_version = 2
            self.time = mcc_time
            self.token, self.app_uuid, self.signature = match_v2.groups()
            return

        match_v1 = X_MWS_AUTH_PATTERN.match(x_mws_authentication)
        if match_v1:
            self.protocol_version = 1
            self.time = x_mws_time
            self.token, self.app_uuid, self.signature = match_v1.groups()
