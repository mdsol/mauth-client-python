import os

class Config:
    APP_UUID = os.environ.get("APP_UUID")
    MAUTH_URL = os.environ.get("MAUTH_URL")
    PRIVATE_KEY = os.environ.get("PRIVATE_KEY")
    V2_ONLY_AUTHENTICATE = (str(os.environ.get("V2_ONLY_AUTHENTICATE")).lower() == "true")
    V2_ONLY_SIGN_REQUESTS = (str(os.environ.get("V2_ONLY_SIGN_REQUESTS")).lower() == "true")
