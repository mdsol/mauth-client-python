import os


class Config:
    APP_UUID = os.environ.get("APP_UUID")
    MAUTH_URL = os.environ.get("MAUTH_URL")
    MAUTH_API_VERSION = os.environ.get("MAUTH_API_VERSION", "v1")
    MAUTH_MODE = os.environ.get("MAUTH_MODE", "local")
    PRIVATE_KEY = os.environ.get("PRIVATE_KEY")
    V2_ONLY_AUTHENTICATE = str(os.environ.get("V2_ONLY_AUTHENTICATE")).lower() == "true"
    SIGN_VERSIONS = os.environ.get("MAUTH_SIGN_VERSIONS", "v1")
