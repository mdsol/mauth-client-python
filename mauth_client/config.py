import os
from .utils import to_rsa_format


class Config:
    APP_UUID = os.getenv("APP_UUID", os.getenv("MAUTH_APP_UUID"))
    MAUTH_URL = os.getenv("MAUTH_URL")
    MAUTH_API_VERSION = os.getenv("MAUTH_API_VERSION", "v1")
    MAUTH_MODE = os.getenv("MAUTH_MODE", "local")
    _private_key_env = os.getenv("PRIVATE_KEY", os.getenv("MAUTH_PRIVATE_KEY", ""))
    PRIVATE_KEY = to_rsa_format(_private_key_env) if _private_key_env else None
    V2_ONLY_AUTHENTICATE = str(os.getenv("V2_ONLY_AUTHENTICATE")).lower() == "true"
    SIGN_VERSIONS = os.getenv("MAUTH_SIGN_VERSIONS", "v1")
