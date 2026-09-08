from base64 import b64decode
from mauth_client.config import Config
from mauth_client.requests_mauth import MAuth
from mauth_client.utils import to_rsa_format

# Present in both the PKCS#1 ("RSA PRIVATE KEY") and PKCS#8 ("PRIVATE KEY") PEM markers.
PRIVATE_KEY_MARKER = "PRIVATE KEY"


def generate_mauth():
    return MAuth(Config.APP_UUID, _get_private_key())


def _get_private_key():
    private_key = Config.PRIVATE_KEY
    if not private_key:
        return private_key

    if PRIVATE_KEY_MARKER not in private_key:
        try:
            import boto3

            kms_client = boto3.client("kms")
            private_key = kms_client.decrypt(CiphertextBlob=b64decode(private_key))["Plaintext"].decode("ascii")
        except ModuleNotFoundError:
            pass

    return to_rsa_format(private_key)
