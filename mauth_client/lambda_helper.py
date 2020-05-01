from base64 import b64decode
from mauth_client.config import Config
from mauth_client.requests_mauth import MAuth

RSA_PRIVATE_KEY = "RSA PRIVATE KEY"


def generate_mauth():
    return MAuth(Config.APP_UUID, _get_private_key())


def _get_private_key():
    private_key = Config.PRIVATE_KEY
    if RSA_PRIVATE_KEY not in private_key:
        import boto3

        kms_client = boto3.client("kms")
        private_key = kms_client.decrypt(CiphertextBlob=b64decode(private_key))["Plaintext"].decode("ascii")

    return private_key.replace(" ", "\n").replace("\nRSA\nPRIVATE\nKEY", " RSA PRIVATE KEY")
