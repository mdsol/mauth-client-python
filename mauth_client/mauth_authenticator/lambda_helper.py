import codecs
import os
from base64 import b64decode
import boto3
from mauth_client.requests_mauth import MAuth


def generate_mauth():
    kms_client = boto3.client('kms')
    app_uuid = os.environ['APP_UUID']
    encrypted = os.environ['PRIVATE_KEY']
    private_key = kms_client.decrypt(CiphertextBlob=b64decode(encrypted))['Plaintext'] \
                            .decode('ascii') \
                            .replace(' ', '\n').replace('\nRSA\nPRIVATE\nKEY', ' RSA PRIVATE KEY') \
                            .encode('ascii')

    return MAuth(app_uuid, private_key)
