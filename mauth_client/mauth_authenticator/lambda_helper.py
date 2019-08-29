import codecs
import os
from base64 import b64decode
import boto3
from requests_mauth import MAuth


def generate_mauth():
    kms_client = boto3.client('kms')
    app_uuid = os.environ['APP_UUID']
    encrypted = os.environ['PRIVATE_KEY']
    private_key = kms_client.decrypt(CiphertextBlob=b64decode(encrypted))['Plaintext'] \
                            .decode('ascii') \
                            .replace(' ', '\n').replace('\nRSA\nPRIVATE\nKEY', ' RSA PRIVATE KEY') \
                            .encode('ascii')

    return MAuth(app_uuid, private_key)

def generate_trace_id():
    return str(codecs.encode(os.urandom(8), 'hex_codec').decode('utf-8'))

def create_x_b3_headers(trace_id):
    return {
        'X-B3-TraceId': trace_id,
        'X-B3-SpanId': trace_id,
        'X-B3-ParentSpanId': '',
        'X-B3-Flags': '0',
        'X-B3-Sampled': '0',
    }

def get_codebase_revision():
    codebase_revision_path = "./codebase_revision"
    codebase_revision = None
    if os.path.exists(codebase_revision_path):
        with open(codebase_revision_path, 'r') as f:
            codebase_revision = f.readline().strip()

    return codebase_revision
