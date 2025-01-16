# file to handle loading and parsing of mauth protocol test suite cases in order
# to run them as unit tests

from datetime import datetime, timezone
import glob
import os
import json

from mauth_client.signer import Signer

TEST_SUITE_RELATIVE_PATH = "mauth-protocol-test-suite"
MAUTH_PROTOCOL_DIR = os.path.join(os.path.dirname(__file__), TEST_SUITE_RELATIVE_PATH)
CASE_PATH = os.path.join(MAUTH_PROTOCOL_DIR, "protocols/MWSV2")


class ProtocolTestSuiteHelper:
    def __init__(self):
        if not os.path.isdir(MAUTH_PROTOCOL_DIR):
            self.request_time = None
            self.public_key = None
            return

        with open(os.path.join(MAUTH_PROTOCOL_DIR, "signing-config.json"), "r") as config_file:
            config = json.load(config_file)

        with open(os.path.join(MAUTH_PROTOCOL_DIR, config["private_key_file"]), "r") as key_file:
            private_key = key_file.read()

        with open(os.path.join(MAUTH_PROTOCOL_DIR, "signing-params/rsa-key-pub"), "r") as key_file:
            self.public_key = key_file.read()

        self.request_time = datetime.fromtimestamp(float(config["request_time"]), timezone.utc)
        self.app_uuid = config["app_uuid"]
        self.signer = Signer(config["app_uuid"], private_key, "v2")
        self.additional_attributes = {"app_uuid": config["app_uuid"], "time": config["request_time"]}

    def cases(self):
        return glob.glob(os.path.join(CASE_PATH, "*"))


class ProtocolTestSuiteParser:
    def __init__(self, case_path):
        self.case_name = os.path.basename(case_path)
        self.request_attributes = self.build_request_attributes(case_path)
        self.sts = self.read_file_by_extension(case_path, "sts")
        self.sig = self.read_file_by_extension(case_path, "sig")
        self.auth_headers = {k: str(v) for k, v in self.read_json_by_extension(case_path, "authz").items()}

    def build_request_attributes(self, case_path):
        req = self.read_json_by_extension(case_path, "req")
        body_file_path = os.path.join(case_path, req["body_filepath"]) if "body_filepath" in req else ""
        body = self.read_file(body_file_path, "rb") if body_file_path else req.get("body")
        return {"method": req.get("verb"), "url": "https://example.org{}".format(req.get("url")), "body": body}

    @staticmethod
    def read_json_by_extension(case_path, extension):
        files = glob.glob(os.path.join(case_path, "*.{}".format(extension)))
        with open(files[0], "r") as f:
            return json.load(f)

    @classmethod
    def read_file_by_extension(cls, case_path, extension):
        files = glob.glob(os.path.join(case_path, "*.{}".format(extension)))
        return cls.read_file(files[0]) if files else None

    @staticmethod
    def read_file(file_path, mode="r"):
        with open(file_path, mode) as f:
            return f.read()
