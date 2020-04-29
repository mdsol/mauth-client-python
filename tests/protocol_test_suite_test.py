import pytest
import unittest
from unittest.mock import MagicMock
from freezegun import freeze_time
import logging

from mauth_client.authenticator import LocalAuthenticator
from mauth_client.key_holder import KeyHolder
from mauth_client.signable import RequestSignable
from mauth_client.signed import Signed
from .protocol_test_suite_helper import ProtocolTestSuiteHelper, ProtocolTestSuiteParser

TEST_SUITE = ProtocolTestSuiteHelper()


class ProtocolTestSuiteTest(unittest.TestCase):
    def setUp(self):
        self.__get_public_key__ = KeyHolder.get_public_key
        KeyHolder.get_public_key = MagicMock(return_value=TEST_SUITE.public_key)
        self.logger = logging.getLogger()

    def tearDown(self):
        # reset the KeyHolder.get_public_key method
        KeyHolder.get_public_key = self.__get_public_key__

    @pytest.mark.protocol_suite
    @freeze_time(TEST_SUITE.request_time)
    def test_protocol_test_suite(self):
        for case_path in TEST_SUITE.cases():
            parser = ProtocolTestSuiteParser(case_path)
            request_signable = RequestSignable(**parser.request_attributes)
            signed_headers_v2 = TEST_SUITE.signer.signed_headers_v2(request_signable, TEST_SUITE.additional_attributes)
            if "authentication-only" not in case_path:
                with self.subTest(test="string_to_sign_v2", case_name=parser.case_name):
                    string_to_sign = request_signable.string_to_sign_v2(TEST_SUITE.additional_attributes)
                    self.assertEqual(string_to_sign.decode("utf-8"), parser.sts)

                with self.subTest(test="signature", case_name=parser.case_name):
                    self.assertEqual(TEST_SUITE.signer.signature_v2(parser.sts), parser.sig)

                with self.subTest(test="authentication headers", case_name=parser.case_name):
                    self.assertEqual(signed_headers_v2, parser.auth_headers)

            with self.subTest(test="authentication", case_name=parser.case_name):
                signed = Signed.from_headers(signed_headers_v2)
                authenticator = LocalAuthenticator(request_signable, signed, self.logger)
                self.assertTrue(authenticator._authenticate())
