import unittest
from datetime import datetime
import os
from freezegun import freeze_time
from mauth_client.signable import RequestSignable
from mauth_client.signer import Signer

APP_UUID = "5ff4257e-9c16-11e0-b048-0026bbfffe5e"
EPOCH = "1309891855"  # 2011-07-05 18:50:00 UTC
EPOCH_DATETIME = datetime.fromtimestamp(float(EPOCH))
REQUEST_ATTRIBUTES = {"method": "GET", "url": "https://example.org/studies/123/users?k=v"}
ADDITIONAL_ATTRIBUTES = {"app_uuid": APP_UUID, "time": EPOCH}

with open(os.path.join(os.path.dirname(__file__), "blank.jpeg"), "rb") as binary_file:
    BINARY_FILE_BODY = binary_file.read()

REQUEST_ATTRIBUTES_WITH_BINARY_BODY = {
    "method": "PUT",
    "url": "https://example.org/v1/pictures?key=-_.~!@#$%^*()+{}|:\"'`<>?&∞=v&キ=v&0=v&a=v&a=b&a=c&a=a&k=&k=v",
    "body": BINARY_FILE_BODY,
}


class SignerTest(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(os.path.dirname(__file__), "keys", "test_mauth.priv.key"), "r") as key_file:
            private_key = key_file.read()
        self.signer = Signer(APP_UUID, private_key)
        self.signer_v2_only = Signer(APP_UUID, private_key, True)
        self.signable = RequestSignable(**REQUEST_ATTRIBUTES)
        self.signable_with_binary_body = RequestSignable(**REQUEST_ATTRIBUTES_WITH_BINARY_BODY)

    @freeze_time(EPOCH_DATETIME)
    def test_signed_headers(self):
        expected = {
            "X-MWS-Authentication": r"\AMWS {}:".format(APP_UUID),
            "X-MWS-Time": EPOCH,
            "MCC-Authentication": r"MWSV2 {}:[^;]*;".format(APP_UUID),
            "MCC-Time": EPOCH,
        }

        signed_headers = self.signer.signed_headers(self.signable, ADDITIONAL_ATTRIBUTES)
        self.assertEqual(signed_headers.keys(), expected.keys())
        self.assertRegex(signed_headers["X-MWS-Authentication"], expected["X-MWS-Authentication"])
        self.assertRegex(signed_headers["MCC-Authentication"], expected["MCC-Authentication"])
        self.assertEqual(signed_headers["X-MWS-Time"], expected["X-MWS-Time"])
        self.assertEqual(signed_headers["MCC-Time"], expected["MCC-Time"])

    @freeze_time(EPOCH_DATETIME)
    def test_signed_headers_v2_only(self):
        expected = {"MCC-Authentication": r"MWSV2 {}:[^;]*;".format(APP_UUID), "MCC-Time": EPOCH}

        signed_headers = self.signer_v2_only.signed_headers(self.signable, ADDITIONAL_ATTRIBUTES)
        self.assertEqual(signed_headers.keys(), expected.keys())
        self.assertRegex(signed_headers["MCC-Authentication"], expected["MCC-Authentication"])
        self.assertEqual(signed_headers["MCC-Time"], expected["MCC-Time"])

    def test_signature_v1(self):
        tested = self.signer.signature_v1("Hello world")
        self.assertEqual(
            tested,
            "F/GAuGYEykrtrmIE/XtETSi0QUoKxUwwTXljT1tUiqNHmyH2NRhKQ1flqusaB7H6bwPBb+FzXzfmiO32lJs6SxMjltqM/FjwucVNhn1BW+"
            "KXFnZniPh3M0+FwwspksX9xc/KcWEPebtIIEM5cX2rBl43xlvwYtS/+D+obo1AVPv2l5qd+Gwl9b61kYF/aoPGx+bVnmWZK8e8BZxZOjjG"
            "jmQAOYRYgGWzolLLnzIZ6xy6efY3D9jPXXDqgnqWQvwLStkKJIydrkXUTd0m36X6mD00qHgI7xoYSLgqxNSg1EgO8yuette8BKl9D+YbIE"
            "J3xFnaZmCfVGks0M9tmZ2PXg==",
        )

    def test_signature_v1_unicode(self):
        tested = self.signer.signature_v1("こんにちはÆ")
        self.assertEqual(
            tested,
            "cHrT3G7zCA2aRcY5jtvNlm0orafBOn924rQ9aSQS1lvNCwbg/LMnTsV+jHZUtOyDFSvErBwd9ga1FrsjOQDfhNoU1K+pVQ11nHU23cHQi0"
            "bsYByKPIDh1jMW4wNtP+A7Z/Xh0CIESBc+SaeIjPznMunocwci34kN4AXWudkZ2+xZxqfZiX6TVrwmREppsgoZD2ODVt6FtnBvcGd0sRAa"
            "9A3Iy+EaB8wOM5kaUyusfGcxeCYuCGN1FHjd1AkBkm2I4wbsxQInKDyYQXjMv3fA5oMw4nxhL/AJzUx3xWWCG5pub1/YB3jWwQgtGjpxvb"
            "5LhHT9S/JtuT8RU01JukC8dQ==",
        )

    def test_signature_v2(self):
        tested = self.signer.signature_v2("Hello world")
        self.assertEqual(
            tested,
            "KODkSEnqjr52EWOFvrRj2igwMR8EHsFYpBzDSEWge7UenB3u8OKP1nXeg1oJ0X1z8S+fpODMOh6NaGalEZgoyk0VRZ/BhFRiOg/xCMm6DA"
            "2J48EtBt8DYONVKTp4W2e2OU68NMGlj2upkjSsiD8MoIu2SHYwdkjx4PwKl2sPbQtKnsyl6kgSfhGd+1WsgTELDfeNdy3mSX7iJtKkpmUV"
            "5DZ1P0BcPCLbh/2KfAHx4sDIHFUf+U06ei/WVNzz1l5+fpwE0EV/lxtMLcCFUVQlM9li8Yjpsh0EbwzuV24pMB0xhwvci4B7JSYbLK76JU"
            "BthhwzUtXzyuzfQi4lNeXR7g==",
        )

    def test_signature_v2_unicode(self):
        tested = self.signer.signature_v2("こんにちはÆ")
        self.assertEqual(
            tested,
            "F9OqgCXr6vKAVBoU8Iogg09HhMZ+FpcJ8Q8DJ/M82vCDjVdxYQ1BYpuyXWN2jIH5CWKnYvXxF49aKwiXuo7bgUArNZZJuwRzI5hSEwsY6w"
            "eVzlsO8DmdDR62MKozK9NBEr7nnVka8NFEWrprWNPrgvy//YK5NAPSt+tLq/7qk5+qJZRjAjAhl09FD2pzYNGZkLx24UuPPfPSkvQKcybc"
            "AgY5y17FNkQTYYudjBy2hG6Df+Op77VjKx5yaLHZfoKcOmxc6UdE09kkoS5rsW2Y65kLi4xWbLK3i+VUC+WCqL8Vt7McJFMAwOyACDJPr4"
            "Z3VtHUZgnT9b5n7c7U/CItRg==",
        )

    def test_signature_v1_binary_body(self):
        string_to_sign_v1 = self.signable_with_binary_body.string_to_sign_v1(ADDITIONAL_ATTRIBUTES)
        tested = self.signer.signature_v1(string_to_sign_v1)
        self.assertEqual(
            tested,
            "hDKYDRnzPFL2gzsru4zn7c7E7KpEvexeF4F5IR+puDxYXrMmuT2/fETZty5NkGGTZQ1nI6BTYGQGsU/73TkEAm7SvbJZcB2duLSCn8H5D0"
            "S1cafory1gnL1TpMPBlY8J/lq/Mht2E17eYw+P87FcpvDShINzy8GxWHqfquBqO8ml4XtirVEtAlI0xlkAsKkVq4nj7rKZUMS85mzogjUA"
            "Jn3WgpGCNXVU+EK+qElW5QXk3I9uozByZhwBcYt5Cnlg15o99+53wKzMMmdvFmVjA1DeUaSO7LMIuw4ZNLVdDcHJx7ZSpAKZ/EA34u1fYN"
            "ECFcw5CSKOjdlU7JFr4o8Phw==",
        )

    def test_signature_v2_binary_body(self):
        string_to_sign_v2 = self.signable_with_binary_body.string_to_sign_v2(ADDITIONAL_ATTRIBUTES)
        tested = self.signer.signature_v2(string_to_sign_v2)
        self.assertEqual(
            tested,
            "kNmQchPnfSZOo29GHHDcp+res452+IIiWK/h7HmPdFsTU510X+eWPLaYONmfd2fMAuVLncDAiOPxyOS4WXap69szL37k9537ujnEU15I+j"
            "+vINTspCnAIbtZ9ia35c+gQyPgNQo7F1RxNl1P3hfXJ4qNXIrMSc/DlKpieNzmXQFPFs9zZxK5VPvdS0QBsuQFSMN71o2Rupf+NRStxvH5"
            "5pVej/mjJj4PbeCgAX2N6Vi0dqU2GLgcx+0U5j5FphLUIdqF6/6FKRqPRSCLX5hEyFf2c4stRnNWSpP/y/gGFtdIVxFzKEe42cL3FmYSM4"
            "YFTKn3wGgViw0W+CzkbDXJqQ==",
        )
