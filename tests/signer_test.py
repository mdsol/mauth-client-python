import unittest
from datetime import datetime
import os
from freezegun import freeze_time
from mauth_client.signable import RequestSignable
from mauth_client.signer import Signer

APP_UUID = '5ff4257e-9c16-11e0-b048-0026bbfffe5e'
EPOCH = '1309891855'  # 2011-07-05 18:50:00 UTC
EPOCH_DATETIME = datetime.fromtimestamp(float(EPOCH))
REQUEST_ATTRIBUTES = {
    "method": "PUT",
    "url": 'https://example.org/v1/pictures?key=-_.~ !@#$%^*()+{}|:"\'`<>?&∞=v&キ=v&0=v&a=v&a=b&a=c&a=a&k=&k=v'
}
ADDITIONAL_ATTRIBUTES = { "app_uuid": APP_UUID, "time": EPOCH }

with open(os.path.join(os.path.dirname(__file__), "blank.jpeg"), "rb") as binary_file:
    BINARY_FILE_BODY = binary_file.read()

REQUEST_ATTRIBUTES_WITH_BINARY_BODY = {
    **REQUEST_ATTRIBUTES,
    "body": BINARY_FILE_BODY
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
            "MCC-Time": EPOCH
        }

        signed_headers = self.signer.signed_headers(self.signable, ADDITIONAL_ATTRIBUTES)
        self.assertEqual(signed_headers.keys(), expected.keys())
        self.assertRegex(signed_headers["X-MWS-Authentication"], expected["X-MWS-Authentication"])
        self.assertRegex(signed_headers["MCC-Authentication"], expected["MCC-Authentication"])
        self.assertEqual(signed_headers["X-MWS-Time"], expected["X-MWS-Time"])
        self.assertEqual(signed_headers["MCC-Time"], expected["MCC-Time"])

    @freeze_time(EPOCH_DATETIME)
    def test_signed_headers_v2_only(self):
        expected = {
            "MCC-Authentication": r"MWSV2 {}:[^;]*;".format(APP_UUID),
            "MCC-Time": EPOCH
        }

        signed_headers = self.signer_v2_only.signed_headers(self.signable, ADDITIONAL_ATTRIBUTES)
        self.assertEqual(signed_headers.keys(), expected.keys())
        self.assertRegex(signed_headers["MCC-Authentication"], expected["MCC-Authentication"])
        self.assertEqual(signed_headers["MCC-Time"], expected["MCC-Time"])

    def test_signature_v1(self):
        tested = self.signer.signature_v1("Hello world")
        self.assertEqual(tested, "F/GAuGYEykrtrmIE/XtETSi0QUoKxUwwTXljT1tUiqNHmyH2NRhKQ1flqusaB7H6bwPBb+FzXzfmiO32lJs6SxMjltqM/FjwucVNhn1BW+KXFnZniPh3M0+FwwspksX9xc/KcWEPebtIIEM5cX2rBl43xlvwYtS/+D+obo1AVPv2l5qd+Gwl9b61kYF/aoPGx+bVnmWZK8e8BZxZOjjGjmQAOYRYgGWzolLLnzIZ6xy6efY3D9jPXXDqgnqWQvwLStkKJIydrkXUTd0m36X6mD00qHgI7xoYSLgqxNSg1EgO8yuette8BKl9D+YbIEJ3xFnaZmCfVGks0M9tmZ2PXg==")

    def test_signature_v1_unicode(self):
        tested = self.signer.signature_v1("こんにちはÆ")
        self.assertEqual(tested, "cHrT3G7zCA2aRcY5jtvNlm0orafBOn924rQ9aSQS1lvNCwbg/LMnTsV+jHZUtOyDFSvErBwd9ga1FrsjOQDfhNoU1K+pVQ11nHU23cHQi0bsYByKPIDh1jMW4wNtP+A7Z/Xh0CIESBc+SaeIjPznMunocwci34kN4AXWudkZ2+xZxqfZiX6TVrwmREppsgoZD2ODVt6FtnBvcGd0sRAa9A3Iy+EaB8wOM5kaUyusfGcxeCYuCGN1FHjd1AkBkm2I4wbsxQInKDyYQXjMv3fA5oMw4nxhL/AJzUx3xWWCG5pub1/YB3jWwQgtGjpxvb5LhHT9S/JtuT8RU01JukC8dQ==")

    def test_signature_v2(self):
        tested = self.signer.signature_v2("Hello world")
        self.assertEqual(tested, "KODkSEnqjr52EWOFvrRj2igwMR8EHsFYpBzDSEWge7UenB3u8OKP1nXeg1oJ0X1z8S+fpODMOh6NaGalEZgoyk0VRZ/BhFRiOg/xCMm6DA2J48EtBt8DYONVKTp4W2e2OU68NMGlj2upkjSsiD8MoIu2SHYwdkjx4PwKl2sPbQtKnsyl6kgSfhGd+1WsgTELDfeNdy3mSX7iJtKkpmUV5DZ1P0BcPCLbh/2KfAHx4sDIHFUf+U06ei/WVNzz1l5+fpwE0EV/lxtMLcCFUVQlM9li8Yjpsh0EbwzuV24pMB0xhwvci4B7JSYbLK76JUBthhwzUtXzyuzfQi4lNeXR7g==")

    def test_signature_v2_unicode(self):
        tested = self.signer.signature_v2("こんにちはÆ")
        self.assertEqual(tested, "F9OqgCXr6vKAVBoU8Iogg09HhMZ+FpcJ8Q8DJ/M82vCDjVdxYQ1BYpuyXWN2jIH5CWKnYvXxF49aKwiXuo7bgUArNZZJuwRzI5hSEwsY6weVzlsO8DmdDR62MKozK9NBEr7nnVka8NFEWrprWNPrgvy//YK5NAPSt+tLq/7qk5+qJZRjAjAhl09FD2pzYNGZkLx24UuPPfPSkvQKcybcAgY5y17FNkQTYYudjBy2hG6Df+Op77VjKx5yaLHZfoKcOmxc6UdE09kkoS5rsW2Y65kLi4xWbLK3i+VUC+WCqL8Vt7McJFMAwOyACDJPr4Z3VtHUZgnT9b5n7c7U/CItRg==")

    def test_signature_v1_binary_body(self):
        string_to_sign_v1 = self.signable_with_binary_body.string_to_sign_v1(ADDITIONAL_ATTRIBUTES)
        tested = self.signer.signature_v1(string_to_sign_v1)
        self.assertEqual(tested, "hDKYDRnzPFL2gzsru4zn7c7E7KpEvexeF4F5IR+puDxYXrMmuT2/fETZty5NkGGTZQ1nI6BTYGQGsU/73TkEAm7SvbJZcB2duLSCn8H5D0S1cafory1gnL1TpMPBlY8J/lq/Mht2E17eYw+P87FcpvDShINzy8GxWHqfquBqO8ml4XtirVEtAlI0xlkAsKkVq4nj7rKZUMS85mzogjUAJn3WgpGCNXVU+EK+qElW5QXk3I9uozByZhwBcYt5Cnlg15o99+53wKzMMmdvFmVjA1DeUaSO7LMIuw4ZNLVdDcHJx7ZSpAKZ/EA34u1fYNECFcw5CSKOjdlU7JFr4o8Phw==")

    def test_signature_v2_binary_body(self):
        string_to_sign_v2 = self.signable_with_binary_body.string_to_sign_v2(ADDITIONAL_ATTRIBUTES)
        tested = self.signer.signature_v2(string_to_sign_v2)
        self.assertEqual(tested, "GpZIRB8RIxlfsjcROBElMEwa0r7jr632GkBe+R8lOv72vVV7bFMbJwQUHYm6vL/NKC7g4lJwvWcF60lllIUGwv/KWUOQwerqo5yCNoNumxjgDKjq7ILl8iFxsrV9LdvxwGyEBEwAPKzoTmW9xradxmjn4ZZVMnQKEMns6iViBkwaAW2alp4ZtVfJIZHRRyiuFnITWH1PniyG0kI4Li16kY25VfmzfNkdAi0Cnl27Cy1+DtAl1zVnz6ObMAdtmsEtplvlqsRCRsdd37VfuUxUlolNpr5brjzTwXksScUjX80/HMnui5ZlFORGjHebeZG5QVCouZPKBWTWsELGx1iyaw==")

    def test_signature_v1_empty_body(self):
        string_to_sign_v1 = self.signable.string_to_sign_v1(ADDITIONAL_ATTRIBUTES)
        tested = self.signer.signature_v1(string_to_sign_v1)
        self.assertEqual(tested, "UxcRuPRLzjO70NUDG/v71vfs8t/8xyaKN7LTgt6IiV+ul4GRpp3b9EzmF8/b7OTlX3Bsxl7o+E1wfuf4AuqQKE5IqZuhNqZ2t2TPIFdeV4VeF4Eh+gWs6de0KERnEWMTH7OjJsSEQ1gdA7tB3wQhhnf7CpJgMc3P1dSONVgq9qIchspw6L4dadN5bzxH99hN1E/0iPd+qGIeczuhtPMuiNaZRjhFjr2ZsIqn0pYqF+u2czKXd76sZGiBYuUpp/5dQvXBK9v2JlXUmiCoa2LcPj55HR0YEqcPE0mV0k9hyJMwJZeeTKBS5g3QDxoPpB61/+sLuyNp2P/cWrvU03P9dQ==")

    def test_signature_v2_empty_body(self):
        string_to_sign_v2 = self.signable.string_to_sign_v2(ADDITIONAL_ATTRIBUTES)
        tested = self.signer.signature_v2(string_to_sign_v2)
        self.assertEqual(tested, "jDB6fhwUA11ZSLb2W4ueS4l9hsguqmgcRez58kUo25iuMT5Uj9wWz+coHSpOd39B0cNW5D5UY6nWifw4RJIv/q8MdqS43WVgnCDSrNsSxpQ/ic6U3I3151S69PzSRZ+aR/I5A85Q9FgWB6wDNf4iX/BmZopfd5XjsLEyDymTRYedmB4DmONlTrsjVPs1DS2xY5xQyxIcxEUpVGDfTNroRTu5REBTttWbUB7BRXhKCc2pfRnUYPBo4Fa7nM8lI7J1/jUasMMLelr6hvcc6t21RCHhf4p9VlpokUOdN8slXU/kkC+OMUE04I021AUnZSpdhd/IoVR1JJDancBRzWA2HQ==")
