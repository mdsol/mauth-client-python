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
        with open(os.path.join(os.path.dirname(__file__), "keys", "fake_mauth.priv.key"), "r") as key_file:
            self.private_key = key_file.read()
        self.signer = Signer(APP_UUID, self.private_key, "v1,v2")
        self.signer_v1_only = Signer(APP_UUID, self.private_key, "v1")
        self.signer_v2_only = Signer(APP_UUID, self.private_key, "v2")
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
    def test_signed_headers_v1_only(self):
        expected = {"X-MWS-Authentication": r"\AMWS {}:".format(APP_UUID), "X-MWS-Time": EPOCH}

        signed_headers = self.signer_v1_only.signed_headers(self.signable, ADDITIONAL_ATTRIBUTES)
        self.assertEqual(signed_headers.keys(), expected.keys())
        self.assertRegex(signed_headers["X-MWS-Authentication"], expected["X-MWS-Authentication"])
        self.assertEqual(signed_headers["X-MWS-Time"], expected["X-MWS-Time"])

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
            "1oTyoecqng4TE7ycGoW6qFMSPpA4C9TiZVDANHN4T/76LxtcCqmTTn9VCsVIDRWGKl3O5EzJEUYIfbI2QjsMdxtOk1BmMJspX08nAhRxZA"
            "j3urNaBDkKPKmCiDgpaBNwJHlAVPi9LuVun6rFqRASkjz7jDTt+EVgrWHnJxcikXYMx32VYFteQXPQNpYmPqrduJVuadcgCZWqBqVWGVHR"
            "pRdb2OXYPkJ3FEnvPZtSnufcgrticJBD5PDY6LKYmhNwgvVOXjSPRDxsDnqc5fSn4+zQYAZHo4ZbarRpPoj9C+YXp+BDb8gfm7wyuwKLSt"
            "UE5cck4dbWae+Vvle5QrObNw==",
        )

    def test_signature_v1_unicode(self):
        tested = self.signer.signature_v1("こんにちはÆ")
        self.assertEqual(
            tested,
            "F7t8/AJCbGFDbIsE41u0CqsT4VB2lm0hXlQdCw2Io/5fBjJOGMZTiHEUj604YSb/zWKgFZYYUNpY+aVXZH7EjkB/Lg1l8MIid1OMV9Ok/U"
            "bhMzvcPrHoi8DqOzvbx/+be4hN9GpDiY5woBak2E7NgI0x8sagpUXjMqnRR47O3PCLsE0x0PjkSGztWFt2aRWYSlRASi96Z8ESLhF76KbI"
            "G7iekW54/EusK+qGA3sewlWbCuBisVBoF8yRtukwq065vz7VZx1GPNGbmB+MF6uGvxh+hhcYbq/kbcuHoAtqrp0oJJqXRbvPzrUZKZW86O"
            "tQzekMkzapDDMfJhE0V+SxNw==",
        )

    def test_signature_v2(self):
        tested = self.signer.signature_v2("Hello world")
        self.assertEqual(
            tested,
            "G7jZk1nf5kd+oOzHfMsTS18pNkZea22pT6XsJaH5XCKqP4tYoua5isDWtipagwmjveEr3dG2tUC9KwiOLDGO30xiO4fdZwhyUb3mBrtELC"
            "rBz0nXoH7BlhV4LmRVtiPtVwLHauRb01KglPx0WoyuOEbrCO4ikwls75s/wv22Xk6kVFYx2y1r+HQWpeqQETarQs/x/2W610TqDjNdXU0V"
            "FRKJ8w0ERWlt5lJGBhp0zaoguyyVMvC8fjNHFORNIZHYVd0DOQAOlHmJD+0JdNo+2qcrA2d3G4+vc/pWRV+lI2buudyOGSnURZhKan/S0j"
            "Ue9yF2tS+3wXulqfLM3pFhwA==",
        )

    def test_signature_v2_unicode(self):
        tested = self.signer.signature_v2("こんにちはÆ")
        self.assertEqual(
            tested,
            "eHvTMmEH31a9Tz6ZikHNUQPtii5iSjbkukQcFflQR6BtWL+HlZGgyjcL8jOT9oVMxkFV2eITrBA4hBPGznJlQ22yRca82tcOBKznllqTPT"
            "0vk8t2oX4ruPjFO1vaw/Eiko3r29+VflYibAEmP5m+SqhUZn5BWeDlFAkp6UqVOtfQzX7I6J/M7tsgw8PZQp6FUUDtXPSLFAkIPpcW/wND"
            "siV5wjlQzdlDAMc+Onc0lMFUcG0uH2W3ciUe5I2+ID4EvuprEUFDy8FYzXativ9p3k5TGtt7u0BXd39ll4r7p6pdby6+JgFjT2ITg3N5iC"
            "q17UFV5tFUABZ3dak/wT0apA==",
        )

    def test_signature_v1_binary_body(self):
        string_to_sign_v1 = self.signable_with_binary_body.string_to_sign_v1(ADDITIONAL_ATTRIBUTES)
        tested = self.signer.signature_v1(string_to_sign_v1)
        self.assertEqual(
            tested,
            "19C27KyNwGA3KByjpQi7MssyDGBAha4ByuPmIobaZ9PRnXa42ZD1njD5ZQVuNMDHtL+Zfo851UGmPphaqgJeSK4niqUOM2dhwMuj6QAE+z"
            "0IFfhJvIXrIp1FAavMSlrdeDRqsVWjlwfoZeqY3HJk1vfY+7YMYApIPagmZH/3OoSB84k3o6WYplGtT8KvKRi8GDlq6D+gLLtAo9ocgQAO"
            "OhSzNyCowNcMUKXq8LlVXFguekawC8oEz+zJ0zJhDh9NnXMfp3fIg0a2MBDZhQSRLFUo/AMczZBGMl63nIQWq029/0f3xdiiQf3Trv4wBS"
            "zCiMSnPMg4uOjfDZY0tMR1JA==",
        )

    def test_signature_v2_binary_body(self):
        string_to_sign_v2 = self.signable_with_binary_body.string_to_sign_v2(ADDITIONAL_ATTRIBUTES)
        tested = self.signer.signature_v2(string_to_sign_v2)
        self.assertEqual(
            tested,
            "s9cqo1kIqiw9lvCxXq2ObAIJOU/m0tap79ox8mvKKS8QabGvIJblwRn5YiUwYb2VHix0q3teU4+CYuLe5+wuxhwtraAfNwZQt0eIfyO3AX"
            "Q001BVaROq75GW7bEFKoy0TOx4dgaFTHTs56Pr6A3cC4IPGBpV5Utlx6ck0Wd6u6rU7BDtZLawVl6wg3fvXn23iFP1D0QwouldyCtL9y9E"
            "TjWzTnFSz9cRPrZ4dzKyVeUwsCCGSkcYTz+jYTfvsv51OVOdxaTscyGWyTC2V4QRScONESHZ7Yhs8C6YgTgMdtNGyozqHreLB4ptP2HdII"
            "a7Nv2jIZUozyjkED+G0OEisA==",
        )

    def test_sign_versions(self):
        signer = Signer(APP_UUID, self.private_key, "v1, V2,v777")
        self.assertEqual(signer.sign_versions, ["v1", "v2", "v777"])

    def test_sign_versions_bad_version(self):
        with self.assertRaises(ValueError) as exc:
            Signer(APP_UUID, self.private_key, "v1,vv2")
        self.assertEqual(
            str(exc.exception), "SIGN_VERSIONS must be comma-separated MAuth protocol versions (e.g. 'v1,v2')"
        )
