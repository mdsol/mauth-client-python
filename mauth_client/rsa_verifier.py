import base64
import rsa
from .exceptions import UnableToAuthenticateError
from .key_holder import KeyHolder
from .utils import make_bytes, hexdigest


class RSAVerifier:
    """
    Wrapper of the rsa library for verifying
    """

    def __init__(self, app_uuid):
        """
        :param app_uuid:
        """
        key_text = KeyHolder.get_public_key(app_uuid)
        if "BEGIN PUBLIC KEY" in key_text:
            # Load a PKCS#1 PEM-encoded public key
            self.public_key = rsa.PublicKey.load_pkcs1_openssl_pem(keyfile=key_text)

        elif "BEGIN RSA PUBLIC KEY" in key_text:
            # Loads a PKCS#1.5 PEM-encoded public key
            self.public_key = rsa.PublicKey.load_pkcs1(keyfile=key_text, format="PEM")

        else:
            # Unable to identify the key type
            raise UnableToAuthenticateError("Unable to identify Public Key type from Signature.")

    def verify_v1(self, expected, signature):
        try:
            padded = self.public_decrypt(signature)
            actual = self.unpad_message(padded)

            if hexdigest(expected) == actual.decode("utf-8"):
                return True

            return False

        except ValueError:
            return False

    def verify_v2(self, expected, signature):
        try:
            rsa.verify(make_bytes(expected), base64.b64decode(signature), self.public_key)
            return True

        except rsa.VerificationError:
            return False

    def public_decrypt(self, signature):
        """
        Decrypt a String encrypted with a private key, returns the hash

        :param str signature: encrypted signature
        :return: signature hash
        :rtype: str
        """
        # base64 decode
        decoded = base64.b64decode(make_bytes(signature))
        # transform the decoded signature to int
        encrypted = rsa.transform.bytes2int(decoded)
        payload = rsa.core.decrypt_int(encrypted, self.public_key.e, self.public_key.n)
        padded = rsa.transform.int2bytes(payload, rsa.common.byte_size(self.public_key.n))
        return padded

    @staticmethod
    def unpad_message(padded):
        """
        Removes the padding from the string

        :param padded: padded string
        :rtype: str
        """
        return padded[padded.index(b"\x00", 2) + 1 :]
