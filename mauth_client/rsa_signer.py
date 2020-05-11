# This module exists to reproduce, with the rsa library, the raw signature required by MAuth
# which in OpenSSL is created with private_encrypt(hash). It provides an RSA sign class built from
# code that came from https://www.dlitz.net/software/pycrypto/api/current/ no copyright of that original
# code is claimed.

import rsa
from .utils import make_bytes, hexdigest


class RSASigner:
    """
    Wrapper of the rsa library for signing
    """

    def __init__(self, private_key_data):
        """
        :param private_key_data:
        """
        self.private_key = rsa.PrivateKey.load_pkcs1(private_key_data, "PEM")

    def sign_v2(self, string_to_sign):
        """Signs the data using SHA512 for V2 protocol

        :param str string_to_sign: The string to sign
        :rtype: str
        """
        return rsa.sign(make_bytes(string_to_sign), self.private_key, "SHA-512")

    def sign_v1(self, string_to_sign):
        """Signs the data in a emulation of the OpenSSL private_encrypt method for V1 protocol

        :param str string_to_sign: The string to sign
        :rtype: str
        """
        hashed = hexdigest(string_to_sign).encode("US-ASCII")
        keylength = rsa.common.byte_size(self.private_key.n)
        padded = self.pad_for_signing(hashed, keylength)
        padded = make_bytes(padded)
        payload = rsa.transform.bytes2int(padded)
        encrypted = rsa.core.encrypt_int(payload, self.private_key.d, self.private_key.n)
        return rsa.transform.int2bytes(encrypted, keylength)

    @staticmethod
    def pad_for_signing(message, target_length):
        """Pulled from rsa pkcs1.py,

        Pads the message for signing, returning the padded message.

        The padding is always a repetition of FF bytes::

            00 01 PADDING 00 MESSAGE

        Sample code::

            >>> block = RSASigner.pad_for_signing("hello", 16)
            >>> len(block)
            16
            >>> block[0:2]
            "\x00\x01"
            >>> block[-6:]
            "\x00hello"
            >>> block[2:-6]
            "\xff\xff\xff\xff\xff\xff\xff\xff"

        :param message: message to pad in readiness for signing
        :type message: str
        :param target_length: target length for padded string
        :type target_length: int

        :rtype: str
        :return: suitably padded string
        """

        max_msglength = target_length - 11
        msglength = len(message)

        if msglength > max_msglength:  # pragma: no cover
            raise OverflowError(
                "%i bytes needed for message, but there is only" " space for %i" % (msglength, max_msglength)
            )

        padding_length = target_length - msglength - 3

        return b"".join([b"\x00\x01", padding_length * b"\xff", b"\x00", message])
