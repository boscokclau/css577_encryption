"""
Created on Apr 11, 2021

@author: boscolau
"""
import unittest

from ciphershemes import *

AES128WithSHA256 = "AES128WithSHA256"
AES128WithSHA512 = "AES128WithSHA512"
AES256WithSHA256 = "AES256WithSHA256"
AES256WithSHA512 = "AES256WithSHA512"
DES3WithSHA256 = "3DESWithSHA256"
DES3WithSHA512 = "3DESWithSHA512"

CIPHER_NAME = "cipher_name"
HASH_NAME = "hash_name"
SCHEME = "scheme"
NONE_EXCEPTION_CLASS_EXPECT = None
NONE_EX_MSG = None

schemes_expects = {
    "AES128WithSHA256": {NAME: "AES128WithSHA256", CIPHER: AES, KEY_LENGTH_IN_BYTES: 16, BLOCK_SIZE_IN_BYTES: 16},
    "AES128WithSHA512": {NAME: "AES128WithSHA512", CIPHER: AES, KEY_LENGTH_IN_BYTES: 16, BLOCK_SIZE_IN_BYTES: 16},

    "AES256WithSHA256": {NAME: "AES256WithSHA256", CIPHER: AES, KEY_LENGTH_IN_BYTES: 32, BLOCK_SIZE_IN_BYTES: 16},
    "AES256WithSHA512": {NAME: "AES256WithSHA512", CIPHER: AES, KEY_LENGTH_IN_BYTES: 32, BLOCK_SIZE_IN_BYTES: 16},

    "3DESWithSHA256": {NAME: "3DESWithSHA256", CIPHER: DES3, KEY_LENGTH_IN_BYTES: 24, BLOCK_SIZE_IN_BYTES: 8},
    "3DESWithSHA512": {NAME: "3DESWithSHA512", CIPHER: DES3, KEY_LENGTH_IN_BYTES: 24, BLOCK_SIZE_IN_BYTES: 8}
}


class GetCipherScheme(unittest.TestCase):
    def setUp(self):
        print("Testing:", self._testMethodName)

    def test_AES128_SHA256(self):
        data = {CIPHER_NAME: "aes128", HASH_NAME: "sha256"}
        expect = {SCHEME: schemes_expects[AES128WithSHA256]}

        self.verify_get_cipher_scheme(data, expect, NONE_EXCEPTION_CLASS_EXPECT, NONE_EX_MSG)

    def test_AES128_SHA512(self):
        data = {CIPHER_NAME: "aes128", HASH_NAME: "sha512"}
        expect = {SCHEME: schemes_expects[AES128WithSHA512]}

        self.verify_get_cipher_scheme(data, expect, NONE_EXCEPTION_CLASS_EXPECT, NONE_EX_MSG)

    def test_AES256_SHA256(self):
        data = {CIPHER_NAME: "aes256", HASH_NAME: "sha256"}
        expect = {SCHEME: schemes_expects[AES256WithSHA256]}

        self.verify_get_cipher_scheme(data, expect, NONE_EXCEPTION_CLASS_EXPECT, NONE_EX_MSG)

    def test_AES256_SHA512(self):
        data = {CIPHER_NAME: "aes256", HASH_NAME: "sha512"}
        expect = {SCHEME: schemes_expects[AES256WithSHA512]}

        self.verify_get_cipher_scheme(data, expect, NONE_EXCEPTION_CLASS_EXPECT, NONE_EX_MSG)

    def test_3DES_SHA256(self):
        data = {CIPHER_NAME: "3des", HASH_NAME: "sha256"}
        expect = {SCHEME: schemes_expects[DES3WithSHA256]}

        self.verify_get_cipher_scheme(data, expect, NONE_EXCEPTION_CLASS_EXPECT, NONE_EX_MSG)

    def test_3DES_SHA512(self):
        data = {CIPHER_NAME: "3des", HASH_NAME: "sha512"}
        expect = {SCHEME: schemes_expects[DES3WithSHA512]}

        self.verify_get_cipher_scheme(data, expect, NONE_EXCEPTION_CLASS_EXPECT, NONE_EX_MSG)

    def test_unsupported_cipher(self):
        data = {CIPHER_NAME: "des3", HASH_NAME: "sha512"}
        expect = {SCHEME: schemes_expects[DES3WithSHA512]}

        self.verify_get_cipher_scheme(data, expect, ValueError, "Cipher not supported: DES3")

    def test_unsupported_sha_algorithm(self):
        data = {CIPHER_NAME: "3des", HASH_NAME: "sha384"}
        expect = {SCHEME: schemes_expects[DES3WithSHA512]}

        self.verify_get_cipher_scheme(data, expect, ValueError, "Hash not supported: SHA384")

    ###################################################
    ### Verifiers
    ##################################################
    def verify_get_cipher_scheme(self, data: dict, expect: dict, exception_class_expect: BaseException, ex_msg: str):
        scheme_expect = expect[SCHEME]

        try:
            scheme = get_cipher_scheme(data[CIPHER_NAME], data[HASH_NAME])
            self.assertEqual(scheme_expect, scheme)

            if exception_class_expect is not None:
                self.fail(f"Exception should have been thrown, of class: {str(exception_class_expect)}")
        except BaseException as be:
            self.assertIsInstance(be, exception_class_expect)
            self.assertEqual(ex_msg, str(be))
            print(str(be))


if __name__ == '__main__':
    unittest.main()
