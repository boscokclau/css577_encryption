import unittest

from keycreationlib import *
from keycreationlib_tests_constants import *


########################################################################################################################
## Tests: create_master_key
########################################################################################################################
class CreateHmacKey(unittest.TestCase):
    def setUp(self):
        print("Test:", self.__class__.__name__ + "." + self._testMethodName)

    def test_aes128_sha256(self):
        data = {SECRET: "password", CIPHER: "aes128", HMAC_HASH: "sha256", KDF: "pbkdf2"}
        expect = {KEY: EXPECT_HMAC_KEY_SHA256_16b}

        self.verify_create_hmac_key(data, expect, NONE_EXCEPTION_CLASS_EXPECT, NONE_EX_MSG)

    def test_aes128_sha512(self):
        data = {SECRET: "password", CIPHER: "aes128", HMAC_HASH: "sha512", KDF: "pbkdf2"}
        expect = {KEY: EXPECT_HMAC_KEY_SHA512_16b}

        self.verify_create_hmac_key(data, expect, NONE_EXCEPTION_CLASS_EXPECT, NONE_EX_MSG)

    def test_aes256_sha256(self):
        data = {SECRET: "password", CIPHER: "aes256", HMAC_HASH: "sha256", KDF: "pbkdf2"}
        expect = {KEY: EXPECT_HMAC_KEY_SHA256_32b}

        self.verify_create_hmac_key(data, expect, NONE_EXCEPTION_CLASS_EXPECT, NONE_EX_MSG)

    def test_aes256_sha512(self):
        data = {SECRET: "password", CIPHER: "aes256", HMAC_HASH: "sha512", KDF: "pbkdf2"}
        expect = {KEY: EXPECT_HMAC_KEY_SHA512_32b}

        self.verify_create_hmac_key(data, expect, NONE_EXCEPTION_CLASS_EXPECT, NONE_EX_MSG)

    def test_3des_sha256(self):
        data = {SECRET: "password", CIPHER: "3des", HMAC_HASH: "sha256", KDF: "pbkdf2"}
        expect = {KEY: EXPECT_HMAC_KEY_SHA256_24b}

        self.verify_create_hmac_key(data, expect, NONE_EXCEPTION_CLASS_EXPECT, NONE_EX_MSG)

    def test_3des_sha512(self):
        data = {SECRET: "password", CIPHER: "3des", HMAC_HASH: "sha512", KDF: "pbkdf2"}
        expect = {KEY: EXPECT_HMAC_KEY_SHA512_24b}

        self.verify_create_hmac_key(data, expect, NONE_EXCEPTION_CLASS_EXPECT, NONE_EX_MSG)

    def test_unsupported_cipher(self):
        data = {SECRET: "password", CIPHER: "aes192", HMAC_HASH: "sha512", KDF: "pbkdf2"}
        expect = {KEY: EXPECT_HMAC_KEY_SHA512_24b}

        self.verify_create_hmac_key(data, expect, ValueError, "Cipher not supported: AES192")

    def test_unsupported_hmac_hash(self):
        data = {SECRET: "password", CIPHER: "aes256", HMAC_HASH: "sha384", KDF: "pbkdf2"}
        expect = {KEY: EXPECT_HMAC_KEY_SHA512_32b}

        self.verify_create_hmac_key(data, expect, ValueError, "Hash not supported: SHA384")

    def test_unsupported_kdf(self):
        data = {SECRET: "password", CIPHER: "aes256", HMAC_HASH: "sha512", KDF: "bcrypt"}
        expect = {KEY: EXPECT_HMAC_KEY_SHA512_32b}

        self.verify_create_hmac_key(data, expect, ValueError, "Unsupported kdf: bcrypt")

    ############################
    ## Verifiers
    ############################
    def verify_create_hmac_key(self, data: dict, expect: dict, exception_class_expect: BaseException,
                               ex_msg: str):

        try:
            key = create_hmac_key(data[SECRET], data[CIPHER], data[HMAC_HASH], data[KDF])

            self.assertEqual(expect[KEY], key)

            if exception_class_expect is not None:
                self.fail(f"Exception should have been thrown, of class: {str(exception_class_expect)}")
        except BaseException as be:
            self.assertIsInstance(be, exception_class_expect)
            self.assertEqual(ex_msg, str(be))
            print(str(be))


########################################################################################################################
## Main
########################################################################################################################
if __name__ == '__main__':
    unittest.main()
