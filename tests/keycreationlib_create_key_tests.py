import unittest

from keycreationlib import *
from keycreationlib_tests_constants import *


########################################################################################################################
## Tests: create_key
########################################################################################################################
class CreateKey(unittest.TestCase):
    def setUp(self):
        print("Test:", self.__class__.__name__ + "." + self._testMethodName)

    def test_happy_path(self):
        data = {SECRET: "password", SALT: "salt", ITERATIONS: 1000, KEY_LENGTH: 32, HMAC_HASH: "sha256", KDF: "pbkdf2"}
        expect = {KEY: BASE_KEY}

        self.verify_create_key(data, expect, NONE_EXCEPTION_CLASS_EXPECT, NONE_EX_MSG)

    def test_unsupported_hash(self):
        data = {SECRET: "password", SALT: "salt", ITERATIONS: 1000, KEY_LENGTH: 32, HMAC_HASH: "sha384", KDF: "pbkdf2"}
        expect = {KEY: BASE_KEY}

        self.verify_create_key(data, expect, ValueError, "Unsupported hmac_hash: sha384")

    def test_unsupported_kdf(self):
        data = {SECRET: "password", SALT: "salt", ITERATIONS: 1000, KEY_LENGTH: 32, HMAC_HASH: "sha256", KDF: "bcrypt"}
        expect = {KEY: BASE_KEY}

        self.verify_create_key(data, expect, ValueError, "Unsupported kdf: bcrypt")

    ############################
    ## Verifiers
    ############################
    def verify_create_key(self, data: dict, expect: dict, exception_class_expect: BaseException, ex_msg: str):

        try:
            key = create_key(data[SECRET], data[SALT], data[ITERATIONS], data[KEY_LENGTH], data[HMAC_HASH], data[KDF])
            key = binascii.hexlify(key).decode()

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
