import hashlib
import unittest
import itertools
from tests.data import (
    valid_seckeys,
    invalid_seckeys,
    invalid_seckey_length,
    invalid_pubkey_length,
    not_bytes,
    not_c_char_array,
)
from pysecp256k1 import ec_pubkey_create, ec_pubkey_parse, ec_seckey_verify
from pysecp256k1.low_level import Libsecp256k1Exception, has_secp256k1_ecdh

if has_secp256k1_ecdh:
    from pysecp256k1.ecdh import ecdh, ECDH_HASHFP_CLS


skip_reason = "secp256k1 is not compiled with module 'ecdh'"


@unittest.skipUnless(has_secp256k1_ecdh, skip_reason)
class TestPysecp256k1ECDHValidation(unittest.TestCase):
    def test_ecdh_invalid_input_type_seckey(self):
        pubkey = ec_pubkey_create(valid_seckeys[0])
        for invalid_seckey in invalid_seckeys:
            with self.assertRaises(Libsecp256k1Exception):
                ecdh(invalid_seckey, pubkey)

        for invalid_seckey in invalid_seckey_length:
            with self.assertRaises(ValueError):
                ecdh(invalid_seckey, pubkey)

        for invalid_type in not_bytes:
            with self.assertRaises(ValueError):
                ecdh(invalid_type, pubkey)

    def test_ecdh_invalid_input_type_pubkey(self):
        seckey = valid_seckeys[0]
        for invalid_pubkey in invalid_pubkey_length:
            with self.assertRaises(ValueError):
                ecdh(seckey, invalid_pubkey)

        for invalid_type in not_c_char_array:
            with self.assertRaises(ValueError):
                ecdh(seckey, invalid_type)


@unittest.skipUnless(has_secp256k1_ecdh, skip_reason)
class TestPysecp256k1ECDH(unittest.TestCase):
    def test_ecdh(self):
        for alice_seckey, bob_seckey in itertools.combinations(valid_seckeys, 2):
            alice_pubkey = ec_pubkey_create(alice_seckey)
            bob_pubkey = ec_pubkey_create(bob_seckey)
            shared_key0 = ecdh(alice_seckey, bob_pubkey)
            shared_key1 = ecdh(bob_seckey, alice_pubkey)
            self.assertEqual(shared_key0, shared_key1)

        for invalid_seckey in invalid_seckeys:
            with self.assertRaises(Libsecp256k1Exception):
                ecdh(invalid_seckey, ec_pubkey_create(valid_seckeys[0]))

    def test_ecdh_custom_hash_func(self):
        def py_ckcc_hashfp(output, x, y, data=None):
            try:
                m = hashlib.sha256()
                m.update(x.contents.raw)
                m.update(y.contents.raw)
                output.contents.raw = m.digest()
                return 1
            except:
                return 0

        ckcc_hashfp = ECDH_HASHFP_CLS(py_ckcc_hashfp)

        his_pubkey = b"\x82\xfbw\x91\xe1\xbbk|\x99Q\xd1\xfb\x90\x9b\xe4\x11\x9e\x80q\xdd&G\x16\xa0D\x130\x8asf!\x88\x9dG>\xbb\xc9:\xb5:#\r\x8e\xf4\x02\x16\x03\x91\x8d\xebbPf\x97\x90\x9f<\xc4L\x0bJ\x1c=\xe2"
        his_pubkey_p = ec_pubkey_parse(b"\x04" + his_pubkey)

        # test vectors form https://github.com/switck/libngu/blob/master/ngu/ngu_tests/test_k1_gen.py
        test_vectors = [
            (
                b"12121212121212121212121212121212",
                b"m\x9b*a\xfaXg\x95\xe3\x8d.\xe8\xbb\xc3\xd6o\xb5oa\x9e\xd9\xb0\xb5\xf1.v\xad\x9d\x98'\xe0|",
            ),
            (
                b"\x0f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
                b")\x86L\x9c[\x95\xe8\t\xb5\xe5\x19\xa8\xeb\xf7\xae\xeb\xe1\xc4P\x8d\x1eJG\xe1\xec\xef\xa4\xf6\x9c\x1d\x8a\x9a",
            ),
            (
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
                b"\xd8,\xb5N\xdd\xb7 \xb3\xb9`\xa7\x8d\x8dV\x189S9\xb8/\xb7\xf9J\xe5\x1a\xa1\xe7\x8fvU\tI",
            ),
        ]

        for seckey, target in test_vectors:
            ec_seckey_verify(seckey)
            res = ecdh(seckey, his_pubkey_p, hashfp=ckcc_hashfp)
            assert res == target
