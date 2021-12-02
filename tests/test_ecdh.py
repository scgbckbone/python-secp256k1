import unittest
from tests.data import (
    valid_seckeys, invalid_seckeys, invalid_seckey_length,
    invalid_pubkey_length, not_bytes, not_c_char_array
)
from pysecp256k1 import ec_pubkey_create
from pysecp256k1.low_level import Libsecp256k1Exception
from pysecp256k1.ecdh import ecdh


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


class TestPysecp256k1ECDH(unittest.TestCase):
    def test_ecdh(self):
        alice_seckey = valid_seckeys[0]
        bob_seckey = valid_seckeys[1]
        alice_pubkey = ec_pubkey_create(alice_seckey)
        bob_pubkey = ec_pubkey_create(bob_seckey)
        shared_key0 = ecdh(alice_seckey, bob_pubkey)
        shared_key1 = ecdh(bob_seckey, alice_pubkey)
        self.assertEqual(shared_key0, shared_key1)
