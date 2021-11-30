import os
import unittest
import hashlib
from tests.data import (
    valid_seckeys, invalid_keypair_length, not_c_char_array, not_bytes,
    invalid_seckey_length
)
from pysecp256k1.extrakeys import keypair_create, keypair_xonly_pub
from pysecp256k1.schnorrsig import (
    schnorrsig_sign,
    schnorrsig_sign_custom,
    schnorrsig_verify,
)


class TestPysecp256k1Schnorrsig(unittest.TestCase):
    def test_schnorrsig_sign_invalid_input_type_keypair(self):
        for invalid_keypair in invalid_keypair_length:
            with self.assertRaises(ValueError):
                schnorrsig_sign(invalid_keypair, os.urandom(32))

        for invalid_type in not_c_char_array:
            with self.assertRaises(ValueError):
                schnorrsig_sign(invalid_type, os.urandom(32))

    def test_schnorrsig_sign_invalid_input_type_msg32(self):
        keypair = keypair_create(valid_seckeys[1])
        for invalid_msg in invalid_seckey_length:
            with self.assertRaises(ValueError):
                schnorrsig_sign(keypair, invalid_msg)

        for invalid_type in not_bytes:
            with self.assertRaises(ValueError):
                schnorrsig_sign(keypair, invalid_type)

    def test_schnorrsig_sign_invalid_input_type_aux_rand32(self):
        pass

    def test_schnorrsig_sign_custom_invalid_input_type_keypair(self):
        pass

    def test_schnorrsig_sign_custom_invalid_input_type_msg(self):
        pass

    def test_schnorrsig_verify_invalid_input_type_compact_sig(self):
        pass

    def test_schnorrsig_verify_invalid_input_type_msg(self):
        pass

    def test_schnorrsig_verify_invalid_input_type_xonly_pubkey(self):
        pass

    def test_schnorrsig(self):
        for seckey in valid_seckeys:
            keypair = keypair_create(seckey)
            xonly_pubkey, parity = keypair_xonly_pub(keypair)
            msg = hashlib.sha256(b"super secret message").digest()
            var_length_msg = msg + msg  # 64 bytes

            signature0 = schnorrsig_sign(keypair, msg)
            signature0_custom = schnorrsig_sign_custom(keypair, msg)
            self.assertEqual(signature0, signature0_custom)
            signature1 = schnorrsig_sign(keypair, msg, aux_rand32=os.urandom(32))

            self.assertTrue(schnorrsig_verify(signature0, msg, xonly_pubkey))
            self.assertTrue(schnorrsig_verify(signature1, msg, xonly_pubkey))

            signature1_custom = schnorrsig_sign_custom(keypair, var_length_msg)
            self.assertTrue(schnorrsig_verify(signature1_custom, var_length_msg, xonly_pubkey))
