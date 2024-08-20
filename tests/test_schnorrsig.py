import ctypes
import os
import unittest
import hashlib
from tests.data import (
    valid_seckeys,
    invalid_keypair_length,
    not_c_char_array,
    not_bytes,
    invalid_seckey_length,
    invalid_pubkey_length,
    invalid_compact_sig_length,
)
from pysecp256k1.low_level import (
    Libsecp256k1Exception,
    has_secp256k1_schnorrsig,
    has_secp256k1_extrakeys,
)
from pysecp256k1.low_level.constants import SCHNORRSIG_EXTRAPARAMS_MAGIC

if has_secp256k1_extrakeys:
    from pysecp256k1.extrakeys import keypair_create, keypair_xonly_pub
if has_secp256k1_schnorrsig:
    from pysecp256k1.schnorrsig import (
        schnorrsig_sign32,
        schnorrsig_sign_custom,
        schnorrsig_verify,
        SchnorrsigExtraparams,
    )


skip_reason = "secp256k1 is not compiled with module 'schnorrsig'"


@unittest.skipUnless(has_secp256k1_schnorrsig, skip_reason)
class TestPysecp256k1SchnorrsigValidation(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.b32 = valid_seckeys[0]
        cls.compact_sig = 64 * b"\x00"
        cls.keypair = keypair_create(valid_seckeys[1])
        cls.xonly_pubkey, cls.parity = keypair_xonly_pub(cls.keypair)

    def test_schnorrsig_sign32_invalid_input_type_keypair(self):
        for invalid_keypair in invalid_keypair_length:
            with self.assertRaises(ValueError):
                schnorrsig_sign32(invalid_keypair, self.b32)

        for invalid_type in not_c_char_array:
            with self.assertRaises(ValueError):
                schnorrsig_sign32(invalid_type, self.b32)

    def test_schnorrsig_sign32_invalid_input_type_msg32(self):
        for invalid_msg in invalid_seckey_length:
            with self.assertRaises(ValueError):
                schnorrsig_sign32(self.keypair, invalid_msg)

        for invalid_type in not_bytes:
            with self.assertRaises(ValueError):
                schnorrsig_sign32(self.keypair, invalid_type)

    def test_schnorrsig_sign32_invalid_input_type_aux_rand32(self):
        for invalid_msg in invalid_seckey_length:
            with self.assertRaises(ValueError):
                schnorrsig_sign32(self.keypair, self.b32, aux_rand32=invalid_msg)

        for invalid_type in not_bytes[1:]:  # omit None as it is optional
            with self.assertRaises(ValueError):
                schnorrsig_sign32(self.keypair, self.b32, aux_rand32=invalid_type)

    def test_schnorrsig_sign_custom_invalid_input_type_keypair(self):
        for invalid_keypair in invalid_keypair_length:
            with self.assertRaises(ValueError):
                schnorrsig_sign_custom(invalid_keypair, self.b32)

        for invalid_type in not_c_char_array:
            with self.assertRaises(ValueError):
                schnorrsig_sign_custom(invalid_type, self.b32)

    def test_schnorrsig_sign_custom_invalid_input_type_msg(self):
        for invalid_type in not_bytes:
            with self.assertRaises(ValueError):
                schnorrsig_sign_custom(self.keypair, invalid_type)

    def test_schnorrsig_verify_invalid_input_type_compact_sig(self):
        for invalid_sig in invalid_compact_sig_length:
            with self.assertRaises(ValueError):
                schnorrsig_verify(invalid_sig, self.b32, self.xonly_pubkey)

        for invalid_type in not_bytes:
            with self.assertRaises(ValueError):
                schnorrsig_verify(invalid_type, self.b32, self.xonly_pubkey)

    def test_schnorrsig_verify_invalid_input_type_msg(self):
        for invalid_type in not_bytes:
            with self.assertRaises(ValueError):
                schnorrsig_verify(self.compact_sig, invalid_type, self.xonly_pubkey)

    def test_schnorrsig_verify_invalid_input_type_xonly_pubkey(self):
        for invalid_xonly in invalid_pubkey_length:
            with self.assertRaises(ValueError):
                schnorrsig_verify(self.compact_sig, self.b32, invalid_xonly)

        for invalid_type in not_c_char_array:
            with self.assertRaises(ValueError):
                schnorrsig_verify(self.compact_sig, self.b32, invalid_type)


@unittest.skipUnless(has_secp256k1_schnorrsig, skip_reason)
class TestPysecp256k1Schnorrsig(unittest.TestCase):
    def test_schnorrsig(self):
        msg32 = hashlib.sha256(b"super secret message").digest()
        var_length_msg = msg32 + msg32  # 64 bytes
        with self.assertRaises(Libsecp256k1Exception):
            schnorrsig_sign32(ctypes.create_string_buffer(96), msg32)

        with self.assertRaises(Libsecp256k1Exception):
            schnorrsig_sign_custom(ctypes.create_string_buffer(96), msg32)

        for seckey in valid_seckeys:
            keypair = keypair_create(seckey)
            xonly_pubkey, parity = keypair_xonly_pub(keypair)
            signature0 = schnorrsig_sign32(keypair, msg32)
            signature0_custom = schnorrsig_sign_custom(keypair, msg32)
            self.assertEqual(signature0, signature0_custom)
            random_32 = os.urandom(32)
            signature1 = schnorrsig_sign32(keypair, msg32, aux_rand32=random_32)
            extraparams = SchnorrsigExtraparams(
                SCHNORRSIG_EXTRAPARAMS_MAGIC,
                None,  # custom nonce function goes here
                ctypes.cast(ctypes.create_string_buffer(random_32), ctypes.c_void_p),
            )
            signature1_custom = schnorrsig_sign_custom(
                keypair, msg32, extraparams
            )
            self.assertEqual(signature1, signature1_custom)
            self.assertTrue(schnorrsig_verify(signature0, msg32, xonly_pubkey))
            self.assertTrue(schnorrsig_verify(signature1, msg32, xonly_pubkey))

            signature1_custom = schnorrsig_sign_custom(keypair, var_length_msg)
            self.assertTrue(
                schnorrsig_verify(signature1_custom, var_length_msg, xonly_pubkey)
            )
            self.assertFalse(
                schnorrsig_verify(signature0, msg32 + b"\x01", xonly_pubkey)
            )
            self.assertFalse(
                schnorrsig_verify(signature0, msg32, ctypes.create_string_buffer(64))
            )
            self.assertFalse(schnorrsig_verify(64 * b"\x01", msg32, xonly_pubkey))
