import os
import ctypes
import unittest
from tests.data import (
    invalid_seckeys,
    valid_seckeys,
    invalid_seckey_length,
    invalid_compact_sig_length,
    not_bytes,
    not_int,
    invalid_rec_ids,
    invalid_recoverable_signature_length,
    not_c_char_array,
)
from pysecp256k1.low_level import Libsecp256k1Exception, has_secp256k1_recovery
from pysecp256k1 import (
    ec_pubkey_create,
    ecdsa_sign,
    tagged_sha256,
    ecdsa_signature_serialize_compact,
)

if has_secp256k1_recovery:
    from pysecp256k1.recovery import (
        ecdsa_recoverable_signature_parse_compact,
        ecdsa_recoverable_signature_serialize_compact,
        ecdsa_recoverable_signature_convert,
        ecdsa_sign_recoverable,
        ecdsa_recover,
    )


skip_reason = "secp256k1 is not compiled with module 'recovery'"


@unittest.skipUnless(has_secp256k1_recovery, skip_reason)
class TestPysecp256k1RecoveryValidation(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.compact_sig = 64 * b"\x00"
        cls.recoverable_sig = ctypes.create_string_buffer(65)

    def test_ecdsa_recoverable_signature_parse_compact_invalid_input_type_compact_sig(
        self,
    ):
        for invalid_sig in invalid_compact_sig_length:
            with self.assertRaises(ValueError):
                ecdsa_recoverable_signature_parse_compact(invalid_sig, 0)

        for invalid_type in not_bytes:
            with self.assertRaises(ValueError):
                ecdsa_recoverable_signature_parse_compact(invalid_type, 0)

    def test_ecdsa_recoverable_signature_parse_compact_invalid_input_type_rec_id(self):
        for rec_id_invalid in invalid_rec_ids:
            with self.assertRaises(ValueError):
                ecdsa_recoverable_signature_parse_compact(
                    self.compact_sig, rec_id_invalid
                )

        for invalid_type in not_int:
            with self.assertRaises(ValueError):
                ecdsa_recoverable_signature_parse_compact(
                    self.compact_sig, invalid_type
                )

    def test_ecdsa_recoverable_signature_convert_invalid_input_type_rec_sig(self):
        for invalid_sig in invalid_recoverable_signature_length:
            with self.assertRaises(ValueError):
                ecdsa_recoverable_signature_convert(invalid_sig)

        for invalid_type in not_c_char_array:
            with self.assertRaises(ValueError):
                ecdsa_recoverable_signature_convert(invalid_type)

    def test_ecdsa_recoverable_signature_serialize_compact_invalid_input_type_rec_sig(
        self,
    ):
        for invalid_sig in invalid_recoverable_signature_length:
            with self.assertRaises(ValueError):
                ecdsa_recoverable_signature_serialize_compact(invalid_sig)

        for invalid_type in not_c_char_array:
            with self.assertRaises(ValueError):
                ecdsa_recoverable_signature_serialize_compact(invalid_type)

    def test_ecdsa_sign_recoverable_invalid_input_type_seckey(self):
        msg = b"moremoremoremore"
        tag = b"TapLeaf"
        msg_hash = tagged_sha256(tag, msg)
        for invalid_seckey in invalid_seckeys:
            with self.assertRaises(Libsecp256k1Exception):
                ecdsa_sign_recoverable(invalid_seckey, msg_hash)

        for invalid_seckey in invalid_seckey_length:
            with self.assertRaises(ValueError):
                ecdsa_sign_recoverable(invalid_seckey, msg_hash)

        for invalid_type in not_bytes:
            with self.assertRaises(ValueError):
                ecdsa_sign_recoverable(invalid_type, msg_hash)

    def test_ecdsa_sign_recoverable_invalid_input_type_msghash32(self):
        for invalid_msg in invalid_seckey_length:
            with self.assertRaises(ValueError):
                ecdsa_sign_recoverable(valid_seckeys[0], invalid_msg)

        for invalid_type in not_bytes:
            with self.assertRaises(ValueError):
                ecdsa_sign_recoverable(valid_seckeys[1], invalid_type)

    def test_ecdsa_recover_invalid_input_type_rec_sig(self):
        msg = b"moremoremoremore"
        tag = b"TapLeaf"
        msg_hash = tagged_sha256(tag, msg)
        for invalid_sig in invalid_recoverable_signature_length:
            with self.assertRaises(ValueError):
                ecdsa_recover(invalid_sig, msg_hash)

        for invalid_type in not_c_char_array:
            with self.assertRaises(ValueError):
                ecdsa_recover(invalid_type, msg_hash)

    def test_ecdsa_recover_invalid_input_type_msghash32(self):
        for invalid_msg in invalid_seckey_length:
            with self.assertRaises(ValueError):
                ecdsa_recover(self.compact_sig, invalid_msg)

        for invalid_type in not_bytes:
            with self.assertRaises(ValueError):
                ecdsa_recover(self.compact_sig, invalid_type)


@unittest.skipUnless(has_secp256k1_recovery, skip_reason)
class TestPysecp256k1Recovery(unittest.TestCase):
    def test_recovery(self):
        msg = b"moremoremoremore"
        tag = b"TapLeaf"
        msg_hash = tagged_sha256(tag, msg)
        for seckey in invalid_seckeys:
            with self.assertRaises(Libsecp256k1Exception):
                ecdsa_sign_recoverable(seckey, msg_hash)
        for seckey in valid_seckeys:
            pubkey = ec_pubkey_create(seckey)
            rec_sig = ecdsa_sign_recoverable(seckey, msg_hash)
            converted_rec_sig = ecdsa_recoverable_signature_convert(rec_sig)
            sig = ecdsa_sign(seckey, msg_hash)
            self.assertEqual(converted_rec_sig.raw, sig.raw)
            compact_sig_ser = ecdsa_signature_serialize_compact(sig)
            compact_rec_sig_ser, recid = ecdsa_recoverable_signature_serialize_compact(
                rec_sig
            )
            rec_sig_parsed = ecdsa_recoverable_signature_parse_compact(
                compact_rec_sig_ser, recid
            )
            # try to parse it but with wrong (yet valid) rec_id
            rec_sig_parsed_wrong = ecdsa_recoverable_signature_parse_compact(
                compact_rec_sig_ser, 3 if recid <= 2 else 0
            )
            self.assertEqual(rec_sig_parsed.raw, rec_sig.raw)
            self.assertNotEqual(rec_sig_parsed_wrong.raw, rec_sig.raw)
            self.assertEqual(compact_rec_sig_ser, compact_sig_ser)
            self.assertTrue(recid in (0, 1, 2, 3))
            rec_pubkey = ecdsa_recover(rec_sig, msg_hash)
            self.assertEqual(pubkey.raw, rec_pubkey.raw)

    def test_ecdsa_recover_invalid(self):
        seckey = valid_seckeys[0]
        target_pubkey = ec_pubkey_create(seckey)
        msghash32 = valid_seckeys[2]
        rec_sig0 = ecdsa_sign_recoverable(seckey, msghash32)
        # https://github.com/bitcoin-core/secp256k1/issues/1024#issuecomment-985193303
        # correct signature and incorrect msghash32
        # if 1 is returned - It means it found a public key
        # for which the provided (message, signature) pair was valid.
        recovered_pk = ecdsa_recover(rec_sig0, os.urandom(32))
        # recovered must be different than target
        self.assertNotEqual(recovered_pk.raw, target_pubkey.raw)
        # incorrect sig
        with self.assertRaises(Libsecp256k1Exception):
            ecdsa_recover(ctypes.create_string_buffer(65), msghash32)
