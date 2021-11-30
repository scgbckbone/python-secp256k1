import unittest
from tests.data import invalid_seckeys, valid_seckeys
from pysecp256k1.low_level import Libsecp256k1Exception
from pysecp256k1 import (
    ec_pubkey_create,
    ecdsa_sign,
    tagged_sha256,
    ecdsa_signature_serialize_compact
)
from pysecp256k1.recovery import (
    ecdsa_recoverable_signature_parse_compact,
    ecdsa_recoverable_signature_serialize_compact,
    ecdsa_recoverable_signature_convert,
    ecdsa_sign_recoverable,
    ecdsa_recover
)


class TestPysecp256k1Recovery(unittest.TestCase):
    def test_recovery(self):
        msg = b"moremoremoremore"
        tag = b"TapLeaf"
        msg_hash = tagged_sha256(tag, msg)
        for seckey in invalid_seckeys[:2]:
            with self.assertRaises(Libsecp256k1Exception):
                ecdsa_sign_recoverable(seckey, msg_hash)
        for seckey in invalid_seckeys[2:]:
            with self.assertRaises(ValueError):
                ecdsa_sign_recoverable(seckey, msg_hash)
        for seckey in valid_seckeys:
            pubkey = ec_pubkey_create(seckey)
            rec_sig = ecdsa_sign_recoverable(seckey, msg_hash)
            converted_rec_sig = ecdsa_recoverable_signature_convert(rec_sig)
            sig = ecdsa_sign(seckey, msg_hash)
            self.assertEqual(converted_rec_sig.raw, sig.raw)
            compact_sig_ser = ecdsa_signature_serialize_compact(sig)
            compact_rec_sig_ser, recid = ecdsa_recoverable_signature_serialize_compact(rec_sig)
            rec_sig_parsed = ecdsa_recoverable_signature_parse_compact(compact_rec_sig_ser, recid)
            self.assertEqual(rec_sig_parsed.raw, rec_sig.raw)
            self.assertEqual(compact_rec_sig_ser, compact_sig_ser)
            self.assertTrue(recid in (0, 1, 2, 3))
            rec_pubkey = ecdsa_recover(rec_sig, msg_hash)
            self.assertEqual(pubkey.raw, rec_pubkey.raw)
