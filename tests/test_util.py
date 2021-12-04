import unittest
from pysecp256k1.low_level.util import assert_zero_return_code, enforce_length
from pysecp256k1.low_level.constants import SECKEY_LENGTH, COMPACT_SIGNATURE_LENGTH


class TestUtil(unittest.TestCase):
    def test_assert_zero_return_code(self):
        self.assertIsNone(assert_zero_return_code(0))
        with self.assertRaises(AssertionError):
            assert_zero_return_code(1)

    def test_enforce_length(self):
        b32 = SECKEY_LENGTH * b"\x00"
        b64 = COMPACT_SIGNATURE_LENGTH * b"\x01"
        self.assertIsNone(enforce_length(b32, "seckey", length=32))
        self.assertIsNone(enforce_length(b64, "sig", length=64))
        with self.assertRaises(ValueError) as exc:
            enforce_length(b32 + b"\x00", "seckey", length=32)
        self.assertEqual(str(exc.exception), "'seckey' must be exactly 32 bytes")
        with self.assertRaises(ValueError) as exc:
            enforce_length(b64 + b"\x00", "signature_ser", length=[64, 72, 71])
        self.assertEqual(
            str(exc.exception), "Length of 'signature_ser' must be one of [64, 72, 71]"
        )
