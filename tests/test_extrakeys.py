import os
import unittest
import hashlib
from tests.data import (
    valid_seckeys, invalid_seckeys, invalid_seckey_length,
    invalid_xonly_pubkey_length, not_bytes, invalid_pubkey_length,
    not_c_char_array, not_int, invalid_keypair_length
)
from pysecp256k1.low_level import Libsecp256k1Exception
from pysecp256k1 import (
    ec_pubkey_create,
    ec_seckey_verify,
    ec_seckey_tweak_add,
    ec_seckey_negate,
)
from pysecp256k1.extrakeys import (
    keypair_create,
    keypair_pub,
    keypair_sec,
    keypair_xonly_pub,
    keypair_xonly_tweak_add,
    xonly_pubkey_parse,
    xonly_pubkey_serialize,
    xonly_pubkey_from_pubkey,
    xonly_pubkey_tweak_add,
    xonly_pubkey_tweak_add_check,
    xonly_pubkey_cmp,
)


class TestPysecp256k1Extrakeys(unittest.TestCase):
    def test_xonly_pubkey_parse_invalid_input_type_xonly_pubkey_ser(self):
        for invalid_xonly_ser in invalid_xonly_pubkey_length:
            with self.assertRaises(ValueError):
                xonly_pubkey_parse(invalid_xonly_ser)

        for invalid_type in not_bytes:
            with self.assertRaises(ValueError):
                xonly_pubkey_parse(invalid_type)

    def test_xonly_pubkey_serialize_invalid_input_type_xonly_pubkey(self):
        for invalid_xonly_pubkey in invalid_pubkey_length:
            with self.assertRaises(ValueError):
                xonly_pubkey_serialize(invalid_xonly_pubkey)

        for invalid_type in not_c_char_array:
            with self.assertRaises(ValueError):
                xonly_pubkey_serialize(invalid_type)

    def test_xonly_pubkey_cmp_invalid_input_type_xonly_pubkey(self):
        keypair = keypair_create(valid_seckeys[0])
        valid_xonly_pubkey, pk_parity = keypair_xonly_pub(keypair)
        for invalid_xonly_pubkey in invalid_pubkey_length:
            with self.assertRaises(ValueError):
                xonly_pubkey_cmp(invalid_xonly_pubkey, valid_xonly_pubkey)

        for invalid_type in not_c_char_array:
            with self.assertRaises(ValueError):
                xonly_pubkey_cmp(invalid_type, valid_xonly_pubkey)

        for invalid_xonly_pubkey in invalid_pubkey_length:
            with self.assertRaises(ValueError):
                xonly_pubkey_cmp(valid_xonly_pubkey, invalid_xonly_pubkey)

        for invalid_type in not_c_char_array:
            with self.assertRaises(ValueError):
                xonly_pubkey_cmp(valid_xonly_pubkey, invalid_type)

    def test_xonly_pubkey_from_pubkey_invalid_input_type_pubkey(self):
        for invalid_pubkey in invalid_pubkey_length:
            with self.assertRaises(ValueError):
                xonly_pubkey_from_pubkey(invalid_pubkey)

        for invalid_type in not_c_char_array:
            with self.assertRaises(ValueError):
                xonly_pubkey_from_pubkey(invalid_type)

    def test_xonly_pubkey_tweak_add_invalid_input_type_xonly_pubkey(self):
        for invalid_xonly_pubkey in invalid_pubkey_length:
            with self.assertRaises(ValueError):
                xonly_pubkey_tweak_add(invalid_xonly_pubkey, os.urandom(32))

        for invalid_type in not_c_char_array:
            with self.assertRaises(ValueError):
                xonly_pubkey_tweak_add(invalid_type, os.urandom(32))

    def test_xonly_pubkey_tweak_add_invalid_input_type_tweak32(self):
        keypair = keypair_create(valid_seckeys[0])
        valid_xonly_pubkey, pk_parity = keypair_xonly_pub(keypair)
        for invalid_tweak in invalid_seckey_length:
            with self.assertRaises(ValueError):
                xonly_pubkey_tweak_add(valid_xonly_pubkey, invalid_tweak)

        for invalid_type in not_bytes:
            with self.assertRaises(ValueError):
                xonly_pubkey_tweak_add(valid_xonly_pubkey, invalid_type)

    def test_xonly_pubkey_tweak_add_check_invalid_input_type_tweaked_pubkey32(self):
        keypair = keypair_create(valid_seckeys[0])
        valid_xonly_pubkey, pk_parity = keypair_xonly_pub(keypair)
        for invalid_xonly_ser in invalid_xonly_pubkey_length:
            with self.assertRaises(ValueError):
                xonly_pubkey_tweak_add_check(
                    invalid_xonly_ser, 0, valid_xonly_pubkey, os.urandom(32)
                )

        for invalid_type in not_bytes:
            with self.assertRaises(ValueError):
                xonly_pubkey_tweak_add_check(
                    invalid_type, 0, valid_xonly_pubkey, os.urandom(32)
                )

    def test_xonly_pubkey_tweak_add_check_invalid_input_type_tweaked_pk_parity(self):
        keypair = keypair_create(valid_seckeys[0])
        valid_xonly_pubkey, pk_parity = keypair_xonly_pub(keypair)
        for invalid_type in not_int:
            with self.assertRaises(ValueError):
                xonly_pubkey_tweak_add_check(
                    os.urandom(32), invalid_type, valid_xonly_pubkey, os.urandom(32)
                )

    def test_xonly_pubkey_tweak_add_check_invalid_input_type_internal_pubkey(self):
        for invalid_xonly_pubkey in invalid_pubkey_length:
            with self.assertRaises(ValueError):
                xonly_pubkey_tweak_add_check(
                    os.urandom(32), 0, invalid_xonly_pubkey, os.urandom(32)
                )

        for invalid_type in not_c_char_array:
            with self.assertRaises(ValueError):
                xonly_pubkey_tweak_add_check(
                    os.urandom(32), 0, invalid_type, os.urandom(32)
                )

    def test_xonly_pubkey_tweak_add_check_invalid_input_type_tweak32(self):
        keypair = keypair_create(valid_seckeys[0])
        valid_xonly_pubkey, pk_parity = keypair_xonly_pub(keypair)
        for invalid_tweak in invalid_seckey_length:
            with self.assertRaises(ValueError):
                xonly_pubkey_tweak_add_check(
                    os.urandom(32), 0, valid_xonly_pubkey, invalid_tweak
                )

        for invalid_type in not_bytes:
            with self.assertRaises(ValueError):
                xonly_pubkey_tweak_add_check(
                    os.urandom(32), 0, valid_xonly_pubkey, invalid_type
                )

    def test_keypair_create_invalid_input_type_seckey(self):
        for invalid_seckey in invalid_seckey_length:
            with self.assertRaises(ValueError):
                keypair_create(invalid_seckey)

        for invalid_type in not_bytes:
            with self.assertRaises(ValueError):
                keypair_create(invalid_type)

    def test_keypair_sec_invalid_input_type_keypair(self):
        for invalid_keypair in invalid_keypair_length:
            with self.assertRaises(ValueError):
                keypair_sec(invalid_keypair)

        for invalid_type in not_c_char_array:
            with self.assertRaises(ValueError):
                keypair_sec(invalid_type)

    def test_keypair_pub_invalid_input_type_keypair(self):
        for invalid_keypair in invalid_keypair_length:
            with self.assertRaises(ValueError):
                keypair_pub(invalid_keypair)

        for invalid_type in not_c_char_array:
            with self.assertRaises(ValueError):
                keypair_pub(invalid_type)

    def test_keypair_xonly_pub_invalid_input_type_keypair(self):
        for invalid_keypair in invalid_keypair_length:
            with self.assertRaises(ValueError):
                keypair_xonly_pub(invalid_keypair)

        for invalid_type in not_c_char_array:
            with self.assertRaises(ValueError):
                keypair_xonly_pub(invalid_type)

    def test_keypair_xonly_tweak_add_invalid_input_type_keypair(self):
        for invalid_keypair in invalid_keypair_length:
            with self.assertRaises(ValueError):
                keypair_xonly_tweak_add(invalid_keypair, os.urandom(32))

        for invalid_type in not_c_char_array:
            with self.assertRaises(ValueError):
                keypair_xonly_tweak_add(invalid_type, os.urandom(32))

    def test_keypair_xonly_tweak_add_invalid_input_type_tweak32(self):
        keypair = keypair_create(valid_seckeys[2])
        for invalid_tweak in invalid_seckey_length:
            with self.assertRaises(ValueError):
                keypair_xonly_tweak_add(keypair, invalid_tweak)

        for invalid_type in not_bytes:
            with self.assertRaises(ValueError):
                keypair_xonly_tweak_add(keypair, invalid_type)

    def test_extrakeys(self):
        for seckey in invalid_seckeys:
            with self.assertRaises(Libsecp256k1Exception) as exc:
                keypair_create(seckey)
            self.assertEqual(
                str(exc.exception),
                "secret key is invalid"
            )
        for seckey in invalid_seckey_length:
            with self.assertRaises(ValueError) as exc:
                keypair_create(seckey)
            self.assertEqual(
                str(exc.exception),
                "'seckey' must be exactly 32 bytes"
            )
        for seckey in valid_seckeys:
            keypair = keypair_create(seckey)
            assert seckey == keypair_sec(keypair)
            raw_pubkey = ec_pubkey_create(seckey)
            assert raw_pubkey.raw == keypair_pub(keypair).raw
            xonly_pub, parity = xonly_pubkey_from_pubkey(raw_pubkey)
            xonly_pub1, parity1 = keypair_xonly_pub(keypair)
            assert xonly_pub.raw == xonly_pub1.raw
            assert parity == parity1
            ser_xonly_pub = xonly_pubkey_serialize(xonly_pub)
            assert xonly_pubkey_parse(ser_xonly_pub).raw == xonly_pub.raw

            valid_tweak = hashlib.sha256(valid_seckeys[0]).digest()
            assert ec_seckey_verify(valid_tweak) is None
            # tweak keypair
            tweaked_keypair = keypair_xonly_tweak_add(keypair, valid_tweak)
            tweaked_xonly_pub = xonly_pubkey_tweak_add(xonly_pub, valid_tweak)
            tweaked_xonly_pub1, parity2 = keypair_xonly_pub(tweaked_keypair)
            ser_tweaked_xonly_pub = xonly_pubkey_serialize(tweaked_xonly_pub)
            assert tweaked_xonly_pub.raw == tweaked_xonly_pub1.raw
            self.assertTrue(
                xonly_pubkey_tweak_add_check(ser_tweaked_xonly_pub, parity2, xonly_pub, valid_tweak)
            )
            # https://github.com/bitcoin-core/secp256k1/issues/1021
            if parity == 0:
                tweaked_seckey = ec_seckey_tweak_add(seckey, valid_tweak)
            else:
                tweaked_seckey = ec_seckey_tweak_add(ec_seckey_negate(seckey), valid_tweak)
            assert tweaked_seckey == keypair_sec(tweaked_keypair)
