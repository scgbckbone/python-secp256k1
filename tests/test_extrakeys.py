import ctypes
import unittest
import hashlib
from tests.data import (
    valid_seckeys,
    invalid_seckeys,
    invalid_seckey_length,
    invalid_xonly_pubkey_length,
    not_bytes,
    invalid_pubkey_length,
    not_c_char_array,
    not_int,
    invalid_keypair_length,
    serialized_pubkeys_compressed,
)
from pysecp256k1.low_level import Libsecp256k1Exception, has_secp256k1_extrakeys
from pysecp256k1 import (
    ec_pubkey_create,
    ec_seckey_verify,
    ec_seckey_tweak_add,
    ec_seckey_negate,
)

if has_secp256k1_extrakeys:
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


skip_reason = "secp256k1 is not compiled with module 'extrakeys'"


@unittest.skipUnless(has_secp256k1_extrakeys, skip_reason)
class TestPysecp256k1ExtrakeysValidation(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.b32 = valid_seckeys[1]
        cls.keypair = keypair_create(valid_seckeys[0])
        cls.xonly_pubkey, cls.pk_parity = keypair_xonly_pub(cls.keypair)

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
        for invalid_xonly_pubkey in invalid_pubkey_length:
            with self.assertRaises(ValueError):
                xonly_pubkey_cmp(invalid_xonly_pubkey, self.xonly_pubkey)

        for invalid_type in not_c_char_array:
            with self.assertRaises(ValueError):
                xonly_pubkey_cmp(invalid_type, self.xonly_pubkey)

        for invalid_xonly_pubkey in invalid_pubkey_length:
            with self.assertRaises(ValueError):
                xonly_pubkey_cmp(self.xonly_pubkey, invalid_xonly_pubkey)

        for invalid_type in not_c_char_array:
            with self.assertRaises(ValueError):
                xonly_pubkey_cmp(self.xonly_pubkey, invalid_type)

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
                xonly_pubkey_tweak_add(invalid_xonly_pubkey, self.b32)

        for invalid_type in not_c_char_array:
            with self.assertRaises(ValueError):
                xonly_pubkey_tweak_add(invalid_type, self.b32)

    def test_xonly_pubkey_tweak_add_invalid_input_type_tweak32(self):
        for invalid_tweak in invalid_seckey_length:
            with self.assertRaises(ValueError):
                xonly_pubkey_tweak_add(self.xonly_pubkey, invalid_tweak)

        for invalid_type in not_bytes:
            with self.assertRaises(ValueError):
                xonly_pubkey_tweak_add(self.xonly_pubkey, invalid_type)

    def test_xonly_pubkey_tweak_add_check_invalid_input_type_tweaked_pubkey32(self):
        for invalid_xonly_ser in invalid_xonly_pubkey_length:
            with self.assertRaises(ValueError):
                xonly_pubkey_tweak_add_check(
                    invalid_xonly_ser, 0, self.xonly_pubkey, self.b32
                )

        for invalid_type in not_bytes:
            with self.assertRaises(ValueError):
                xonly_pubkey_tweak_add_check(
                    invalid_type, 0, self.xonly_pubkey, self.b32
                )

    def test_xonly_pubkey_tweak_add_check_invalid_input_type_tweaked_pk_parity(self):
        for invalid_pk_parity in [-1, 2, 3]:
            with self.assertRaises(ValueError):
                xonly_pubkey_tweak_add_check(
                    self.b32, invalid_pk_parity, self.xonly_pubkey, self.b32
                )

        for invalid_type in not_int:
            with self.assertRaises(ValueError):
                xonly_pubkey_tweak_add_check(
                    self.b32, invalid_type, self.xonly_pubkey, self.b32
                )

    def test_xonly_pubkey_tweak_add_check_invalid_input_type_internal_pubkey(self):
        for invalid_xonly_pubkey in invalid_pubkey_length:
            with self.assertRaises(ValueError):
                xonly_pubkey_tweak_add_check(
                    self.b32, 0, invalid_xonly_pubkey, self.b32
                )

        for invalid_type in not_c_char_array:
            with self.assertRaises(ValueError):
                xonly_pubkey_tweak_add_check(self.b32, 0, invalid_type, self.b32)

    def test_xonly_pubkey_tweak_add_check_invalid_input_type_tweak32(self):
        for invalid_tweak in invalid_seckey_length:
            with self.assertRaises(ValueError):
                xonly_pubkey_tweak_add_check(
                    self.b32, 0, self.xonly_pubkey, invalid_tweak
                )

        for invalid_type in not_bytes:
            with self.assertRaises(ValueError):
                xonly_pubkey_tweak_add_check(
                    self.b32, 0, self.xonly_pubkey, invalid_type
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
                keypair_xonly_tweak_add(invalid_keypair, self.b32)

        for invalid_type in not_c_char_array:
            with self.assertRaises(ValueError):
                keypair_xonly_tweak_add(invalid_type, self.b32)

    def test_keypair_xonly_tweak_add_invalid_input_type_tweak32(self):
        for invalid_tweak in invalid_seckey_length:
            with self.assertRaises(ValueError):
                keypair_xonly_tweak_add(self.keypair, invalid_tweak)

        for invalid_type in not_bytes:
            with self.assertRaises(ValueError):
                keypair_xonly_tweak_add(self.keypair, invalid_type)


@unittest.skipUnless(has_secp256k1_extrakeys, skip_reason)
class TestPysecp256k1Extrakeys(unittest.TestCase):
    def test_xonly_pubkey_parse_serialize(self):
        for pk_ser in serialized_pubkeys_compressed:
            xonly_ser = pk_ser[1:]
            xonly_pubkey = xonly_pubkey_parse(xonly_ser)
            self.assertEqual(xonly_pubkey_serialize(xonly_pubkey), xonly_ser)

        with self.assertRaises(Libsecp256k1Exception):
            xonly_pubkey_parse(32 * b"\x00")

    def test_xonly_pubkey_cmp(self):
        # without first byte the ascending order of indexes is: 0,2,1
        pks = [xonly_pubkey_parse(ser[1:]) for ser in serialized_pubkeys_compressed[:3]]
        xonly_pubkey0, xonly_pubkey1, xonly_pubkey2 = pks
        self.assertTrue(xonly_pubkey_cmp(xonly_pubkey0, xonly_pubkey1) < 0)
        self.assertTrue(xonly_pubkey_cmp(xonly_pubkey0, xonly_pubkey0) == 0)
        self.assertTrue(xonly_pubkey_cmp(xonly_pubkey1, xonly_pubkey2) > 0)

    def test_keypair_create(self):
        for invalid_seckey in invalid_seckeys:
            with self.assertRaises(Libsecp256k1Exception) as exc:
                keypair_create(invalid_seckey)
            self.assertEqual(str(exc.exception), "secret key is invalid")

    def test_keypair_sec(self):
        for seckey in valid_seckeys:
            keypair = keypair_create(seckey)
            sk = keypair_sec(keypair)
            self.assertEqual(seckey, sk)

        null = ctypes.create_string_buffer(96)
        null_sk = keypair_sec(null)
        self.assertEqual(null_sk, invalid_seckeys[1])

    def test_keypair_pub(self):
        for seckey in valid_seckeys:
            keypair = keypair_create(seckey)
            pubkey = ec_pubkey_create(seckey)
            self.assertEqual(pubkey.raw, keypair_pub(keypair).raw)

        null = ctypes.create_string_buffer(96)
        null_pk = keypair_pub(null)
        self.assertEqual(null_pk.raw, ctypes.create_string_buffer(64).raw)

    def test_keypair_xonly_pub(self):
        for seckey in valid_seckeys:
            pubkey = ec_pubkey_create(seckey)
            keypair = keypair_create(seckey)
            xonly_pubkey, pk_parity = keypair_xonly_pub(keypair)
            xonly_pubkey0, pk_parity0 = xonly_pubkey_from_pubkey(pubkey)
            self.assertEqual(xonly_pubkey.raw, xonly_pubkey0.raw)
            self.assertEqual(pk_parity, pk_parity0)

        null = ctypes.create_string_buffer(96)
        with self.assertRaises(Libsecp256k1Exception):
            keypair_xonly_pub(null)

    def test_tweaking_extrakeys(self):
        for seckey in valid_seckeys:
            raw_pubkey = ec_pubkey_create(seckey)
            keypair = keypair_create(seckey)
            xonly_pub, parity = xonly_pubkey_from_pubkey(raw_pubkey)
            xonly_pub1, parity1 = keypair_xonly_pub(keypair)
            self.assertEqual(xonly_pub.raw, xonly_pub1.raw)
            self.assertEqual(parity, parity1)
            ser_xonly_pub = xonly_pubkey_serialize(xonly_pub)
            self.assertEqual(xonly_pubkey_parse(ser_xonly_pub).raw, xonly_pub.raw)

            valid_tweak = hashlib.sha256(seckey).digest()
            self.assertIsNone(ec_seckey_verify(valid_tweak))
            # tweak keypair
            tweaked_keypair = keypair_xonly_tweak_add(keypair, valid_tweak)
            tweaked_pubkey = xonly_pubkey_tweak_add(xonly_pub, valid_tweak)
            tweaked_xonly_pub, parity2 = xonly_pubkey_from_pubkey(tweaked_pubkey)
            tweaked_xonly_pub1, parity3 = keypair_xonly_pub(tweaked_keypair)
            self.assertEqual(parity2, parity3)
            ser_tweaked_xonly_pub = xonly_pubkey_serialize(tweaked_xonly_pub)
            self.assertEqual(tweaked_xonly_pub.raw, tweaked_xonly_pub1.raw)
            self.assertTrue(
                xonly_pubkey_tweak_add_check(
                    ser_tweaked_xonly_pub, parity2, xonly_pub, valid_tweak
                )
            )
            # https://github.com/bitcoin-core/secp256k1/issues/1021
            if parity == 0:
                tweaked_seckey = ec_seckey_tweak_add(seckey, valid_tweak)
            else:
                tweaked_seckey = ec_seckey_tweak_add(
                    ec_seckey_negate(seckey), valid_tweak
                )
            assert tweaked_seckey == keypair_sec(tweaked_keypair)

            # incorrect serialization ok pubkey
            self.assertFalse(
                xonly_pubkey_tweak_add_check(
                    ser_tweaked_xonly_pub[:-1] + b"\xff",
                    parity2,
                    xonly_pub,
                    valid_tweak,
                )
            )
            # incorrect parity
            self.assertFalse(
                xonly_pubkey_tweak_add_check(
                    ser_tweaked_xonly_pub, 0 if parity2 else 1, xonly_pub, valid_tweak
                )
            )
            # invalid internal key
            self.assertFalse(
                xonly_pubkey_tweak_add_check(
                    ser_tweaked_xonly_pub, parity2, tweaked_xonly_pub, valid_tweak
                )
            )
            # invalid tweak
            self.assertFalse(
                xonly_pubkey_tweak_add_check(
                    ser_tweaked_xonly_pub, parity2, tweaked_xonly_pub, seckey
                )
            )

    def test_xonly_pubkey_add_null_tweak(self):
        tweak_null = 32 * b"\x00"
        with self.assertRaises(Libsecp256k1Exception):
            ec_seckey_verify(tweak_null)  # this means tweak is invalid
        seckey = valid_seckeys[0]
        self.assertIsNone(ec_seckey_verify(seckey))  # this means seckey is valid
        raw_pubkey = ec_pubkey_create(seckey)
        xonly_pubkey, parity = xonly_pubkey_from_pubkey(raw_pubkey)
        pubkey = xonly_pubkey_tweak_add(
            xonly_pubkey, tweak_null
        )  # this should raise but won't
        self.assertEqual(
            pubkey.raw, xonly_pubkey.raw
        )  # instead xonly pubkey is untweaked

    def test_keypair_xonly_add_null_tweak(self):
        tweak_null = 32 * b"\x00"
        with self.assertRaises(Libsecp256k1Exception):
            ec_seckey_verify(tweak_null)  # this means tweak is invalid
        seckey = valid_seckeys[0]
        self.assertIsNone(ec_seckey_verify(seckey))  # this means seckey is valid
        keypair = keypair_create(seckey)
        res = keypair_xonly_tweak_add(
            keypair, tweak_null
        )  # this should raise but won't
        self.assertEqual(res.raw, keypair.raw)  # instead keypair is untweaked

    def test_invalid_x_coordinate(self):
        # https://suredbits.com/taproot-funds-burned-on-the-bitcoin-blockchain/
        invalid_key_hex = (
            "658204033e46a1fa8cceb84013cfe2d376ca72d5f595319497b95b08aa64a970"
        )
        invalid_key_bytes = bytes.fromhex(invalid_key_hex)
        with self.assertRaises(Libsecp256k1Exception):
            xonly_pubkey_parse(invalid_key_bytes)
