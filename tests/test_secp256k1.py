import os
import ctypes
import unittest
import hashlib
from tests.data import (
    invalid_seckeys,
    valid_seckeys,
    serialized_pubkeys_compressed,
    serialized_pubkeys,
    invalid_seckey_length,
    not_bytes,
    not_c_char_array,
    invalid_pubkey_serialization_length,
    invalid_pubkey_length,
    not_bool,
    invalid_signature_length,
    invalid_compact_sig_length,
    valid_compact_sig_serializations,
    valid_der_sig_serializations,
)
from pysecp256k1.low_level import Libsecp256k1Exception
from pysecp256k1 import (
    ec_seckey_verify,
    ec_pubkey_create,
    ec_pubkey_serialize,
    ec_pubkey_cmp,
    ec_pubkey_parse,
    ec_seckey_negate,
    ec_pubkey_negate,
    ec_seckey_tweak_add,
    ec_pubkey_tweak_add,
    ec_pubkey_combine,
    ecdsa_verify,
    ecdsa_sign,
    ecdsa_signature_serialize_der,
    ecdsa_signature_parse_der,
    tagged_sha256,
    ec_pubkey_tweak_mul,
    ec_seckey_tweak_mul,
    ecdsa_signature_parse_compact,
    ecdsa_signature_serialize_compact,
    ecdsa_signature_normalize,
)


class TestPysecp256k1Validation(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.b32 = os.urandom(32)
        cls.pubkey0 = ec_pubkey_create(valid_seckeys[0])
        cls.pubkey1 = ec_pubkey_create(valid_seckeys[1])

    def test_context_create_invalid_input_type_flags(self):
        pass

    def test_context_clone_invalid_input_type_ctx(self):
        pass

    def test_context_destroy_invalid_input_type_ctx(self):
        pass

    def test_context_randomize_invalid_input_type_ctx(self):
        pass

    def test_context_randomize_invalid_input_type_seed32(self):
        pass

    def test_ec_pubkey_parse_invalid_input_type_pubkey_ser(self):
        for invalid_pubkey_ser in invalid_pubkey_serialization_length:
            with self.assertRaises(ValueError):
                ec_pubkey_parse(invalid_pubkey_ser)

        for invalid_type in not_bytes:
            with self.assertRaises(ValueError):
                ec_pubkey_parse(invalid_type)

    def test_ec_pubkey_serialize_invalid_input_type_pubkey(self):
        for invalid_pubkey in invalid_pubkey_length:
            with self.assertRaises(ValueError):
                ec_pubkey_serialize(invalid_pubkey)

        for invalid_type in not_c_char_array:
            with self.assertRaises(ValueError):
                ec_pubkey_serialize(invalid_type)

    def test_ec_pubkey_serialize_invalid_input_type_compressed(self):
        for invalid_type in not_bool:
            with self.assertRaises(ValueError):
                ec_pubkey_serialize(self.pubkey0, invalid_type)

    def test_ec_pubkey_cmp_invalid_input_type_pubkey(self):
        for invalid_pubkey in invalid_pubkey_length:
            with self.assertRaises(ValueError):
                ec_pubkey_cmp(self.pubkey0, invalid_pubkey)

        for invalid_type in not_c_char_array:
            with self.assertRaises(ValueError):
                ec_pubkey_cmp(self.pubkey0, invalid_type)

        for invalid_pubkey in invalid_pubkey_length:
            with self.assertRaises(ValueError):
                ec_pubkey_cmp(invalid_pubkey, self.pubkey1)

        for invalid_type in not_c_char_array:
            with self.assertRaises(ValueError):
                ec_pubkey_cmp(invalid_type, self.pubkey1)

    def test_ecdsa_signature_parse_compact_invalid_input_type_compact_sig(self):
        for invalid_sig in invalid_compact_sig_length:
            with self.assertRaises(ValueError):
                ecdsa_signature_parse_compact(invalid_sig)

        for invalid_type in not_bytes:
            with self.assertRaises(ValueError):
                ecdsa_signature_parse_compact(invalid_type)

    def test_ecdsa_signature_parse_der_invalid_input_type_der_sig(self):
        for invalid_type in not_bytes:
            with self.assertRaises(ValueError):
                ecdsa_signature_parse_der(invalid_type)

    def test_ecdsa_signature_serialize_der_invalid_input_type_sig(self):
        for invalid_sig in invalid_signature_length:
            with self.assertRaises(ValueError):
                ecdsa_signature_serialize_der(invalid_sig)

        for invalid_type in not_c_char_array:
            with self.assertRaises(ValueError):
                ecdsa_signature_serialize_der(invalid_type)

    def test_ecdsa_signature_serialize_compact_invalid_input_type_sig(self):
        for invalid_sig in invalid_signature_length:
            with self.assertRaises(ValueError):
                ecdsa_signature_serialize_compact(invalid_sig)

        for invalid_type in not_c_char_array:
            with self.assertRaises(ValueError):
                ecdsa_signature_serialize_compact(invalid_type)

    def test_ecdsa_verify_invalid_input_type_sig(self):
        for invalid_sig in invalid_signature_length:
            with self.assertRaises(ValueError):
                ecdsa_verify(invalid_sig, self.pubkey0, self.b32)

        for invalid_type in not_c_char_array:
            with self.assertRaises(ValueError):
                ecdsa_verify(invalid_type, self.pubkey0, self.b32)

    def test_ecdsa_verify_invalid_input_type_pubkey(self):
        sig = ctypes.create_string_buffer(64)
        for invalid_pubkey in invalid_pubkey_length:
            with self.assertRaises(ValueError):
                ecdsa_verify(sig, invalid_pubkey, self.b32)

        for invalid_type in not_c_char_array:
            with self.assertRaises(ValueError):
                ecdsa_verify(sig, invalid_type, self.b32)

    def test_ecdsa_verify_invalid_input_type_msghash32(self):
        sig = ctypes.create_string_buffer(64)
        for invalid_msg in invalid_seckey_length:
            with self.assertRaises(ValueError):
                ecdsa_verify(sig, self.pubkey0, invalid_msg)

        for invalid_type in not_bytes:
            with self.assertRaises(ValueError):
                ecdsa_verify(sig, self.pubkey1, invalid_type)

    def test_ecdsa_signature_normalize_invalid_input_type_sig(self):
        for invalid_sig in invalid_signature_length:
            with self.assertRaises(ValueError):
                ecdsa_signature_normalize(invalid_sig)

        for invalid_type in not_c_char_array:
            with self.assertRaises(ValueError):
                ecdsa_signature_normalize(invalid_type)

    def test_ecdsa_sign_invalid_input_type_seckey(self):
        for invalid_seckey in invalid_seckey_length:
            with self.assertRaises(ValueError):
                ecdsa_sign(invalid_seckey, self.b32)

        for invalid_type in not_bytes:
            with self.assertRaises(ValueError):
                ecdsa_sign(invalid_type, self.b32)

    def test_ecdsa_sign_invalid_input_type_msghash32(self):
        for invalid_msghash32 in invalid_seckey_length:
            with self.assertRaises(ValueError):
                ecdsa_sign(valid_seckeys[0], invalid_msghash32)

        for invalid_type in not_bytes:
            with self.assertRaises(ValueError):
                ecdsa_sign(valid_seckeys[1], invalid_type)

    def test_ec_seckey_verify_invalid_input_type_seckey(self):
        for invalid_seckey in invalid_seckey_length:
            with self.assertRaises(ValueError):
                ec_seckey_verify(invalid_seckey)

        for invalid_type in not_bytes:
            with self.assertRaises(ValueError):
                ec_seckey_verify(invalid_type)

    def test_ec_pubkey_create_invalid_input_type_seckey(self):
        for invalid_seckey in invalid_seckey_length:
            with self.assertRaises(ValueError):
                ec_pubkey_create(invalid_seckey)

        for invalid_type in not_bytes:
            with self.assertRaises(ValueError):
                ec_pubkey_create(invalid_type)

    def test_ec_seckey_negate_invalid_input_type_seckey(self):
        for invalid_seckey in invalid_seckey_length:
            with self.assertRaises(ValueError):
                ec_seckey_negate(invalid_seckey)

        for invalid_type in not_bytes:
            with self.assertRaises(ValueError):
                ec_seckey_negate(invalid_type)

    def test_ec_pubkey_negate_invalid_input_type_pubkey(self):
        for invalid_pubkey in invalid_pubkey_length:
            with self.assertRaises(ValueError):
                ec_pubkey_negate(invalid_pubkey)

        for invalid_type in not_c_char_array:
            with self.assertRaises(ValueError):
                ec_pubkey_negate(invalid_type)

    def test_ec_seckey_tweak_add_invalid_input_type_seckey(self):
        for invalid_seckey in invalid_seckey_length:
            with self.assertRaises(ValueError):
                ec_seckey_tweak_add(invalid_seckey, self.b32)

        for invalid_type in not_bytes:
            with self.assertRaises(ValueError):
                ec_seckey_tweak_add(invalid_type, self.b32)

    def test_ec_seckey_tweak_add_invalid_input_type_tweak32(self):
        for invalid_tweak in invalid_seckey_length:
            with self.assertRaises(ValueError):
                ec_seckey_tweak_add(valid_seckeys[0], invalid_tweak)

        for invalid_type in not_bytes:
            with self.assertRaises(ValueError):
                ec_seckey_tweak_add(valid_seckeys[1], invalid_type)

    def test_ec_pubkey_tweak_add_invalid_input_type_pubkey(self):
        for invalid_pubkey in invalid_pubkey_length:
            with self.assertRaises(ValueError):
                ec_pubkey_tweak_add(invalid_pubkey, self.b32)

        for invalid_type in not_c_char_array:
            with self.assertRaises(ValueError):
                ec_pubkey_tweak_add(invalid_type, self.b32)

    def test_ec_pubkey_tweak_add_invalid_input_type_tweak32(self):
        for invalid_tweak in invalid_seckey_length:
            with self.assertRaises(ValueError):
                ec_pubkey_tweak_add(self.pubkey0, invalid_tweak)

        for invalid_type in not_bytes:
            with self.assertRaises(ValueError):
                ec_pubkey_tweak_add(self.pubkey1, invalid_type)

    def test_ec_seckey_tweak_mul_invalid_input_type_seckey(self):
        for invalid_seckey in invalid_seckey_length:
            with self.assertRaises(ValueError):
                ec_seckey_tweak_mul(invalid_seckey, self.b32)

        for invalid_type in not_bytes:
            with self.assertRaises(ValueError):
                ec_seckey_tweak_mul(invalid_type, self.b32)

    def test_ec_seckey_tweak_mul_invalid_input_type_tweak32(self):
        for invalid_tweak in invalid_seckey_length:
            with self.assertRaises(ValueError):
                ec_seckey_tweak_mul(valid_seckeys[0], invalid_tweak)

        for invalid_type in not_bytes:
            with self.assertRaises(ValueError):
                ec_seckey_tweak_mul(valid_seckeys[1], invalid_type)

    def test_ec_pubkey_tweak_mul_invalid_input_type_pubkey(self):
        for invalid_pubkey in invalid_pubkey_length:
            with self.assertRaises(ValueError):
                ec_pubkey_tweak_mul(invalid_pubkey, self.b32)

        for invalid_type in not_c_char_array:
            with self.assertRaises(ValueError):
                ec_pubkey_tweak_mul(invalid_type, self.b32)

    def test_ec_pubkey_tweak_mul_invalid_input_type_tweak32(self):
        for invalid_tweak in invalid_seckey_length:
            with self.assertRaises(ValueError):
                ec_pubkey_tweak_mul(self.pubkey1, invalid_tweak)

        for invalid_type in not_bytes:
            with self.assertRaises(ValueError):
                ec_pubkey_tweak_mul(self.pubkey0, invalid_type)

    def test_ec_pubkey_combine_invalid_input_type_pubkeys(self):
        # empty list
        with self.assertRaises(ValueError):
            ec_pubkey_combine([])
        # length 1
        with self.assertRaises(ValueError):
            ec_pubkey_combine([self.pubkey0])
        # not list
        for invalid_type in [
            (self.pubkey0, self.pubkey1),
            {"pk1": self.pubkey0, "pk2": self.pubkey1},
        ]:
            with self.assertRaises(ValueError):
                ec_pubkey_combine(invalid_type)
        for invalid_type in not_c_char_array:
            pubkey_list = [self.pubkey0, self.pubkey1, invalid_type]
            with self.assertRaises(ValueError):
                ec_pubkey_combine(pubkey_list)

    def test_tagged_sha256_invalid_input_type_tag(self):
        for invalid_type in not_bytes:
            with self.assertRaises(ValueError):
                tagged_sha256(invalid_type, b"message")

    def test_tagged_sha256_invalid_input_type_msg(self):
        for invalid_type in not_bytes:
            with self.assertRaises(ValueError):
                tagged_sha256(b"tag", invalid_type)


class TestPysecp256k1(unittest.TestCase):
    def test_ec_pubkey_parse(self):
        # swap marker - uncompressed marker for compressed pubkey
        for ser_pub in serialized_pubkeys_compressed:
            invalid_ser_pub = b"\x04" + ser_pub[1:]
            with self.assertRaises(Libsecp256k1Exception):
                ec_pubkey_parse(invalid_ser_pub)

        # swap marker - compressed marker for uncompressed pubkey
        for ser_pub in serialized_pubkeys:
            invalid_ser_pub = b"\x02" + ser_pub[1:]
            with self.assertRaises(Libsecp256k1Exception):
                ec_pubkey_parse(invalid_ser_pub)

        # not a public key
        with self.assertRaises(Libsecp256k1Exception):
            ec_pubkey_parse(os.urandom(33))

        # compressed
        for ser_pub, seckey in zip(serialized_pubkeys_compressed, valid_seckeys):
            self.assertEqual(ec_pubkey_parse(ser_pub).raw, ec_pubkey_create(seckey).raw)

        # uncompressed
        for ser_pub, seckey in zip(serialized_pubkeys, valid_seckeys):
            self.assertEqual(ec_pubkey_parse(ser_pub).raw, ec_pubkey_create(seckey).raw)

    def test_ec_pubkey_serialize(self):
        # NULL
        self.assertEqual(ec_pubkey_serialize(ctypes.create_string_buffer(64)), b"")
        # compressed
        for seckey, ser_pub in zip(valid_seckeys, serialized_pubkeys_compressed):
            self.assertEqual(ec_pubkey_serialize(ec_pubkey_create(seckey)), ser_pub)
        # uncompressed
        for seckey, ser_pub in zip(valid_seckeys, serialized_pubkeys):
            self.assertEqual(
                ec_pubkey_serialize(ec_pubkey_create(seckey), compressed=False), ser_pub
            )

    def test_ec_pubkey_cmp(self):
        for i in range(len(serialized_pubkeys)):
            self.assertTrue(
                ec_pubkey_cmp(
                    ec_pubkey_parse(serialized_pubkeys[i]),
                    ec_pubkey_parse(serialized_pubkeys_compressed[i]),
                )
                == 0  # meaning that they are equal
            )
        # first 3 are in ascending order
        pubkey0 = ec_pubkey_parse(serialized_pubkeys_compressed[0])
        pubkey1 = ec_pubkey_parse(serialized_pubkeys_compressed[1])
        pubkey2 = ec_pubkey_parse(serialized_pubkeys_compressed[2])
        self.assertTrue(
            # first public key is less than the second
            ec_pubkey_cmp(pubkey0, pubkey1)
            < 0
        )
        self.assertTrue(
            # the first public key is greater than the second
            ec_pubkey_cmp(pubkey2, pubkey0)
            > 0
        )

    def test_ecdsa_signature_parse_ser_compact(self):
        # NULL
        sig = ecdsa_signature_parse_compact(64 * b"\x00")
        self.assertEqual(sig.raw, 64 * b"\x00")
        # order
        with self.assertRaises(Libsecp256k1Exception):
            ecdsa_signature_parse_compact(2 * invalid_seckeys[0])
        for compact_sig_ser in valid_compact_sig_serializations:
            sig = ecdsa_signature_parse_compact(compact_sig_ser)
            self.assertEqual(ecdsa_signature_serialize_compact(sig), compact_sig_ser)
        for seckey in valid_seckeys:
            msg = hashlib.sha256(seckey).digest()
            raw_sig = ecdsa_sign(seckey, msg)
            raw_sig = ecdsa_signature_normalize(raw_sig)
            compact_ser_sig = ecdsa_signature_serialize_compact(raw_sig)
            compact_parsed_sig = ecdsa_signature_parse_compact(compact_ser_sig)
            self.assertEqual(raw_sig.raw, compact_parsed_sig.raw)

    def test_ecdsa_signature_parse_ser_der(self):
        # NULL COMPACT instead of DER
        with self.assertRaises(Libsecp256k1Exception):
            ecdsa_signature_parse_der(64 * b"\x00")
        with self.assertRaises(Libsecp256k1Exception):
            ecdsa_signature_parse_der(os.urandom(71))
        with self.assertRaises(Libsecp256k1Exception):
            ecdsa_signature_parse_der(os.urandom(72))
        with self.assertRaises(Libsecp256k1Exception):
            ecdsa_signature_parse_der(os.urandom(73))
        for der_sig_ser in valid_der_sig_serializations:
            sig = ecdsa_signature_parse_der(der_sig_ser)
            self.assertEqual(ecdsa_signature_serialize_der(sig), der_sig_ser)
        for seckey in valid_seckeys:
            msg = hashlib.sha256(seckey).digest()
            raw_sig = ecdsa_sign(seckey, msg)
            raw_sig = ecdsa_signature_normalize(raw_sig)
            compact_ser_sig = ecdsa_signature_serialize_der(raw_sig)
            compact_parsed_sig = ecdsa_signature_parse_der(compact_ser_sig)
            self.assertEqual(raw_sig.raw, compact_parsed_sig.raw)

    def test_ecdsa_sign_verify(self):
        msg0 = hashlib.sha256(valid_seckeys[0]).digest()
        msg1 = hashlib.sha256(valid_seckeys[1]).digest()
        raw_sig = ecdsa_sign(valid_seckeys[2], msg0)
        # incorrect pubkey
        pubkey = ec_pubkey_create(valid_seckeys[1])
        self.assertFalse(ecdsa_verify(raw_sig, pubkey, msg0))
        # incorrect msg
        pubkey = ec_pubkey_create(valid_seckeys[2])
        self.assertFalse(ecdsa_verify(raw_sig, pubkey, msg1))
        # valid runs
        for seckey in valid_seckeys:
            raw_sig = ecdsa_sign(seckey, msg0)
            raw_sig = ecdsa_signature_normalize(raw_sig)
            raw_pub = ec_pubkey_create(seckey)
            self.assertTrue(ecdsa_verify(raw_sig, raw_pub, msg0))
        # invalid seckey
        for invalid_seckey in invalid_seckeys:
            with self.assertRaises(Libsecp256k1Exception):
                ecdsa_sign(invalid_seckey, msg0)

    def test_ec_seckey_verify(self):
        # INVALID KEY
        for seckey in invalid_seckeys:
            with self.assertRaises(Libsecp256k1Exception):
                ec_seckey_verify(seckey)

        # VALID KEY
        for seckey in valid_seckeys:
            self.assertIsNone(ec_seckey_verify(seckey))

    def test_ec_pubkey_create(self):
        for seckey in invalid_seckeys:
            with self.assertRaises(Libsecp256k1Exception):
                ec_pubkey_create(seckey)

        for seckey in valid_seckeys:
            raw_pubkey = ec_pubkey_create(seckey)

    def test_ec_seckey_negate(self):
        for invalid_seckey in invalid_seckeys:
            with self.assertRaises(Libsecp256k1Exception):
                ec_seckey_negate(invalid_seckey)
        for seckey in valid_seckeys:
            self.assertEqual(seckey, ec_seckey_negate(ec_seckey_negate(seckey)))

    def test_ec_pubkey_negate(self):
        for seckey in valid_seckeys:
            raw_pubkey = ec_pubkey_create(seckey)
            self.assertEqual(
                raw_pubkey.raw, ec_pubkey_negate(ec_pubkey_negate(raw_pubkey)).raw
            )

    def test_ec_seckey_tweak_add(self):
        valid_tweak = valid_seckeys[0]
        for seckey in invalid_seckeys[:1]:
            with self.assertRaises(Libsecp256k1Exception) as exc:
                # invalid seckey
                ec_seckey_tweak_add(seckey, valid_tweak)
            self.assertEqual(
                str(exc.exception),
                "arguments are invalid or the resulting secret key would be invalid"
                " (only when the tweak is the negation of the secret key)",
            )
            with self.assertRaises(Libsecp256k1Exception) as exc:
                # invalid tweak
                ec_seckey_tweak_add(valid_tweak, seckey)
            self.assertEqual(
                str(exc.exception),
                "arguments are invalid or the resulting secret key would be invalid"
                " (only when the tweak is the negation of the secret key)",
            )
        # tweak is the negation of secret key
        with self.assertRaises(Libsecp256k1Exception):
            ec_seckey_tweak_add(valid_seckeys[0], ec_seckey_negate(valid_seckeys[0]))

        for seckey in valid_seckeys:
            self.assertEqual(len(ec_seckey_tweak_add(seckey, valid_tweak)), 32)

        x, y, z = valid_seckeys[:3]
        xy = ec_seckey_tweak_add(x, y)
        yx = ec_seckey_tweak_add(y, x)
        yz = ec_seckey_tweak_add(y, z)
        xyz = ec_seckey_tweak_add(x, ec_seckey_tweak_add(y, z))
        yzx = ec_seckey_tweak_add(yz, x)
        self.assertEqual(xyz, yzx)
        self.assertEqual(xy, yx)

    def test_ec_seckey_tweak_mul(self):
        valid_tweak = valid_seckeys[0]
        for seckey in invalid_seckeys:
            with self.assertRaises(Libsecp256k1Exception) as exc:
                # invalid seckey
                ec_seckey_tweak_mul(seckey, valid_tweak)
            self.assertEqual(str(exc.exception), "invalid arguments")
            with self.assertRaises(Libsecp256k1Exception) as exc:
                # invalid tweak
                ec_seckey_tweak_mul(valid_tweak, seckey)
            self.assertEqual(str(exc.exception), "invalid arguments")
        # tweak is the negation of secret key - can be in mul
        ec_seckey_tweak_mul(valid_seckeys[0], ec_seckey_negate(valid_seckeys[0]))

        for seckey in valid_seckeys:
            self.assertEqual(len(ec_seckey_tweak_mul(seckey, valid_tweak)), 32)

        x, y, z = valid_seckeys[:3]
        xy = ec_seckey_tweak_mul(x, y)
        yx = ec_seckey_tweak_mul(y, x)
        yz = ec_seckey_tweak_mul(y, z)
        xyz = ec_seckey_tweak_mul(x, ec_seckey_tweak_mul(y, z))
        yzx = ec_seckey_tweak_mul(yz, x)
        self.assertEqual(xyz, yzx)
        self.assertEqual(xy, yx)

    def test_ec_pubkey_tweak_add(self):
        valid_seckey = valid_seckeys[0]
        raw_pubkey = ec_pubkey_create(valid_seckey)
        # null tweak and curve order
        # TODO null triggers illegal callback
        for seckey in invalid_seckeys[:1]:
            with self.assertRaises(Libsecp256k1Exception) as exc:
                ec_pubkey_tweak_add(raw_pubkey, tweak32=seckey)
            self.assertEqual(
                str(exc.exception),
                "arguments are invalid or the resulting public key would be invalid"
                " (only when the tweak is the negation of the corresponding secret key)",
            )

        # compressed
        tweak = valid_seckeys[2]
        sx, sy = valid_seckeys[:2]
        raw_px, raw_py = (
            ec_pubkey_parse(pk) for pk in serialized_pubkeys_compressed[:2]
        )
        sxt = ec_seckey_tweak_add(sx, tweak)
        sxt_p = ec_pubkey_create(sxt)
        syt = ec_seckey_tweak_add(sy, tweak)
        syt_p = ec_pubkey_create(syt)

        pxt = ec_pubkey_tweak_add(raw_px, tweak)
        pyt = ec_pubkey_tweak_add(raw_py, tweak)
        self.assertEqual(sxt_p.raw, pxt.raw)
        self.assertEqual(syt_p.raw, pyt.raw)

    def test_ec_pubkey_tweak_mul(self):
        valid_seckey = valid_seckeys[0]
        raw_pubkey = ec_pubkey_create(valid_seckey)
        for seckey in invalid_seckeys:
            with self.assertRaises(Libsecp256k1Exception) as exc:
                ec_pubkey_tweak_mul(raw_pubkey, tweak32=seckey)
            self.assertEqual(str(exc.exception), "invalid arguments")
        # compressed
        tweak = valid_seckeys[2]
        sx, sy = valid_seckeys[:2]
        raw_px, raw_py = (
            ec_pubkey_parse(pk) for pk in serialized_pubkeys_compressed[:2]
        )
        sxt = ec_seckey_tweak_mul(sx, tweak)
        sxt_p = ec_pubkey_create(sxt)
        syt = ec_seckey_tweak_mul(sy, tweak)
        syt_p = ec_pubkey_create(syt)

        pxt = ec_pubkey_tweak_mul(raw_px, tweak)
        pyt = ec_pubkey_tweak_mul(raw_py, tweak)
        self.assertEqual(sxt_p.raw, pxt.raw)
        self.assertEqual(syt_p.raw, pyt.raw)

    def test_tweak_mul_seckey_pubkey_cmp(self):
        for seckey in valid_seckeys:
            tweak = hashlib.sha256(seckey).digest()
            self.assertIsNone(ec_seckey_verify(seckey))
            raw_pubkey = ec_pubkey_create(seckey)
            tweaked_pk0 = ec_pubkey_tweak_mul(raw_pubkey, tweak)
            tweaked_sk = ec_seckey_tweak_mul(seckey, tweak)
            tweaked_pk1 = ec_pubkey_create(tweaked_sk)
            self.assertEqual(tweaked_pk0.raw, tweaked_pk1.raw)

    def test_tweak_add_seckey_pubkey_cmp(self):
        for seckey in valid_seckeys:
            tweak = hashlib.sha256(seckey).digest()
            self.assertIsNone(ec_seckey_verify(tweak))
            raw_pubkey = ec_pubkey_create(seckey)
            tweaked_pk0 = ec_pubkey_tweak_add(raw_pubkey, tweak)
            tweaked_sk = ec_seckey_tweak_add(seckey, tweak)
            tweaked_pk1 = ec_pubkey_create(tweaked_sk)
            self.assertEqual(tweaked_pk0.raw, tweaked_pk1.raw)

    def test_ec_pubkey_combine(self):
        parsed_pubkeys = [
            ec_pubkey_parse(pk) for pk in serialized_pubkeys_compressed[:3]
        ]
        x, y, z = valid_seckeys[:3]
        xy = ec_seckey_tweak_add(x, y)
        xyz = ec_seckey_tweak_add(x, ec_seckey_tweak_add(y, z))

        xy_pub = ec_pubkey_combine(parsed_pubkeys[:2])
        self.assertEqual(xy_pub.raw, ec_pubkey_create(xy).raw)
        xyz_pub = ec_pubkey_combine(parsed_pubkeys)
        self.assertEqual(xyz_pub.raw, ec_pubkey_create(xyz).raw)

        null_pks = [ctypes.create_string_buffer(64) for _ in range(3)]
        res = ec_pubkey_combine(null_pks)
        self.assertEqual(res.raw, null_pks[0].raw)

    # ec_pubkey_tweak_mul and ec_seckey_tweak_mul do raise for NULL tweak
    def test_pubkey_mul_null_tweak(self):
        tweak_null = 32 * b"\x00"
        with self.assertRaises(Libsecp256k1Exception):
            ec_seckey_verify(tweak_null)  # this means tweak is invalid
        seckey = valid_seckeys[0]
        self.assertIsNone(ec_seckey_verify(seckey))  # this means seckey is valid
        raw_pubkey = ec_pubkey_create(seckey)
        with self.assertRaises(Libsecp256k1Exception) as exc:
            ec_pubkey_tweak_mul(raw_pubkey, tweak_null)  # this raises
        self.assertEqual(str(exc.exception), "invalid arguments")

    def test_seckey_mul_null_tweak(self):
        tweak_null = 32 * b"\x00"
        with self.assertRaises(Libsecp256k1Exception):
            ec_seckey_verify(tweak_null)  # this means tweak is invalid
        seckey = valid_seckeys[0]
        self.assertIsNone(ec_seckey_verify(seckey))  # this means seckey is valid
        with self.assertRaises(Libsecp256k1Exception) as exc:
            ec_seckey_tweak_mul(seckey, tweak_null)  # this raises
        self.assertEqual(str(exc.exception), "invalid arguments")

    # ec_pubkey_tweak_add, ec_seckey_tweak_add, xonly_pubkey_tweak_add,
    # keypair_xonly_tweak_add do NOT raise for NULL tweak
    def test_pubkey_add_null_tweak(self):
        tweak_null = 32 * b"\x00"
        with self.assertRaises(Libsecp256k1Exception):
            ec_seckey_verify(tweak_null)  # this means tweak is invalid
        seckey = valid_seckeys[0]
        self.assertIsNone(ec_seckey_verify(seckey))  # this means seckey is valid
        raw_pubkey = ec_pubkey_create(seckey)
        res = ec_pubkey_tweak_add(raw_pubkey, tweak_null)  # this should raise but won't
        self.assertEqual(res.raw, raw_pubkey.raw)  # instead pubkey is untweaked

    def test_seckey_add_null_tweak(self):
        tweak_null = 32 * b"\x00"
        with self.assertRaises(Libsecp256k1Exception):
            ec_seckey_verify(tweak_null)  # this means tweak is invalid
        seckey = valid_seckeys[0]
        self.assertIsNone(ec_seckey_verify(seckey))  # this means seckey is valid
        res = ec_seckey_tweak_add(seckey, tweak_null)  # this should raise but won't
        self.assertEqual(res, seckey)  # instead seckey is untweaked

    def test_tagged_sha256(self):
        msg = b"moremoremoremore"
        tag = b"TapLeaf"
        res = tagged_sha256(tag, msg)
        res0 = hashlib.sha256((hashlib.sha256(tag).digest() * 2) + msg).digest()
        self.assertEqual(res, res0)
