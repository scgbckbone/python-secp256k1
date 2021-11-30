import ctypes
import unittest
import hashlib
from tests.data import invalid_seckeys, valid_seckeys, serialized_pubkeys_compressed, serialized_pubkeys
from pysecp256k1.low_level import Libsecp256k1Exception
from pysecp256k1.low_level.constants import secp256k1_pubkey
from pysecp256k1 import (
    ec_seckey_verify, ec_pubkey_create, ec_pubkey_serialize,
    ec_pubkey_parse, ec_seckey_negate, ec_pubkey_negate, ec_seckey_tweak_add,
    ec_pubkey_tweak_add, ec_pubkey_combine, ecdsa_verify, ecdsa_sign,
    ecdsa_signature_serialize_der, ecdsa_signature_parse_der, ecdsa_signature_normalize,
    ec_pubkey_tweak_mul, ec_seckey_tweak_mul, tagged_sha256,
    ecdsa_signature_parse_compact, ecdsa_signature_serialize_compact,
)
from pysecp256k1.extrakeys import (
    keypair_create, xonly_pubkey_from_pubkey, keypair_xonly_tweak_add,
    xonly_pubkey_tweak_add,
)


class TestPysecp256k1Base(unittest.TestCase):
    def test_ec_seckey_verify(self):
        # INVALID KEY
        for seckey in invalid_seckeys[:2]:
            with self.assertRaises(Libsecp256k1Exception):
                ec_seckey_verify(seckey)

        for seckey in invalid_seckeys[2:]:
            with self.assertRaises(ValueError):
                ec_seckey_verify(seckey)

        # VALID KEY
        for seckey in valid_seckeys:
            assert ec_seckey_verify(seckey) is None

    def test_ec_pubkey_create(self):
        for seckey in invalid_seckeys[:2]:
            with self.assertRaises(Libsecp256k1Exception):
                ec_pubkey_create(seckey)

        for seckey in invalid_seckeys[2:]:
            with self.assertRaises(ValueError):
                ec_pubkey_create(seckey)

        for seckey in valid_seckeys:
            raw_pubkey = ec_pubkey_create(seckey)
            self.assertIsInstance(raw_pubkey, secp256k1_pubkey)
            self.assertEqual(len(raw_pubkey), 64)

    def test_ec_pubkey_serialize(self):
        # invalid length
        for n in (63, 65):
            with self.assertRaises(ValueError):
                ec_pubkey_serialize(ctypes.create_string_buffer(n))
        # compressed
        for seckey, ser_pub in zip(valid_seckeys, serialized_pubkeys_compressed):
            self.assertEqual(ec_pubkey_serialize(ec_pubkey_create(seckey)), ser_pub)
        # uncompressed
        for seckey, ser_pub in zip(valid_seckeys, serialized_pubkeys):
            self.assertEqual(ec_pubkey_serialize(ec_pubkey_create(seckey), compressed=False), ser_pub)

    def test_ec_pubkey_parse(self):
        # invalid
        # TODO add more invalid tests from original repo (tests.c -> run_ec_pubkey_parse_test)
        with self.assertRaises(ValueError):
            invalid_pubkey = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00BR\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00d\xef\xa1{wa\xe1\xe4'\x06\x98\x9f\xb4\x83\xb8\xd2\xd4\x9b\xf7\x8f\xae\x98\x03\xf0\x99\xb84\xed\xeb\x00"
            ec_pubkey_parse(invalid_pubkey)
        # compressed
        for ser_pub, seckey in zip(serialized_pubkeys_compressed, valid_seckeys):
            self.assertEqual(ec_pubkey_parse(ser_pub).raw, ec_pubkey_create(seckey).raw)

        # uncompressed
        for ser_pub, seckey in zip(serialized_pubkeys, valid_seckeys):
            self.assertEqual(ec_pubkey_parse(ser_pub).raw, ec_pubkey_create(seckey).raw)

    def test_ec_seckey_negate(self):
        for seckey in valid_seckeys:
            self.assertEqual(seckey, ec_seckey_negate(ec_seckey_negate(seckey)))

    def test_ec_pubkey_negate(self):
        for seckey in valid_seckeys:
            raw_pubkey = ec_pubkey_create(seckey)
            self.assertEqual(
                raw_pubkey.raw,
                ec_pubkey_negate(ec_pubkey_negate(raw_pubkey)).raw
            )

    def test_ec_seckey_tweak_add(self):
        valid_tweak = valid_seckeys[0]
        for seckey in invalid_seckeys[:1]:  # TODO github issue - ignoring zero tweak for now
            with self.assertRaises(Libsecp256k1Exception) as exc:
                # invalid seckey
                ec_seckey_tweak_add(seckey, valid_tweak)
            self.assertEqual(
                str(exc.exception),
                "arguments are invalid or the resulting secret key would be invalid"
                " (only when the tweak is the negation of the secret key)"
            )
            with self.assertRaises(Libsecp256k1Exception) as exc:
                # invalid tweak
                ec_seckey_tweak_add(valid_tweak, seckey)
            self.assertEqual(
                str(exc.exception),
                "arguments are invalid or the resulting secret key would be invalid"
                " (only when the tweak is the negation of the secret key)"
            )
        for seckey in invalid_seckeys[2:]:
            with self.assertRaises(ValueError) as exc:
                # invalid seckey
                ec_seckey_tweak_add(seckey, valid_tweak)
            self.assertEqual(str(exc.exception), "'seckey' must be exactly 32 bytes")
            with self.assertRaises(ValueError) as exc:
                # invalid tweak
                ec_seckey_tweak_add(valid_tweak, seckey)
            self.assertEqual(str(exc.exception), "'tweak32' must be exactly 32 bytes")

        for seckey in valid_seckeys:
            # TODO shouldn't this fail as we tweak with itself?
            ec_seckey_tweak_add(seckey, valid_tweak)

        x, y, z = valid_seckeys
        xy = ec_seckey_tweak_add(x, y)
        yx = ec_seckey_tweak_add(y, x)
        yz = ec_seckey_tweak_add(y, z)
        xyz = ec_seckey_tweak_add(x, ec_seckey_tweak_add(y, z))
        yzx = ec_seckey_tweak_add(yz, x)
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
                " (only when the tweak is the negation of the corresponding secret key)"
            )
        # invalid tweak length
        for seckey in invalid_seckeys[2:]:
            with self.assertRaises(ValueError) as exc:
                ec_pubkey_tweak_add(raw_pubkey, tweak32=seckey)
            self.assertEqual(
                str(exc.exception),
                "'tweak32' must be exactly 32 bytes"
            )

        # compressed
        tweak = valid_seckeys[2]
        sx, sy = valid_seckeys[:2]
        raw_px, raw_py = (
            ec_pubkey_parse(pk)
            for pk in serialized_pubkeys_compressed[:2]
        )
        sxt = ec_seckey_tweak_add(sx, tweak)
        sxt_p = ec_pubkey_create(sxt)
        syt = ec_seckey_tweak_add(sy, tweak)
        syt_p = ec_pubkey_create(syt)

        pxt = ec_pubkey_tweak_add(raw_px, tweak)
        pyt = ec_pubkey_tweak_add(raw_py, tweak)
        self.assertEqual(sxt_p.raw, pxt.raw)
        self.assertEqual(syt_p.raw, pyt.raw)

    def test_ec_pubkey_combine(self):
        parsed_pubkeys = [ec_pubkey_parse(pk) for pk in serialized_pubkeys_compressed]
        with self.assertRaises(ValueError):
            ec_pubkey_combine([parsed_pubkeys[0]])
        with self.assertRaises(ValueError):
            ec_pubkey_combine(parsed_pubkeys + [1])

        x, y, z = valid_seckeys
        xy = ec_seckey_tweak_add(x, y)
        xyz = ec_seckey_tweak_add(x, ec_seckey_tweak_add(y, z))

        xy_pub = ec_pubkey_combine(parsed_pubkeys[:2])
        self.assertEqual(xy_pub.raw, ec_pubkey_create(xy).raw)
        xyz_pub = ec_pubkey_combine(parsed_pubkeys)
        self.assertEqual(xyz_pub.raw, ec_pubkey_create(xyz).raw)

    def test_ecdsa_sign(self):
        for seckey in valid_seckeys:
            msg = hashlib.sha256(seckey).digest()
            raw_sig = ecdsa_sign(seckey, msg)
            raw_sig = ecdsa_signature_normalize(raw_sig)
            raw_pub = ec_pubkey_create(seckey)
            self.assertTrue(ecdsa_verify(raw_sig, raw_pub, msg))

    def test_ecdsa_verify(self):
        pass

    def ecdsa_signature_parse_der(self):
        pass

    def test_ecdsa_signature_serialize_der(self):
        for seckey in valid_seckeys:
            msg = hashlib.sha256(seckey).digest()
            raw_sig = ecdsa_sign(seckey, msg)
            raw_sig = ecdsa_signature_normalize(raw_sig)
            ser_sig = ecdsa_signature_serialize_der(raw_sig)
            parsed_sig = ecdsa_signature_parse_der(ser_sig)
            self.assertEqual(raw_sig.raw, parsed_sig.raw)

    def test_tweak_mul(self):
        # TODO invalid csaes
        for seckey in valid_seckeys:
            tweak = hashlib.sha256(seckey).digest()
            assert ec_seckey_verify(tweak) is None
            raw_pubkey = ec_pubkey_create(seckey)
            tweaked_pk0 = ec_pubkey_tweak_mul(raw_pubkey, tweak)
            tweaked_sk = ec_seckey_tweak_mul(seckey, tweak)
            tweaked_pk1 = ec_pubkey_create(tweaked_sk)
            self.assertEqual(tweaked_pk0.raw, tweaked_pk1.raw)

    # ec_pubkey_tweak_mul and ec_seckey_tweak_mul do raise for NULL tweak
    def test_pubkey_mul_null_tweak(self):
        tweak_null = 32 * b"\x00"
        with self.assertRaises(Libsecp256k1Exception):
            ec_seckey_verify(tweak_null)  # this means tweak is invalid
        seckey = valid_seckeys[0]
        assert ec_seckey_verify(seckey) is None  # this means seckey is valid
        raw_pubkey = ec_pubkey_create(seckey)
        with self.assertRaises(Libsecp256k1Exception) as exc:
            ec_pubkey_tweak_mul(raw_pubkey, tweak_null)  # this raises
        self.assertEqual(
            str(exc.exception),
            "invalid arguments"
        )

    def test_seckey_mul_null_tweak(self):
        tweak_null = 32 * b"\x00"
        with self.assertRaises(Libsecp256k1Exception):
            ec_seckey_verify(tweak_null)  # this means tweak is invalid
        seckey = valid_seckeys[0]
        assert ec_seckey_verify(seckey) is None  # this means seckey is valid
        with self.assertRaises(Libsecp256k1Exception) as exc:
            ec_seckey_tweak_mul(seckey, tweak_null)  # this raises
        self.assertEqual(
            str(exc.exception),
            "invalid arguments"
        )

    # ec_pubkey_tweak_add, ec_seckey_tweak_add, xonly_pubkey_tweak_add,
    # keypair_xonly_tweak_add do NOT raise for NULL tweak
    def test_pubkey_add_null_tweak(self):
        tweak_null = 32 * b"\x00"
        with self.assertRaises(Libsecp256k1Exception):
            ec_seckey_verify(tweak_null)  # this means tweak is invalid
        seckey = valid_seckeys[0]
        assert ec_seckey_verify(seckey) is None  # this means seckey is valid
        raw_pubkey = ec_pubkey_create(seckey)
        res = ec_pubkey_tweak_add(raw_pubkey, tweak_null)  # this should raise but won't
        assert res.raw == raw_pubkey.raw  # instead pubkey is untweaked

    def test_seckey_add_null_tweak(self):
        tweak_null = 32 * b"\x00"
        with self.assertRaises(Libsecp256k1Exception):
            ec_seckey_verify(tweak_null)  # this means tweak is invalid
        seckey = valid_seckeys[0]
        assert ec_seckey_verify(seckey) is None  # this means seckey is valid
        res = ec_seckey_tweak_add(seckey, tweak_null)  # this should raise but won't
        assert res == seckey  # instead seckey is untweaked

    def test_xonly_pubkey_add_null_tweak(self):
        tweak_null = 32 * b"\x00"
        with self.assertRaises(Libsecp256k1Exception):
            ec_seckey_verify(tweak_null)  # this means tweak is invalid
        seckey = valid_seckeys[0]
        assert ec_seckey_verify(seckey) is None  # this means seckey is valid
        raw_pubkey = ec_pubkey_create(seckey)
        xonly_pubkey, parity = xonly_pubkey_from_pubkey(raw_pubkey)
        res = xonly_pubkey_tweak_add(xonly_pubkey, tweak_null)  # this should raise but won't
        assert res.raw == xonly_pubkey.raw  # instead xonly pubkey is untweaked

    def test_keypair_xonly_add_null_tweak(self):
        tweak_null = 32 * b"\x00"
        with self.assertRaises(Libsecp256k1Exception):
            ec_seckey_verify(tweak_null)  # this means tweak is invalid
        seckey = valid_seckeys[0]
        assert ec_seckey_verify(seckey) is None  # this means seckey is valid
        keypair = keypair_create(seckey)
        res = keypair_xonly_tweak_add(keypair, tweak_null)  # this should raise but won't
        assert res.raw == keypair.raw  # instead keypair is untweaked

    def test_tagged_sha256(self):
        msg = b"moremoremoremore"
        tag = b"TapLeaf"
        res = tagged_sha256(tag, msg)
        res0 = hashlib.sha256((hashlib.sha256(tag).digest() * 2) + msg).digest()
        assert res == res0

    def test_ecdsa_compact_sig(self):
        for seckey in valid_seckeys:
            msg = hashlib.sha256(seckey).digest()
            raw_sig = ecdsa_sign(seckey, msg)
            raw_sig = ecdsa_signature_normalize(raw_sig)
            compact_ser_sig = ecdsa_signature_serialize_compact(raw_sig)
            compact_parsed_sig = ecdsa_signature_parse_compact(compact_ser_sig)
            self.assertEqual(raw_sig.raw, compact_parsed_sig.raw)



