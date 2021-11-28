import os
import ctypes
import unittest
import hashlib
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
    keypair_create, keypair_pub, keypair_sec, xonly_pubkey_parse,
    xonly_pubkey_serialize, xonly_pubkey_from_pubkey, xonly_pubkey_cmp,
    keypair_xonly_pub, keypair_xonly_tweak_add, xonly_pubkey_tweak_add,
    xonly_pubkey_tweak_add_check,

)
from pysecp256k1.schnorrsig import schnorrsig_sign, schnorrsig_verify, schnorrsig_sign_custom
from pysecp256k1.ecdh import ecdh
from pysecp256k1.recovery import (
    ecdsa_recover, ecdsa_sign_recoverable, ecdsa_recoverable_signature_convert,
    ecdsa_recoverable_signature_parse_compact,
    ecdsa_recoverable_signature_serialize_compact,
)


class TestPysecp256k1Base(unittest.TestCase):
    invalid_seckeys = [
            b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xba\xae\xdc\xe6\xafH\xa0;\xbf\xd2^\x8c\xd06AA",  # curve order
            b"\x00" * 32,  # null
            b"\x00" * 33,  # too long
            b"\x00" * 31,  # too short

        ]
    valid_seckeys = [
            b'\x1e\xfa\x14\xd7*\xdd\x84Me\xf6^p\xcek\xc0\xab\x1d\x07\xb5\xaa\xd9L\x01:\x91SS\x8dS\x0b\x1f\x87',
            b'\x97\xe0{\xd6\x7f\xe1\xc52(5\x81\xc9\xfeg_\x8d\x1b0\xecwv\x9a\xf5\xfd\xae\t\xf0y\xdc\x19Z\xde',
            b"\xd4\x8c\x88Q/\x15\xc6(\xc6\x11\xaeU\xd0\xb5`\x9b\xcfcZ1'\xec\x83S\x08\x82\x9c:\xce2\xdc\x81",
        ]
    serialized_pubkeys_compressed = [
        b'\x03Bs\x01a\xce>\x8b\x9dzw\x7fK\x0f\x0cp\x1f5\x7f\xe5<\xbf\xa6p\xbc\xaf\n\xdb\xc4}}\xf7E',
        b'\x02\x1bY\xc0\xea\xa56Z\r\xbf\x1f8\xff\xc1\x1c\xb1\x9c1\xbe\x9a"\x92\xbd\xcb~\x8f\xb4-\xa3*[\x1e\x93',
        b'\x02\xf0\x08\xb4\xe5\xad\xe1#n\x97\xdc]=\x81\xea\xb7\xbe\x85S\xce\x88\xc5\x08\x1c\xba|\xe8\x11C\xd3\x05\x80)',
    ]
    serialized_pubkeys = [
        b'\x04Bs\x01a\xce>\x8b\x9dzw\x7fK\x0f\x0cp\x1f5\x7f\xe5<\xbf\xa6p\xbc\xaf\n\xdb\xc4}}\xf7Eq9n\x990\x14|\xa4j\xb5v\x81\x18w\xf0\xf1\xa3\xdd\xac\xf2\xf6F\x18$S$\xa2\xcf}l \x8f',
        b'\x04\x1bY\xc0\xea\xa56Z\r\xbf\x1f8\xff\xc1\x1c\xb1\x9c1\xbe\x9a"\x92\xbd\xcb~\x8f\xb4-\xa3*[\x1e\x93Ry,/\x94]\x0f\xb5\xbc~\xd8\xb2\xfa`i\xe6\xc7\x042\xaa\x16\xd1G\x17GL(\xae\xd2\xdd&\xd8',
        b"\x04\xf0\x08\xb4\xe5\xad\xe1#n\x97\xdc]=\x81\xea\xb7\xbe\x85S\xce\x88\xc5\x08\x1c\xba|\xe8\x11C\xd3\x05\x80)'\xaa\xecy\x7f\xcdaH\xea\xe1\xff*\xcf\xc0\x01_\xdc\x0f|\x11\x0e,R\x9c\x17\xa5b\xb90&/\x8e",
    ]

    def test_ec_seckey_verify(self):
        # INVALID KEY
        for seckey in self.invalid_seckeys[:2]:
            with self.assertRaises(Libsecp256k1Exception):
                ec_seckey_verify(seckey)

        for seckey in self.invalid_seckeys[2:]:
            with self.assertRaises(ValueError):
                ec_seckey_verify(seckey)

        # VALID KEY
        for seckey in self.valid_seckeys:
            assert ec_seckey_verify(seckey) is None

    def test_ec_pubkey_create(self):
        for seckey in self.invalid_seckeys[:2]:
            with self.assertRaises(Libsecp256k1Exception):
                ec_pubkey_create(seckey)

        for seckey in self.invalid_seckeys[2:]:
            with self.assertRaises(ValueError):
                ec_pubkey_create(seckey)

        for seckey in self.valid_seckeys:
            raw_pubkey = ec_pubkey_create(seckey)
            self.assertIsInstance(raw_pubkey, secp256k1_pubkey)
            self.assertEqual(len(raw_pubkey), 64)

    def test_ec_pubkey_serialize(self):
        # invalid length
        for n in (63, 65):
            with self.assertRaises(ValueError):
                ec_pubkey_serialize(ctypes.create_string_buffer(n))
        # compressed
        for seckey, ser_pub in zip(self.valid_seckeys, self.serialized_pubkeys_compressed):
            self.assertEqual(ec_pubkey_serialize(ec_pubkey_create(seckey)), ser_pub)
        # uncompressed
        for seckey, ser_pub in zip(self.valid_seckeys, self.serialized_pubkeys):
            self.assertEqual(ec_pubkey_serialize(ec_pubkey_create(seckey), compressed=False), ser_pub)

    def test_ec_pubkey_parse(self):
        # invalid
        # TODO add more invalid tests from original repo (tests.c -> run_ec_pubkey_parse_test)
        with self.assertRaises(ValueError):
            invalid_pubkey = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00BR\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00d\xef\xa1{wa\xe1\xe4'\x06\x98\x9f\xb4\x83\xb8\xd2\xd4\x9b\xf7\x8f\xae\x98\x03\xf0\x99\xb84\xed\xeb\x00"
            ec_pubkey_parse(invalid_pubkey)
        # compressed
        for ser_pub, seckey in zip(self.serialized_pubkeys_compressed, self.valid_seckeys):
            self.assertEqual(ec_pubkey_parse(ser_pub).raw, ec_pubkey_create(seckey).raw)

        # uncompressed
        for ser_pub, seckey in zip(self.serialized_pubkeys, self.valid_seckeys):
            self.assertEqual(ec_pubkey_parse(ser_pub).raw, ec_pubkey_create(seckey).raw)

    def test_ec_seckey_negate(self):
        for seckey in self.valid_seckeys:
            self.assertEqual(seckey, ec_seckey_negate(ec_seckey_negate(seckey)))

    def test_ec_pubkey_negate(self):
        for seckey in self.valid_seckeys:
            raw_pubkey = ec_pubkey_create(seckey)
            self.assertEqual(
                raw_pubkey.raw,
                ec_pubkey_negate(ec_pubkey_negate(raw_pubkey)).raw
            )

    def test_ec_seckey_tweak_add(self):
        valid_tweak = self.valid_seckeys[0]
        for seckey in self.invalid_seckeys[:1]:  # TODO github issue - ignoring zero tweak for now
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
        for seckey in self.invalid_seckeys[2:]:
            with self.assertRaises(ValueError) as exc:
                # invalid seckey
                ec_seckey_tweak_add(seckey, valid_tweak)
            self.assertEqual(str(exc.exception), "'seckey' must be exactly 32 bytes")
            with self.assertRaises(ValueError) as exc:
                # invalid tweak
                ec_seckey_tweak_add(valid_tweak, seckey)
            self.assertEqual(str(exc.exception), "'tweak32' must be exactly 32 bytes")

        for seckey in self.valid_seckeys:
            # TODO shouldn't this fail as we tweak with itself?
            ec_seckey_tweak_add(seckey, valid_tweak)

        x, y, z = self.valid_seckeys
        xy = ec_seckey_tweak_add(x, y)
        yx = ec_seckey_tweak_add(y, x)
        yz = ec_seckey_tweak_add(y, z)
        xyz = ec_seckey_tweak_add(x, ec_seckey_tweak_add(y, z))
        yzx = ec_seckey_tweak_add(yz, x)
        self.assertEqual(xyz, yzx)

        self.assertEqual(xy, yx)

    def test_ec_pubkey_tweak_add(self):
        valid_seckey = self.valid_seckeys[0]
        raw_pubkey = ec_pubkey_create(valid_seckey)
        # null tweak and curve order
        # TODO null triggers illegal callback
        for seckey in self.invalid_seckeys[:1]:
            with self.assertRaises(Libsecp256k1Exception) as exc:
                ec_pubkey_tweak_add(raw_pubkey, tweak32=seckey)
            self.assertEqual(
                str(exc.exception),
                "arguments are invalid or the resulting public key would be invalid"
                " (only when the tweak is the negation of the corresponding secret key)"
            )
        # invalid tweak length
        for seckey in self.invalid_seckeys[2:]:
            with self.assertRaises(ValueError) as exc:
                ec_pubkey_tweak_add(raw_pubkey, tweak32=seckey)
            self.assertEqual(
                str(exc.exception),
                "'tweak32' must be exactly 32 bytes"
            )

        # compressed
        tweak = self.valid_seckeys[2]
        sx, sy = self.valid_seckeys[:2]
        raw_px, raw_py = (
            ec_pubkey_parse(pk)
            for pk in self.serialized_pubkeys_compressed[:2]
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
        parsed_pubkeys = [ec_pubkey_parse(pk) for pk in self.serialized_pubkeys_compressed]
        with self.assertRaises(ValueError):
            ec_pubkey_combine([parsed_pubkeys[0]])
        with self.assertRaises(ValueError):
            ec_pubkey_combine(parsed_pubkeys + [1])

        x, y, z = self.valid_seckeys
        xy = ec_seckey_tweak_add(x, y)
        xyz = ec_seckey_tweak_add(x, ec_seckey_tweak_add(y, z))

        xy_pub = ec_pubkey_combine(parsed_pubkeys[:2])
        self.assertEqual(xy_pub.raw, ec_pubkey_create(xy).raw)
        xyz_pub = ec_pubkey_combine(parsed_pubkeys)
        self.assertEqual(xyz_pub.raw, ec_pubkey_create(xyz).raw)

    def test_ecdsa_sign(self):
        for seckey in self.valid_seckeys:
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
        for seckey in self.valid_seckeys:
            msg = hashlib.sha256(seckey).digest()
            raw_sig = ecdsa_sign(seckey, msg)
            raw_sig = ecdsa_signature_normalize(raw_sig)
            ser_sig = ecdsa_signature_serialize_der(raw_sig)
            parsed_sig = ecdsa_signature_parse_der(ser_sig)
            self.assertEqual(raw_sig.raw, parsed_sig.raw)

    def test_extrakeys(self):
        #TODO create own module
        #and split the tests
        for seckey in self.invalid_seckeys[:2]:
            with self.assertRaises(Libsecp256k1Exception) as exc:
                keypair_create(seckey)
            self.assertEqual(
                str(exc.exception),
                "secret key is invalid"
            )
        for seckey in self.invalid_seckeys[2:]:
            with self.assertRaises(ValueError) as exc:
                keypair_create(seckey)
            self.assertEqual(
                str(exc.exception),
                "'seckey' must be exactly 32 bytes"
            )
        for seckey in self.valid_seckeys:
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

            valid_tweak = hashlib.sha256(self.valid_seckeys[0]).digest()
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
            tweaked_seckey = ec_seckey_tweak_add(seckey, valid_tweak)

            # shouldn't below work ? it does not... meh
            #assert tweaked_seckey == keypair_sec(tweaked_keypair)

    def test_schnorrsig(self):
        # TODO own module
        for seckey in self.valid_seckeys:
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

    def test_tweak_mul(self):
        # TODO invalid csaes
        for seckey in self.valid_seckeys:
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
        seckey = self.valid_seckeys[0]
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
        seckey = self.valid_seckeys[0]
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
        seckey = self.valid_seckeys[0]
        assert ec_seckey_verify(seckey) is None  # this means seckey is valid
        raw_pubkey = ec_pubkey_create(seckey)
        res = ec_pubkey_tweak_add(raw_pubkey, tweak_null)  # this should raise but won't
        assert res.raw == raw_pubkey.raw  # instead pubkey is untweaked

    def test_seckey_add_null_tweak(self):
        tweak_null = 32 * b"\x00"
        with self.assertRaises(Libsecp256k1Exception):
            ec_seckey_verify(tweak_null)  # this means tweak is invalid
        seckey = self.valid_seckeys[0]
        assert ec_seckey_verify(seckey) is None  # this means seckey is valid
        res = ec_seckey_tweak_add(seckey, tweak_null)  # this should raise but won't
        assert res == seckey  # instead seckey is untweaked

    def test_xonly_pubkey_add_null_tweak(self):
        tweak_null = 32 * b"\x00"
        with self.assertRaises(Libsecp256k1Exception):
            ec_seckey_verify(tweak_null)  # this means tweak is invalid
        seckey = self.valid_seckeys[0]
        assert ec_seckey_verify(seckey) is None  # this means seckey is valid
        raw_pubkey = ec_pubkey_create(seckey)
        xonly_pubkey, parity = xonly_pubkey_from_pubkey(raw_pubkey)
        res = xonly_pubkey_tweak_add(xonly_pubkey, tweak_null)  # this should raise but won't
        assert res.raw == xonly_pubkey.raw  # instead xonly pubkey is untweaked

    def test_keypair_xonly_add_null_tweak(self):
        tweak_null = 32 * b"\x00"
        with self.assertRaises(Libsecp256k1Exception):
            ec_seckey_verify(tweak_null)  # this means tweak is invalid
        seckey = self.valid_seckeys[0]
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
        for seckey in self.valid_seckeys:
            msg = hashlib.sha256(seckey).digest()
            raw_sig = ecdsa_sign(seckey, msg)
            raw_sig = ecdsa_signature_normalize(raw_sig)
            compact_ser_sig = ecdsa_signature_serialize_compact(raw_sig)
            compact_parsed_sig = ecdsa_signature_parse_compact(compact_ser_sig)
            self.assertEqual(raw_sig.raw, compact_parsed_sig.raw)

    def test_ecdh(self):
        alice_seckey = self.valid_seckeys[0]
        bob_seckey = self.valid_seckeys[1]
        alice_pubkey = ec_pubkey_create(alice_seckey)
        bob_pubkey = ec_pubkey_create(bob_seckey)
        shared_key0 = ecdh(alice_seckey, bob_pubkey)
        shared_key1 = ecdh(bob_seckey, alice_pubkey)
        self.assertEqual(shared_key0, shared_key1)

    def test_recovery(self):
        msg = b"moremoremoremore"
        tag = b"TapLeaf"
        msg_hash = tagged_sha256(tag, msg)
        for seckey in self.invalid_seckeys[:2]:
            with self.assertRaises(Libsecp256k1Exception):
                ecdsa_sign_recoverable(seckey, msg_hash)
        for seckey in self.invalid_seckeys[2:]:
            with self.assertRaises(ValueError):
                ecdsa_sign_recoverable(seckey, msg_hash)
        for seckey in self.valid_seckeys:
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


