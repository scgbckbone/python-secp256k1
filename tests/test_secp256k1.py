import ctypes
import unittest
import hashlib
from pysecp256k1 import (
    ec_seckey_verify, ec_pubkey_create, secp256k1_pubkey, ec_pubkey_serialize,
    ec_pubkey_parse, ec_seckey_negate, ec_pubkey_negate, ec_seckey_tweak_add,
    ec_pubkey_tweak_add, ec_pubkey_combine, ecdsa_verify, ecdsa_sign,
    ecdsa_signature_serialize_der, ecdsa_signature_parse_der, ecdsa_signature_normalize
)


class TestPysecp256k1Base(unittest.TestCase):
    invalid_seckeys = [
            b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xba\xae\xdc\xe6\xafH\xa0;\xbf\xd2^\x8c\xd06AA',  # curve order
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
        for seckey in self.invalid_seckeys:
            with self.assertRaises(ValueError):
                ec_seckey_verify(seckey)

        # VALID KEY
        for seckey in self.valid_seckeys:
            assert ec_seckey_verify(seckey) is None

    def test_ec_pubkey_create(self):
        for seckey in self.invalid_seckeys:
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
            with self.assertRaises(ValueError) as exc:
                # invalid seckey
                ec_seckey_tweak_add(seckey, valid_tweak)
            self.assertEqual(
                str(exc.exception),
                "Invalid arguments or invalid resulting key"
            )
            with self.assertRaises(ValueError) as exc:
                # invalid tweak
                ec_seckey_tweak_add(valid_tweak, seckey)
            self.assertEqual(
                str(exc.exception),
                "Invalid arguments or invalid resulting key"
            )
        for seckey in self.invalid_seckeys[2:]:
            with self.assertRaises(ValueError) as exc:
                # invalid seckey
                ec_seckey_tweak_add(seckey, valid_tweak)
            self.assertEqual(str(exc.exception), "secret data must be 32 bytes")
            with self.assertRaises(ValueError) as exc:
                # invalid tweak
                ec_seckey_tweak_add(valid_tweak, seckey)
            self.assertEqual(str(exc.exception), "tweak data must be 32 bytes")

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
        for seckey in self.invalid_seckeys[2:]:
            with self.assertRaises(ValueError):
                ec_pubkey_tweak_add(raw_pubkey, seckey)

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
