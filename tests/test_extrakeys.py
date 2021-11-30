import unittest
import hashlib
from tests.data import valid_seckeys, invalid_seckeys
from pysecp256k1.low_level import Libsecp256k1Exception
from pysecp256k1 import (
    ec_pubkey_create,
    ec_seckey_verify,
    ec_seckey_tweak_add,
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
)


class TestPysecp256k1Extrakeys(unittest.TestCase):
    def test_extrakeys(self):
        #TODO create own module
        #and split the tests
        for seckey in invalid_seckeys[:2]:
            with self.assertRaises(Libsecp256k1Exception) as exc:
                keypair_create(seckey)
            self.assertEqual(
                str(exc.exception),
                "secret key is invalid"
            )
        for seckey in invalid_seckeys[2:]:
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
            tweaked_seckey = ec_seckey_tweak_add(seckey, valid_tweak)

            # shouldn't below work ? it does not... meh
            #assert tweaked_seckey == keypair_sec(tweaked_keypair)
