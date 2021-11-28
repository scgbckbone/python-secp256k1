import os
import unittest
import hashlib
from tests import valid_seckeys
from pysecp256k1.extrakeys import keypair_create, keypair_xonly_pub
from pysecp256k1.schnorrsig import (
    schnorrsig_sign,
    schnorrsig_sign_custom,
    schnorrsig_verify,
)


class TestPysecp256k1Schnorrsig(unittest.TestCase):
    def test_schnorrsig(self):
        # TODO own module
        for seckey in valid_seckeys:
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
