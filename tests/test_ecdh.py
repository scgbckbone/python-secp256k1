import unittest
from tests import valid_seckeys
from pysecp256k1 import ec_pubkey_create
from pysecp256k1.ecdh import ecdh


class TestPysecp256k1ECDH(unittest.TestCase):
    def test_ecdh(self):
        alice_seckey = valid_seckeys[0]
        bob_seckey = valid_seckeys[1]
        alice_pubkey = ec_pubkey_create(alice_seckey)
        bob_pubkey = ec_pubkey_create(bob_seckey)
        shared_key0 = ecdh(alice_seckey, bob_pubkey)
        shared_key1 = ecdh(bob_seckey, alice_pubkey)
        self.assertEqual(shared_key0, shared_key1)
