import hashlib
import unittest

from tests.data import valid_seckeys, valid_compact_sig_serializations
from pysecp256k1 import (
    ec_pubkey_create,
    ec_pubkey_negate,
    ec_pubkey_tweak_add,
    ec_pubkey_tweak_mul,
    ec_pubkey_combine,
    ec_pubkey_sort,
    ecdsa_sign,
    ecdsa_signature_normalize,
    ecdsa_signature_parse_compact,
)
from pysecp256k1.low_level import has_secp256k1_extrakeys

if has_secp256k1_extrakeys:
    from pysecp256k1.extrakeys import (
        keypair_create,
        keypair_xonly_pub,
        keypair_xonly_tweak_add,
        xonly_pubkey_from_pubkey,
        xonly_pubkey_tweak_add,
    )


N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141


class TestPubkeyOpsDoNotMutate(unittest.TestCase):

    def test_ec_pubkey_negate(self):
        for seckey in valid_seckeys:
            pubkey = ec_pubkey_create(seckey)
            original = pubkey.raw
            negated = ec_pubkey_negate(pubkey)
            self.assertIsNot(negated, pubkey)
            self.assertEqual(pubkey.raw, original)
            self.assertNotEqual(negated.raw, original)
            # double negate gives back the original content (and still a fresh object)
            negated_twice = ec_pubkey_negate(negated)
            self.assertIsNot(negated_twice, negated)
            self.assertEqual(negated_twice.raw, original)

    def test_ec_pubkey_tweak_add(self):
        tweak = valid_seckeys[2]
        for seckey in valid_seckeys[:3]:
            pubkey = ec_pubkey_create(seckey)
            original = pubkey.raw
            tweaked = ec_pubkey_tweak_add(pubkey, tweak)
            self.assertIsNot(tweaked, pubkey)
            self.assertEqual(pubkey.raw, original)
            self.assertNotEqual(tweaked.raw, original)

    def test_ec_pubkey_tweak_mul(self):
        tweak = valid_seckeys[2]
        for seckey in valid_seckeys[:3]:
            pubkey = ec_pubkey_create(seckey)
            original = pubkey.raw
            tweaked = ec_pubkey_tweak_mul(pubkey, tweak)
            self.assertIsNot(tweaked, pubkey)
            self.assertEqual(pubkey.raw, original)
            self.assertNotEqual(tweaked.raw, original)


class TestSignatureNormalizeDoesNotMutate(unittest.TestCase):

    def test_low_s_input_no_op_returns_distinct_buffer(self):
        # secp256k1 produces low-S signatures, so normalize is a no-op for
        # content -- but it must still return a distinct buffer.
        seckey = valid_seckeys[0]
        sig = ecdsa_sign(seckey, hashlib.sha256(seckey).digest())
        original = sig.raw
        normalized = ecdsa_signature_normalize(sig)
        self.assertIsNot(normalized, sig)
        self.assertEqual(sig.raw, original)
        self.assertEqual(normalized.raw, original)  # no-op for content

    def test_high_s_input_normalizes_into_distinct_buffer(self):
        # Force the actually-mutating branch by constructing a high-S form
        # of a known low-S signature: high_s_sig = (R, N - S).
        compact_low_s = valid_compact_sig_serializations[0]
        r, s_low_bytes = compact_low_s[:32], compact_low_s[32:]
        s_low = int.from_bytes(s_low_bytes, "big")
        s_high = (N - s_low).to_bytes(32, "big")
        high_s_sig = ecdsa_signature_parse_compact(r + s_high)
        original = high_s_sig.raw

        normalized = ecdsa_signature_normalize(high_s_sig)
        self.assertIsNot(normalized, high_s_sig)
        self.assertEqual(high_s_sig.raw, original)              # input preserved
        self.assertNotEqual(normalized.raw, original)           # output mutated
        # normalizing the result is a no-op (already canonical)
        self.assertEqual(ecdsa_signature_normalize(normalized).raw, normalized.raw)


class TestPubkeyCombineDoesNotMutate(unittest.TestCase):

    def test_inputs_unchanged_after_combine(self):
        pubkeys = [ec_pubkey_create(sk) for sk in valid_seckeys[:3]]
        snapshots = [pk.raw for pk in pubkeys]
        combined = ec_pubkey_combine(pubkeys)
        # combined is a fresh buffer
        for pk in pubkeys:
            self.assertIsNot(combined, pk)
        # every input still has its original content
        for pk, snap in zip(pubkeys, snapshots):
            self.assertEqual(pk.raw, snap)
        # combined isn't accidentally one of the inputs
        for snap in snapshots:
            self.assertNotEqual(combined.raw, snap)


class TestPubkeySortDoesNotMutateMembers(unittest.TestCase):

    def test_input_list_and_members_unchanged(self):
        pubkeys = [ec_pubkey_create(sk) for sk in valid_seckeys[:5]]
        list_id = id(pubkeys)
        member_ids = [id(pk) for pk in pubkeys]
        snapshots = [pk.raw for pk in pubkeys]

        sorted_pks = ec_pubkey_sort(pubkeys)

        # caller's list is not the returned one
        self.assertIsNot(sorted_pks, pubkeys)
        self.assertEqual(id(pubkeys), list_id)
        # caller's list still holds the same Python objects in the same order
        self.assertEqual([id(pk) for pk in pubkeys], member_ids)
        # every member's bytes are unchanged
        for pk, snap in zip(pubkeys, snapshots):
            self.assertEqual(pk.raw, snap)
        # the sorted result is a permutation of the inputs (same multiset of bytes)
        self.assertEqual(
            sorted(pk.raw for pk in sorted_pks),
            sorted(snapshots),
        )


@unittest.skipUnless(
    has_secp256k1_extrakeys, "secp256k1 is not compiled with module 'extrakeys'"
)
class TestExtrakeysOpsDoNotMutate(unittest.TestCase):

    def test_keypair_xonly_tweak_add_does_not_mutate(self):
        tweak = hashlib.sha256(valid_seckeys[0]).digest()
        for seckey in valid_seckeys[:3]:
            keypair = keypair_create(seckey)
            original = keypair.raw
            tweaked = keypair_xonly_tweak_add(keypair, tweak)
            self.assertIsNot(tweaked, keypair)
            self.assertEqual(keypair.raw, original)
            self.assertNotEqual(tweaked.raw, original)

    def test_xonly_pubkey_tweak_add_does_not_mutate(self):
        tweak = hashlib.sha256(valid_seckeys[0]).digest()
        for seckey in valid_seckeys[:3]:
            pubkey = ec_pubkey_create(seckey)
            xonly_pub, _ = xonly_pubkey_from_pubkey(pubkey)
            original = xonly_pub.raw
            tweaked = xonly_pubkey_tweak_add(xonly_pub, tweak)
            self.assertIsNot(tweaked, xonly_pub)
            self.assertEqual(xonly_pub.raw, original)

    def test_xonly_pubkey_from_pubkey_does_not_mutate(self):
        # Read-only on its pubkey input. Pinned because a maintenance refactor
        # could plausibly reuse the input buffer for the xonly output.
        for seckey in valid_seckeys[:3]:
            pubkey = ec_pubkey_create(seckey)
            original = pubkey.raw
            xonly_pub, _ = xonly_pubkey_from_pubkey(pubkey)
            self.assertIsNot(xonly_pub, pubkey)
            self.assertEqual(pubkey.raw, original)

    def test_keypair_xonly_pub_does_not_mutate(self):
        # Read-only on the keypair. Same defensive pin as above.
        for seckey in valid_seckeys[:3]:
            keypair = keypair_create(seckey)
            original = keypair.raw
            xonly_pub, _ = keypair_xonly_pub(keypair)
            self.assertIsNot(xonly_pub, keypair)
            self.assertEqual(keypair.raw, original)


if __name__ == "__main__":
    unittest.main()
