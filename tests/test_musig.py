import unittest, os
from pysecp256k1.low_level import Libsecp256k1Exception, has_secp256k1_musig
from pysecp256k1.low_level.constants import MuSigSession, MuSigPartialSig, MuSigKeyAggCache
from pysecp256k1 import ec_pubkey_create, ec_seckey_verify, ec_pubkey_sort, ec_seckey_negate
from pysecp256k1.extrakeys import keypair_create, xonly_pubkey_from_pubkey, keypair_pub, keypair_sec
from pysecp256k1.schnorrsig import schnorrsig_verify
from tests.data import (invalid_musig_nonce_ser_length, not_bytes, invalid_musig_nonce_length,
                        not_c_char_array, invalid_seckey_length, invalid_musig_part_sig_length,
                        invalid_musig_keyagg_cache_lenght, valid_seckeys, invalid_pubkey_length,
                        valid_pubnonce_serializations, invalid_keypair_length,
                        invalid_musig_session_length, invalid_seckeys)
if has_secp256k1_musig:
    from pysecp256k1.musig import (musig_pubnonce_parse, musig_pubnonce_serialize, musig_aggnonce_parse,
                                   musig_aggnonce_serialize, musig_partial_sig_parse,
                                   musig_partial_sig_serialize, musig_pubkey_agg, musig_pubkey_get,
                                   musig_pubkey_ec_tweak_add, musig_pubkey_xonly_tweak_add,
                                   musig_nonce_gen, musig_nonce_agg, musig_nonce_process,
                                   musig_partial_sign, musig_partial_sig_verify, musig_partial_sig_agg)


skip_reason = "secp256k1 is not compiled with module 'musig'"


@unittest.skipUnless(has_secp256k1_musig, skip_reason)
class TestPysecp256k1MusigValidation(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.b32 = valid_seckeys[1]
        cls.keyagg_cache = MuSigKeyAggCache()
        cls.keypair = keypair_create(valid_seckeys[0])
        cls.pubkey0 = ec_pubkey_create(valid_seckeys[0])
        cls.pubkey1 = ec_pubkey_create(valid_seckeys[1])
        cls.pubnonce0 = musig_pubnonce_parse(valid_pubnonce_serializations[0])
        cls.pubnonce1 = musig_pubnonce_parse(valid_pubnonce_serializations[1])
        cls.aggnonce = musig_nonce_agg([cls.pubnonce0, cls.pubnonce1])
        cls.session = MuSigSession()
        cls.part_sig0 = MuSigPartialSig()
        cls.part_sig1 = MuSigPartialSig()

    def test_musig_pubnonce_parse_invalid_input_type_pubnonce66(self):
        for invalid_nonce_ser in invalid_musig_nonce_ser_length:
            with self.assertRaises(AssertionError):
                musig_pubnonce_parse(invalid_nonce_ser)

        for invalid_type in not_bytes:
            with self.assertRaises(AssertionError):
                musig_pubnonce_parse(invalid_type)

    def test_musig_pubnonce_serialize_invalid_input_type_pubnonce(self):
        for invalid_nonce in invalid_musig_nonce_length:
            with self.assertRaises(AssertionError):
                musig_pubnonce_serialize(invalid_nonce)

        for invalid_type in not_c_char_array:
            with self.assertRaises(AssertionError):
                musig_pubnonce_serialize(invalid_type)

    def test_musig_aggnonce_parse_invalid_input_type_aggnonce66(self):
        for invalid_nonce_ser in invalid_musig_nonce_ser_length:
            with self.assertRaises(AssertionError):
                musig_aggnonce_parse(invalid_nonce_ser)

        for invalid_type in not_bytes:
            with self.assertRaises(AssertionError):
                musig_aggnonce_parse(invalid_type)

    def test_musig_aggnonce_serialize_invalid_input_type_aggnonce(self):
        for invalid_nonce in invalid_musig_nonce_length:
            with self.assertRaises(AssertionError):
                musig_aggnonce_serialize(invalid_nonce)

        for invalid_type in not_c_char_array:
            with self.assertRaises(AssertionError):
                musig_aggnonce_serialize(invalid_type)

    def test_musig_partial_sig_parse_invalid_input_type_sig32(self):
        # musig partial sig has same length constraints as secret key (has to be 32 bytes)
        for invalid_part_sig32 in invalid_seckey_length:
            with self.assertRaises(AssertionError):
                musig_partial_sig_parse(invalid_part_sig32)

        for invalid_type in not_bytes:
            with self.assertRaises(AssertionError):
                musig_partial_sig_parse(invalid_type)

    def test_musig_partial_sig_serialize_invalid_input_type_sig(self):
        for invalid_part_sig in invalid_musig_part_sig_length:
            with self.assertRaises(AssertionError):
                musig_partial_sig_serialize(invalid_part_sig)

        for invalid_type in not_c_char_array:
            with self.assertRaises(AssertionError):
                musig_partial_sig_serialize(invalid_type)

    def test_musig_pubkey_agg_invalid_input_type_keyagg_cache(self):
        for invalid_keyagg_cache in invalid_musig_keyagg_cache_lenght:
            with self.assertRaises(AssertionError):
                musig_pubkey_agg([self.pubkey0, self.pubkey1], invalid_keyagg_cache)

        for invalid_type in not_c_char_array[1:]:  # can be None
            with self.assertRaises(AssertionError):
                musig_pubkey_agg([self.pubkey0, self.pubkey1], invalid_type)

    def test_musig_pubkey_agg_invalid_input_type_pubkeys(self):
        # empty list
        with self.assertRaises(AssertionError):
            musig_pubkey_agg([], self.keyagg_cache)
        # length 1
        with self.assertRaises(AssertionError):
            musig_pubkey_agg([self.pubkey0], self.keyagg_cache)
        # not list
        for invalid_type in [
            (self.pubkey0, self.pubkey1),
            {"pk1": self.pubkey0, "pk2": self.pubkey1},
            [self.part_sig0, self.part_sig1],
        ]:
            with self.assertRaises(AssertionError):
                musig_pubkey_agg(invalid_type, self.keyagg_cache)
        for invalid_type in not_c_char_array:
            pubkey_list = [self.pubkey0, self.pubkey1, invalid_type]
            with self.assertRaises(AssertionError):
                musig_pubkey_agg(pubkey_list, self.keyagg_cache)

    def test_musig_pubkey_get_invalid_input_type_keyagg_cache(self):
        for invalid_keyagg_cache in invalid_musig_keyagg_cache_lenght:
            with self.assertRaises(AssertionError):
                musig_pubkey_get(invalid_keyagg_cache)

        for invalid_type in not_c_char_array[1:]:  # can be None
            with self.assertRaises(AssertionError):
                musig_pubkey_get(invalid_type)

    def test_musig_pubkey_ec_tweak_add_invalid_input_type_tweak32(self):
        for invalid_tweak in invalid_seckey_length:
            with self.assertRaises(AssertionError):
                musig_pubkey_ec_tweak_add(invalid_tweak, self.keyagg_cache)

        for invalid_type in not_bytes:
            with self.assertRaises(AssertionError):
                musig_pubkey_ec_tweak_add(invalid_type, self.keyagg_cache)

        # below tweaks does not pass ec_seckey_verify
        for invalid_seckey in invalid_seckeys:
            with self.assertRaises(Libsecp256k1Exception):
                musig_pubkey_ec_tweak_add(invalid_seckey, self.keyagg_cache)

    def test_musig_pubkey_ec_tweak_add_invalid_input_type_keyagg_cache(self):
        for invalid_keyagg_cache in invalid_musig_keyagg_cache_lenght:
            with self.assertRaises(AssertionError):
                musig_pubkey_ec_tweak_add(self.b32, invalid_keyagg_cache)

        for invalid_type in not_c_char_array[1:]:  # can be None
            with self.assertRaises(AssertionError):
                musig_pubkey_ec_tweak_add(self.b32, invalid_type)

    def test_musig_pubkey_xonly_tweak_add_invalid_input_type_tweak32(self):
        for invalid_tweak in invalid_seckey_length:
            with self.assertRaises(AssertionError):
                musig_pubkey_xonly_tweak_add(invalid_tweak, self.keyagg_cache)

        for invalid_type in not_bytes:
            with self.assertRaises(AssertionError):
                musig_pubkey_xonly_tweak_add(invalid_type, self.keyagg_cache)

        # below tweaks does not pass ec_seckey_verify
        for invalid_seckey in invalid_seckeys:
            with self.assertRaises(Libsecp256k1Exception):
                musig_pubkey_xonly_tweak_add(invalid_seckey, self.keyagg_cache)

    def test_musig_pubkey_xonly_tweak_add_invalid_input_type_keyagg_cache(self):
        for invalid_keyagg_cache in invalid_musig_keyagg_cache_lenght:
            with self.assertRaises(AssertionError):
                musig_pubkey_xonly_tweak_add(self.b32, invalid_keyagg_cache)

        for invalid_type in not_c_char_array[1:]:  # can be None
            with self.assertRaises(AssertionError):
                musig_pubkey_xonly_tweak_add(self.b32, invalid_type)

    def test_musig_nonce_gen_invalid_input_type_pubkey(self):
        for invalid_pubkey in invalid_pubkey_length:
            with self.assertRaises(AssertionError):
                musig_nonce_gen(invalid_pubkey)

        for invalid_type in not_c_char_array:
            with self.assertRaises(AssertionError):
                musig_nonce_gen(invalid_type)

    def test_musig_nonce_gen_invalid_input_type_session_secrand32(self):
        for invalid_session_secrand32 in invalid_seckey_length:
            with self.assertRaises(AssertionError):
                musig_nonce_gen(self.pubkey0, invalid_session_secrand32)

        for invalid_type in not_bytes[1:]:  # can be None
            with self.assertRaises(AssertionError):
                musig_nonce_gen(self.pubkey0, invalid_type)

    def test_musig_nonce_gen_invalid_input_type_seckey(self):
        for invalid_seckey in invalid_seckey_length:
            with self.assertRaises(AssertionError):
                musig_nonce_gen(self.pubkey0, self.b32, invalid_seckey)

        for invalid_type in not_bytes[1:]:  # can be None
            with self.assertRaises(AssertionError):
                musig_nonce_gen(self.pubkey0, self.b32, invalid_type)

    def test_musig_nonce_gen_invalid_input_type_mg32(self):
        for invalid_msg32 in invalid_seckey_length:
            with self.assertRaises(AssertionError):
                musig_nonce_gen(self.pubkey0, self.b32, self.b32, invalid_msg32)

        for invalid_type in not_bytes[1:]:  # can be None
            with self.assertRaises(AssertionError):
                musig_nonce_gen(self.pubkey0, self.b32, self.b32, invalid_type)

    def test_musig_nonce_gen_invalid_input_type_keyagg_cache(self):
        for invalid_keyagg_cache in invalid_musig_keyagg_cache_lenght:
            with self.assertRaises(AssertionError):
                musig_nonce_gen(self.pubkey0, self.b32, self.b32, self.b32, invalid_keyagg_cache,
                                self.b32)

        for invalid_type in not_c_char_array[1:]:  # can be None
            with self.assertRaises(AssertionError):
                musig_nonce_gen(self.pubkey0, self.b32, self.b32, self.b32, invalid_type, self.b32)

    def test_musig_nonce_gen_invalid_input_type_extra_input32(self):
        for invalid_extra_input32 in invalid_seckey_length:
            with self.assertRaises(AssertionError):
                musig_nonce_gen(self.pubkey0, self.b32, self.b32, self.b32, self.keyagg_cache,
                                invalid_extra_input32)

        for invalid_type in not_bytes[1:]:  # can be None
            with self.assertRaises(AssertionError):
                musig_nonce_gen(self.pubkey0, self.b32, self.b32, self.b32, self.keyagg_cache,
                                invalid_type)

    def test_musig_nonce_agg_invalid_input_type_pubnonces(self):
        # empty list
        with self.assertRaises(AssertionError):
            musig_nonce_agg([])
        # length 1
        with self.assertRaises(AssertionError):
            musig_nonce_agg([self.pubnonce0])
        # not list
        for invalid_type in [
            (self.pubnonce0, self.pubnonce1),
            {"pn1": self.pubnonce0, "pn2": self.pubnonce1},
            [self.pubkey0, self.pubkey1],
        ]:
            with self.assertRaises(AssertionError):
                musig_nonce_agg(invalid_type)
        for invalid_type in not_c_char_array:
            pubkey_list = [self.pubnonce0, self.pubnonce1, invalid_type]
            with self.assertRaises(AssertionError):
                musig_nonce_agg(pubkey_list)

    def test_musig_nonce_process_invalid_input_type_agg_nonce(self):
        for invalid_nonce in invalid_musig_nonce_length:
            with self.assertRaises(AssertionError):
                musig_nonce_process(invalid_nonce, self.b32, self.keyagg_cache)

        for invalid_type in not_c_char_array:
            with self.assertRaises(AssertionError):
                musig_nonce_process(invalid_type, self.b32, self.keyagg_cache)

    def test_musig_nonce_process_invalid_input_type_msg32(self):
        for invalid_msg32 in invalid_seckey_length:
            with self.assertRaises(AssertionError):
                musig_nonce_process(self.aggnonce, invalid_msg32, self.keyagg_cache)

        for invalid_type in not_bytes:
            with self.assertRaises(AssertionError):
                musig_nonce_process(self.aggnonce, invalid_type, self.keyagg_cache)

    def test_musig_nonce_process_invalid_input_type_keyagg_cache(self):
        for invalid_keyagg_cache in invalid_musig_keyagg_cache_lenght:
            with self.assertRaises(AssertionError):
                musig_nonce_process(self.aggnonce, self.b32, invalid_keyagg_cache)

        for invalid_type in not_c_char_array:
            with self.assertRaises(AssertionError):
                musig_nonce_process(self.aggnonce, self.b32, invalid_type)

    def test_musig_partial_sign_invalid_input_type_secnonce(self):
        for invalid_nonce in invalid_musig_nonce_length:
            with self.assertRaises(AssertionError):
                musig_partial_sign(invalid_nonce, self.keypair, self.keyagg_cache, self.session)

        for invalid_type in not_c_char_array:
            with self.assertRaises(AssertionError):
                musig_partial_sign(invalid_type, self.keypair, self.keyagg_cache, self.session)

    def test_musig_partial_sign_invalid_input_type_keypair(self):
        for invalid_keypair in invalid_keypair_length:
            with self.assertRaises(AssertionError):
                musig_partial_sign(self.aggnonce, invalid_keypair, self.keyagg_cache, self.session)

        for invalid_type in not_c_char_array:
            with self.assertRaises(AssertionError):
                musig_partial_sign(self.aggnonce, invalid_type, self.keyagg_cache, self.session)

    def test_musig_partial_sign_invalid_input_type_keyagg_cache(self):
        for invalid_keyagg_cache in invalid_musig_keyagg_cache_lenght:
            with self.assertRaises(AssertionError):
                musig_partial_sign(self.aggnonce, self.keypair, invalid_keyagg_cache, self.session)

        for invalid_type in not_c_char_array:
            with self.assertRaises(AssertionError):
                musig_partial_sign(self.aggnonce, self.keypair, invalid_type, self.session)

    def test_musig_partial_sign_invalid_input_type_session(self):
        for invalid_session in invalid_musig_session_length:
            with self.assertRaises(AssertionError):
                musig_partial_sign(self.aggnonce, self.keypair, self.keyagg_cache, invalid_session)

        for invalid_type in not_c_char_array:
            with self.assertRaises(AssertionError):
                musig_partial_sign(self.aggnonce, self.keypair, self.keyagg_cache, invalid_type)

    def test_musig_partial_sig_verify_invalid_input_type_sig(self):
        for invalid_part_sig in invalid_musig_part_sig_length:
            with self.assertRaises(AssertionError):
                musig_partial_sig_verify(invalid_part_sig, self.pubnonce1, self.pubkey1,
                                         self.keyagg_cache, self.session)

        for invalid_type in not_c_char_array:
            with self.assertRaises(AssertionError):
                musig_partial_sig_verify(invalid_type, self.pubnonce1, self.pubkey1,
                                         self.keyagg_cache, self.session)

    def test_musig_partial_sig_verify_invalid_input_type_pubnonce(self):
        for invalid_nonce in invalid_musig_nonce_length:
            with self.assertRaises(AssertionError):
                musig_partial_sig_verify(self.part_sig0, invalid_nonce, self.pubkey1,
                                         self.keyagg_cache, self.session)

        for invalid_type in not_c_char_array:
            with self.assertRaises(AssertionError):
                musig_partial_sig_verify(self.part_sig0, invalid_type, self.pubkey1,
                                         self.keyagg_cache, self.session)

    def test_musig_partial_sig_verify_invalid_input_type_pubkey(self):
        for invalid_pubkey in invalid_pubkey_length:
            with self.assertRaises(AssertionError):
                musig_partial_sig_verify(self.part_sig0, self.pubnonce1, invalid_pubkey,
                                         self.keyagg_cache, self.session)

        for invalid_type in not_c_char_array:
            with self.assertRaises(AssertionError):
                musig_partial_sig_verify(self.part_sig0, self.pubnonce1, invalid_type,
                                         self.keyagg_cache, self.session)

    def test_musig_partial_sig_verify_invalid_input_type_keyagg_cache(self):
        for invalid_keyagg_cache in invalid_musig_keyagg_cache_lenght:
            with self.assertRaises(AssertionError):
                musig_partial_sig_verify(self.part_sig0, self.pubnonce1, self.pubkey1,
                                         invalid_keyagg_cache, self.session)

        for invalid_type in not_c_char_array:
            with self.assertRaises(AssertionError):
                musig_partial_sig_verify(self.part_sig0, self.pubnonce1, self.pubkey1,
                                         invalid_type, self.session)

    def test_musig_partial_sig_verify_invalid_input_type_session(self):
        for invalid_session in invalid_musig_session_length:
            with self.assertRaises(AssertionError):
                musig_partial_sig_verify(self.part_sig0, self.pubnonce1, self.pubkey1,
                                         self.keyagg_cache, invalid_session)

        for invalid_type in not_c_char_array:
            with self.assertRaises(AssertionError):
                musig_partial_sig_verify(self.part_sig0, self.pubnonce1, self.pubkey1,
                                         self.keyagg_cache, invalid_type)

    def test_musig_partial_sig_agg_invalid_input_type_session(self):
        for invalid_session in invalid_musig_session_length:
            with self.assertRaises(AssertionError):
                musig_partial_sig_agg(invalid_session, [self.part_sig0, self.part_sig1])

        for invalid_type in not_c_char_array:
            with self.assertRaises(AssertionError):
                musig_partial_sig_agg(invalid_type, [self.part_sig0, self.part_sig1])

    def test_musig_partial_sig_agg_invalid_input_type_partial_sigs(self):
        # empty list
        with self.assertRaises(AssertionError):
            musig_partial_sig_agg(self.session, [])
        # length 1
        with self.assertRaises(AssertionError):
            musig_partial_sig_agg(self.session, [self.part_sig0])
        # not list
        for invalid_type in [
            (self.part_sig0, self.part_sig1),
            {"ps1": self.part_sig0, "ps2": self.part_sig1},
            [self.pubnonce0, self.pubnonce1],
        ]:
            with self.assertRaises(AssertionError):
                musig_partial_sig_agg(self.session, invalid_type)
        for invalid_type in not_c_char_array:
            pubkey_list = [self.part_sig0, self.part_sig1, invalid_type]
            with self.assertRaises(AssertionError):
                musig_partial_sig_agg(self.session, pubkey_list)


class TestPysecp256k1Musig(unittest.TestCase):

    def test_integration(self):

        keyagg_cache = MuSigKeyAggCache()
        msg = 32 * b"b"
        tweak_bip32 = 32 * b"a"
        xonly_tweak = 32 * b"c"

        signers = []
        pubkeys = []
        N_signers = 5

        for i in range(N_signers):
            sk = os.urandom(32)
            ec_seckey_verify(sk)
            pk = ec_pubkey_create(sk)
            signers.append([sk, pk])
            pubkeys.append(pk)

        pubkeys = ec_pubkey_sort(pubkeys)
        musig_pubkey_agg(pubkeys, keyagg_cache)

        musig_pubkey_ec_tweak_add(tweak_bip32, keyagg_cache)
        tweaked_pk = musig_pubkey_xonly_tweak_add(xonly_tweak, keyagg_cache)
        tweaked_xpk, _ = xonly_pubkey_from_pubkey(tweaked_pk)

        pubnonces = []
        for i, slist in enumerate(signers):
            session_sec = os.urandom(32)
            sn, pn = musig_nonce_gen(slist[1], session_secrand32=session_sec, seckey=slist[0],
                                     msg32=msg, keyagg_cache=keyagg_cache)

            pn_ser = musig_pubnonce_serialize(pn)
            assert pn_ser == musig_pubnonce_serialize(musig_pubnonce_parse(pn_ser))
            pubnonces.append(pn)
            slist.append(sn)

        agg_nonce = musig_nonce_agg(pubnonces)
        an_ser = musig_aggnonce_serialize(agg_nonce)
        assert an_ser == musig_aggnonce_serialize(musig_aggnonce_parse(an_ser))

        partial_sigs = []
        sessions = []
        for i, (sk, pk, secn) in enumerate(signers):
            session = musig_nonce_process(agg_nonce, msg, keyagg_cache)
            sig = musig_partial_sign(secn, keypair_create(sk), keyagg_cache, session)

            # re-sign with the same secnonce causes error (secnonce overwritten with zeros after sign)
            try:
                musig_partial_sign(secn, keypair_create(sk), keyagg_cache, session)
                raise ValueError  # must fail
            except Libsecp256k1Exception: pass

            sig_ser = musig_partial_sig_serialize(sig)
            assert sig_ser == musig_partial_sig_serialize(musig_partial_sig_parse(sig_ser))
            partial_sigs.append(sig)
            sessions.append(session)

        for i, sig in enumerate(partial_sigs):
            assert musig_partial_sig_verify(sig, pubnonces[i], signers[i][1], keyagg_cache, sessions[i])

        agg_sig = musig_partial_sig_agg(sessions[0], partial_sigs)
        assert schnorrsig_verify(agg_sig, msg, tweaked_xpk)


if __name__ == '__main__':
    unittest.main()
