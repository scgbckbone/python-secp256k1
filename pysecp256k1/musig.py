import ctypes, os
from typing import List, Tuple, Optional
from pysecp256k1.low_level import (lib, secp256k1_context_sign, secp256k1_context_verify,
                                   assert_zero_return_code, has_secp256k1_musig,
                                   Libsecp256k1Exception)
from pysecp256k1.low_level.constants import (INTERNAL_MUSIG_NONCE_LENGTH, INTERNAL_PUBKEY_LENGTH,
                                             INTERNAL_SIGNATURE_LENGTH, INTERNAL_MUSIG_SESSION_LENGTH,
                                             INTERNAL_MUSIG_PARTIAL_SIG_LENGTH, MUSIG_NONCE_LENGTH,
                                             MUSIG_PARTIAL_SIG_LENGTH, COMPACT_SIGNATURE_LENGTH,
                                             Secp256k1Pubkey, Secp256k1Keypair, MuSigPubNonce,
                                             Secp256k1XonlyPubkey, MuSigAggNonce, MuSigSession,
                                             MuSigSecNonce, MuSigKeyAggCache, MuSigPartialSig)


if not has_secp256k1_musig:
    raise RuntimeError("secp256k1 does not provide musig support")


def musig_pubnonce_parse(pubnonce66: bytes) -> MuSigPubNonce:

    assert isinstance(pubnonce66, bytes) and len(pubnonce66) == MUSIG_NONCE_LENGTH

    pubnonce = ctypes.create_string_buffer(INTERNAL_MUSIG_NONCE_LENGTH)
    result = lib.secp256k1_musig_pubnonce_parse(secp256k1_context_verify, pubnonce, pubnonce66)
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception("invalid arguemnts")
    return pubnonce


def musig_pubnonce_serialize(pubnonce: MuSigPubNonce) -> bytes:

    assert isinstance(pubnonce, MuSigPubNonce)

    pubnonce_ser = ctypes.create_string_buffer(MUSIG_NONCE_LENGTH)
    assert lib.secp256k1_musig_pubnonce_serialize(secp256k1_context_verify, pubnonce_ser, pubnonce)
    return pubnonce_ser.raw[:MUSIG_NONCE_LENGTH]


def musig_aggnonce_parse(aggnonce66: bytes) -> MuSigAggNonce:

    assert isinstance(aggnonce66, bytes) and len(aggnonce66) == MUSIG_NONCE_LENGTH

    aggnonce = ctypes.create_string_buffer(INTERNAL_MUSIG_NONCE_LENGTH)
    result = lib.secp256k1_musig_aggnonce_parse(secp256k1_context_verify, aggnonce, aggnonce66)
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception("invalid arguemnts")
    return aggnonce


def musig_aggnonce_serialize(aggnonce: MuSigAggNonce) -> bytes:

    assert isinstance(aggnonce, MuSigAggNonce)

    aggnonce_ser = ctypes.create_string_buffer(MUSIG_NONCE_LENGTH)
    assert lib.secp256k1_musig_aggnonce_serialize(secp256k1_context_verify, aggnonce_ser, aggnonce)
    return aggnonce_ser.raw[:MUSIG_NONCE_LENGTH]


def musig_partial_sig_parse(sig32: bytes) -> MuSigPartialSig:

    assert isinstance(sig32, bytes) and len(sig32) == MUSIG_PARTIAL_SIG_LENGTH

    sig = ctypes.create_string_buffer(INTERNAL_MUSIG_PARTIAL_SIG_LENGTH)
    assert lib.secp256k1_musig_partial_sig_parse(secp256k1_context_verify, sig, sig32)
    return sig


def musig_partial_sig_serialize(sig: MuSigPartialSig) -> bytes:

    assert isinstance(sig, MuSigPartialSig)

    res = ctypes.create_string_buffer(MUSIG_PARTIAL_SIG_LENGTH)
    assert lib.secp256k1_musig_partial_sig_serialize(secp256k1_context_verify, res, sig)
    return res.raw[:MUSIG_PARTIAL_SIG_LENGTH]


def musig_pubkey_agg(pubkeys: List[Secp256k1Pubkey],
                     keyagg_cache: Optional[MuSigKeyAggCache] = None) -> Secp256k1XonlyPubkey:

    assert isinstance(pubkeys, list) and len(pubkeys) > 1
    assert isinstance(keyagg_cache, MuSigKeyAggCache)

    length = len(pubkeys)
    arr = (ctypes.POINTER(Secp256k1Pubkey) * length)()
    for i, pk in enumerate(pubkeys):
        assert isinstance(pk, Secp256k1Pubkey)
        arr[i] = ctypes.pointer(pk)

    agg_pubkey = ctypes.create_string_buffer(INTERNAL_PUBKEY_LENGTH)
    result = lib.secp256k1_musig_pubkey_agg(secp256k1_context_verify, agg_pubkey,
                                            keyagg_cache, arr, length)
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception("invalid arguemnts")

    return agg_pubkey


def musig_pubkey_get(keyagg_cache: MuSigKeyAggCache) -> Secp256k1Pubkey:

    assert isinstance(keyagg_cache, MuSigKeyAggCache)

    agg_pubkey = ctypes.create_string_buffer(INTERNAL_PUBKEY_LENGTH)
    result = lib.secp256k1_musig_pubkey_get(secp256k1_context_verify, agg_pubkey, keyagg_cache)
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception("invalid arguemnts")

    return agg_pubkey


def musig_pubkey_ec_tweak_add(tweak32: bytes, keyagg_cache: MuSigKeyAggCache) -> Secp256k1Pubkey:

    assert isinstance(tweak32, bytes) and len(tweak32) == 32
    assert isinstance(keyagg_cache, MuSigKeyAggCache)

    tweaked_pubkey = ctypes.create_string_buffer(INTERNAL_PUBKEY_LENGTH)
    result = lib.secp256k1_musig_pubkey_ec_tweak_add(secp256k1_context_verify, tweaked_pubkey,
                                                     keyagg_cache, tweak32)
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception("invalid arguemnts")

    return tweaked_pubkey


def musig_pubkey_xonly_tweak_add(tweak32: bytes, keyagg_cache: MuSigKeyAggCache) -> Secp256k1Pubkey:

    assert isinstance(tweak32, bytes) and len(tweak32) == 32
    assert isinstance(keyagg_cache, MuSigKeyAggCache)

    tweaked_pubkey = ctypes.create_string_buffer(INTERNAL_PUBKEY_LENGTH)
    result = lib.secp256k1_musig_pubkey_xonly_tweak_add(secp256k1_context_verify, tweaked_pubkey,
                                                        keyagg_cache, tweak32)
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception("invalid arguemnts")

    return tweaked_pubkey


def musig_nonce_gen(pubkey: Secp256k1Pubkey, session_secrand32: Optional[bytes] = None,
                    seckey: Optional[bytes] = None, msg32: Optional[bytes] = None,
                    keyagg_cache: Optional[MuSigKeyAggCache] = None,
                    extra_input32: Optional[bytes]=None) -> Tuple[MuSigSecNonce, MuSigPubNonce]:

    assert isinstance(pubkey, Secp256k1Pubkey)
    if session_secrand32 is None:
        session_secrand32 = os.urandom(32)
    assert isinstance(session_secrand32, bytes) and len(session_secrand32) == 32
    if seckey:
        assert isinstance(seckey, bytes) and len(seckey) == 32
    if msg32:
        assert isinstance(msg32, bytes) and len(msg32) == 32
    if keyagg_cache:
        assert isinstance(keyagg_cache, MuSigKeyAggCache)
    if extra_input32:
        assert isinstance(extra_input32, bytes) and len(extra_input32) == 32

    # seckey -> pubkey should be verified
    secnonce = ctypes.create_string_buffer(INTERNAL_MUSIG_NONCE_LENGTH)
    pubnonce = ctypes.create_string_buffer(INTERNAL_MUSIG_NONCE_LENGTH)
    result = lib.secp256k1_musig_nonce_gen(secp256k1_context_sign, secnonce, pubnonce,
                                           session_secrand32, seckey, pubkey, msg32, keyagg_cache,
                                           extra_input32)
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception("invalid arguemnts")

    return secnonce, pubnonce


def musig_nonce_agg(pubnonces: List[MuSigPubNonce]) -> MuSigAggNonce:
    assert isinstance(pubnonces, list) and len(pubnonces) > 1

    length = len(pubnonces)
    arr = (ctypes.POINTER(MuSigPubNonce) * length)()
    for i, pn in enumerate(pubnonces):
        assert isinstance(pn, MuSigPubNonce)
        arr[i] = ctypes.pointer(pn)

    agg_nonce = ctypes.create_string_buffer(INTERNAL_MUSIG_NONCE_LENGTH)
    result = lib.secp256k1_musig_nonce_agg(secp256k1_context_sign, agg_nonce, arr, length)
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception("invalid arguemnts")

    return agg_nonce


def musig_nonce_process(agg_nonce: MuSigAggNonce, msg32: bytes,
                        keyagg_cache: MuSigKeyAggCache) -> MuSigSession:

    assert isinstance(agg_nonce, MuSigAggNonce)
    assert isinstance(msg32, bytes) and len(msg32) == 32
    assert isinstance(keyagg_cache, MuSigKeyAggCache)

    session = ctypes.create_string_buffer(INTERNAL_MUSIG_SESSION_LENGTH)
    result = lib.secp256k1_musig_nonce_process(secp256k1_context_sign, session, agg_nonce,
                                               msg32, keyagg_cache)
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception("invalid arguemnts")

    return session


def musig_partial_sign(secnonce: MuSigSecNonce, keypair: Secp256k1Keypair,
                       keyagg_cache: MuSigKeyAggCache, session: MuSigSession) -> MuSigPartialSig:

    assert isinstance(secnonce, MuSigSecNonce)
    assert isinstance(keypair, Secp256k1Keypair)
    assert isinstance(keyagg_cache, MuSigKeyAggCache)
    assert isinstance(session, MuSigSession)

    sig = ctypes.create_string_buffer(INTERNAL_MUSIG_PARTIAL_SIG_LENGTH)
    result = lib.secp256k1_musig_partial_sign(secp256k1_context_sign, sig, secnonce, keypair,
                                                        keyagg_cache, session)
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception("invalid arguemnts")

    return sig


def musig_partial_sig_verify(sig: MuSigPartialSig, pubnonce: MuSigPubNonce, pubkey: Secp256k1Pubkey,
                             keyagg_cache: MuSigKeyAggCache, session: MuSigSession) -> bool:

    assert isinstance(sig, MuSigPartialSig)
    assert isinstance(pubnonce, MuSigPubNonce)
    assert isinstance(pubkey, Secp256k1Pubkey)
    assert isinstance(keyagg_cache, MuSigKeyAggCache)
    assert isinstance(session, MuSigSession)

    result = lib.secp256k1_musig_partial_sig_verify(secp256k1_context_verify, sig, pubnonce, pubkey,
                                                    keyagg_cache, session)
    return bool(result)


def musig_partial_sig_agg(session: MuSigSession, partial_sigs: List[MuSigPartialSig]) -> bytes:

    assert isinstance(session, MuSigSession)
    assert isinstance(partial_sigs, list) and len(partial_sigs) > 1

    length = len(partial_sigs)
    arr = (ctypes.POINTER(MuSigPartialSig) * length)()
    for i, ps in enumerate(partial_sigs):
        assert isinstance(ps, MuSigPartialSig)
        arr[i] = ctypes.pointer(ps)

    sig64 = ctypes.create_string_buffer(INTERNAL_SIGNATURE_LENGTH)
    result = lib.secp256k1_musig_partial_sig_agg(secp256k1_context_sign, sig64, session,
                                                 arr, length)
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception("invalid arguemnts")

    return sig64.raw[:COMPACT_SIGNATURE_LENGTH]


__all__ = (
    "musig_pubnonce_parse",
    "musig_pubnonce_serialize",
    "musig_aggnonce_parse",
    "musig_aggnonce_serialize",
    "musig_partial_sig_parse",
    "musig_partial_sig_serialize",
    "musig_pubkey_agg",
    "musig_pubkey_get",
    "musig_pubkey_ec_tweak_add",
    "musig_pubkey_xonly_tweak_add",
    "musig_nonce_gen",
    "musig_nonce_agg",
    "musig_nonce_process",
    "musig_partial_sign",
    "musig_partial_sig_verify",
    "musig_partial_sig_agg",
)