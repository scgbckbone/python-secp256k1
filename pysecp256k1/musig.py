import ctypes, os
from typing import List, Tuple
from pysecp256k1.low_level import (
    lib,
    secp256k1_context_sign,
    secp256k1_context_verify,
    assert_zero_return_code,
    has_secp256k1_musig,
    Libsecp256k1Exception,
)
from pysecp256k1.low_level.constants import (
    INTERNAL_MUSIG_NONCE_LENGTH,
    INTERNAL_PUBKEY_LENGTH,
    INTERNAL_SIGNATURE_LENGTH,
    INTERNAL_MUSIG_SESSION_LENGTH,
    INTERNAL_MUSIG_PARTIAL_SIG_LENGTH,
    MUSIG_NONCE_LENGTH,
    MUSIG_PARTIAL_SIG_LENGTH,
    Secp256k1Pubkey,
    Secp256k1Keypair,
    Secp256k1XonlyPubkey,
    MuSigPubNonce,
    MuSigAggNonce,
    MuSigSecNonce,
    MuSigKeyAggCache,
    MuSigSession,
    MuSigPartialSig,
)


if not has_secp256k1_musig:
    raise RuntimeError("secp256k1 does not provide musig support")


def musig_nonce_gen(pubkey: Secp256k1Pubkey, session_secrand32: bytes = None, seckey: bytes = None,
                    msg32=None, keyagg_cache: MuSigKeyAggCache = None, extra_input32=None
                    ) -> Tuple[MuSigSecNonce, MuSigPubNonce]:
    if session_secrand32 is None:
        session_secrand32 = os.urandom(32)
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
    length = len(pubnonces)
    arr = (ctypes.POINTER(MuSigPubNonce) * length)()
    for i, pk in enumerate(pubnonces):
        arr[i] = ctypes.pointer(pk)

    agg_nonce = ctypes.create_string_buffer(INTERNAL_MUSIG_NONCE_LENGTH)
    result = lib.secp256k1_musig_nonce_agg(secp256k1_context_sign, agg_nonce, arr, length)
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception("invalid arguemnts")

    return agg_nonce


def musig_nonce_process(agg_nonce: MuSigAggNonce, msg32: bytes,
                        keyagg_cache: MuSigKeyAggCache) -> MuSigSession:

    session = ctypes.create_string_buffer(INTERNAL_MUSIG_SESSION_LENGTH)
    result = lib.secp256k1_musig_nonce_process(secp256k1_context_sign, session, agg_nonce,
                                               msg32, keyagg_cache)
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception("invalid arguemnts")

    return session


def musig_pubnonce_serialize(pubnonce: MuSigPubNonce) -> bytes:
    pubnonce_ser = ctypes.create_string_buffer(MUSIG_NONCE_LENGTH)
    assert lib.secp256k1_musig_pubnonce_serialize(secp256k1_context_verify, pubnonce_ser, pubnonce)
    return pubnonce_ser.raw


def musig_pubnonce_parse(pubnonce66: bytes) -> MuSigPubNonce:
    pubnonce = ctypes.create_string_buffer(INTERNAL_MUSIG_NONCE_LENGTH)
    result = lib.secp256k1_musig_pubnonce_parse(secp256k1_context_verify, pubnonce, pubnonce66)
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception("invalid arguemnts")
    return pubnonce


def musig_aggnonce_serialize(aggnonce: MuSigAggNonce) -> bytes:
    aggnonce_ser = ctypes.create_string_buffer(MUSIG_NONCE_LENGTH)
    assert lib.secp256k1_musig_aggnonce_serialize(secp256k1_context_verify, aggnonce_ser, aggnonce)
    return aggnonce_ser.raw


def musig_aggnonce_parse(aggnonce66: bytes) -> MuSigAggNonce:
    aggnonce = ctypes.create_string_buffer(INTERNAL_MUSIG_NONCE_LENGTH)
    result = lib.secp256k1_musig_aggnonce_parse(secp256k1_context_verify, aggnonce, aggnonce66)
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception("invalid arguemnts")
    return aggnonce


def musig_pubkey_agg(pubkeys: List[Secp256k1Pubkey], keyagg_cache: MuSigKeyAggCache=None) -> Secp256k1XonlyPubkey:
    length = len(pubkeys)
    arr = (ctypes.POINTER(Secp256k1Pubkey) * length)()
    for i, pk in enumerate(pubkeys):
        arr[i] = ctypes.pointer(pk)

    agg_pubkey = ctypes.create_string_buffer(INTERNAL_PUBKEY_LENGTH)
    result = lib.secp256k1_musig_pubkey_agg(secp256k1_context_verify, agg_pubkey,
                                            keyagg_cache, arr, length)
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception("invalid arguemnts")

    return agg_pubkey


def musig_pubkey_get(keyagg_cache: MuSigKeyAggCache) -> Secp256k1Pubkey:
    agg_pubkey = ctypes.create_string_buffer(INTERNAL_PUBKEY_LENGTH)
    result = lib.secp256k1_musig_pubkey_get(secp256k1_context_verify, agg_pubkey, keyagg_cache)
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception("invalid arguemnts")

    return agg_pubkey


def musig_pubkey_ec_tweak_add(tweak32: bytes, keyagg_cache: MuSigKeyAggCache) -> Secp256k1Pubkey:
    tweaked_pubkey = ctypes.create_string_buffer(INTERNAL_PUBKEY_LENGTH)
    result = lib.secp256k1_musig_pubkey_ec_tweak_add(secp256k1_context_verify, tweaked_pubkey,
                                                     keyagg_cache, tweak32)
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception("invalid arguemnts")

    return tweaked_pubkey


def musig_pubkey_xonly_tweak_add(tweak32: bytes, keyagg_cache: MuSigKeyAggCache) -> Secp256k1Pubkey:
    tweaked_pubkey = ctypes.create_string_buffer(INTERNAL_PUBKEY_LENGTH)
    result = lib.secp256k1_musig_pubkey_xonly_tweak_add(secp256k1_context_verify, tweaked_pubkey,
                                                        keyagg_cache, tweak32)
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception("invalid arguemnts")

    return tweaked_pubkey


def musig_partial_sig_serialize(sig: MuSigPartialSig) -> bytes:
    res = ctypes.create_string_buffer(MUSIG_PARTIAL_SIG_LENGTH)
    assert lib.secp256k1_musig_partial_sig_serialize(secp256k1_context_verify, res, sig)
    return res.raw


def musig_partial_sig_parse(sig32: bytes) -> MuSigPartialSig:
    sig = ctypes.create_string_buffer(INTERNAL_MUSIG_PARTIAL_SIG_LENGTH)
    assert lib.secp256k1_musig_partial_sig_parse(secp256k1_context_verify, sig, sig32)
    return sig


def musig_partial_sign(secnonce: MuSigSecNonce, keypair: Secp256k1Keypair,
                       keyagg_cache: MuSigKeyAggCache, session: MuSigSession) -> MuSigPartialSig:

    sig = ctypes.create_string_buffer(INTERNAL_MUSIG_PARTIAL_SIG_LENGTH)
    result = lib.secp256k1_musig_partial_sign(secp256k1_context_sign, sig, secnonce, keypair,
                                                        keyagg_cache, session)
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception("invalid arguemnts")

    return sig


def musig_partial_sig_verify(sig: MuSigPartialSig, pubnonce: MuSigPubNonce, pubkey: Secp256k1Pubkey,
                             keyagg_cache: MuSigKeyAggCache, session: MuSigSession) -> bool:

    result = lib.secp256k1_musig_partial_sig_verify(secp256k1_context_verify, sig, pubnonce, pubkey,
                                                    keyagg_cache, session)
    return bool(result)


def musig_partial_sig_agg(session: MuSigSession, partial_sigs: List[MuSigPartialSig]) -> bytes:
    length = len(partial_sigs)
    arr = (ctypes.POINTER(MuSigPartialSig) * length)()
    for i, pk in enumerate(partial_sigs):
        arr[i] = ctypes.pointer(pk)

    sig64 = ctypes.create_string_buffer(INTERNAL_SIGNATURE_LENGTH)
    result = lib.secp256k1_musig_partial_sig_agg(secp256k1_context_sign, sig64, session,
                                                 arr, length)
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception("invalid arguemnts")

    return sig64.raw