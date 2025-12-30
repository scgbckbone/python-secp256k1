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
    """
    Parse a signer's public nonce.

    :param pubnonce66: public nonce serialization (66 bytes)
    :return: initialized MuSigPubNonce object
    :raises AssertionError: if pubnonce66 is not of type bytes and length 66
    :raises Libsecp256k1Exception: if public nonce cannot be parsed
    """
    assert isinstance(pubnonce66, bytes) and len(pubnonce66) == MUSIG_NONCE_LENGTH

    pubnonce = ctypes.create_string_buffer(INTERNAL_MUSIG_NONCE_LENGTH)
    result = lib.secp256k1_musig_pubnonce_parse(secp256k1_context_verify, pubnonce, pubnonce66)
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception("invalid public nonce")
    return pubnonce


def musig_pubnonce_serialize(pubnonce: MuSigPubNonce) -> bytes:
    """
    Serialize a signer's public nonce.

    :param pubnonce: initialized MuSigPubNonce object
    :return: public nonce serialization (66 bytes)
    :raises AssertionError: if pubnonce is not of type MuSigPubNonce
    """
    assert isinstance(pubnonce, MuSigPubNonce)

    pubnonce_ser = ctypes.create_string_buffer(MUSIG_NONCE_LENGTH)
    assert lib.secp256k1_musig_pubnonce_serialize(secp256k1_context_verify, pubnonce_ser, pubnonce)
    return pubnonce_ser.raw[:MUSIG_NONCE_LENGTH]


def musig_aggnonce_parse(aggnonce66: bytes) -> MuSigAggNonce:
    """
    Parse an aggregate public nonce.

    :param aggnonce66: aggregate nonce serialization (66 bytes)
    :return: initialized MuSigAggNonce object
    :raises AssertionError: if aggnonce66 is not of type bytes and length 66
    :raises Libsecp256k1Exception: if aggregate nonce cannot be parsed
    """
    assert isinstance(aggnonce66, bytes) and len(aggnonce66) == MUSIG_NONCE_LENGTH

    aggnonce = ctypes.create_string_buffer(INTERNAL_MUSIG_NONCE_LENGTH)
    result = lib.secp256k1_musig_aggnonce_parse(secp256k1_context_verify, aggnonce, aggnonce66)
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception("invalid aggregate nonce")
    return aggnonce


def musig_aggnonce_serialize(aggnonce: MuSigAggNonce) -> bytes:
    """
    Serialize an aggregate public nonce.

    :param aggnonce: initialized MuSigAggNonce object
    :return: aggregate nonce serialization (66 bytes)
    :raises AssertionError: if aggnonce is not of type MuSigAggNonce
    """
    assert isinstance(aggnonce, MuSigAggNonce)

    aggnonce_ser = ctypes.create_string_buffer(MUSIG_NONCE_LENGTH)
    assert lib.secp256k1_musig_aggnonce_serialize(secp256k1_context_verify, aggnonce_ser, aggnonce)
    return aggnonce_ser.raw[:MUSIG_NONCE_LENGTH]


def musig_partial_sig_parse(sig32: bytes) -> MuSigPartialSig:
    """
    Parse a MuSig partial signature.

    :param sig32: partial signature serialization (32 bytes)
    :return: initialized MuSigPartialSig object
    :raises AssertionError: if sig32 is not of type bytes and length 32
    :raises Libsecp256k1Exception: if partial signature cannot be parsed
    """
    assert isinstance(sig32, bytes) and len(sig32) == MUSIG_PARTIAL_SIG_LENGTH

    sig = ctypes.create_string_buffer(INTERNAL_MUSIG_PARTIAL_SIG_LENGTH)
    result = lib.secp256k1_musig_partial_sig_parse(secp256k1_context_verify, sig, sig32)
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception("invalid partial signature")
    return sig


def musig_partial_sig_serialize(sig: MuSigPartialSig) -> bytes:
    """
    Serialize a MuSig partial signature.

    :param sig: initialized MuSigPartialSig object
    :return: partial signature serialization (32 bytes)
    :raises AssertionError: if sig is not of type MuSigPartialSig
    """
    assert isinstance(sig, MuSigPartialSig)

    res = ctypes.create_string_buffer(MUSIG_PARTIAL_SIG_LENGTH)
    assert lib.secp256k1_musig_partial_sig_serialize(secp256k1_context_verify, res, sig)
    return res.raw[:MUSIG_PARTIAL_SIG_LENGTH]


def musig_pubkey_agg(pubkeys: List[Secp256k1Pubkey],
                     keyagg_cache: Optional[MuSigKeyAggCache] = None) -> Secp256k1XonlyPubkey:
    """
    Computes an aggregate public key and uses it to initialize a keyagg_cache.

    Different orders of `pubkeys` result in different `agg_pk`s.

    Before aggregating, the pubkeys can be sorted with `secp256k1_ec_pubkey_sort`
    which ensures the same `agg_pk` result for the same multiset of pubkeys.
    This is useful to do before `pubkey_agg`, such that the order of pubkeys
    does not affect the aggregate public key.

    :param pubkeys: list of initialized Secp256k1Pubkey objects
    :param keyagg_cache: optional initialized MuSigKeyAggCache object
    :return: initialized aggregate key of type Secp256k1XonlyPubkey
    :raises AssertionError: if pubkeys is not type of list of length at least 2
                            if pubkeys member is not of type Secp256k1Pubkey
                            if keyagg_cache is not of type MuSigKeyAggCache
    :raises Libsecp256k1Exception: if arguments are invalid
    """
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
    """
    Obtain the aggregate public key from a keyagg_cache.

    This is only useful if you need the non-xonly public key, in particular for
    plain (non-xonly) tweaking or batch-verifying multiple key aggregations.

    :param keyagg_cache: initialized MuSigKeyAggCache object
    :return: initialized aggregate key of type Secp256k1Pubkey
    :raises AssertionError: if keyagg_cache is not of type MuSigKeyAggCache
    :raises Libsecp256k1Exception: if arguments are invalid
    """
    assert isinstance(keyagg_cache, MuSigKeyAggCache)

    agg_pubkey = ctypes.create_string_buffer(INTERNAL_PUBKEY_LENGTH)
    result = lib.secp256k1_musig_pubkey_get(secp256k1_context_verify, agg_pubkey, keyagg_cache)
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception("invalid arguemnts")

    return agg_pubkey


def musig_pubkey_ec_tweak_add(tweak32: bytes, keyagg_cache: MuSigKeyAggCache) -> Secp256k1Pubkey:
    """
    Apply plain "EC" tweaking to a public key in a given keyagg_cache by adding
    the generator multiplied with `tweak32` to it. This is useful for deriving
    child keys from an aggregate public key via BIP 32 where `tweak32` is set to
    a hash as defined in BIP 32.

    Callers are responsible for deriving `tweak32` in a way that does not reduce
    the security of MuSig (for example, by following BIP 32).

    The tweaking method is the same as `secp256k1_ec_pubkey_tweak_add`. So after
    the following pseudocode buf and buf2 have identical contents (absent
    earlier failures).

    secp256k1_musig_pubkey_agg(..., keyagg_cache, pubkeys, ...)
    secp256k1_musig_pubkey_get(..., agg_pk, keyagg_cache)
    secp256k1_musig_pubkey_ec_tweak_add(..., output_pk, tweak32, keyagg_cache)
    secp256k1_ec_pubkey_serialize(..., buf, ..., output_pk, ...)
    secp256k1_ec_pubkey_tweak_add(..., agg_pk, tweak32)
    secp256k1_ec_pubkey_serialize(..., buf2, ..., agg_pk, ...)

    This function is required if you want to _sign_ for a tweaked aggregate key.
    If you are only computing a public key but not intending to create a
    signature for it, use `secp256k1_ec_pubkey_tweak_add` instead.

    :param tweak32: 32-byte tweak. The tweak is valid if it passes `secp256k1_ec_seckey_verify`
                    and is not equal to the secret key corresponding to the public key represented
                    by keyagg_cache or its negation
    :param keyagg_cache: initialized MuSigKeyAggCache object
    :return: initialized tweaked public key of type Secp256k1Pubkey
    :raises AssertionError: if tweak32 is not of type bytes and length 32
                            if keyagg_cache is not of type MuSigKeyAggCache
    :raises Libsecp256k1Exception: if arguments are invalid
    """
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
    """
    Apply x-only tweaking to a public key in a given keyagg_cache by adding the
    generator multiplied with `tweak32` to it. This is useful for creating
    Taproot outputs where `tweak32` is set to a TapTweak hash as defined in BIP
    341.

    Callers are responsible for deriving `tweak32` in a way that does not reduce
    the security of MuSig (for example, by following Taproot BIP 341).

    The tweaking method is the same as `secp256k1_xonly_pubkey_tweak_add`. So in
    the following pseudocode xonly_pubkey_tweak_add_check (absent earlier
    failures) returns 1.

    secp256k1_musig_pubkey_agg(..., agg_pk, keyagg_cache, pubkeys, ...)
    secp256k1_musig_pubkey_xonly_tweak_add(..., output_pk, keyagg_cache, tweak32)
    secp256k1_xonly_pubkey_serialize(..., buf, output_pk)
    secp256k1_xonly_pubkey_tweak_add_check(..., buf, ..., agg_pk, tweak32)

    This function is required if you want to _sign_ for a tweaked aggregate key.
    If you are only computing a public key but not intending to create a
    signature for it, use `secp256k1_xonly_pubkey_tweak_add` instead.

    :param tweak32: 32-byte tweak. The tweak is valid if it passes `secp256k1_ec_seckey_verify`
                    and is not equal to the secret key corresponding to the public key represented
                    by keyagg_cache or its negation
    :param keyagg_cache: initialized MuSigKeyAggCache object
    :return: initialized tweaked public key of type Secp256k1Pubkey
    :raises AssertionError: if tweak32 is not of type bytes and length 32
                            if keyagg_cache is not of type MuSigKeyAggCache
    :raises Libsecp256k1Exception: if arguments are invalid
    """
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
    """
    Starts a signing session by generating a nonce

    This function outputs a secret nonce that will be required for signing and a
    corresponding public nonce that is intended to be sent to other signers.

    MuSig differs from regular Schnorr signing in that implementers _must_ take
    special care to not reuse a nonce. This can be ensured by following these rules:

    1. Each call to this function must have a UNIQUE session_secrand32 that must
       NOT BE REUSED in subsequent calls to this function and must be KEPT
       SECRET (even from other signers).
    2. If you already know the seckey, message or aggregate public key
       cache, they can be optionally provided to derive the nonce and increase
       misuse-resistance. The extra_input32 argument can be used to provide
       additional data that does not repeat in normal scenarios, such as the
       current time.
    3. Avoid copying (or serializing) the secnonce. This reduces the possibility
       that it is used more than once for signing.

    Remember that nonce reuse will leak the secret key!
    Note that using the same seckey for multiple MuSig sessions is fine.

    :param pubkey: initialized public key of type Secp256k1Pubkey of the signer creating the nonce.
                   The secnonce output of this function cannot be used to sign for any other public key.
                   While the public key should correspond to the provided seckey, a mismatch will not
                   cause the function to fail.
    :param session_secrand32: optional 32 bytes of randomness Must be unique to this
                              call to musig_nonce_gen and must be uniformly random.
                              if not provided, this library uses os.urandom(32)
    :param seckey: optional 32-byte secret key that will later be used for signing
    :param msg32: optional 32-byte message that will later be used for signing
    :param keyagg_cache: optional initialized MuSigKeyAggCache object that was used
                         to create the aggregate (and potentially tweaked) public key
    :param extra_input32: optional 32 bytes that is input to the nonce derivation function
    :return: tuple of length 2 with initialized MuSigSecNonce, MuSigPubNonce objects
    :raises AssertionError: if pubkey is not of type Secp256k1Pubkey
                            if [optional] session_secrand32 is not of type bytes and length 32
                            if [optional] seckey is not of type bytes and length 32
                            if [optional] msg32 is not of type bytes and length 32
                            if [optional] keyagg_cache is not of type MuSigKeyAggCache
                            if [optional] extra_input32 is not of type bytes and length 32
    :raises Libsecp256k1Exception: if arguments are invalid
    """
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
    """
    Aggregates the nonces of all signers into a single nonce.

    If the aggregator does not compute the aggregate nonce correctly, the final
    signature will be invalid.

    :param pubnonces: list of initialized MuSigPubNonce objects
    :raises AssertionError: if pubnonces is not type of list of length at least 2
                            if pubnonces member is not of type MuSigPubNonce
    :raises Libsecp256k1Exception: if arguments are invalid
    """
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
    """
    Takes the aggregate nonce and creates a session that is required for signing
    and verification of partial signatures.

    :param agg_nonce: initialized aggregate nonce of type MuSigAggNonce
    :param msg32: 32 bytes msg to sign
    :param keyagg_cache: initialized MuSigKeyAggCache object
    :return: initialized MuSigSession object
    :raises AssertionError: if agg_nonce is not of type MuSigAggNonce
                            if msg32 is not of type bytes and length 32
                            if keyagg_cache is not of type MuSigKeyAggCache
    :raises Libsecp256k1Exception: if arguments are invalid
    """
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
    """
    Produces a partial signature.

    This function overwrites the given secnonce with zeros and will abort if given a
    secnonce that is all zeros. This is the best effort attempt to protect against nonce
    reuse. However, this is of course easily defeated if the secnonce has been
    copied (or serialized). Remember that nonce reuse will leak the secret key!

    For signing to succeed, the secnonce provided to this function must have
    been generated for the provided keypair. This means that when signing for a
    keypair consisting of a seckey and pubkey, the secnonce must have been
    created by calling musig_nonce_gen with that pubkey. Otherwise, the
    illegal_callback is called.

    This function does not verify the output partial signature, deviating from
    the BIP 327 specification. It is recommended to verify the output partial
    signature with `musig_partial_sig_verify` to prevent random or
    adversarially provoked computation errors.

    :param secnonce: initialized secnonce of type MuSigSecNonce
    :param keypair: initialized keypair of type Secp256k1Keypair used for signing
    :param keyagg_cache: initialized MuSigKeyAggCache object
    :param session: initialized MuSigSession object that was created with musig_nonce_process
    :return: initialized MuSigPartialSig object
    :raises AssertionError: if secnonce is not of type MusigSecNonce
                            if keypair is not of type Secp256k1Keypair
                            if keyagg_cache is not of type MuSigKeyAggCache
                            if session is not of type MusigSession
    :raises Libsecp256k1Exception: if arguments are invalid or secnonce was reused
    """
    assert isinstance(secnonce, MuSigSecNonce)
    assert isinstance(keypair, Secp256k1Keypair)
    assert isinstance(keyagg_cache, MuSigKeyAggCache)
    assert isinstance(session, MuSigSession)

    sig = ctypes.create_string_buffer(INTERNAL_MUSIG_PARTIAL_SIG_LENGTH)
    result = lib.secp256k1_musig_partial_sign(secp256k1_context_sign, sig, secnonce, keypair,
                                                        keyagg_cache, session)
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception("invalid arguments or secnonce reused")

    return sig


def musig_partial_sig_verify(sig: MuSigPartialSig, pubnonce: MuSigPubNonce, pubkey: Secp256k1Pubkey,
                             keyagg_cache: MuSigKeyAggCache, session: MuSigSession) -> bool:
    """
    Verifies an individual signer's partial signature.

    The signature is verified for a specific signing session. In order to avoid
    accidentally verifying a signature from a different or non-existing signing
    session, you must ensure the following:
      1. The `keyagg_cache` argument is identical to the one used to create the
         `session` with `musig_nonce_process`.
      2. The `pubkey` argument must be identical to the one sent by the signer
         before aggregating it with `musig_pubkey_agg` to create the
         `keyagg_cache`.
      3. The `pubnonce` argument must be identical to the one sent by the signer
         before aggregating it with `musig_nonce_agg` and using the result to
         create the `session` with `musig_nonce_process`.

    It is not required to call this function in regular MuSig sessions, because
    if any partial signature does not verify, the final signature will not
    verify either, so the problem will be caught. However, this function
    provides the ability to identify which specific partial signature fails
    verification.

    :param sig: partial signature of type MusigPartialSig to verify
    :param pubnonce: initialized MuSigPubNonce object of a signer in session
    :param pubkey: initialized Secp256k1Pubkey public key of the signer in the signing session
    :param keyagg_cache: initialized MuSigKeyAggCache object
    :param session: initialized MuSigSession object that was created with musig_nonce_process
    :return: True if signature verified, False otherwise, or if arguments are invalid
    :raises AssertionError: if sig is not of type MuSigPartialSig
                            if pubnonce is not of type MuSigPubNonce
                            if pubkey is not of type Secp256k1Pubkey
                            if keyagg_cache is not of type MuSigKeyAggCache
                            if session is not of type MusigSession
    """
    assert isinstance(sig, MuSigPartialSig)
    assert isinstance(pubnonce, MuSigPubNonce)
    assert isinstance(pubkey, Secp256k1Pubkey)
    assert isinstance(keyagg_cache, MuSigKeyAggCache)
    assert isinstance(session, MuSigSession)

    result = lib.secp256k1_musig_partial_sig_verify(secp256k1_context_verify, sig, pubnonce, pubkey,
                                                    keyagg_cache, session)
    return bool(result)


def musig_partial_sig_agg(session: MuSigSession, partial_sigs: List[MuSigPartialSig]) -> bytes:
    """
    Aggregates partial signatures.

    :param session: MuSigSession object that was created with musig_nonce_process
    :param partial_sigs: list of partial signatures of type MuSigPartialSig
    :return: complete (but possibly invalid) Schnorr signature bytes of length 64
    :raises AssertionError: if session is not of type MusigSession
                            if partial_sigs is not type of list of length at least 2
                            if partial_sigs member is not of type MuSigPubNonce
    :raises Libsecp256k1Exception: if arguments are invalid
    """
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