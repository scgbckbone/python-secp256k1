import ctypes
from typing import Tuple
from pysecp256k1.low_level import (lib, secp256k1_context_sign, secp256k1_context_verify,
                                   assert_zero_return_code, has_secp256k1_extrakeys,
                                   Libsecp256k1Exception)
from pysecp256k1.low_level.constants import (Secp256k1Pubkey, Secp256k1XonlyPubkey, Secp256k1Keypair,
                                             INTERNAL_PUBKEY_LENGTH, INTERNAL_KEYPAIR_LENGTH,
                                             XONLY_PUBKEY_LENGTH, SECKEY_LENGTH, HASH32,
                                             VALID_PUBKEY_PARITY)


if not has_secp256k1_extrakeys:
    raise RuntimeError(
        "secp256k1 is not compiled with module 'extrakeys'. "
        "use '--enable-module-extrakeys' together with '--enable-experimental'"
        " during ./configure"
    )


def xonly_pubkey_parse(xonly_pubkey_ser: bytes) -> Secp256k1XonlyPubkey:
    """
    Parse a 32-byte sequence into a xonly_pubkey object.

    :param xonly_pubkey_ser: serialized xonly public key
    :return: initialized xonly pubkey
    :raises AssertionError: if xonly_pubkey_ser is not of type bytes and length 32
    :raises Libsecp256k1Exception: if public key could not be parsed or is invalid
    """
    assert isinstance(xonly_pubkey_ser, bytes) and len(xonly_pubkey_ser) == XONLY_PUBKEY_LENGTH

    xonly_pubkey = ctypes.create_string_buffer(INTERNAL_PUBKEY_LENGTH)
    result = lib.secp256k1_xonly_pubkey_parse(
        secp256k1_context_verify, xonly_pubkey, xonly_pubkey_ser
    )
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception(
            "xonly public key could not be parsed or is invalid"
        )
    return xonly_pubkey


def xonly_pubkey_serialize(xonly_pubkey: Secp256k1XonlyPubkey) -> bytes:
    """
    Serialize an xonly_pubkey object into a 32-byte sequence.

    :param xonly_pubkey: initialized xonly pubkey
    :return: serialized xonly public key
    :raises AssertionError: if xonly_pubkey is invalid type
    """
    assert isinstance(xonly_pubkey, Secp256k1XonlyPubkey)

    xonly_pubkey_ser = ctypes.create_string_buffer(XONLY_PUBKEY_LENGTH)
    lib.secp256k1_xonly_pubkey_serialize(
        secp256k1_context_sign, xonly_pubkey_ser, xonly_pubkey
    )
    return xonly_pubkey_ser.raw[:XONLY_PUBKEY_LENGTH]


def xonly_pubkey_cmp(xonly_pubkey0: Secp256k1XonlyPubkey, xonly_pubkey1: Secp256k1XonlyPubkey) -> int:
    """
    Compare two x-only public keys using lexicographic order.

    :param xonly_pubkey0: initialized xonly pubkey no. 0
    :param xonly_pubkey1: initialized xonly pubkey no. 1
    :return: <0 if the first public key is less than the second
             >0 if the first public key is greater than the second
             0 if the two public keys are equal
    :raises AsseriotnError: if arguments are invalid type
    """
    assert isinstance(xonly_pubkey0, Secp256k1XonlyPubkey)
    assert isinstance(xonly_pubkey1, Secp256k1XonlyPubkey)

    return lib.secp256k1_xonly_pubkey_cmp(
        secp256k1_context_sign, xonly_pubkey0, xonly_pubkey1
    )


def xonly_pubkey_from_pubkey(pubkey: Secp256k1Pubkey) -> Tuple[Secp256k1XonlyPubkey, int]:
    """
    Converts a Secp256k1Pubkey into a Secp256k1XonlyPubkey.

    :param pubkey: initialized public key
    :return: initialized xonly public key and its parity (set to 1 if the point
             encoded by xonly_pubkey is the negation of the pubkey and set to 0
             otherwise)
    :raises AssertionError: if pubkey is invalid type
    :raises Libsecp256k1Exception: if converting pubkey failed
    """
    assert isinstance(pubkey, Secp256k1Pubkey)

    xonly_pubkey = ctypes.create_string_buffer(INTERNAL_PUBKEY_LENGTH)

    pk_parity = ctypes.c_int()
    pk_parity.value = -1

    result = lib.secp256k1_xonly_pubkey_from_pubkey(
        secp256k1_context_verify, xonly_pubkey, ctypes.byref(pk_parity), pubkey
    )
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception("failed to convert pubkey")
    return xonly_pubkey, pk_parity.value


def xonly_pubkey_tweak_add(xonly_pubkey: Secp256k1XonlyPubkey, tweak32: bytes) -> Secp256k1Pubkey:
    """
    Tweak an x-only public key by adding the generator multiplied with tweak32
    to it.

    Note that the resulting point can not in general be represented by an x-only
    pubkey because it may have an odd Y coordinate. Instead, the output_pubkey
    is a normal Secp256k1Pubkey.

    :param xonly_pubkey: initialized xonly pubkey
    :param tweak32: 32-byte tweak
    :return: tweaked public key
    :raises AssertionError: if xonly_pubkey is invalid type
                            if tweak32 is not of type bytes and length 32
    :raises Libsecp256k1Exception: arguments are invalid or the resulting public
                                   key would be invalid (only when the tweak is
                                   the negation of the corresponding secret key)
    """
    assert isinstance(xonly_pubkey, Secp256k1XonlyPubkey)
    assert isinstance(tweak32, bytes) and len(tweak32) == HASH32

    tweaked_pubkey = ctypes.create_string_buffer(INTERNAL_PUBKEY_LENGTH)
    result = lib.secp256k1_xonly_pubkey_tweak_add(
        secp256k1_context_verify, tweaked_pubkey, xonly_pubkey, tweak32
    )
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception(
            "arguments are invalid or the resulting public key "
            "would be invalid (only when the tweak is the negation "
            "of the corresponding secret key)"
        )
    return tweaked_pubkey


def xonly_pubkey_tweak_add_check(tweaked_pubkey32: bytes, tweaked_pk_parity: int,
                                 internal_pubkey: Secp256k1XonlyPubkey, tweak32: bytes) -> bool:
    """
    Checks that a tweaked pubkey is the result of calling
    secp256k1_xonly_pubkey_tweak_add with internal_pubkey and tweak32.

    :param tweaked_pubkey32: serialized xonly public key that was tweaked
    :param tweaked_pk_parity: the parity of the tweaked pubkey
                              (whose serialization is passed in as tweaked_pubkey32)
    :param internal_pubkey: x-only public key object to apply the tweak to
    :param tweak32: 32-byte tweak
    :return: whether tweaked key is the result of tweaking internal with tweak
    :raises AssertionError: if tweaked_pubkey32 is not of type bytes and length 32
                            if tweaked_pk_parity is not of type int and in [0, 1]
                            if internal_pubkey is invalid type
                            if tweak32 is not of type bytes and length 32
    """
    assert isinstance(tweaked_pubkey32, bytes) and len(tweaked_pubkey32) == XONLY_PUBKEY_LENGTH
    assert isinstance(tweaked_pk_parity, int) and tweaked_pk_parity in VALID_PUBKEY_PARITY
    assert isinstance(internal_pubkey, Secp256k1XonlyPubkey)
    assert isinstance(tweak32, bytes) and len(tweak32) == HASH32

    result = lib.secp256k1_xonly_pubkey_tweak_add_check(
        secp256k1_context_verify,
        tweaked_pubkey32,
        tweaked_pk_parity,
        internal_pubkey,
        tweak32,
    )
    if result != 1:
        assert_zero_return_code(result)
        return False
    return True


def keypair_create(seckey: bytes) -> Secp256k1Keypair:
    """
    Compute the keypair for a secret key.

    :param seckey: 32-byte secret key
    :return: initialized keypair
    :raises AssertionError: if secret key is not of type bytes and length 32
    :raises Libsecp256k1Exception: if secret key is invalid
    """
    assert isinstance(seckey, bytes) and len(seckey) == SECKEY_LENGTH

    keypair = ctypes.create_string_buffer(INTERNAL_KEYPAIR_LENGTH)
    result = lib.secp256k1_keypair_create(secp256k1_context_sign, keypair, seckey)

    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception("secret key is invalid")
    return keypair


def keypair_sec(keypair: Secp256k1Keypair) -> bytes:
    """
    Get the secret key from a keypair.

    :param keypair: initialized keypair
    :return: 32-byte secret key
    :raises AssertionError: if keypair is invalid type
    :raises Libsecp256k1Exception: if arguments are invalid
    """
    assert isinstance(keypair, Secp256k1Keypair)

    seckey = ctypes.create_string_buffer(SECKEY_LENGTH)
    result = lib.secp256k1_keypair_sec(secp256k1_context_verify, seckey, keypair)
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception("invalid arguments")
    return seckey.raw[:SECKEY_LENGTH]


def keypair_pub(keypair: Secp256k1Keypair) -> Secp256k1Pubkey:
    """
    Get the public key from a keypair.

    :param keypair: initialized keypair
    :return: initialized public key
    :raises AssertionError: if keypair is invalid type
    :raises Libsecp256k1Exception: if arguments are invalid
    """
    assert isinstance(keypair, Secp256k1Keypair)

    pubkey = ctypes.create_string_buffer(INTERNAL_PUBKEY_LENGTH)
    result = lib.secp256k1_keypair_pub(secp256k1_context_verify, pubkey, keypair)
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception("invalid arguments")
    return pubkey


def keypair_xonly_pub(keypair: Secp256k1Keypair) -> Tuple[Secp256k1XonlyPubkey, int]:
    """
    Get the x-only public key from a keypair.

    This is the same as calling secp256k1_keypair_pub and then
    secp256k1_xonly_pubkey_from_pubkey.

    :param keypair: initialized keypair
    :return: initialized xonly public key and its parity (set to 1 if the point
             encoded by xonly_pubkey is the negation of the pubkey and set to 0
             otherwise)
    :raises AssertionError: if keypair is invalid type
    :raises Libsecp256k1Exception: if arguments are invalid
    """
    assert isinstance(keypair, Secp256k1Keypair)

    xonly_pubkey = ctypes.create_string_buffer(INTERNAL_PUBKEY_LENGTH)
    pk_parity = ctypes.c_int()
    pk_parity.value = -1

    result = lib.secp256k1_keypair_xonly_pub(
        secp256k1_context_verify, xonly_pubkey, ctypes.byref(pk_parity), keypair
    )
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception("invalid arguments")
    return xonly_pubkey, pk_parity.value


def keypair_xonly_tweak_add(keypair: Secp256k1Keypair, tweak32: bytes) -> Secp256k1Keypair:
    """
    Tweak a keypair by adding tweak32 to the secret key and updating the public
    key accordingly.

    Calling this function and then keypair_pub results in the same public key
    as calling keypair_xonly_pub and then xonly_pubkey_tweak_add.

    :param keypair: initialized keypair
    :param tweak32: 32-byte tweak
    :return: tweaked keypair
    :raises AssertionError: if keypair is invalid type
                            if tweak32 is not of type bytes and length 32
    :raises Libsecp256k1Exception: if arguments are invalid
    """
    assert isinstance(keypair, Secp256k1Keypair)
    assert isinstance(tweak32, bytes) and len(tweak32) == HASH32

    result = lib.secp256k1_keypair_xonly_tweak_add(
        secp256k1_context_verify, keypair, tweak32
    )
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception("invalid arguments")
    return keypair


__all__ = (
    "xonly_pubkey_parse",
    "xonly_pubkey_serialize",
    "xonly_pubkey_cmp",
    "xonly_pubkey_from_pubkey",
    "xonly_pubkey_tweak_add",
    "xonly_pubkey_tweak_add_check",
    "keypair_create",
    "keypair_sec",
    "keypair_pub",
    "keypair_xonly_pub",
    "keypair_xonly_tweak_add",
)
