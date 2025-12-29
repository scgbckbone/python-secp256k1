import ctypes
from typing import Tuple
from pysecp256k1.low_level import (lib, secp256k1_context_sign, secp256k1_context_verify,
                                   assert_zero_return_code, has_secp256k1_recovery,
                                   Libsecp256k1Exception)
from pysecp256k1.low_level.constants import (COMPACT_SIGNATURE_LENGTH, VALID_RECOVERY_IDS, HASH32,
                                             INTERNAL_RECOVERABLE_SIGNATURE_LENGTH, SECKEY_LENGTH,
                                             INTERNAL_SIGNATURE_LENGTH, INTERNAL_PUBKEY_LENGTH,
                                             Secp256k1Pubkey, Secp256k1ECDSARecSig, Secp256k1ECDSASig)


if not has_secp256k1_recovery:
    raise RuntimeError(
        "secp256k1 is not compiled with module 'recovery'. "
        "Use '--enable-module-recovery' during ./configure"
    )


def ecdsa_recoverable_signature_parse_compact(compact_sig: bytes, rec_id: int) -> Secp256k1ECDSARecSig:
    """
    Parse a compact ECDSA signature (64 bytes + recovery id).

    :param compact_sig: 64-byte compact signature serialization
    :param rec_id: recovery id (0, 1, 2 or 3)
    :return: ECDSA recoverable signature
    :raises AssertionError: if compact_sig is not of type bytes and length 64
                            if rec_id is not of type int and one of 0,1,2 or 3
    """
    assert isinstance(compact_sig, bytes) and len(compact_sig) == COMPACT_SIGNATURE_LENGTH
    assert isinstance(rec_id, int) and rec_id in VALID_RECOVERY_IDS

    rec_sig = ctypes.create_string_buffer(INTERNAL_RECOVERABLE_SIGNATURE_LENGTH)
    result = lib.secp256k1_ecdsa_recoverable_signature_parse_compact(
        secp256k1_context_verify, rec_sig, compact_sig, rec_id
    )
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception("signature could not be parsed")
    return rec_sig


def ecdsa_recoverable_signature_convert(rec_sig: Secp256k1ECDSARecSig) -> Secp256k1ECDSASig:
    """
    Convert a recoverable signature into a normal signature.

    :param rec_sig: initialized ECDSA recoverable signature
    :return: initialized ECDSA signature
    :raises AssertionError: if rec_sig is invalid type
    """
    assert isinstance(rec_sig, Secp256k1ECDSARecSig)

    sig = ctypes.create_string_buffer(INTERNAL_SIGNATURE_LENGTH)
    lib.secp256k1_ecdsa_recoverable_signature_convert(
        secp256k1_context_verify, sig, rec_sig
    )
    return sig


def ecdsa_recoverable_signature_serialize_compact(rec_sig: Secp256k1ECDSARecSig) -> Tuple[bytes, int]:
    """
    Serialize an ECDSA signature in compact format (64 bytes + recovery id).

    :param rec_sig: initialized ECDSA recoverable signature
    :return: 64-byte compact signature serialization and recovery id
    :raises AssertionError: if rec_sig is invalid type
    """
    assert isinstance(rec_sig, Secp256k1ECDSARecSig)

    rec_id = ctypes.c_int()
    rec_id.value = 0
    output = ctypes.create_string_buffer(COMPACT_SIGNATURE_LENGTH)
    lib.secp256k1_ecdsa_recoverable_signature_serialize_compact(
        secp256k1_context_sign, output, ctypes.byref(rec_id), rec_sig
    )
    return output.raw[:COMPACT_SIGNATURE_LENGTH], rec_id.value


def ecdsa_sign_recoverable(seckey: bytes, msghash32: bytes) -> Secp256k1ECDSARecSig:
    """
    Create a recoverable ECDSA signature.

    :param seckey: 32-byte secret key
    :param msghash32: the 32-byte message hash being signed
    :return: initialized ECDSA recoverable signature
    :raises AssertionError: if secret key is not of type bytes and length 32
                            if msghash32 is not of type bytes and length 32
    :raises Libsecp256k1Exception: if nonce generation function failed,
                                   or the secret key was invalid
    """
    assert isinstance(seckey, bytes) and len(seckey) == SECKEY_LENGTH
    assert isinstance(msghash32, bytes) and len(msghash32) == HASH32

    rec_sig = ctypes.create_string_buffer(INTERNAL_RECOVERABLE_SIGNATURE_LENGTH)
    result = lib.secp256k1_ecdsa_sign_recoverable(
        secp256k1_context_sign, rec_sig, msghash32, seckey, None, None
    )
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception(
            "nonce generation function failed, or the secret key was invalid"
        )
    return rec_sig


def ecdsa_recover(rec_sig: Secp256k1ECDSARecSig, msghash32: bytes) -> Secp256k1Pubkey:
    """
    Recover an ECDSA public key from a signature.

    :param rec_sig: initialized ECDSA recoverable signature
    :param msghash32: the 32-byte message hash being signed
    :return: recovered public key
    :raises AssertionError: if rec_sig is invalid type
                            if msghash32 is not of type bytes and length 32
    :raises Libsecp256k1Exception: if public key recovery failed
    """
    assert isinstance(rec_sig, Secp256k1ECDSARecSig)
    assert isinstance(msghash32, bytes) and len(msghash32) == HASH32

    pubkey = ctypes.create_string_buffer(INTERNAL_PUBKEY_LENGTH)
    result = lib.secp256k1_ecdsa_recover(
        secp256k1_context_verify, pubkey, rec_sig, msghash32
    )
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception("failed to recover pubkey")
    return pubkey


_all__ = (
    "ecdsa_recoverable_signature_parse_compact",
    "ecdsa_recoverable_signature_convert",
    "ecdsa_recoverable_signature_serialize_compact",
    "ecdsa_sign_recoverable",
    "ecdsa_recover",
)
