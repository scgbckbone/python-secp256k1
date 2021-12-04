import ctypes
from typing import Tuple
from pysecp256k1.low_level import (
    lib,
    secp256k1_context_sign,
    secp256k1_context_verify,
    enforce_type,
    assert_zero_return_code,
    has_secp256k1_recovery,
    Libsecp256k1Exception,
)
from pysecp256k1.low_level.constants import (
    COMPACT_SIGNATURE_LENGTH,
    INTERNAL_RECOVERABLE_SIGNATURE_LENGTH,
    INTERNAL_SIGNATURE_LENGTH,
    INTERNAL_PUBKEY_LENGTH,
    secp256k1_pubkey,
    secp256k1_ecdsa_recoverable_signature,
    secp256k1_ecdsa_signature,
)

if not has_secp256k1_recovery:
    raise RuntimeError(
        "secp256k1 is not compiled with module 'recovery'. "
        "Use '--enable-module-recovery' during ./configure"
    )


# Parse a compact ECDSA signature (64 bytes + recovery id).
#
# Returns: 1 when the signature could be parsed, 0 otherwise
# Args: ctx:     a secp256k1 context object
# Out:  sig:     a pointer to a signature object
# In:   input64: a pointer to a 64-byte compact signature
#       recid:   the recovery id (0, 1, 2 or 3)
#
@enforce_type
def ecdsa_recoverable_signature_parse_compact(
    compact_sig: bytes, rec_id: int
) -> secp256k1_ecdsa_recoverable_signature:
    """
    Parse a compact ECDSA signature (64 bytes + recovery id).

    :param compact_sig: 64-byte compact signature serialization
    :type compact_sig: bytes
    :param rec_id: recovery id (0, 1, 2 or 3)
    :type rec_id: int
    :return: ECDSA recoverable signature
    :rtype: secp256k1_ecdsa_recoverable_signature
    :raises ValueError: if compact_sig is not of type bytes and length 64
    :raises ValueError: if rec_id is not of type int and one of 0 or 1
    """
    rec_sig = ctypes.create_string_buffer(INTERNAL_RECOVERABLE_SIGNATURE_LENGTH)
    result = lib.secp256k1_ecdsa_recoverable_signature_parse_compact(
        secp256k1_context_verify, rec_sig, compact_sig, rec_id
    )
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception("signature could not be parsed")
    return rec_sig


# Convert a recoverable signature into a normal signature.
#
# Returns: 1
# Args: ctx:    a secp256k1 context object.
# Out:  sig:    a pointer to a normal signature.
# In:   sigin:  a pointer to a recoverable signature.
#
@enforce_type
def ecdsa_recoverable_signature_convert(
    rec_sig: secp256k1_ecdsa_recoverable_signature,
) -> secp256k1_ecdsa_signature:
    """
    Convert a recoverable signature into a normal signature.

    :param rec_sig: initialized ECDSA recoverable signature
    :type rec_sig: secp256k1_ecdsa_recoverable_signature
    :return: initialized ECDSA signature
    :rtype: secp256k1_ecdsa_signature
    :raises ValueError: if rec_sig is invalid type
    """
    sig = ctypes.create_string_buffer(INTERNAL_SIGNATURE_LENGTH)
    lib.secp256k1_ecdsa_recoverable_signature_convert(
        secp256k1_context_verify, sig, rec_sig
    )
    return sig


# Serialize an ECDSA signature in compact format (64 bytes + recovery id).
#
# Returns: 1
# Args: ctx:      a secp256k1 context object.
# Out:  output64: a pointer to a 64-byte array of the compact signature.
#       recid:    a pointer to an integer to hold the recovery id.
# In:   sig:      a pointer to an initialized signature object.
#
@enforce_type
def ecdsa_recoverable_signature_serialize_compact(
    rec_sig: secp256k1_ecdsa_recoverable_signature,
) -> Tuple[bytes, int]:
    """
    Serialize an ECDSA signature in compact format (64 bytes + recovery id).

    :param rec_sig: initialized ECDSA recoverable signature
    :type rec_sig: secp256k1_ecdsa_recoverable_signature
    :return: 64-byte compact signature serialization and recovery id
    :rtype: Tuple[bytes, int]
    :raises ValueError: if arguments are invalid
    """
    rec_id = ctypes.c_int()
    rec_id.value = 0
    output = ctypes.create_string_buffer(COMPACT_SIGNATURE_LENGTH)
    lib.secp256k1_ecdsa_recoverable_signature_serialize_compact(
        secp256k1_context_sign, output, ctypes.byref(rec_id), rec_sig
    )
    return output.raw[:COMPACT_SIGNATURE_LENGTH], rec_id.value


# Create a recoverable ECDSA signature.
#
# Returns: 1: signature created
#          0: the nonce generation function failed, or the secret key was invalid.
# Args:    ctx:       pointer to a context object, initialized for signing.
# Out:     sig:       pointer to an array where the signature will be placed.
# In:      msghash32: the 32-byte message hash being signed.
#          seckey:    pointer to a 32-byte secret key.
#          noncefp:   pointer to a nonce generation function. If NULL,
#                     secp256k1_nonce_function_default is used.
#          ndata:     pointer to arbitrary data used by the nonce generation function
#                     (can be NULL for secp256k1_nonce_function_default).
#
@enforce_type
def ecdsa_sign_recoverable(
    seckey: bytes, msghash32: bytes
) -> secp256k1_ecdsa_recoverable_signature:
    """
    Create a recoverable ECDSA signature.

    :param seckey: 32-byte secret key
    :type seckey: bytes
    :param msghash32: the 32-byte message hash being signed
    :type msghash32: bytes
    :return: initialized ECDSA recoverable signature
    :rtype: secp256k1_ecdsa_recoverable_signature
    :raises ValueError: if secret key is not of type bytes and length 32
    :raises ValueError: if msghash32 is not of type bytes and length 32
    :raises Libsecp256k1Exception: if nonce generation function failed,
                                   or the secret key was invalid
    """
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


# Recover an ECDSA public key from a signature.
#
# Returns: 1: public key successfully recovered (which guarantees a correct signature).
#          0: otherwise.
# Args:    ctx:       pointer to a context object, initialized for verification.
# Out:     pubkey:    pointer to the recovered public key.
# In:      sig:       pointer to initialized signature that supports pubkey recovery.
#          msghash32: the 32-byte message hash assumed to be signed.
#
@enforce_type
def ecdsa_recover(
    rec_sig: secp256k1_ecdsa_recoverable_signature, msghash32: bytes
) -> secp256k1_pubkey:
    """
    Recover an ECDSA public key from a signature.

    :param rec_sig: initialized ECDSA recoverable signature
    :type rec_sig: secp256k1_ecdsa_recoverable_signature
    :param msghash32: the 32-byte message hash being signed
    :type msghash32: bytes
    :return: recovered public key
    :rtype: secp256k1_pubkey
    :raises ValueError: if rec_sig is invalid type
    :raises ValueError: if msghash32 is not of type bytes and length 32
    :raises Libsecp256k1Exception: if public key recovery failed
    """
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
