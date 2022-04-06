import ctypes
from typing import Optional
from pysecp256k1.low_level import (
    lib,
    secp256k1_context_sign,
    secp256k1_context_verify,
    enforce_type,
    assert_zero_return_code,
    has_secp256k1_schnorrsig,
    Libsecp256k1Exception,
)
from pysecp256k1.low_level.constants import (
    Secp256k1Keypair,
    Secp256k1XonlyPubkey,
    SCHNORRSIG_EXTRAPARAMS_MAGIC,
    COMPACT_SIGNATURE_LENGTH,
)

if not has_secp256k1_schnorrsig:
    raise RuntimeError(
        "secp256k1 is not compiled with module 'schnorrsig'. "
        "use '--enable-module-schnorrsig' together with '--enable-experimental'"
        " during ./configure"
    )


class SchnorrsigExtraparams(ctypes.Structure):
    _fields_ = [
        ("magic", ctypes.c_char * 4),
        ("noncefp", ctypes.c_void_p),
        ("ndata", ctypes.c_void_p),
    ]


# Create a Schnorr signature.
#
# Does _not_ strictly follow BIP-340 because it does not verify the resulting
# signature. Instead, you can manually use secp256k1_schnorrsig_verify and
# abort if it fails.
#
# This function only signs 32-byte messages. If you have messages of a
# different size (or the same size but without a context-specific tag
# prefix), it is recommended to create a 32-byte message hash with
# secp256k1_tagged_sha256 and then sign the hash. Tagged hashing allows
# providing an context-specific tag for domain separation. This prevents
# signatures from being valid in multiple contexts by accident.
#
# Returns 1 on success, 0 on failure.
# Args:    ctx: pointer to a context object, initialized for signing.
# Out:   sig64: pointer to a 64-byte array to store the serialized signature.
# In:    msg32: the 32-byte message being signed.
#      keypair: pointer to an initialized keypair.
#   aux_rand32: 32 bytes of fresh randomness. While recommended to provide
#               this, it is only supplemental to security and can be NULL. A
#               NULL argument is treated the same as an all-zero one. See
#               BIP-340 "Default Signing" for a full explanation of this
#               argument and for guidance if randomness is expensive.
#
@enforce_type
def schnorrsig_sign32(
    keypair: Secp256k1Keypair, msg32: bytes, aux_rand32: Optional[bytes] = None
) -> bytes:
    """
    Create a Schnorr signature.

    Does _not_ strictly follow BIP-340 because it does not verify the resulting
    signature. Instead, you can manually use secp256k1_schnorrsig_verify and
    abort if it fails.

    This function only signs 32-byte messages. If you have messages of a
    different size (or the same size but without a context-specific tag
    prefix), it is recommended to create a 32-byte message hash with
    secp256k1_tagged_sha256 and then sign the hash. Tagged hashing allows
    providing an context-specific tag for domain separation. This prevents
    signatures from being valid in multiple contexts by accident.

    :param keypair: initialized keypair
    :param msg32: 32-byte message being signed
    :param aux_rand32: 32 bytes of fresh randomness. While recommended to provide
                       this, it is only supplemental to security and can be None.
                       None argument is treated the same as an all-zero one. See
                       BIP-340 "Default Signing" for a full explanation of this
                       argument and for guidance if randomness is expensive.
    :return: 64-byte serialized Schnorr signature
    :raises ValueError: if keypair is invalid type
                        if msg32 is not of type bytes and length 32
                        if aux_rand32 is not of type bytes and length 32
    :raises Libsecp256k1Exception: if schnorrsig_sign32 returned failure
    """
    compact_sig = ctypes.create_string_buffer(COMPACT_SIGNATURE_LENGTH)
    result = lib.secp256k1_schnorrsig_sign32(
        secp256k1_context_sign, compact_sig, msg32, keypair, aux_rand32
    )
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception("secp256k1_schnorrsig_sign32 returned failure")
    return compact_sig.raw[:COMPACT_SIGNATURE_LENGTH]


# Create a Schnorr signature with a more flexible API.
#
# Same arguments as secp256k1_schnorrsig_sign32 except that it allows signing
# variable length messages and accepts a pointer to an extraparams object that
# allows customizing signing by passing additional arguments.
#
# Creates the same signatures as schnorrsig_sign32 if msglen is 32 and the
# extraparams.ndata is the same as aux_rand32.
#
# In:     msg: the message being signed. Can only be NULL if msglen is 0.
#      msglen: length of the message
# extraparams: pointer to a extraparams object (can be NULL)
#
@enforce_type
def schnorrsig_sign_custom(
    keypair: Secp256k1Keypair, msg: bytes, aux_rand32: Optional[bytes] = None
) -> bytes:
    """
    Create a Schnorr signature with a more flexible API.

    Same arguments as secp256k1_schnorrsig_sign except that it allows signing
    variable length messages.

    Creates the same signatures as schnorrsig_sign32 if aux_rand32 is the same
    and msglen is 32.

    :param keypair: initialized keypair
    :param msg: message being signed
    :param aux_rand32: 32 bytes of fresh randomness. While recommended to provide
                   this, it is only supplemental to security and can be None.
                   None argument is treated the same as an all-zero one. See
                   BIP-340 "Default Signing" for a full explanation of this
                   argument and for guidance if randomness is expensive.
    :return: 64-byte serialized Schnorr signature
    :raises ValueError: if keypair is invalid type
                        if msg is not of type bytes
    :raises Libsecp256k1Exception: if schnorrsig_sign_custom returned failure
    """
    extraparams = None
    compact_sig = ctypes.create_string_buffer(COMPACT_SIGNATURE_LENGTH)
    if aux_rand32 is not None:
        extraparams = SchnorrsigExtraparams(
            SCHNORRSIG_EXTRAPARAMS_MAGIC,
            None,
            ctypes.cast(ctypes.create_string_buffer(aux_rand32), ctypes.c_void_p),
        )
        extraparams = ctypes.byref(extraparams)

    result = lib.secp256k1_schnorrsig_sign_custom(
        secp256k1_context_sign, compact_sig, msg, len(msg), keypair, extraparams
    )
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception("secp256k1_schnorrsig_sign_custom returned failure")
    return compact_sig.raw[:COMPACT_SIGNATURE_LENGTH]


# Verify a Schnorr signature.
#
# Returns: 1: correct signature
#          0: incorrect signature
# Args:    ctx: a secp256k1 context object, initialized for verification.
# In:    sig64: pointer to the 64-byte signature to verify.
#          msg: the message being verified. Can only be NULL if msglen is 0.
#       msglen: length of the message
#       pubkey: pointer to an x-only public key to verify with (cannot be NULL)
#
@enforce_type
def schnorrsig_verify(
    compact_sig: bytes, msg: bytes, xonly_pubkey: Secp256k1XonlyPubkey
) -> bool:
    """
    Verify a Schnorr signature.

    :param compact_sig: 64-byte compact signature serialization
    :param msg: message being verified
    :param xonly_pubkey: initialized xonly pubkey
    :return: whether signature is correct
    :raises ValueError: if compact_sig is not of type bytes and length 64
                        if msg is not of type bytes
                        if xonly_pubkey is invalid type
    """
    result = lib.secp256k1_schnorrsig_verify(
        secp256k1_context_verify, compact_sig, msg, len(msg), xonly_pubkey
    )
    if result != 1:
        assert_zero_return_code(result)
        return False
    return True


__all__ = ("schnorrsig_sign32", "schnorrsig_sign_custom", "schnorrsig_verify")
