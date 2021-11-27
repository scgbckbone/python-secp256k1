import ctypes
from typing import Optional
from pysecp256k1 import (
    lib, secp256k1_context_sign, secp256k1_context_verify, enforce_type,
    assert_zero_return_code,
)
from pysecp256k1.low_level.constants import (
    secp256k1_keypair, secp256k1_xonly_pubkey, COMPACT_SIGNATURE_SIZE, HASH32
)


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
def schnorrsig_sign(keypair: secp256k1_keypair, msghash32: bytes, aux_rand32: Optional[bytes] = None) -> bytes:
    enforce_type(keypair, secp256k1_keypair, "keypair")
    enforce_type(msghash32, bytes, "msghash32", length=HASH32)
    if aux_rand32 is not None:
        enforce_type(aux_rand32, bytes, "aux_rand32", length=HASH32)
    compact_sig = ctypes.create_string_buffer(COMPACT_SIGNATURE_SIZE)
    result = lib.secp256k1_schnorrsig_sign(
        secp256k1_context_sign, compact_sig, msghash32, keypair, aux_rand32
    )
    if result != 1:
        assert_zero_return_code(result)
        raise RuntimeError('secp256k1_schnorrsig_sign returned failure')
    return compact_sig.raw[:COMPACT_SIGNATURE_SIZE]


# Create a Schnorr signature with a more flexible API.
#
# Same arguments as secp256k1_schnorrsig_sign except that it allows signing
# variable length messages and accepts a pointer to an extraparams object that
# allows customizing signing by passing additional arguments.
#
# Creates the same signatures as schnorrsig_sign if msglen is 32 and the
# extraparams.ndata is the same as aux_rand32.
#
# In:     msg: the message being signed. Can only be NULL if msglen is 0.
#      msglen: length of the message
# extraparams: pointer to a extraparams object (can be NULL)
#
def schnorrsig_sign_custom(keypair: secp256k1_keypair, msg: bytes) -> bytes:
    enforce_type(keypair, secp256k1_keypair, "keypair")
    enforce_type(msg, bytes, "msg")
    compact_sig = ctypes.create_string_buffer(COMPACT_SIGNATURE_SIZE)
    result = lib.secp256k1_schnorrsig_sign_custom(
        secp256k1_context_sign, compact_sig, msg, len(msg), keypair, None
    )
    if result != 1:
        assert_zero_return_code(result)
        raise RuntimeError('secp256k1_schnorrsig_sign_custom returned failure')
    return compact_sig.raw[:COMPACT_SIGNATURE_SIZE]


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
def schnorrsig_verify(compact_sig: bytes, msg: bytes, xonly_pubkey: secp256k1_xonly_pubkey) -> bool:
    enforce_type(compact_sig, bytes, "compact_sig", length=COMPACT_SIGNATURE_SIZE)
    enforce_type(msg, bytes, "msg")
    enforce_type(xonly_pubkey, secp256k1_xonly_pubkey, "xonly_pubkey")
    result = lib.secp256k1_schnorrsig_verify(
        secp256k1_context_verify, compact_sig, msg, len(msg), xonly_pubkey
    )
    if result != 1:
        assert_zero_return_code(result)
        return False
    return True
