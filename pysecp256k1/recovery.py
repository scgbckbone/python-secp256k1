import ctypes
from pysecp256k1.low_level import (
    lib, secp256k1_context_sign, secp256k1_context_verify, enforce_type,
    assert_zero_return_code, has_secp256k1_recovery, Libsecp256k1Exception,
    enforce_length
)
from pysecp256k1.low_level.constants import (
    COMPACT_SIGNATURE_SIZE, INTERNAL_RECOVERABLE_SIGNATURE_SIZE,
    INTERNAL_SIGNATURE_SIZE, INTERNAL_PUBKEY_SIZE, HASH32, SECKEY_SIZE,
    secp256k1_ecdsa_recoverable_signature, secp256k1_pubkey,
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
def ecdsa_recoverable_signature_parse_compact(compact_sig: bytes, rec_id: int) -> secp256k1_ecdsa_recoverable_signature:
    enforce_length(compact_sig, "compact_sig", length=COMPACT_SIGNATURE_SIZE)
    rec_sig = ctypes.create_string_buffer(INTERNAL_RECOVERABLE_SIGNATURE_SIZE)
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
def ecdsa_recoverable_signature_convert(rec_sig: secp256k1_ecdsa_recoverable_signature) -> secp256k1_ecdsa_signature:
    sig = ctypes.create_string_buffer(INTERNAL_SIGNATURE_SIZE)
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
def ecdsa_recoverable_signature_serialize_compact(rec_sig: secp256k1_ecdsa_recoverable_signature):
    rec_id = ctypes.c_int()
    rec_id.value = 0
    output = ctypes.create_string_buffer(COMPACT_SIGNATURE_SIZE)
    lib.secp256k1_ecdsa_recoverable_signature_serialize_compact(
        secp256k1_context_sign, output, ctypes.byref(rec_id), rec_sig
    )
    return output.raw[:COMPACT_SIGNATURE_SIZE], rec_id.value


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
def ecdsa_sign_recoverable(seckey: bytes, msghash32: bytes) -> secp256k1_ecdsa_recoverable_signature:
    enforce_length(seckey, "seckey", length=SECKEY_SIZE)
    enforce_length(msghash32, "msghash32", length=HASH32)
    rec_sig = ctypes.create_string_buffer(INTERNAL_RECOVERABLE_SIGNATURE_SIZE)
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
def ecdsa_recover(rec_sig: secp256k1_ecdsa_recoverable_signature, msghash32: bytes) -> secp256k1_pubkey:
    enforce_length(msghash32, "msghash32", length=HASH32)
    pubkey = ctypes.create_string_buffer(INTERNAL_PUBKEY_SIZE)
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
    "ecdsa_recover"
)
