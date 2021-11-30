import ctypes
from pysecp256k1.low_level import (
    lib, secp256k1_context_sign, enforce_type, assert_zero_return_code,
    has_secp256k1_ecdh, Libsecp256k1Exception, enforce_length
)
from pysecp256k1.low_level.constants import secp256k1_pubkey, SECKEY_SIZE

if not has_secp256k1_ecdh:
    raise RuntimeError(
        "secp256k1 is not compiled with module 'ecdh'. "
        "Use '--enable-module-ecdh' during ./configure"
    )


# Compute an EC Diffie-Hellman secret in constant time
#
# Returns: 1: exponentiation was successful
#          0: scalar was invalid (zero or overflow) or hashfp returned 0
# Args:    ctx:        pointer to a context object.
# Out:     output:     pointer to an array to be filled by hashfp.
# In:      pubkey:     a pointer to a secp256k1_pubkey containing an initialized public key.
#          seckey:     a 32-byte scalar with which to multiply the point.
#          hashfp:     pointer to a hash function. If NULL,
#                      secp256k1_ecdh_hash_function_sha256 is used
#                      (in which case, 32 bytes will be written to output).
#          data:       arbitrary data pointer that is passed through to hashfp
#                      (can be NULL for secp256k1_ecdh_hash_function_sha256).
#
@enforce_type
def ecdh(seckey: bytes, pubkey: secp256k1_pubkey) -> bytes:
    enforce_length(seckey, "seckey", length=SECKEY_SIZE)
    output = ctypes.create_string_buffer(SECKEY_SIZE)
    result = lib.secp256k1_ecdh(
        secp256k1_context_sign, output, pubkey, seckey, None, None
    )
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception(
            "scalar was invalid (zero or overflow) or hashfp returned 0"
        )
    return output.raw[:SECKEY_SIZE]


__all__ = (
    "ecdh"
)
