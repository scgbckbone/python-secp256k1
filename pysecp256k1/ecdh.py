import ctypes
from pysecp256k1 import lib, secp256k1_context_sign
from pysecp256k1 import secp256k1_pubkey


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
def ecdh(seckey: bytes, pubkey: secp256k1_pubkey) -> bytes:
    if len(seckey) != 32:
        raise ValueError("secret data must be 32 bytes")
    output = ctypes.create_string_buffer(32)
    result = lib.secp256k1_ecdh(
        secp256k1_context_sign, output, pubkey, seckey, None, None
    )
    if result != 1:
        assert result == 0, f"Non-standard return code: {result}"
        raise RuntimeError("scalar was invalid (zero or overflow) or hashfp returned 0")
    return output.raw
