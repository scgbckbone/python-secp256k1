import ctypes
from pysecp256k1.low_level import (
    lib,
    secp256k1_context_sign,
    enforce_type,
    assert_zero_return_code,
    has_secp256k1_ecdh,
    Libsecp256k1Exception,
    ctypes_functype,
)
from pysecp256k1.low_level.constants import Secp256k1Pubkey, SECKEY_LENGTH

if not has_secp256k1_ecdh:
    raise RuntimeError(
        "secp256k1 is not compiled with module 'ecdh'. "
        "Use '--enable-module-ecdh' during ./configure"
    )


ECDH_HASHFP_CLS = ctypes_functype(
    ctypes.c_int,
    ctypes.POINTER(ctypes.c_char * 32),
    ctypes.POINTER(ctypes.c_char * 32),
    ctypes.POINTER(ctypes.c_char * 32),
    ctypes.c_void_p,
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
def ecdh(
    seckey: bytes, pubkey: Secp256k1Pubkey, hashfp: ECDH_HASHFP_CLS = None
) -> bytes:
    """
    Compute an EC Diffie-Hellman secret in constant time.

    :param seckey: 32-byte scalar with which to multiply the point
    :param pubkey: initialized public key
    :param hashfp: custom hash function, if None use secp256k1_ecdh_hash_function_sha256
    :return: EC Diffie-Hellman secret
    :raises ValueError: if secret key is not of type bytes and length 32
                        if pubkey is invalid type
    :raises Libsecp256k1Exception: if scalar was invalid (zero or overflow)
                                   or hashfp returned 0
    """
    output = ctypes.create_string_buffer(SECKEY_LENGTH)
    result = lib.secp256k1_ecdh(
        secp256k1_context_sign, output, pubkey, seckey, hashfp, None
    )
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception(
            "scalar was invalid (zero or overflow) or hashfp returned 0"
        )
    return output.raw[:SECKEY_LENGTH]


__all__ = "ecdh"
