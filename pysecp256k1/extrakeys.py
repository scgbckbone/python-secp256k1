import ctypes
from typing import Tuple
from pysecp256k1.low_level import (
    lib,
    secp256k1_context_sign,
    secp256k1_context_verify,
    enforce_type,
    assert_zero_return_code,
    has_secp256k1_extrakeys,
    Libsecp256k1Exception,
)
from pysecp256k1.low_level.constants import (
    secp256k1_pubkey,
    secp256k1_xonly_pubkey,
    secp256k1_keypair,
    INTERNAL_PUBKEY_LENGTH,
    INTERNAL_KEYPAIR_LENGTH,
    XONLY_PUBKEY_LENGTH,
    SECKEY_LENGTH,
)

if not has_secp256k1_extrakeys:
    raise RuntimeError(
        "secp256k1 is not compiled with module 'extrakeys'. "
        "use '--enable-module-extrakeys' together with '--enable-experimental'"
        " during ./configure"
    )


# Parse a 32-byte sequence into a xonly_pubkey object.
#
# Returns: 1 if the public key was fully valid.
#          0 if the public key could not be parsed or is invalid.
#
# Args:   ctx: a secp256k1 context object.
# Out: pubkey: pointer to a pubkey object. If 1 is returned, it is set to a
#              parsed version of input. If not, it's set to an invalid value.
# In: input32: pointer to a serialized xonly_pubkey.
#
@enforce_type
def xonly_pubkey_parse(xonly_pubkey_ser: bytes) -> secp256k1_xonly_pubkey:
    xonly_pubkey = ctypes.create_string_buffer(INTERNAL_PUBKEY_LENGTH)
    result = lib.secp256k1_xonly_pubkey_parse(
        secp256k1_context_verify, xonly_pubkey, xonly_pubkey_ser
    )
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception("public key could not be parsed or is invalid")
    return xonly_pubkey


# Serialize an xonly_pubkey object into a 32-byte sequence.
#
# Returns: 1 always.
#
# Args:     ctx: a secp256k1 context object.
# Out: output32: a pointer to a 32-byte array to place the serialized key in.
# In:    pubkey: a pointer to a secp256k1_xonly_pubkey containing an initialized public key.
#
@enforce_type
def xonly_pubkey_serialize(xonly_pubkey: secp256k1_xonly_pubkey) -> bytes:
    xonly_pubkey_ser = ctypes.create_string_buffer(XONLY_PUBKEY_LENGTH)
    lib.secp256k1_xonly_pubkey_serialize(
        secp256k1_context_sign, xonly_pubkey_ser, xonly_pubkey
    )
    return xonly_pubkey_ser.raw[:XONLY_PUBKEY_LENGTH]


# Compare two x-only public keys using lexicographic order
#
# Returns: <0 if the first public key is less than the second
#          >0 if the first public key is greater than the second
#          0 if the two public keys are equal
# Args: ctx:      a secp256k1 context object.
# In:   pubkey1:  first public key to compare
#       pubkey2:  second public key to compare
#
@enforce_type
def xonly_pubkey_cmp(
    xonly_pubkey0: secp256k1_xonly_pubkey, xonly_pubkey1: secp256k1_xonly_pubkey
) -> int:
    return lib.secp256k1_xonly_pubkey_cmp(
        secp256k1_context_sign, xonly_pubkey0, xonly_pubkey1
    )


# Converts a secp256k1_pubkey into a secp256k1_xonly_pubkey.
#
# Returns: 1 if the public key was successfully converted
#          0 otherwise
#
# Args:         ctx: pointer to a context object.
# Out: xonly_pubkey: pointer to an x-only public key object for placing the converted public key.
#         pk_parity: Ignored if NULL. Otherwise, pointer to an integer that
#                    will be set to 1 if the point encoded by xonly_pubkey is
#                    the negation of the pubkey and set to 0 otherwise.
# In:        pubkey: pointer to a public key that is converted.
#
@enforce_type
def xonly_pubkey_from_pubkey(
    pubkey: secp256k1_pubkey,
) -> Tuple[secp256k1_xonly_pubkey, int]:
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


# Tweak an x-only public key by adding the generator multiplied with tweak32
# to it.
#
# Note that the resulting point can not in general be represented by an x-only
# pubkey because it may have an odd Y coordinate. Instead, the output_pubkey
# is a normal secp256k1_pubkey.
#
# Returns: 0 if the arguments are invalid or the resulting public key would be
#          invalid (only when the tweak is the negation of the corresponding
#          secret key). 1 otherwise.
#
# Args:           ctx: pointer to a context object initialized for verification.
# Out:  output_pubkey: pointer to a public key to store the result. Will be set
#                      to an invalid value if this function returns 0.
# In: internal_pubkey: pointer to an x-only pubkey to apply the tweak to.
#             tweak32: pointer to a 32-byte tweak. If the tweak is invalid
#                      according to secp256k1_ec_seckey_verify, this function
#                      returns 0. For uniformly random 32-byte arrays the
#                      chance of being invalid is negligible (around 1 in 2^128).
#
@enforce_type
def xonly_pubkey_tweak_add(
    xonly_pubkey: secp256k1_xonly_pubkey, tweak32: bytes
) -> secp256k1_pubkey:
    tweaked_pubkey = ctypes.create_string_buffer(INTERNAL_PUBKEY_LENGTH)
    result = lib.secp256k1_xonly_pubkey_tweak_add(
        secp256k1_context_verify, tweaked_pubkey, xonly_pubkey, tweak32
    )
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception(
            "0 if the arguments are invalid or the resulting public key "
            "would be invalid (only when the tweak is the negation "
            "of the corresponding secret key)"
        )
    return tweaked_pubkey


# Checks that a tweaked pubkey is the result of calling
# secp256k1_xonly_pubkey_tweak_add with internal_pubkey and tweak32.
#
# The tweaked pubkey is represented by its 32-byte x-only serialization and
# its pk_parity, which can both be obtained by converting the result of
# tweak_add to a secp256k1_xonly_pubkey.
#
# Note that this alone does _not_ verify that the tweaked pubkey is a
# commitment. If the tweak is not chosen in a specific way, the tweaked pubkey
# can easily be the result of a different internal_pubkey and tweak.
#
# Returns: 0 if the arguments are invalid or the tweaked pubkey is not the
#          result of tweaking the internal_pubkey with tweak32. 1 otherwise.
# Args:            ctx: pointer to a context object initialized for verification.
# In: tweaked_pubkey32: pointer to a serialized xonly_pubkey.
#    tweaked_pk_parity: the parity of the tweaked pubkey (whose serialization
#                       is passed in as tweaked_pubkey32). This must match the
#                       pk_parity value that is returned when calling
#                       secp256k1_xonly_pubkey with the tweaked pubkey, or
#                       this function will fail.
#      internal_pubkey: pointer to an x-only public key object to apply the tweak to.
#              tweak32: pointer to a 32-byte tweak.
#
@enforce_type
def xonly_pubkey_tweak_add_check(
    tweaked_pubkey32: bytes,
    tweaked_pk_parity: int,
    internal_pubkey: secp256k1_xonly_pubkey,
    tweak32: bytes,
) -> bool:
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


# Compute the keypair for a secret key.
#
# Returns: 1: secret was valid, keypair is ready to use
#          0: secret was invalid, try again with a different secret
# Args:    ctx: pointer to a context object, initialized for signing.
# Out: keypair: pointer to the created keypair.
# In:   seckey: pointer to a 32-byte secret key.
#
@enforce_type
def keypair_create(seckey: bytes) -> secp256k1_keypair:
    keypair = ctypes.create_string_buffer(INTERNAL_KEYPAIR_LENGTH)
    result = lib.secp256k1_keypair_create(secp256k1_context_sign, keypair, seckey)

    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception("secret key is invalid")
    return keypair


# Get the secret key from a keypair.
#
# Returns: 0 if the arguments are invalid. 1 otherwise.
# Args:   ctx: pointer to a context object.
# Out: seckey: pointer to a 32-byte buffer for the secret key.
# In: keypair: pointer to a keypair.
#
@enforce_type
def keypair_sec(keypair: secp256k1_keypair) -> bytes:
    seckey = ctypes.create_string_buffer(SECKEY_LENGTH)
    result = lib.secp256k1_keypair_sec(secp256k1_context_verify, seckey, keypair)
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception("invalid arguments")
    return seckey.raw[:SECKEY_LENGTH]


# Get the public key from a keypair.
#
# Returns: 0 if the arguments are invalid. 1 otherwise.
# Args:    ctx: pointer to a context object.
# Out: pubkey: pointer to a pubkey object. If 1 is returned, it is set to
#              the keypair public key. If not, it's set to an invalid value.
# In: keypair: pointer to a keypair.
#
@enforce_type
def keypair_pub(keypair: secp256k1_keypair) -> secp256k1_pubkey:
    pubkey = ctypes.create_string_buffer(INTERNAL_PUBKEY_LENGTH)
    result = lib.secp256k1_keypair_pub(secp256k1_context_verify, pubkey, keypair)
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception("invalid arguments")
    return pubkey


# Get the x-only public key from a keypair.
#
# This is the same as calling secp256k1_keypair_pub and then
# secp256k1_xonly_pubkey_from_pubkey.
#
# Returns: 0 if the arguments are invalid. 1 otherwise.
# Args:   ctx: pointer to a context object.
# Out: pubkey: pointer to an xonly_pubkey object. If 1 is returned, it is set
#              to the keypair public key after converting it to an
#              xonly_pubkey. If not, it's set to an invalid value.
#   pk_parity: Ignored if NULL. Otherwise, pointer to an integer that will be set to the
#              pk_parity argument of secp256k1_xonly_pubkey_from_pubkey.
# In: keypair: pointer to a keypair.
#
@enforce_type
def keypair_xonly_pub(keypair: secp256k1_keypair) -> Tuple[secp256k1_xonly_pubkey, int]:
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


# Tweak a keypair by adding tweak32 to the secret key and updating the public
# key accordingly.
#
# Calling this function and then secp256k1_keypair_pub results in the same
# public key as calling secp256k1_keypair_xonly_pub and then
# secp256k1_xonly_pubkey_tweak_add.
#
# Returns: 0 if the arguments are invalid or the resulting keypair would be
#          invalid (only when the tweak is the negation of the keypair's
#          secret key). 1 otherwise.
#
# Args:       ctx: pointer to a context object initialized for verification.
# In/Out: keypair: pointer to a keypair to apply the tweak to. Will be set to
#                  an invalid value if this function returns 0.
# In:     tweak32: pointer to a 32-byte tweak. If the tweak is invalid according
#                  to secp256k1_ec_seckey_verify, this function returns 0. For
#                  uniformly random 32-byte arrays the chance of being invalid
#                  is negligible (around 1 in 2^128).
#
@enforce_type
def keypair_xonly_tweak_add(keypair: secp256k1_keypair, tweak32: bytes):
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
