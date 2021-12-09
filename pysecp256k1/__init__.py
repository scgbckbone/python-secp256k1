import os
import ctypes
from typing import List, Optional
from pysecp256k1.low_level import (
    lib,
    secp256k1_context_sign,
    secp256k1_context_verify,
    enforce_type,
    assert_zero_return_code,
    Libsecp256k1Exception,
    callback_func_type,
)
from pysecp256k1.low_level.constants import (
    Secp256k1Context,
    Secp256k1Pubkey,
    Secp256k1ECDSASignature,
    PUBLIC_KEY_LENGTH,
    COMPRESSED_PUBLIC_KEY_LENGTH,
    COMPACT_SIGNATURE_LENGTH,
    DER_SIGNATURE_LENGTH,
    INTERNAL_PUBKEY_LENGTH,
    INTERNAL_SIGNATURE_LENGTH,
    SECP256K1_EC_UNCOMPRESSED,
    SECP256K1_EC_COMPRESSED,
    SECP256K1_CONTEXT_SIGN,
    SECP256K1_CONTEXT_VERIFY,
    SECKEY_LENGTH,
    HASH32,
)


# Create a secp256k1 context object (in dynamically allocated memory).
#
# This function uses malloc to allocate memory. It is guaranteed that malloc is
# called at most once for every call of this function. If you need to avoid dynamic
# memory allocation entirely, see the functions in secp256k1_preallocated.h.
#
# Returns: a newly created context object.
# In:      flags: which parts of the context to initialize.
#
# See also secp256k1_context_randomize.
#
@enforce_type
def context_create(flags: int) -> Secp256k1Context:
    if flags not in (
        SECP256K1_CONTEXT_SIGN,
        SECP256K1_CONTEXT_VERIFY,
        (SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY),
    ):
        raise ValueError(
            "Value for flags is unexpected. "
            "Must be either SECP256K1_CONTEXT_SIGN, SECP256K1_CONTEXT_VERIFY, "
            "or a combination of these two"
        )

    ctx = lib.secp256k1_context_create(flags)
    if ctx is None:
        raise Libsecp256k1Exception("secp256k1_context_create returned None")
    return ctx


# Copy a secp256k1 context object (into dynamically allocated memory).
#
# This function uses malloc to allocate memory. It is guaranteed that malloc is
# called at most once for every call of this function. If you need to avoid dynamic
# memory allocation entirely, see the functions in secp256k1_preallocated.h.
#
# Returns: a newly created context object.
# Args:    ctx: an existing context to copy
#
@enforce_type
def context_clone(ctx: Secp256k1Context) -> Secp256k1Context:
    cloned_ctx = lib.secp256k1_context_clone(ctx)
    if cloned_ctx is None:
        raise Libsecp256k1Exception("secp256k1_context_clone returned None")
    return cloned_ctx


# Destroy a secp256k1 context object (created in dynamically allocated memory).
#
# The context pointer may not be used afterwards.
#
# The context to destroy must have been created using secp256k1_context_create
# or secp256k1_context_clone. If the context has instead been created using
# secp256k1_context_preallocated_create or secp256k1_context_preallocated_clone, the
# behaviour is undefined. In that case, secp256k1_context_preallocated_destroy must
# be used instead.
#
# Args:   ctx: an existing context to destroy, constructed using
#              secp256k1_context_create or secp256k1_context_clone
#
@enforce_type
def context_destroy(ctx: Secp256k1Context) -> None:
    lib.secp256k1_context_destroy(ctx)
    del ctx


# Set a callback function to be called when an illegal argument is passed to
# an API call. It will only trigger for violations that are mentioned
# explicitly in the header.
#
# The philosophy is that these shouldn't be dealt with through a
# specific return value, as calling code should not have branches to deal with
# the case that this code itself is broken.
#
# On the other hand, during debug stage, one would want to be informed about
# such mistakes, and the default (crashing) may be inadvisable.
# When this callback is triggered, the API function called is guaranteed not
# to cause a crash, though its return value and output arguments are
# undefined.
#
# When this function has not been called (or called with fn==NULL), then the
# default handler will be used. The library provides a default handler which
# writes the message to stderr and calls abort. This default handler can be
# replaced at link time if the preprocessor macro
# USE_EXTERNAL_DEFAULT_CALLBACKS is defined, which is the case if the build
# has been configured with --enable-external-default-callbacks. Then the
# following two symbols must be provided to link against:
#  - void secp256k1_default_illegal_callback_fn(const char* message, void* data);
#  - void secp256k1_default_error_callback_fn(const char* message, void* data);
# The library can call these default handlers even before a proper callback data
# pointer could have been set using secp256k1_context_set_illegal_callback or
# secp256k1_context_set_error_callback, e.g., when the creation of a context
# fails. In this case, the corresponding default handler will be called with
# the data pointer argument set to NULL.
#
# Args: ctx:  an existing context object.
# In:   fun:  a pointer to a function to call when an illegal argument is
#             passed to the API, taking a message and an opaque pointer.
#             (NULL restores the default handler.)
#       data: the opaque pointer to pass to fun above, must be NULL for the default handler.
#
# See also secp256k1_context_set_error_callback.
#
@enforce_type
def context_set_illegal_callback(
    ctx: Secp256k1Context, f: callback_func_type, data
) -> None:
    lib.secp256k1_context_set_illegal_callback(ctx, f, data)


# Set a callback function to be called when an internal consistency check
# fails. The default is crashing.
#
# This can only trigger in case of a hardware failure, miscompilation,
# memory corruption, serious bug in the library, or other error would can
# otherwise result in undefined behaviour. It will not trigger due to mere
# incorrect usage of the API (see secp256k1_context_set_illegal_callback
# for that). After this callback returns, anything may happen, including
# crashing.
#
# Args: ctx:  an existing context object.
# In:   fun:  a pointer to a function to call when an internal error occurs,
#             taking a message and an opaque pointer (NULL restores the
#             default handler, see secp256k1_context_set_illegal_callback
#             for details).
#       data: the opaque pointer to pass to fun above, must be NULL for the default handler.
#
# See also secp256k1_context_set_illegal_callback.
#
@enforce_type
def context_set_error_callback(
    ctx: Secp256k1Context, f: callback_func_type, data
) -> None:
    lib.secp256k1_context_set_error_callback(ctx, f, data)


# Parse a variable-length public key into the pubkey object.
#
# Returns: 1 if the public key was fully valid.
#          0 if the public key could not be parsed or is invalid.
# Args: ctx:      a secp256k1 context object.
# Out:  pubkey:   pointer to a pubkey object. If 1 is returned, it is set to a
#                 parsed version of input. If not, its value is undefined.
# In:   input:    pointer to a serialized public key
#       inputlen: length of the array pointed to by input
#
# This function supports parsing compressed (33 bytes, header byte 0x02 or
# 0x03), uncompressed (65 bytes, header byte 0x04), or hybrid (65 bytes, header
# byte 0x06 or 0x07) format public keys.
#
@enforce_type
def ec_pubkey_parse(pubkey_ser: bytes) -> Secp256k1Pubkey:
    """
    Parse a variable-length public key into the pubkey object.

    This function supports parsing following public key formats:
        1.) compressed (33 bytes, header byte 0x02 or 0x03)
        2.) uncompressed (65 bytes, header byte 0x04)
        3.) hybrid (65 bytes, header byte 0x06 or 0x07)

    :param pubkey_ser: public key serialization
    :return: initialized public key
    :raises ValueError: if pubkey_ser is not of length 33 or 65
    :raises Libsecp256k1Exception: if pubkey is invalid or could not be parsed
    """
    pubkey = ctypes.create_string_buffer(INTERNAL_PUBKEY_LENGTH)
    result = lib.secp256k1_ec_pubkey_parse(
        secp256k1_context_verify, pubkey, pubkey_ser, len(pubkey_ser)
    )
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception("pubkey could not be parsed or is invalid")
    return pubkey


# Serialize a pubkey object into a serialized byte sequence.
#
# Returns: 1 always.
# Args:   ctx:        a secp256k1 context object.
# Out:    output:     a pointer to a 65-byte (if compressed==0) or 33-byte (if
#                     compressed==1) byte array to place the serialized key
#                     in.
# In/Out: outputlen:  a pointer to an integer which is initially set to the
#                     size of output, and is overwritten with the written
#                     size.
# In:     pubkey:     a pointer to a secp256k1_pubkey containing an
#                     initialized public key.
#         flags:      SECP256K1_EC_COMPRESSED if serialization should be in
#                     compressed format, otherwise SECP256K1_EC_UNCOMPRESSED.
#
@enforce_type
def ec_pubkey_serialize(pubkey: Secp256k1Pubkey, compressed: bool = True) -> bytes:
    """
    Serialize a pubkey object into a serialized byte sequence.

    :param pubkey: initialized public key
    :param compressed: if serialization should be in compressed format
    :return: public key serialization
    :raises ValueError: if arguments are invalid type
    """
    pub_size = ctypes.c_size_t()
    pub_size.value = COMPRESSED_PUBLIC_KEY_LENGTH if compressed else PUBLIC_KEY_LENGTH
    pubkey_ser = ctypes.create_string_buffer(pub_size.value)

    lib.secp256k1_ec_pubkey_serialize(
        secp256k1_context_verify,
        pubkey_ser,
        ctypes.byref(pub_size),
        pubkey,
        SECP256K1_EC_COMPRESSED if compressed else SECP256K1_EC_UNCOMPRESSED,
    )
    return pubkey_ser.raw[: pub_size.value]


# Compare two public keys using lexicographic (of compressed serialization) order
#
# Returns: <0 if the first public key is less than the second
#          >0 if the first public key is greater than the second
#          0 if the two public keys are equal
# Args: ctx:      a secp256k1 context object.
# In:   pubkey1:  first public key to compare
#       pubkey2:  second public key to compare
#
@enforce_type
def ec_pubkey_cmp(pubkey0: Secp256k1Pubkey, pubkey1: Secp256k1Pubkey) -> int:
    """
    Compare two public keys using lexicographic (of compressed serialization)
    order.

    :param pubkey0: initialized public key no. 0
    :param pubkey1: initialized public key no. 1
    :return: <0 if the first public key is less than the second
             >0 if the first public key is greater than the second
             0 if the two public keys are equal
    :raises ValueError: if arguments are invalid type
    """
    return lib.secp256k1_ec_pubkey_cmp(secp256k1_context_sign, pubkey0, pubkey1)


# Parse an ECDSA signature in compact (64 bytes) format.
#
# Returns: 1 when the signature could be parsed, 0 otherwise.
# Args: ctx:      a secp256k1 context object
# Out:  sig:      a pointer to a signature object
# In:   input64:  a pointer to the 64-byte array to parse
#
# The signature must consist of a 32-byte big endian R value, followed by a
# 32-byte big endian S value. If R or S fall outside of [0..order-1], the
# encoding is invalid. R and S with value 0 are allowed in the encoding.
#
# After the call, sig will always be initialized. If parsing failed or R or
# S are zero, the resulting sig value is guaranteed to fail validation for any
# message and public key.
#
@enforce_type
def ecdsa_signature_parse_compact(compact_sig: bytes) -> Secp256k1ECDSASignature:
    """
    Parse an ECDSA signature in compact (64 bytes) format.

    The signature must consist of a 32-byte big endian R value, followed by a
    32-byte big endian S value. If R or S fall outside of [0..order-1], the
    encoding is invalid. R and S with value 0 are allowed in the encoding.

    After the call, sig will always be initialized. If parsing failed or R or
    S are zero, the resulting sig value is guaranteed to fail validation for any
    message and public key.

    :param compact_sig: compact ECDSA signature serialization
    :return: initialized ECDSA signature
    :raises ValueError: if compact_sig is not of type bytes and length 64
    :raises Libsecp256k1Exception: if compact_sig could not be parsed
    """
    sig = ctypes.create_string_buffer(INTERNAL_SIGNATURE_LENGTH)
    result = lib.secp256k1_ecdsa_signature_parse_compact(
        secp256k1_context_verify, sig, compact_sig
    )
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception("signature could not be parsed")
    return sig


# Parse a DER ECDSA signature.
#
# Returns: 1 when the signature could be parsed, 0 otherwise.
# Args: ctx:      a secp256k1 context object
# Out:  sig:      a pointer to a signature object
# In:   input:    a pointer to the signature to be parsed
#       inputlen: the length of the array pointed to be input
#
# This function will accept any valid DER encoded signature, even if the
# encoded numbers are out of range.
#
# After the call, sig will always be initialized. If parsing failed or the
# encoded numbers are out of range, signature validation with it is
# guaranteed to fail for every message and public key.
#
@enforce_type
def ecdsa_signature_parse_der(der_sig: bytes) -> Secp256k1ECDSASignature:
    """
    Parse a DER ECDSA signature.

    This function will accept any valid DER encoded signature, even if the
    encoded numbers are out of range.

    After the call, sig will always be initialized. If parsing failed or the
    encoded numbers are out of range, signature validation with it is
    guaranteed to fail for every message and public key.

    :param der_sig: DER ECDSA signature serialization
    :return: initialized ECDSA signature
    :raises ValueError: if der_sig is not of type bytes and length 64
    :raises Libsecp256k1Exception: if der_sig could not be parsed
    """
    sig = ctypes.create_string_buffer(INTERNAL_SIGNATURE_LENGTH)
    result = lib.secp256k1_ecdsa_signature_parse_der(
        secp256k1_context_verify, sig, der_sig, len(der_sig)
    )

    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception("signature could not be parsed")
    return sig


# Serialize an ECDSA signature in DER format.
#
# Returns: 1 if enough space was available to serialize, 0 otherwise
# Args:   ctx:       a secp256k1 context object
# Out:    output:    a pointer to an array to store the DER serialization
# In/Out: outputlen: a pointer to a length integer. Initially, this integer
#                    should be set to the length of output. After the call
#                    it will be set to the length of the serialization (even
#                    if 0 was returned).
# In:     sig:       a pointer to an initialized signature object
#
@enforce_type
def ecdsa_signature_serialize_der(sig: Secp256k1ECDSASignature) -> bytes:
    """
    Serialize an ECDSA signature in DER format.

    :param sig: initialized ECDSA signature
    :return: DER ECDSA signature serialization
    :raises ValueError: if sig is invalid type
    :raises Libsecp256k1Exception: if not enough space was available to serialize
    """
    sig_size = ctypes.c_size_t()
    sig_size.value = DER_SIGNATURE_LENGTH
    der_sig = ctypes.create_string_buffer(DER_SIGNATURE_LENGTH)

    result = lib.secp256k1_ecdsa_signature_serialize_der(
        secp256k1_context_sign, der_sig, ctypes.byref(sig_size), sig
    )
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception(
            "not enough space was available to serialize signature"
        )
    return der_sig.raw[: sig_size.value]


# Serialize an ECDSA signature in compact (64 byte) format.
#
# Returns: 1
# Args:   ctx:       a secp256k1 context object
# Out:    output64:  a pointer to a 64-byte array to store the compact serialization
# In:     sig:       a pointer to an initialized signature object
#
# See secp256k1_ecdsa_signature_parse_compact for details about the encoding.
#
@enforce_type
def ecdsa_signature_serialize_compact(sig: Secp256k1ECDSASignature) -> bytes:
    """
    Serialize an ECDSA signature in compact (64 byte) format.

    :param sig: initialized ECDSA signature
    :return: compact ECDSA signature serialization
    :raises ValueError: if sig is invalid type
    """
    compact_sig = ctypes.create_string_buffer(COMPACT_SIGNATURE_LENGTH)
    lib.secp256k1_ecdsa_signature_serialize_compact(
        secp256k1_context_verify, compact_sig, sig
    )
    return compact_sig.raw[:COMPACT_SIGNATURE_LENGTH]


# Verify an ECDSA signature.
#
# Returns: 1: correct signature
#          0: incorrect or unparseable signature
# Args:    ctx:       a secp256k1 context object, initialized for verification.
# In:      sig:       the signature being verified.
#          msghash32: the 32-byte message hash being verified.
#                     The verifier must make sure to apply a cryptographic
#                     hash function to the message by itself and not accept an
#                     msghash32 value directly. Otherwise, it would be easy to
#                     create a "valid" signature without knowledge of the
#                     secret key. See also
#                     https://bitcoin.stackexchange.com/a/81116/35586 for more
#                     background on this topic.
#          pubkey:    pointer to an initialized public key to verify with.
#
# To avoid accepting malleable signatures, only ECDSA signatures in lower-S
# form are accepted.
#
# If you need to accept ECDSA signatures from sources that do not obey this
# rule, apply secp256k1_ecdsa_signature_normalize to the signature prior to
# validation, but be aware that doing so results in malleable signatures.
#
# For details, see the comments for that function.
#
@enforce_type
def ecdsa_verify(
    sig: Secp256k1ECDSASignature, pubkey: Secp256k1Pubkey, msghash32: bytes
) -> bool:
    """
    Verify an ECDSA signature.

    To avoid accepting malleable signatures, only ECDSA signatures in lower-S
    form are accepted.

    If you need to accept ECDSA signatures from sources that do not obey this
    rule, apply secp256k1_ecdsa_signature_normalize to the signature prior to
    validation, but be aware that doing so results in malleable signatures.

    :param sig: initialized ECDSA signature
    :param pubkey: initialized public key
    :param msghash32: the 32-byte message hash being signed
    :return: whether signature is correct or not (or unparseable)
    :raises ValueError: if arguments are invalid type
                        if msghash32 is not of length 32
    """
    result = lib.secp256k1_ecdsa_verify(
        secp256k1_context_verify, sig, msghash32, pubkey
    )
    if result != 1:
        assert_zero_return_code(result)
        return False
    return True


# Convert a signature to a normalized lower-S form.
#
# Returns: 1 if sigin was not normalized, 0 if it already was.
# Args: ctx:    a secp256k1 context object
# Out:  sigout: a pointer to a signature to fill with the normalized form,
#               or copy if the input was already normalized. (can be NULL if
#               you're only interested in whether the input was already
#               normalized).
# In:   sigin:  a pointer to a signature to check/normalize (can be identical to sigout)
#
# With ECDSA a third-party can forge a second distinct signature of the same
# message, given a single initial signature, but without knowing the key. This
# is done by negating the S value modulo the order of the curve, 'flipping'
# the sign of the random point R which is not included in the signature.
#
# Forgery of the same message isn't universally problematic, but in systems
# where message malleability or uniqueness of signatures is important this can
# cause issues. This forgery can be blocked by all verifiers forcing signers
# to use a normalized form.
#
# The lower-S form reduces the size of signatures slightly on average when
# variable length encodings (such as DER) are used and is cheap to verify,
# making it a good choice. Security of always using lower-S is assured because
# anyone can trivially modify a signature after the fact to enforce this
# property anyway.
#
# The lower S value is always between 0x1 and
# 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0,
# inclusive.
#
# No other forms of ECDSA malleability are known and none seem likely, but
# there is no formal proof that ECDSA, even with this additional restriction,
# is free of other malleability. Commonly used serialization schemes will also
# accept various non-unique encodings, so care should be taken when this
# property is required for an application.
#
# The secp256k1_ecdsa_sign function will by default create signatures in the
# lower-S form, and secp256k1_ecdsa_verify will not accept others. In case
# signatures come from a system that cannot enforce this property,
# secp256k1_ecdsa_signature_normalize must be called before verification.
#
@enforce_type
def ecdsa_signature_normalize(
    sig: Secp256k1ECDSASignature,
) -> Secp256k1ECDSASignature:
    """
    Convert a signature to a normalized lower-S form.

    :param sig: initialized ECDSA signature
    :return: initialized ECDSA signature in lower-S form
    :raises ValueError: if sig is invalid type
    """
    lib.secp256k1_ecdsa_signature_normalize(secp256k1_context_verify, sig, sig)
    return sig


# Create an ECDSA signature.
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
#                     (can be NULL). If it is non-NULL and
#                     secp256k1_nonce_function_default is used, then ndata must be a
#                     pointer to 32-bytes of additional data.
#
# The created signature is always in lower-S form. See
# secp256k1_ecdsa_signature_normalize for more details.
#
@enforce_type
def ecdsa_sign(seckey: bytes, msghash32: bytes) -> Secp256k1ECDSASignature:
    """
    Create an ECDSA signature.

    :param seckey: 32-byte secret key
    :param msghash32: the 32-byte message hash being signed
    :return: initialized ECDSA signature
    :raises ValueError: if secret key is not of type bytes and length 32
                        if msghash32 is not of type bytes and length 32
    :raises Libsecp256k1Exception: if nonce generation function failed,
                                   or the secret key was invalid
    """
    sig = ctypes.create_string_buffer(INTERNAL_SIGNATURE_LENGTH)
    result = lib.secp256k1_ecdsa_sign(
        secp256k1_context_sign, sig, msghash32, seckey, None, None
    )
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception(
            "nonce generation function failed, or the secret key was invalid"
        )
    return sig


# Verify an ECDSA secret key.
#
# A secret key is valid if it is not 0 and less than the secp256k1 curve order
# when interpreted as an integer (most significant byte first). The
# probability of choosing a 32-byte string uniformly at random which is an
# invalid secret key is negligible.
#
# Returns: 1: secret key is valid
#          0: secret key is invalid
# Args:    ctx: pointer to a context object.
# In:      seckey: pointer to a 32-byte secret key.
#
@enforce_type
def ec_seckey_verify(seckey: bytes) -> None:
    """
    Verify an ECDSA secret key.

    A secret key is valid if it is not 0 and less than the secp256k1 curve order
    when interpreted as an integer (most significant byte first).

    :param seckey: 32-byte secret key
    :return: None
    :raises ValueError: if secret key is not of type bytes and length 32
    :raises Libsecp256k1Exception: if secret key is invalid
    """
    result = lib.secp256k1_ec_seckey_verify(secp256k1_context_sign, seckey)
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception("secret key is invalid")


# Compute the public key for a secret key.
#
# Returns: 1: secret was valid, public key stores.
#          0: secret was invalid, try again.
# Args:    ctx:    pointer to a context object, initialized for signing.
# Out:     pubkey: pointer to the created public key.
# In:      seckey: pointer to a 32-byte secret key.
#
@enforce_type
def ec_pubkey_create(seckey: bytes) -> Secp256k1Pubkey:
    """
    Compute the public key for a secret key.

    :param seckey: 32-byte secret key
    :return: initialized public key
    :raises ValueError: if secret key is not of type bytes and length 32
    :raises Libsecp256k1Exception: if secret key is invalid
    """
    pubkey = ctypes.create_string_buffer(INTERNAL_PUBKEY_LENGTH)
    result = lib.secp256k1_ec_pubkey_create(secp256k1_context_sign, pubkey, seckey)
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception("secret key is invalid")
    return pubkey


# Negates a secret key in place.
#
# Returns: 0 if the given secret key is invalid according to
#          secp256k1_ec_seckey_verify. 1 otherwise
# Args:   ctx:    pointer to a context object
# In/Out: seckey: pointer to the 32-byte secret key to be negated. If the
#                 secret key is invalid according to
#                 secp256k1_ec_seckey_verify, this function returns 0 and
#                 seckey will be set to some unspecified value.
#
@enforce_type
def ec_seckey_negate(seckey: bytes) -> bytes:
    """
    Negates a secret key in place.

    :param seckey: 32-byte secret key
    :return: negated 32-byte secret key
    :raises ValueError: if secret key is not of type bytes and length 32
    :raises Libsecp256k1Exception: if secret key is invalid
    """
    negated_seckey = ctypes.create_string_buffer(seckey)
    result = lib.secp256k1_ec_seckey_negate(secp256k1_context_sign, negated_seckey)
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception("secret key is invalid")
    return negated_seckey.raw[:SECKEY_LENGTH]


# Negates a public key in place.
#
# Returns: 1 always
# Args:   ctx:        pointer to a context object
# In/Out: pubkey:     pointer to the public key to be negated.
#
@enforce_type
def ec_pubkey_negate(pubkey: Secp256k1Pubkey) -> Secp256k1Pubkey:
    """
    Negates a public key in place.

    :param pubkey: initialized public key
    :return: negated public key
    :raises ValueError: if pubkey is invalid type
    """
    lib.secp256k1_ec_pubkey_negate(secp256k1_context_verify, pubkey)
    return pubkey


# Tweak a secret key by adding tweak to it.
#
# Returns: 0 if the arguments are invalid or the resulting secret key would be
#          invalid (only when the tweak is the negation of the secret key). 1
#          otherwise.
# Args:    ctx:   pointer to a context object.
# In/Out: seckey: pointer to a 32-byte secret key. If the secret key is
#                 invalid according to secp256k1_ec_seckey_verify, this
#                 function returns 0. seckey will be set to some unspecified
#                 value if this function returns 0.
# In:    tweak32: pointer to a 32-byte tweak. If the tweak is invalid according to
#                 secp256k1_ec_seckey_verify, this function returns 0. For
#                 uniformly random 32-byte arrays the chance of being invalid
#                 is negligible (around 1 in 2^128).
#
@enforce_type
def ec_seckey_tweak_add(seckey: bytes, tweak32: bytes) -> bytes:
    """
    Tweak a secret key by adding tweak to it.

    :param seckey: 32-byte secret key
    :param tweak32: 32-byte tweak
    :return: tweaked seckey
    :raises ValueError: if secret key is not of type bytes and length 32
                        if tweak32 is not of type bytes and length 32
    :raises Libsecp256k1Exception: arguments are invalid or the resulting secret
                                   key would be invalid (only when the tweak
                                   is the negation of the secret key)
    """
    tweaked_seckey = ctypes.create_string_buffer(seckey)
    result = lib.secp256k1_ec_seckey_tweak_add(
        secp256k1_context_sign, tweaked_seckey, tweak32
    )
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception(
            "arguments are invalid or the resulting secret key would be invalid"
            " (only when the tweak is the negation of the secret key)"
        )
    return tweaked_seckey.raw[:SECKEY_LENGTH]


# Tweak a public key by adding tweak times the generator to it.
#
# Returns: 0 if the arguments are invalid or the resulting public key would be
#          invalid (only when the tweak is the negation of the corresponding
#          secret key). 1 otherwise.
# Args:    ctx:   pointer to a context object initialized for validation.
# In/Out: pubkey: pointer to a public key object. pubkey will be set to an
#                 invalid value if this function returns 0.
# In:    tweak32: pointer to a 32-byte tweak. If the tweak is invalid according to
#                 secp256k1_ec_seckey_verify, this function returns 0. For
#                 uniformly random 32-byte arrays the chance of being invalid
#                 is negligible (around 1 in 2^128).
#
@enforce_type
def ec_pubkey_tweak_add(pubkey: Secp256k1Pubkey, tweak32: bytes) -> Secp256k1Pubkey:
    """
    Tweak a public key by adding tweak times the generator to it.

    :param pubkey: initialized public key
    :param tweak32: 32-byte tweak
    :return: tweaked pubkey
    :raises ValueError: if pubkey is invalid type
                        if tweak32 is not of type bytes and length 32
    :raises Libsecp256k1Exception: arguments are invalid or the resulting public
                                   key would be invalid (only when the tweak
                                   is the negation of the corresponding secret
                                   key)
    """
    result = lib.secp256k1_ec_pubkey_tweak_add(
        secp256k1_context_verify, pubkey, tweak32
    )
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception(
            "arguments are invalid or the resulting public key would be invalid"
            " (only when the tweak is the negation of the corresponding secret key)"
        )
    return pubkey


# Tweak a secret key by multiplying it by a tweak.
#
# Returns: 0 if the arguments are invalid. 1 otherwise.
# Args:   ctx:    pointer to a context object.
# In/Out: seckey: pointer to a 32-byte secret key. If the secret key is
#                 invalid according to secp256k1_ec_seckey_verify, this
#                 function returns 0. seckey will be set to some unspecified
#                 value if this function returns 0.
# In:    tweak32: pointer to a 32-byte tweak. If the tweak is invalid according to
#                 secp256k1_ec_seckey_verify, this function returns 0. For
#                 uniformly random 32-byte arrays the chance of being invalid
#                 is negligible (around 1 in 2^128).
#
@enforce_type
def ec_seckey_tweak_mul(seckey: bytes, tweak32: bytes) -> bytes:
    """
    Tweak a secret key by multiplying it by a tweak.

    :param seckey: 32-byte secret key
    :param tweak32: 32-byte tweak
    :return: tweaked seckey
    :raises ValueError: if secret key is not of type bytes and length 32
                        if tweak32 is not of type bytes and length 32
    :raises Libsecp256k1Exception: arguments are invalid
    """
    tweaked_seckey = ctypes.create_string_buffer(seckey)
    result = lib.secp256k1_ec_seckey_tweak_mul(
        secp256k1_context_sign, tweaked_seckey, tweak32
    )
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception("invalid arguments")
    return tweaked_seckey.raw[:SECKEY_LENGTH]


# Tweak a public key by multiplying it by a tweak value.
#
# Returns: 0 if the arguments are invalid. 1 otherwise.
# Args:    ctx:   pointer to a context object initialized for validation.
# In/Out: pubkey: pointer to a public key object. pubkey will be set to an
#                 invalid value if this function returns 0.
# In:    tweak32: pointer to a 32-byte tweak. If the tweak is invalid according to
#                 secp256k1_ec_seckey_verify, this function returns 0. For
#                 uniformly random 32-byte arrays the chance of being invalid
#                 is negligible (around 1 in 2^128).
#
@enforce_type
def ec_pubkey_tweak_mul(pubkey: Secp256k1Pubkey, tweak32: bytes) -> Secp256k1Pubkey:
    """
    Tweak a public key by multiplying it by a tweak value.

    :param pubkey: initialized public key
    :param tweak32: 32-byte tweak
    :return: tweaked pubkey
    :raises ValueError: if pubkey is invalid type
                        if tweak32 is not of type bytes and length 32
    :raises Libsecp256k1Exception: arguments are invalid
    """
    result = lib.secp256k1_ec_pubkey_tweak_mul(
        secp256k1_context_verify, pubkey, tweak32
    )
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception("invalid arguments")
    return pubkey


#  Updates the context randomization to protect against side-channel leakage.
#  Returns: 1: randomization successfully updated or nothing to randomize
#           0: error
#  Args:    ctx:       pointer to a context object.
#  In:      seed32:    pointer to a 32-byte random seed (NULL resets to initial state)
#
# While secp256k1 code is written to be constant-time no matter what secret
# values are, it's possible that a future compiler may output code which isn't,
# and also that the CPU may not emit the same radio frequencies or draw the same
# amount power for all values.
#
# This function provides a seed which is combined into the blinding value: that
# blinding value is added before each multiplication (and removed afterwards) so
# that it does not affect function results, but shields against attacks which
# rely on any input-dependent behaviour.
#
# This function has currently an effect only on contexts initialized for signing
# because randomization is currently used only for signing. However, this is not
# guaranteed and may change in the future. It is safe to call this function on
# contexts not initialized for signing; then it will have no effect and return 1.
#
# You should call this after secp256k1_context_create or
# secp256k1_context_clone (and secp256k1_context_preallocated_create or
# secp256k1_context_clone, resp.), and you may call this repeatedly afterwards.
#
@enforce_type
def context_randomize(
    ctx: Secp256k1Context = secp256k1_context_sign, seed32: Optional[bytes] = None
) -> None:
    """
    Updates the context randomization to protect against side-channel leakage.

    If run without any arguments, default secp256k1_context_sign will be
    randomized with entropy from us.urandom.

    :param ctx: context object
    :param seed32: 32-byte random seed
    :return: None
    :raises Libsecp256k1Exception: if context randomization failed
    """
    if seed32 is None:
        seed32 = os.urandom(32)
    result = lib.secp256k1_context_randomize(ctx, seed32)
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception("secp256k1 context randomization failed")


# Add a number of public keys together.
#
# Returns: 1: the sum of the public keys is valid.
#          0: the sum of the public keys is not valid.
# Args:  ctx: pointer to a context object.
# Out:   out: pointer to a public key object for placing the resulting public key.
# In:    ins: pointer to array of pointers to public keys.
#        n:   the number of public keys to add together (must be at least 1).
#
@enforce_type
def ec_pubkey_combine(pubkeys: List[Secp256k1Pubkey]) -> Secp256k1Pubkey:
    """
    Add a number of public keys together.

    :param pubkeys: list of public keys
    :return: resulting public key
    :raises ValueError: if arguments are invalid type
                        if length of list is less than 2
    :raises Libsecp256k1Exception: if the sum of the public keys is not valid
    """
    if len(pubkeys) <= 1:
        raise ValueError("number of pubkeys to combine must be more than one")
    pubkey_arr = (ctypes.c_char_p * len(pubkeys))()
    for i, p in enumerate(pubkeys):
        pubkey_arr[i] = p.raw

    combined_pubkey = ctypes.create_string_buffer(INTERNAL_PUBKEY_LENGTH)
    result = lib.secp256k1_ec_pubkey_combine(
        secp256k1_context_verify, combined_pubkey, pubkey_arr, len(pubkeys)
    )
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception("the sum of the public keys is not valid")

    return combined_pubkey


# Compute a tagged hash as defined in BIP-340.
#
# This is useful for creating a message hash and achieving domain separation
# through an application-specific tag. This function returns
# SHA256(SHA256(tag)||SHA256(tag)||msg). Therefore, tagged hash
# implementations optimized for a specific tag can precompute the SHA256 state
# after hashing the tag hashes.
#
# Returns 0 if the arguments are invalid and 1 otherwise.
# Args:    ctx: pointer to a context object
# Out:  hash32: pointer to a 32-byte array to store the resulting hash
# In:      tag: pointer to an array containing the tag
#       taglen: length of the tag array
#          msg: pointer to an array containing the message
#       msglen: length of the message array
#
@enforce_type
def tagged_sha256(tag: bytes, msg: bytes) -> bytes:
    """
    Compute a tagged hash as defined in BIP-340.

    This is useful for creating a message hash and achieving domain separation
    through an application-specific tag. This function returns
    SHA256(SHA256(tag)||SHA256(tag)||msg).

    :param tag: tag
    :param msg: message
    :return: 32-byte hash
    :raises ValueError: if arguments are invalid type
    :raises Libsecp256k1Exception: arguments are invalid
    """
    hash32 = ctypes.create_string_buffer(HASH32)
    result = lib.secp256k1_tagged_sha256(
        secp256k1_context_verify, hash32, tag, len(tag), msg, len(msg)
    )
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception("invalid arguments")
    return hash32.raw[:HASH32]


__all__ = (
    "ec_pubkey_parse",
    "ec_pubkey_serialize",
    "ec_pubkey_cmp",
    "ecdsa_signature_parse_compact",
    "ecdsa_signature_parse_der",
    "ecdsa_signature_serialize_der",
    "ecdsa_signature_serialize_compact",
    "ecdsa_verify",
    "ecdsa_signature_normalize",
    "ecdsa_sign",
    "ec_seckey_verify",
    "ec_pubkey_create",
    "ec_seckey_negate",
    "ec_pubkey_negate",
    "ec_seckey_tweak_add",
    "ec_pubkey_tweak_add",
    "ec_seckey_tweak_mul",
    "ec_pubkey_tweak_mul",
    "context_randomize",
    "ec_pubkey_combine",
    "tagged_sha256",
)
