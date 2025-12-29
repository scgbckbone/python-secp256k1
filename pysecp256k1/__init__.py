import os
import ctypes
from typing import List, Optional
from pysecp256k1.low_level import (lib, secp256k1_context_sign, secp256k1_context_verify, enforce_type,
    assert_zero_return_code, Libsecp256k1Exception, callback_func_type, ctypes_functype,
)
from pysecp256k1.low_level.constants import (Secp256k1Context, Secp256k1Pubkey, Secp256k1ECDSASig,
                                             PUBLIC_KEY_LENGTH, COMPRESSED_PUBLIC_KEY_LENGTH,
                                             COMPACT_SIGNATURE_LENGTH, DER_SIGNATURE_LENGTH,
                                             INTERNAL_PUBKEY_LENGTH, INTERNAL_SIGNATURE_LENGTH,
                                             SECP256K1_EC_UNCOMPRESSED, SECP256K1_EC_COMPRESSED,
                                             SECP256K1_CONTEXT_SIGN, SECP256K1_CONTEXT_VERIFY,
                                             SECKEY_LENGTH, HASH32)


ECDSA_NONCEFP_CLS = ctypes_functype(
    ctypes.c_int,
    ctypes.POINTER(ctypes.c_char * 32),  # nonce32
    ctypes.POINTER(ctypes.c_char * 32),  # msg32
    ctypes.POINTER(ctypes.c_char * 32),  # secret key
    ctypes.POINTER(ctypes.c_char * 32),  # algo16
    ctypes.c_void_p,  # void *data
    ctypes.c_uint,  # counter
)


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


@enforce_type
def context_clone(ctx: Secp256k1Context) -> Secp256k1Context:
    cloned_ctx = lib.secp256k1_context_clone(ctx)
    if cloned_ctx is None:
        raise Libsecp256k1Exception("secp256k1_context_clone returned None")
    return cloned_ctx


@enforce_type
def context_destroy(ctx: Secp256k1Context) -> None:
    lib.secp256k1_context_destroy(ctx)
    del ctx


@enforce_type
def context_set_illegal_callback(
    ctx: Secp256k1Context, f: callback_func_type, data
) -> None:
    lib.secp256k1_context_set_illegal_callback(ctx, f, data)


@enforce_type
def context_set_error_callback(
    ctx: Secp256k1Context, f: callback_func_type, data
) -> None:
    lib.secp256k1_context_set_error_callback(ctx, f, data)


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
    return pubkey_ser.raw[:pub_size.value]


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


@enforce_type
def ec_pubkey_sort(pubkeys: List[Secp256k1Pubkey]) -> List[Secp256k1Pubkey]:
    """
    Sort public keys using lexicographic (of compressed serialization) order.

    :param pubkeys: list of initialized public keys to sort
    :return: sorted list of intitalized public keys
    :raises ValueError: if arguments are invalid type
    :raises Libsecp256k1Exception: if pubkey is invalid or could not be parsed
    """
    length = len(pubkeys)
    arr = (ctypes.POINTER(Secp256k1Pubkey) * length)()
    for i, pk in enumerate(pubkeys):
        arr[i] = ctypes.pointer(pk)

    result = lib.secp256k1_ec_pubkey_sort(
        secp256k1_context_verify, arr, length
    )
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception("pubkeys could not be parsed or are invalid")

    return [arr[i].contents for i in range(length)]


@enforce_type
def ecdsa_signature_parse_compact(compact_sig: bytes) -> Secp256k1ECDSASig:
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


@enforce_type
def ecdsa_signature_parse_der(der_sig: bytes) -> Secp256k1ECDSASig:
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


@enforce_type
def ecdsa_signature_serialize_der(sig: Secp256k1ECDSASig) -> bytes:
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


@enforce_type
def ecdsa_signature_serialize_compact(sig: Secp256k1ECDSASig) -> bytes:
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


@enforce_type
def ecdsa_verify(sig: Secp256k1ECDSASig, pubkey: Secp256k1Pubkey, msghash32: bytes) -> bool:
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


@enforce_type
def ecdsa_signature_normalize(sig: Secp256k1ECDSASig) -> Secp256k1ECDSASig:
    """
    Convert a signature to a normalized lower-S form.

    :param sig: initialized ECDSA signature
    :return: initialized ECDSA signature in lower-S form
    :raises ValueError: if sig is invalid type
    """
    lib.secp256k1_ecdsa_signature_normalize(secp256k1_context_verify, sig, sig)
    return sig


@enforce_type
def ecdsa_sign(seckey: bytes, msghash32: bytes, noncefp: ctypes.c_void_p = None,
               ndata: ctypes.c_void_p = None) -> Secp256k1ECDSASig:
    """
    Create an ECDSA signature.

    :param seckey: 32-byte secret key
    :param msghash32: the 32-byte message hash being signed
    :param noncefp: pointer to a nonce generation function
    :param ndata: pointer to arbitrary data used by the nonce generation function
    :return: initialized ECDSA signature
    :raises ValueError: if secret key is not of type bytes and length 32
                        if msghash32 is not of type bytes and length 32
    :raises Libsecp256k1Exception: if nonce generation function failed,
                                   or the secret key was invalid
    """
    sig = ctypes.create_string_buffer(INTERNAL_SIGNATURE_LENGTH)
    result = lib.secp256k1_ecdsa_sign(
        secp256k1_context_sign, sig, msghash32, seckey, noncefp, ndata
    )
    if result != 1:
        assert_zero_return_code(result)
        raise Libsecp256k1Exception(
            "nonce generation function failed, or the secret key was invalid"
        )
    return sig


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
