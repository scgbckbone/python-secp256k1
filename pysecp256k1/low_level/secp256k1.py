# Copyright (C) 2018 The python-bitcointx developers
#
# This file is part of python-bitcointx.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcointx, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

# pylama:ignore=E501,E221

# NOTE: for simplicity, when we need to pass an array of structs to secp256k1
# function, we will build an array of bytes out of elements, and then pass
# this array. we are dealing with 32 or 64-byte aligned data,
# so this should be safe.

# NOTE: special care should be taken with functions that may write to parts
# of their arguments, like secp256k1_pedersen_blind_generator_blind_sum,
# which will overwrite the element pointed to by blinding_factor.
# python's byte instance is supposed to be immutable, and for mutable byte
# buffers you should use ctypes.create_string_buffer().

import os
import logging
import ctypes
import ctypes.util
from types import FunctionType
from typing import Any, Optional

from pysecp256k1.low_level.constants import (
    PYSECP_SO,
    SECP256K1_CONTEXT_SIGN,
    SECP256K1_CONTEXT_VERIFY,
    Secp256k1Context,
)
from pysecp256k1.low_level.util import assert_zero_return_code, find_pysecp_env_var


_LOGGER = logging.getLogger(__name__)
sh = logging.StreamHandler()
_LOGGER.addHandler(sh)


has_secp256k1_recovery = False
has_secp256k1_ecdh = False
has_secp256k1_extrakeys = False
has_secp256k1_schnorrsig = False


class Libsecp256k1Exception(EnvironmentError):
    pass


_secp256k1_error_storage = {}


ctypes_functype = getattr(ctypes, "WINFUNCTYPE", getattr(ctypes, "CFUNCTYPE"))
callback_func_type = ctypes_functype(ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p)


@callback_func_type
def _secp256k1_illegal_callback_fn(error_str, _data):
    error_string = str(error_str)
    _LOGGER.error("illegal_argument: %s", error_string)
    _secp256k1_error_storage["last_error"] = {
        "code": -2,
        "type": "illegal_argument",
        "message": error_string,
    }


def _check_ressecp256k1_void_p(
    val: int, _func: FunctionType, _args: Any
) -> ctypes.c_void_p:
    if val == 0:
        err = _secp256k1_error_storage.get("last_error", None)
        if err is None:
            raise Libsecp256k1Exception(
                -3,
                (
                    "error handling callback function was not called, "
                    "error is not known"
                ),
            )
        raise Libsecp256k1Exception(err["code"], err["message"])
    return ctypes.c_void_p(val)


def _add_function_definitions(_secp256k1: ctypes.CDLL) -> None:
    global has_secp256k1_recovery
    global has_secp256k1_extrakeys
    global has_secp256k1_schnorrsig
    global has_secp256k1_ecdh

    _secp256k1.secp256k1_context_create.restype = ctypes.c_void_p
    _secp256k1.secp256k1_context_create.errcheck = _check_ressecp256k1_void_p
    _secp256k1.secp256k1_context_create.argtypes = [ctypes.c_uint]

    _secp256k1.secp256k1_context_clone.restype = ctypes.c_void_p
    _secp256k1.secp256k1_context_clone.errcheck = _check_ressecp256k1_void_p
    _secp256k1.secp256k1_context_clone.argtypes = [ctypes.c_void_p]

    _secp256k1.secp256k1_context_destroy.restype = None
    _secp256k1.secp256k1_context_destroy.argtypes = [ctypes.c_void_p]

    _secp256k1.secp256k1_context_set_illegal_callback.restype = None
    _secp256k1.secp256k1_context_set_illegal_callback.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]

    _secp256k1.secp256k1_context_set_error_callback.restype = None
    _secp256k1.secp256k1_context_set_error_callback.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]

    _secp256k1.secp256k1_ec_pubkey_parse.restype = ctypes.c_int
    _secp256k1.secp256k1_ec_pubkey_parse.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_size_t,
    ]

    _secp256k1.secp256k1_ec_pubkey_serialize.restype = ctypes.c_int
    _secp256k1.secp256k1_ec_pubkey_serialize.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_size_t),
        ctypes.c_char_p,
        ctypes.c_uint,
    ]

    _secp256k1.secp256k1_ec_pubkey_cmp.restype = ctypes.c_int
    _secp256k1.secp256k1_ec_pubkey_cmp.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
    ]

    _secp256k1.secp256k1_ecdsa_signature_parse_compact.restype = ctypes.c_int
    _secp256k1.secp256k1_ecdsa_signature_parse_compact.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
    ]

    _secp256k1.secp256k1_ecdsa_signature_parse_der.restype = ctypes.c_int
    _secp256k1.secp256k1_ecdsa_signature_parse_der.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_size_t,
    ]

    _secp256k1.secp256k1_ecdsa_signature_serialize_der.restype = ctypes.c_int
    _secp256k1.secp256k1_ecdsa_signature_serialize_der.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_size_t),
        ctypes.c_char_p,
    ]

    _secp256k1.secp256k1_ecdsa_signature_serialize_compact.restype = ctypes.c_int
    _secp256k1.secp256k1_ecdsa_signature_serialize_compact.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
    ]

    _secp256k1.secp256k1_ecdsa_verify.restype = ctypes.c_int
    _secp256k1.secp256k1_ecdsa_verify.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
    ]

    _secp256k1.secp256k1_ecdsa_signature_normalize.restype = ctypes.c_int
    _secp256k1.secp256k1_ecdsa_signature_normalize.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
    ]

    _secp256k1.secp256k1_ecdsa_sign.restype = ctypes.c_int
    _secp256k1.secp256k1_ecdsa_sign.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]

    _secp256k1.secp256k1_ec_seckey_verify.restype = ctypes.c_int
    _secp256k1.secp256k1_ec_seckey_verify.argtypes = [ctypes.c_void_p, ctypes.c_char_p]

    _secp256k1.secp256k1_ec_pubkey_create.restype = ctypes.c_int
    _secp256k1.secp256k1_ec_pubkey_create.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
    ]

    _secp256k1.secp256k1_ec_seckey_negate.restype = ctypes.c_int
    _secp256k1.secp256k1_ec_seckey_negate.argtypes = [ctypes.c_void_p, ctypes.c_char_p]

    _secp256k1.secp256k1_ec_pubkey_negate.restype = ctypes.c_int
    _secp256k1.secp256k1_ec_pubkey_negate.argtypes = [ctypes.c_void_p, ctypes.c_char_p]

    _secp256k1.secp256k1_ec_seckey_tweak_add.restype = ctypes.c_int
    _secp256k1.secp256k1_ec_seckey_tweak_add.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
    ]

    _secp256k1.secp256k1_ec_pubkey_tweak_add.restype = ctypes.c_int
    _secp256k1.secp256k1_ec_pubkey_tweak_add.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
    ]

    _secp256k1.secp256k1_ec_seckey_tweak_mul.restype = ctypes.c_int
    _secp256k1.secp256k1_ec_seckey_tweak_mul.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
    ]

    _secp256k1.secp256k1_ec_pubkey_tweak_mul.restype = ctypes.c_int
    _secp256k1.secp256k1_ec_pubkey_tweak_mul.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
    ]

    _secp256k1.secp256k1_context_randomize.restype = ctypes.c_int
    _secp256k1.secp256k1_context_randomize.argtypes = [ctypes.c_void_p, ctypes.c_char_p]

    _secp256k1.secp256k1_ec_pubkey_combine.restype = ctypes.c_int
    _secp256k1.secp256k1_ec_pubkey_combine.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_char_p),
        ctypes.c_int,
    ]

    _secp256k1.secp256k1_tagged_sha256.restype = ctypes.c_int
    _secp256k1.secp256k1_tagged_sha256.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.c_size_t,
    ]

    if getattr(_secp256k1, "secp256k1_ecdsa_sign_recoverable", None):
        has_secp256k1_recovery = True
        _secp256k1.secp256k1_ecdsa_recoverable_signature_parse_compact.restype = (
            ctypes.c_int
        )
        _secp256k1.secp256k1_ecdsa_recoverable_signature_parse_compact.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_int,
        ]

        _secp256k1.secp256k1_ecdsa_recoverable_signature_convert.restype = ctypes.c_int
        _secp256k1.secp256k1_ecdsa_recoverable_signature_convert.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
        ]

        _secp256k1.secp256k1_ecdsa_recoverable_signature_serialize_compact.restype = (
            ctypes.c_int
        )
        _secp256k1.secp256k1_ecdsa_recoverable_signature_serialize_compact.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_int),
            ctypes.c_char_p,
        ]

        _secp256k1.secp256k1_ecdsa_sign_recoverable.restype = ctypes.c_int
        _secp256k1.secp256k1_ecdsa_sign_recoverable.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
        ]

        _secp256k1.secp256k1_ecdsa_recover.restype = ctypes.c_int
        _secp256k1.secp256k1_ecdsa_recover.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
        ]

    if getattr(_secp256k1, "secp256k1_ecdh", None):
        has_secp256k1_ecdh = True
        _secp256k1.secp256k1_ecdh.restype = ctypes.c_int
        _secp256k1.secp256k1_ecdh.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]

    if getattr(_secp256k1, "secp256k1_xonly_pubkey_parse", None):
        has_secp256k1_extrakeys = True
        _secp256k1.secp256k1_xonly_pubkey_parse.restype = ctypes.c_int
        _secp256k1.secp256k1_xonly_pubkey_parse.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
        ]

        _secp256k1.secp256k1_xonly_pubkey_serialize.restype = ctypes.c_int
        _secp256k1.secp256k1_xonly_pubkey_serialize.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
        ]

        _secp256k1.secp256k1_xonly_pubkey_cmp.restype = ctypes.c_int
        _secp256k1.secp256k1_xonly_pubkey_cmp.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
        ]

        _secp256k1.secp256k1_xonly_pubkey_from_pubkey.restype = ctypes.c_int
        _secp256k1.secp256k1_xonly_pubkey_from_pubkey.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_int),
            ctypes.c_char_p,
        ]

        _secp256k1.secp256k1_xonly_pubkey_tweak_add.restype = ctypes.c_int
        _secp256k1.secp256k1_xonly_pubkey_tweak_add.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
        ]

        _secp256k1.secp256k1_xonly_pubkey_tweak_add_check.restype = ctypes.c_int
        _secp256k1.secp256k1_xonly_pubkey_tweak_add_check.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_char_p,
        ]

        _secp256k1.secp256k1_keypair_create.restype = ctypes.c_int
        _secp256k1.secp256k1_keypair_create.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
        ]

        _secp256k1.secp256k1_keypair_sec.restype = ctypes.c_int
        _secp256k1.secp256k1_keypair_sec.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
        ]

        _secp256k1.secp256k1_keypair_pub.restype = ctypes.c_int
        _secp256k1.secp256k1_keypair_pub.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
        ]

        _secp256k1.secp256k1_keypair_xonly_pub.restype = ctypes.c_int
        _secp256k1.secp256k1_keypair_xonly_pub.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_int),
            ctypes.c_char_p,
        ]

        _secp256k1.secp256k1_keypair_xonly_tweak_add.restype = ctypes.c_int
        _secp256k1.secp256k1_keypair_xonly_tweak_add.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
        ]

    if getattr(_secp256k1, "secp256k1_schnorrsig_sign32", None):
        has_secp256k1_schnorrsig = True

        _secp256k1.secp256k1_schnorrsig_sign32.restype = ctypes.c_int
        _secp256k1.secp256k1_schnorrsig_sign32.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
        ]

        _secp256k1.secp256k1_schnorrsig_sign_custom.restype = ctypes.c_int
        _secp256k1.secp256k1_schnorrsig_sign_custom.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_void_p,
        ]

        _secp256k1.secp256k1_schnorrsig_verify.restype = ctypes.c_int
        _secp256k1.secp256k1_schnorrsig_verify.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
        ]


def secp256k1_create_and_init_context(
    _secp256k1: ctypes.CDLL, flags: int
) -> Secp256k1Context:
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

    ctx = _secp256k1.secp256k1_context_create(flags)
    if ctx is None:
        raise RuntimeError("secp256k1_context_create() returned None")

    _secp256k1.secp256k1_context_set_illegal_callback(
        ctx, _secp256k1_illegal_callback_fn, 0
    )
    seed = os.urandom(32)
    result = _secp256k1.secp256k1_context_randomize(ctx, seed)
    if result != 1:
        assert_zero_return_code(result)
        raise RuntimeError("secp256k1 context randomization failed")
    return ctx


def load_secp256k1_library(path: Optional[str] = None) -> ctypes.CDLL:
    """load libsecp256k1 via ctypes, add default function definitions
    to the library handle, and return this handle.

    Callers of this function must assume responsibility for correct usage
    of the underlying C library.
    ctypes is a low-level foreign function interface, and using the underlying
    library though it should be done with the same care as if you would be
    programming in C directly.

    Note that default function definitions are only those that relevant
    to the code that uses them in python code within this library.
    You probably should to add your own definitions for the functions that
    you want to call directly, even if they are defined here by default.
    Although removing the default function definition should be considered
    mild API breakage and should be communicated via release notes.
    """

    if path is None:
        path = ctypes.util.find_library("secp256k1")
        if path is None:
            raise ImportError("secp256k1 library not found")

    try:
        handle = ctypes.cdll.LoadLibrary(path)
    except Exception as e:
        raise ImportError("Cannot load secp256k1 library: {}".format(e))

    _add_function_definitions(handle)

    return handle


lib = load_secp256k1_library(find_pysecp_env_var())

secp256k1_context_sign = secp256k1_create_and_init_context(lib, SECP256K1_CONTEXT_SIGN)
secp256k1_context_verify = secp256k1_create_and_init_context(
    lib, SECP256K1_CONTEXT_VERIFY
)


__all__ = (
    "lib",
    "Libsecp256k1Exception",
    "callback_func_type",
    "secp256k1_context_sign",
    "secp256k1_context_verify",
    "has_secp256k1_schnorrsig",
    "has_secp256k1_extrakeys",
    "has_secp256k1_recovery",
    "has_secp256k1_ecdh",
    "ctypes_functype",
)
