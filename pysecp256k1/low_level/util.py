import os
import typing
import functools
from pysecp256k1.low_level.constants import (
    PYSECP_SO,
    SECKEY_LENGTH,
    PUBLIC_KEY_LENGTH,
    COMPRESSED_PUBLIC_KEY_LENGTH,
    XONLY_PUBKEY_LENGTH,
    HASH32,
    COMPACT_SIGNATURE_LENGTH,
    VALID_RECOVERY_IDS,
    VALID_PUBKEY_PARITY,
)


ARG_LENGTH_MAP = {
    "aux_rand32": HASH32,
    "msghash32": HASH32,
    "msg32": HASH32,
    "tweak32": HASH32,
    "seckey": SECKEY_LENGTH,
    "compact_sig": COMPACT_SIGNATURE_LENGTH,
    "pubkey_ser": [PUBLIC_KEY_LENGTH, COMPRESSED_PUBLIC_KEY_LENGTH],
    "xonly_pubkey_ser": XONLY_PUBKEY_LENGTH,
    "tweaked_pubkey32": XONLY_PUBKEY_LENGTH,
}


def assert_zero_return_code(code: int) -> None:
    assert code == 0, f"Non-standard return code: {code}"


def enforce_type(func):
    """
    This in no way tries to be the generic type enforcer. On the contrary, this
    was built to very specifically suit the needs of this library.
    Pysecp256k1 only operates with few simple types and this decorator only
    cares about the needs of this library.

    Mostly just enforcing basic python types like bytes, int, bool.
    Some specific ctypes types - c_char array of specific length.
    And finally Optional, List and Tuple from typing library.

    Also enforces length of bytes based on ARG_LENGTH_MAP and checks if
    recovery id is from valid range.
    """
    # no need to calculate them every time the function is executed
    type_hints = typing.get_type_hints(func)

    @functools.wraps(func)
    def inner(*args, **kwargs):
        # args, kwargs type enforcement
        all_args = kwargs.copy()
        all_args.update(dict(zip(func.__code__.co_varnames, args)))
        for arg_name, arg in all_args.items():
            correct_type = type_hints[arg_name]
            # if typing.get_origin(correct_type) == list:
            if getattr(correct_type, "__origin__", None) in [list, typing.List]:
                if not isinstance(arg, list):
                    raise ValueError(f"'{arg_name}' must be of type list")
                # _args = typing.get_args(correct_type)
                _args = getattr(correct_type, "__args__", None)
                for element in arg:
                    if not isinstance(element, _args):
                        raise ValueError(
                            f"Elements of '{arg_name}' must be of type " f"{_args}"
                        )
            else:
                # if typing.get_origin(correct_type) == typing.Union:
                if getattr(correct_type, "__origin__", None) == typing.Union:
                    # correct_type = typing.get_args(correct_type)
                    correct_type = getattr(correct_type, "__args__", None)
                if not isinstance(arg, correct_type):
                    raise ValueError(f"'{arg_name}' must be of type {correct_type}")
            # length enforcement
            length = ARG_LENGTH_MAP.get(arg_name, None)
            if length is not None:
                enforce_length(arg, arg_name, length)
            # recovery id check
            if arg_name == "rec_id":
                if arg not in VALID_RECOVERY_IDS:
                    raise ValueError(
                        "Invalid recovery id. Must be one of %s", VALID_RECOVERY_IDS
                    )
            if arg_name == "tweaked_pk_parity":
                if arg not in VALID_PUBKEY_PARITY:
                    raise ValueError(
                        "Invalid pubkey parity. Must be one %s", VALID_PUBKEY_PARITY
                    )

        result = func(*args, **kwargs)

        # return type enforcement
        if "return" in type_hints:
            # origin = typing.get_origin(type_hints["return"])
            origin = getattr(type_hints["return"], "__origin__", None)
            if origin in [tuple, typing.Tuple]:
                if not isinstance(result, tuple):
                    raise ValueError(f"Result must be of type {origin}")
                _args = getattr(type_hints["return"], "__args__", None)
                for i, element in enumerate(result):
                    if not isinstance(element, _args[i]):
                        raise ValueError(f"Element {i} of result must be {_args}")
            else:
                if not isinstance(result, type_hints["return"]):
                    raise ValueError(f"Result must be of type {type_hints['return']}")

        return result

    return inner


def enforce_length(value, name, length):
    if isinstance(length, int):
        if len(value) != length:
            raise ValueError(f"'{name}' must be exactly {length} bytes")
    else:
        # expect this to be iterable
        if len(value) not in length:
            raise ValueError(f"Length of '{name}' must be one of {length}")


def find_pysecp_env_var():
    return os.environ.get(PYSECP_SO, None)


__all__ = (
    "assert_zero_return_code",
    "enforce_length",
    "enforce_type",
    "find_pysecp_env_var",
)
