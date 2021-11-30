import typing
import functools


def assert_zero_return_code(code: int) -> None:
    assert code == 0, f"Non-standard return code: {code}"


def enforce_type(func):
    """
    This in no way tries to be the generic type enforcer. On the contrary, this
    was built to very specifically suit the needs of this library.
    Pysecp256k1 only operates with few simple types and this decorator only
    cares about the needs of this library.

    Mostly just enforcing basic python types like bytes, int, bool.
    Some specific ctypes types - c_char of specific length.
    And finally Optional, List and Tuple from typing library.
    """
    # no need to calculate them every time the function is executed
    type_hints = typing.get_type_hints(func)

    @functools.wraps(func)
    def inner(*args, **kwargs):
        all_args = kwargs.copy()
        all_args.update(dict(zip(func.__code__.co_varnames, args)))
        for arg_name, arg in all_args.items():
            correct_type = type_hints[arg_name]
            if typing.get_origin(correct_type) == list:
                if not isinstance(arg, list):
                    raise ValueError(f"'{arg_name}' must be of type list")
                for element in arg:
                    if not isinstance(element, typing.get_args(correct_type)):
                        raise ValueError(
                            f"Elements of '{arg_name}' must be of type "
                            f"{typing.get_args(correct_type)}"
                        )
            else:
                if typing.get_origin(correct_type) == typing.Union:
                    correct_type = typing.get_args(correct_type)
                if not isinstance(arg, correct_type):
                    raise ValueError(
                        f"'{arg_name}' must be of type "
                        f"{type_hints[arg_name].__qualname__}"
                    )

        result = func(*args, **kwargs)

        if "return" in type_hints:
            origin = typing.get_origin(type_hints["return"])
            if origin == tuple:
                if not isinstance(result, tuple):
                    raise ValueError(f"Result must be of type {origin}")
                _args = typing.get_args(type_hints["return"])
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
            raise ValueError(f" Length of '{name}' must be one of {length}")


__all__ = (
    "assert_zero_return_code",
    "enforce_length",
    "enforce_type"
)
