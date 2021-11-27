
def assert_zero_return_code(code: int) -> None:
    assert code == 0, f"Non-standard return code: {code}"


def enforce_type(value, instance, name, length=None):
    if not isinstance(value, instance):
        raise ValueError(f"'{name}' must be of type {instance.__qualname__}")
    if length:
        if isinstance(length, int):
            if len(value) != length:
                raise ValueError(f"'{name}' must be exactly {length} bytes")
        else:
            # expect this to be iterable
            if len(value) not in length:
                raise ValueError(f" Length of '{name}' must be one of {length}")


__all__ = (
    "assert_zero_return_code",
    "enforce_type",
)
