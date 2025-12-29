import os
from pysecp256k1.low_level.constants import PYSECP_SO


def assert_zero_return_code(code: int) -> None:
    assert code == 0, f"Non-standard return code: {code}"


def find_pysecp_env_var():
    return os.environ.get(PYSECP_SO, None)


__all__ = (
    "assert_zero_return_code",
    "find_pysecp_env_var",
)
