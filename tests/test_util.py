import os
import unittest
from pysecp256k1.low_level.util import (
    assert_zero_return_code,
    find_pysecp_env_var,
)
from pysecp256k1.low_level.constants import (
    PYSECP_SO,
)


class TestUtil(unittest.TestCase):
    def test_assert_zero_return_code(self):
        self.assertIsNone(assert_zero_return_code(0))
        with self.assertRaises(AssertionError):
            assert_zero_return_code(1)

    def test_find_pysecp_env_var(self):
        # make sure no PYSECP_SO in env
        current = os.environ.get(PYSECP_SO, None)
        if current:
            del os.environ[PYSECP_SO]
        assert find_pysecp_env_var() is None
        target = "/random/path/to/libsecp256k1.so.0.0.0"
        target = current or target
        os.environ[PYSECP_SO] = target
        assert find_pysecp_env_var() == target
