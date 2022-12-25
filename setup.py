#!/usr/bin/env python3

import os
from setuptools import setup

__version__ = "0.2.0"

here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, "README.md")) as f:
    README = f.read()

install_requires = []

setup(
    name="python-secp256k1",
    version=__version__,
    license="MIT",
    author="scg",
    author_email="scgbckbone@proton.me",
    description="Ctypes Python3 FFI bindings for libsecp256k1",
    long_description=README,
    long_description_content_type="text/markdown",
    classifiers=[
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
    ],
    url="https://github.com/scgbckbone/python-secp256k1",
    keywords=[
        "bitcoin",
        "secp256k1",
        "ecdsa",
        "schnorr",
    ],
    packages=["pysecp256k1", "pysecp256k1.low_level"],
    zip_safe=False,
    install_requires=install_requires,
    test_suite="tests",
    extras_require={"typing_extensions": ["typing_extensions>=3.6"]},
)
