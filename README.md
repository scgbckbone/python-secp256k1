# python-secp256k1
#### WARNING: In python you do not control memory. Regardless of how secrets are passed to the underlying lib, it still was an object in python before. It will linger in the heap for some time even after going out of scope. It is also impossible to mlock() secrets, your private keys may end up on disk in swap. Use with caution!!!

Python FFI bindings for [libsecp256k1](https://github.com/bitcoin-core/secp256k1) (an experimental and optimized C library for EC operations on curve secp256k1) using [ctypes](https://docs.python.org/3/library/ctypes.html).
Alternative implementation that uses [cffi](https://cffi.readthedocs.io/en/latest/) instead of ctypes is [secp256k1-py](https://github.com/rustyrussell/secp256k1-py).
CFFI is heavier, needs compiler for API mode (parses C headers) while ctypes does not need dependencies at all.

#### Rationale and goal
This library aims to provide a standard way to wrap `libsecp256k1` using `ctypes`.

#### Implementation Details
* Scratch spaces are not implemented.
* methods from `secp256k1_preallocated.h` are not implemented
* This library creates default contexts (sign/verify) at the initialization phase, randomizes them 
and uses them the whole time, you do not need to worry about contexts. In case you need to randomize more often (to protect against side-channel leakage)
use `pysecp256k1.context_randomize`.
* way to provide own hash functions is not implemented - default hash functions are used
* `schnorrsig_sign_custom` does not accept extraparams argument, instead accepts `aux_rand32` as `schnorrsig_sign32` - same as passing `extraparams.ndata`
* Default illegal callback function (that is added to default contexts) logs to stderr. 
* Method names are the same as in `libsecp256k1` but without 'secp256k1_' prefix (i.e. `secp256k1_ec_pubkey_serialize` -> `ec_pubkey_serialize`)
* Modules are structured same as in secp256k1 `include/` directory but without 'secp256k1_' prefix.

|    secp256k1 modules   |    pysecp256k1 modules    |               importing              |
|:----------------------:|:-------------------------:|:------------------------------------:|
|       secp256k1.h      | pysecp256k1.\_\_init__.py |       from pysecp256k1 import *      |
|    secp256k1_ecdh.h    |    pysecp256k1.ecdh.py    |    from pysecp256k1.ecdh import *    |
|  secp256k1_extrakeys.h |  pysecp256k1.extrakeys.py |  from pysecp256k1.extrakeys import * |
|  secp256k1_recovery.h  |  pysecp256k1.recovery.py  |  from pysecp256k1.recovery import *  |
| secp256k1_schnorrsig.h | pysecp256k1.schnorrsig.py | from pysecp256k1.schnorrsig import * |

#### Validation and data types
This library tries to supplement `libsecp256k1` with valid data ONLY, therefore heavy input type validation is in place. 
Validation is implemented via `enforce_type`((can be found in `pysecp256k1.low_level.util`)) which check for correct type (based on type hints) and correct length if possible.

Internal (opaque) secp256k1 data structures are represented as `ctypes.c_char_Array`
to get bytes from `c_char_Array` use `.raw` (see examples).

|          pysecp256k1 class         |       type      |
|:----------------------------------:|:---------------:|
|           Secp256k1Pubkey          | c_char_Array_64 |
|       Secp256k1ECDSASignature      | c_char_Array_64 |
|        Secp256k1XonlyPubkey        | c_char_Array_64 |
|          Secp256k1Keypair          | c_char_Array_96 |
| Secp256k1ECDSARecoverableSignature | c_char_Array_65 |
|          Secp256k1Context          |     c_void_p    |

Apart from `ctypes.c_char_Array` and `ctypes.c_void_p` this library uses a limited number of standard python types.

|            python type           |                                           usage                                            |
|:--------------------------------:|:------------------------------------------------------------------------------------------:|
|               bool               |     result of signature verification functions `ecdsa_verify` and `schnorrsig_verify`      |
|                int               |        recovery id, pubkey parity, result of `ec_pubkey_cmp` and `xonly_pubkey_cmp`        |
|               bytes              | tags, tweaks, messages, message hashes, serialized pubkeys, serialized signatures, seckeys |
|       List[Secp256k1Pubkey]      |                    list of initialized pubkeys for `ec_pubkey_combine`                     |
| Tuple[Secp256k1XonlyPubkey, int] |                        initialized xonly public key and its parity                         |
|         Tuple[bytes, int]        |                    serialized recoverable signature and its recovery id                    |
|          Optional[bytes]         |                   optional random data for `schnorrsig_sign{32,_custom}`                   |

## Installation and dependencies
Only dependency of `pysecp256k1` is `python3.6+` and `libsecp256k1` itself.
To use full feature set build secp256k1 this way:
```shell
git clone https://github.com/bitcoin-core/secp256k1.git
cd secp256k1/
git checkout v0.2.0
./autogen.sh
./configure --enable-module-recovery
make
make check
sudo make install
```
if one builds secp256k1 without schnorrsig for example and then tries to import from it `from pysecp256k1.schnorrsig import schnorrsig_sign32`
`RuntimeError` is raised hinting that `libsecp256k1` is built without shnorrsig support. Same applies for all optional modules.

If one needs to have older version of libsecp256k1 installed in standard path and recent one for this library, 
do NOT do last step from above (`sudo make install`) and instead export absolute path to desired `.so` file in environment variable.
```shell
export PYSECP_SO=/home/johndoe/secp256k1/.libs/libsecp256k1.so.0.0.0
```
Install `python-secp256k1` python package from pypi: 
```shell
python3 -m pip install -U pip wheel
python3 -m pip install python-secp256k1
```

## Examples
```python
import os
from pysecp256k1 import *


seckey = tagged_sha256(b"seckey", os.urandom(32))
print("seckey:", seckey.hex())
ec_seckey_verify(seckey)
pubkey = ec_pubkey_create(seckey)
print("Compressed pubkey:", ec_pubkey_serialize(pubkey).hex())
msg = b"message to be signed"
print("msg:", msg.decode())
msg_hash = tagged_sha256(b"message", msg)
print("msg hash:", msg_hash.hex())
sig = ecdsa_sign(seckey, msg_hash)
print("DER signature:", ecdsa_signature_serialize_der(sig).hex())
print("compact signature:", ecdsa_signature_serialize_compact(sig).hex())
print("Correct signature for pubkey and msg hash:", ecdsa_verify(sig, pubkey, msg_hash))
```

### Schnorrsig
```python
import os
from pysecp256k1 import tagged_sha256
from pysecp256k1.extrakeys import *
from pysecp256k1.schnorrsig import *


seckey = tagged_sha256(b"seckey", os.urandom(32))
print("seckey:", seckey.hex())
keypair = keypair_create(seckey)
xonly_pubkey, pk_parity = keypair_xonly_pub(keypair)
print("xonly pubkey:", xonly_pubkey_serialize(xonly_pubkey).hex())
msg = b"message to be signed"
print("msg:", msg.decode())
msg_hash = tagged_sha256(b"message", msg)
print("msg hash:", msg_hash.hex())
rand_32 = os.urandom(32)
sig = schnorrsig_sign32(keypair, msg_hash, aux_rand32=rand_32)
print("schnorr signature:", sig.hex())
print("Correct signature for xonly pubkey and msg hash:", schnorrsig_verify(sig, msg_hash, xonly_pubkey))
# you can also sign variable length messages
# instead of passing extraparams pointer as in secp256k1 custom takes aux_rand (equivalent of extraparams.ndata)
sig0 = schnorrsig_sign_custom(keypair, msg, aux_rand32=rand_32)
print("schnorr signature:", sig0.hex())
print("Correct signature for xonly pubkey and msg hash:", schnorrsig_verify(sig0, msg, xonly_pubkey))
```

### Recovery
```python
import os
from pysecp256k1 import tagged_sha256
from pysecp256k1 import ec_pubkey_create
from pysecp256k1.recovery import *


msg = b"message to be signed"
print("msg:", msg.decode())
msg_hash = tagged_sha256(b"message", msg)
print("msg hash:", msg_hash.hex())
seckey = tagged_sha256(b"seckey", os.urandom(32))
pubkey = ec_pubkey_create(seckey)
rec_sig = ecdsa_sign_recoverable(seckey, msg_hash)
compact_rec_sig_ser, recid = ecdsa_recoverable_signature_serialize_compact(rec_sig)
print("compact signature:", compact_rec_sig_ser.hex(), "recovery id:", recid)
rec_sig_parsed = ecdsa_recoverable_signature_parse_compact(compact_rec_sig_ser, recid)
assert rec_sig_parsed.raw, rec_sig.raw
rec_pubkey = ecdsa_recover(rec_sig, msg_hash)
print("recovered pubkey is the same as original:", pubkey.raw == rec_pubkey.raw)                                            
```

### ECDH
```python
import os
from pysecp256k1 import tagged_sha256
from pysecp256k1 import ec_pubkey_create
from pysecp256k1.ecdh import ecdh


bob_seckey = tagged_sha256(b"seckey", os.urandom(32))
bob_pubkey = ec_pubkey_create(bob_seckey)
alice_seckey = tagged_sha256(b"seckey", os.urandom(32))
alice_pubkey = ec_pubkey_create(alice_seckey)
shared_secret_bob = ecdh(bob_seckey, alice_pubkey)
shared_secret_alice = ecdh(alice_seckey, bob_pubkey)
print("bob and alice shared secret equals:", shared_secret_bob == shared_secret_alice)
```

### Tweaking
```python
import os
from pysecp256k1 import (
    ec_pubkey_create, ec_seckey_tweak_add, ec_seckey_negate, ec_seckey_verify,
    tagged_sha256
)
from pysecp256k1.extrakeys import (
    keypair_create, keypair_sec, keypair_xonly_pub, xonly_pubkey_from_pubkey,
    xonly_pubkey_serialize, xonly_pubkey_tweak_add_check, xonly_pubkey_parse,
    xonly_pubkey_tweak_add, keypair_xonly_tweak_add
)


seckey = tagged_sha256(b"seckey", os.urandom(32))
raw_pubkey = ec_pubkey_create(seckey)
keypair = keypair_create(seckey)
xonly_pub, parity = xonly_pubkey_from_pubkey(raw_pubkey)
xonly_pub1, parity1 = keypair_xonly_pub(keypair)
assert xonly_pub.raw == xonly_pub1.raw
assert parity == parity1
ser_xonly_pub = xonly_pubkey_serialize(xonly_pub)
assert xonly_pubkey_parse(ser_xonly_pub).raw == xonly_pub.raw

valid_tweak = tagged_sha256(b"tweak", seckey)  # this is random
assert ec_seckey_verify(valid_tweak) is None
# tweak keypair
tweaked_keypair = keypair_xonly_tweak_add(keypair, valid_tweak)
# below returns standard pubkey (not xonly)
tweaked_pubkey = xonly_pubkey_tweak_add(xonly_pub, valid_tweak)
tweaked_xonly_pub, parity2 = xonly_pubkey_from_pubkey(tweaked_pubkey)
tweaked_xonly_pub1, parity3 = keypair_xonly_pub(tweaked_keypair)
assert tweaked_xonly_pub.raw == tweaked_xonly_pub1.raw
assert parity2 == parity3
ser_tweaked_xonly_pub = xonly_pubkey_serialize(tweaked_xonly_pub)
assert xonly_pubkey_tweak_add_check(
    ser_tweaked_xonly_pub, parity2, xonly_pub, valid_tweak
) is True
# https://github.com/bitcoin-core/secp256k1/issues/1021
if parity == 0:
    tweaked_seckey = ec_seckey_tweak_add(seckey, valid_tweak)
else:
    tweaked_seckey = ec_seckey_tweak_add(
        ec_seckey_negate(seckey), valid_tweak
    )
assert tweaked_seckey == keypair_sec(tweaked_keypair)
```

### Negations
```python
import os
from pysecp256k1 import ec_pubkey_create, ec_pubkey_negate, ec_seckey_negate, tagged_sha256


seckey = tagged_sha256(b"seckey", os.urandom(32))
pubkey = ec_pubkey_create(seckey)
# double negation - result is the same seckey
assert seckey == ec_seckey_negate(ec_seckey_negate(seckey))
# double negation - result is the same pubkey
assert pubkey.raw == ec_pubkey_negate(ec_pubkey_negate(pubkey)).raw

```
## Testing
```shell
cd python-secp256k1
python3 -m unittest -vvv
```
or with tox against multiple python interpreters
```shell
cd python-secp256k1
tox
```
