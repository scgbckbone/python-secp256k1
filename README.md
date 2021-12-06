# python-secp256k1

Python3 wrapper of [secp256k1](https://github.com/bitcoin-core/secp256k1) library using [ctypes](https://docs.python.org/3/library/ctypes.html).

This library creates both contexts (sign/verify) at the beginning, randomizes them 
and uses them the whole time, you do not need to worry about contexts (issue here)

Scratch spaces are not implemented. 

Illegal callback logs to to stderr. 

This lib tries to supplement secp256k1 with valid data only. So heavy input/output validation is in place. 

Method names are the same as secp256k1 but without 'secp256k1_' prefix
Modules are structures same as include/

Enumerate data structures used and their rationale

## Installation
To use full feature set build secp256k1 this way:
```shell
git clone https://github.com/bitcoin-core/secp256k1.git
cd secp256k1/
git checkout 61ae37c61261a43c1199d112a79a7ad64442f36d  # last tested
./autogen.sh
./configure --enable-module-ecdh --enable-module-recovery  --enable-module-schnorrsig --enable-experimental
make
make check
sudo make install
```
This library uses the latest master and I only plan to release when secp256k1 releases. 
So until then install like this 
```shell
python3 -m pip install -U pip wheel
python3 -m pip install git+https://github.com/scgbckbone/python-secp256k1.git
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
sig = schnorrsig_sign(keypair, msg_hash, aux_rand32=rand_32)
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
