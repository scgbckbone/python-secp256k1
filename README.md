# python-secp256k1
#### WARNING: In python you do not control memory. Regardless of how secrets are passed to the underlying lib, it still was an object in python before. It will linger in the heap for some time even after going out of scope. It is also impossible to mlock() secrets, your private keys may end up on disk in swap. Use with caution!!!

Python FFI bindings for [libsecp256k1](https://github.com/bitcoin-core/secp256k1) (an experimental and optimized C library for EC operations on curve secp256k1) using [ctypes](https://docs.python.org/3/library/ctypes.html).
Alternative implementation that uses [cffi](https://cffi.readthedocs.io/en/latest/) instead of ctypes is [secp256k1-py](https://github.com/rustyrussell/secp256k1-py).
CFFI is heavier, needs compiler for API mode (parses C headers) while ctypes does not need dependencies at all.

#### Rationale and goal
This library aims to provide a standard way to wrap `libsecp256k1` using `ctypes` for `cpython` implementation.
If `micropython` implementation is needed use [libngu](https://github.com/switck/libngu) - currently opened as [PR](https://github.com/switck/libngu/pull/42)

#### Implementation Details
* Scratch spaces are not implemented.
* methods from `secp256k1_preallocated.h` are not implemented
* This library creates default contexts (sign/verify) at the initialization phase, randomizes them 
and uses them the whole time, you do not need to worry about contexts. In case you need to randomize more often (to protect against side-channel leakage)
use `pysecp256k1.context_randomize`.
* Default illegal callback function (that is added to default contexts) logs to stderr. 
* Method names are the same as in `libsecp256k1` but without `secp256k1_` prefix (i.e. `secp256k1_ec_pubkey_serialize` -> `ec_pubkey_serialize`)
* Modules are structured same as in secp256k1 `include/` directory but without `secp256k1_` prefix.

|     secp256k1 modules     |    pysecp256k1 modules    |              importing               |
|:-------------------------:|:-------------------------:|:------------------------------------:|
|        secp256k1.h        | pysecp256k1.\_\_init__.py |      from pysecp256k1 import *       |
|     secp256k1_ecdh.h      |    pysecp256k1.ecdh.py    |    from pysecp256k1.ecdh import *    |
|   secp256k1_extrakeys.h   | pysecp256k1.extrakeys.py  | from pysecp256k1.extrakeys import *  |
|   secp256k1_recovery.h    |  pysecp256k1.recovery.py  |  from pysecp256k1.recovery import *  |
|  secp256k1_schnorrsig.h   | pysecp256k1.schnorrsig.py | from pysecp256k1.schnorrsig import * |
|     secp256k1_musig.h     |   pysecp256k1.musig.py    |   from pysecp256k1.musig import *    |

#### Validation and data types
This library tries to supplement `libsecp256k1` with valid data ONLY, therefore heavy input type validation is in place. 

Internal (opaque) secp256k1 data structures are represented as `ctypes.c_char_Array`
to get bytes from `c_char_Array` use `.raw` (see examples).

|         pysecp256k1 class          |       type       |
|:----------------------------------:|:----------------:|
|          Secp256k1Pubkey           | c_char_Array_64  |
|      Secp256k1ECDSASignature       | c_char_Array_64  |
|        Secp256k1XonlyPubkey        | c_char_Array_64  |
|          Secp256k1Keypair          | c_char_Array_96  |
| Secp256k1ECDSARecoverableSignature | c_char_Array_65  |
|          Secp256k1Context          |     c_void_p     |
|          MuSigKeyAggCache          | c_char_Array_197 |
|           MuSigSecNonce            | c_char_Array_132 |
|           MuSigPubNonce            | c_char_Array_132 |
|           MuSigAggNonce            | c_char_Array_132 |
|            MuSigSession            | c_char_Array_133 |
|          MuSigPartialSig           | c_char_Array_36  |

Apart from `ctypes.c_char_Array` and `ctypes.c_void_p` this library uses a limited number of standard python types.

|                    python type                    |                                                                usage                                                                |
|:-------------------------------------------------:|:-----------------------------------------------------------------------------------------------------------------------------------:|
|                       bool                        |           result of signature verification functions `ecdsa_verify`, `schnorrsig_verify`, and `musig_partial_sig_verify`            |
|                        int                        |                                                 recovery id and pubkey parity                                                 |
|                       bytes                       |         tags, tweaks, messages, message hashes, serialized pubkeys, serialized signatures, seckeys, serialized musig nonces         |
|               List[Secp256k1Pubkey]               |                    list of initialized pubkeys for `ec_pubkey_combine`, `ec_pubkey_sort`, and `musig_pubkey_agg`                    |
|                List[MuSigPubNonce]                |                                         list of initialized pubnonces for `musig_nonce_agg`                                         |
|               List[MuSigPartialSig]               |                              list of initialized musig partial signatures for `musig_partial_sig_agg`                               |
|         Tuple[Secp256k1XonlyPubkey, int]          |                                             initialized xonly public key and its parity                                             |
|                 Tuple[bytes, int]                 |                                        serialized recoverable signature and its recovery id                                         |
|        Tuple[MuSigSecNonce, MuSigPubNonce]        |                                   initialized secnonce & pubnonce returned from `musig_nonce_gen`                                   |
|                     Optional                      |                                              optional data not requires for operation                                               |

## Installation and dependencies
Only dependency of `pysecp256k1` is `python3.6+` and `libsecp256k1` itself.
To use full feature set build secp256k1 this way:
```shell
git clone https://github.com/bitcoin-core/secp256k1.git
cd secp256k1/
git checkout 0cdc758a56360bf58a851fe91085a327ec97685a  # v0.6.0
./autogen.sh
./configure --enable-module-recovery
make
make check
sudo make install
```
if one builds secp256k1 without schnorrsig for example and then tries to import from it `from pysecp256k1.schnorrsig import schnorrsig_sign32`
`RuntimeError` is raised hinting that `libsecp256k1` is built without schnorrsig support. Same applies for all optional modules.

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
from pysecp256k1.low_level.constants import *
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
extraparams = SchnorrsigExtraparams(
    SCHNORRSIG_EXTRAPARAMS_MAGIC,
    None,  # custom nonce function goes here
    ctypes.cast(ctypes.create_string_buffer(rand_32), ctypes.c_void_p),
)
sig0 = schnorrsig_sign_custom(keypair, msg, extraparams)
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

### MuSig2
```python
import ctypes, os
from pysecp256k1 import ec_pubkey_sort, ec_pubkey_serialize, ec_seckey_verify, ec_pubkey_create
from pysecp256k1.extrakeys import xonly_pubkey_from_pubkey, keypair_create, xonly_pubkey_serialize
from pysecp256k1.schnorrsig import schnorrsig_verify
from pysecp256k1.low_level.constants import MuSigKeyAggCache
from pysecp256k1.musig import (musig_nonce_gen, musig_pubnonce_serialize, musig_pubkey_agg,
                               musig_pubkey_ec_tweak_add, musig_pubkey_xonly_tweak_add,
                               musig_nonce_agg, musig_nonce_process, musig_partial_sign,
                               musig_partial_sig_serialize, musig_partial_sig_agg,
                               musig_partial_sig_verify, musig_aggnonce_serialize)

cache = MuSigKeyAggCache()
msg = 32*b"b"
tweak_bip32 = 32*b"a"
xonly_tweak = 32*b"c"

signers = []
pubkeys = []
N_signers = 3

for i in range(N_signers):
    sk = os.urandom(32)
    ec_seckey_verify(sk)
    pk = ec_pubkey_create(sk)
    print("Signer %d" % i)
    print("seckey", sk.hex())
    print("pubkey", ec_pubkey_serialize(pk).hex())
    print(80 * "=")
    signers.append([sk, pk])
    pubkeys.append(pk)
print()

pubkeys = ec_pubkey_sort(pubkeys)
agg_key = musig_pubkey_agg(pubkeys, cache)
print("aggregate pubkey", ec_pubkey_serialize(agg_key).hex())

tweaked_pk = musig_pubkey_ec_tweak_add(tweak_bip32, cache)
print("tweak bip32", tweak_bip32.hex())
print("tweaked key", ec_pubkey_serialize(tweaked_pk).hex())

tweaked_pk = musig_pubkey_xonly_tweak_add(xonly_tweak, cache)
print("xonly tweak", xonly_tweak.hex())
print("tweaked key", ec_pubkey_serialize(tweaked_pk).hex())

tweaked_xpk, _ = xonly_pubkey_from_pubkey(tweaked_pk)
print("aggregate & tweaked xonly pubkey", xonly_pubkey_serialize(tweaked_xpk).hex())
print()

pubnonces = []
for i, slist in enumerate(signers):
    session_sec = os.urandom(32)
    sn, pn = musig_nonce_gen(slist[1], session_secrand32=session_sec, seckey=slist[0],
                             msg32=msg, keyagg_cache=cache)
    pubnonces.append(pn)
    print("Signer %d pubnonce:" % i, musig_pubnonce_serialize(pn).hex())
    slist.append(sn)

agg_nonce = musig_nonce_agg(pubnonces)
print("aggregate nonce", musig_aggnonce_serialize(agg_nonce).hex())
print()

partial_sigs = []
sessions = []
for i, (sk, pk, secn) in enumerate(signers):
    session = musig_nonce_process(agg_nonce, msg, cache)
    sig = musig_partial_sign(secn, keypair_create(sk), cache, session)
    print("Signer %d part sig" % i, musig_partial_sig_serialize(sig).hex())
    partial_sigs.append(sig)
    sessions.append(session)

for i, sig in enumerate(partial_sigs):
    assert musig_partial_sig_verify(sig, pubnonces[i], signers[i][1], cache, sessions[i])
    print("Signer %d part sig verifies OK" % i)
print()

agg_sig = musig_partial_sig_agg(sessions[0], partial_sigs)
print("aggregate signature", agg_sig.hex())
assert schnorrsig_verify(agg_sig, msg, tweaked_xpk)
print("verifies OK")
print("msg", msg.hex())
print("pubkey", xonly_pubkey_serialize(tweaked_xpk).hex())

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

## Command line interface

`pysecp256k1` also includes a small `argparse` CLI for the useful package-root
commands plus the enabled optional modules: `ecdh`, `extrakeys`, `recovery`,
`schnorrsig`, and `musig`.

Run it with:

```shell
python3 -m pysecp256k1 --help
python3 -m pysecp256k1 <subcommand> --help
```

CLI conventions:

* Subcommand names are function names with underscores replaced by dashes
  (`ecdsa_sign` -> `ecdsa-sign`).
* Byte inputs are hex strings, except message-like fields that also accept
  plain ASCII after hex parsing fails: `tagged-sha256 --tag`, `tagged-sha256
  --msg`, and Schnorr `--msg`.
* `--seckey` can be written as `-s`; `--pubkey` can be written as `-p`.
* Byte outputs are printed as a single hex string on stdout.
* `ecdsa-verify` prints text values.
* Public keys are supplied and returned as serialized public key hex. Use
  `ec-pubkey-parse` to validate a serialized public key and emit canonical
  compressed or uncompressed hex.
* ECDSA signatures are supplied and returned as compact 64-byte signature hex by
  default. Use `--der` where available to emit DER signatures. For
  `ecdsa-signature-normalize`, use `--input-der` and `--output-der` to choose
  input and output encodings independently.
* X-only public keys are supplied and returned as 32-byte hex.
* Keypair commands accept `--seckey` and create the keypair internally because
  keypairs are opaque and have no CLI serialization.
* Commands returning an x-only pubkey with parity print `<xonly-pubkey-hex> <parity>`.
* `ecdh` prints the 32-byte shared secret hex derived from `--seckey` and
  `--pubkey`.
* Recoverable ECDSA signatures are supplied as `--sig <64-byte-compact-hex>`
  plus `--rec-id <0..3>`. Commands that emit a recoverable signature print
  `<compact-sig-hex> <rec-id>`.
* Schnorr signatures are supplied and returned as 64-byte compact signature hex.
  Schnorr signing commands accept `--seckey` and create a keypair internally;
  verification accepts `--xonly-pubkey`.
* `musig-pubkey-agg` prints `<agg-xonly-pubkey-hex> <keyagg-cache-hex>`. The
  key aggregation cache is raw internal hex and is passed back to later MuSig
  commands with `-c`/`--keyagg-cache`.
* MuSig nonce generation prints `<secnonce-hex> <pubnonce-hex>`. The secret
  nonce is exposed only so the CLI can be used to learn the two-round protocol;
  reusing it across sessions can leak the secret key.
* MuSig sessions are printed as raw session hex by `musig-nonce-process` and are
  passed back to `musig-partial-sign`, `musig-partial-sig-verify`, and
  `musig-partial-sig-agg`.
* MuSig secret nonces, sessions, and key aggregation caches are internal
  libsecp256k1 blobs exposed only for this learning CLI. They are not stable
  portable serializations.

Exit codes:

* `0` - success, including a true verification result
* `1` - verification completed and returned false
* `2` - invalid input or libsecp256k1 error; stderr starts with `error:`

Available subcommands:

```text
ec-pubkey-parse
ec-pubkey-sort
ec-pubkey-combine
ec-pubkey-create
ec-pubkey-negate
ec-pubkey-tweak-add
ec-pubkey-tweak-mul
ec-seckey-verify
ec-seckey-negate
ec-seckey-tweak-add
ec-seckey-tweak-mul
ecdsa-sign
ecdsa-verify
ecdsa-signature-parse-compact
ecdsa-signature-parse-der
ecdsa-signature-normalize
tagged-sha256
ecdh
ecdsa-recoverable-signature-parse-compact
ecdsa-recoverable-signature-convert
ecdsa-sign-recoverable
ecdsa-recover
schnorrsig-sign
schnorrsig-verify
musig-pubnonce-parse
musig-aggnonce-parse
musig-partial-sig-parse
musig-pubkey-agg
musig-pubkey-ec-tweak-add
musig-pubkey-xonly-tweak-add
musig-nonce-gen
musig-nonce-gen-counter
musig-nonce-agg
musig-nonce-process
musig-partial-sign
musig-partial-sig-verify
musig-partial-sig-agg
xonly-pubkey-parse
xonly-pubkey-from-pubkey
xonly-pubkey-tweak-add
xonly-pubkey-tweak-add-check
keypair-xonly-pub
keypair-xonly-tweak-add
```

Examples:

```shell
# Create a compressed public key from a 32-byte secret key.
python3 -m pysecp256k1 ec-pubkey-create \
  --seckey 97e07bd67fe1c532283581c9fe675f8d1b30ec77769af5fdae09f079dc195ade

# Validate a serialized public key and emit uncompressed canonical hex.
python3 -m pysecp256k1 ec-pubkey-parse \
  --pubkey 021b59c0eaa5365a0dbf1f38ffc11cb19c31be9a2292bdcb7e8fb42da32a5b1e93 \
  --uncompressed

# Sign a 32-byte message hash. Output is compact signature hex by default.
python3 -m pysecp256k1 ecdsa-sign \
  --seckey 97e07bd67fe1c532283581c9fe675f8d1b30ec77769af5fdae09f079dc195ade \
  --msghash 1111111111111111111111111111111111111111111111111111111111111111

# Verify a compact ECDSA signature.
python3 -m pysecp256k1 ecdsa-verify \
  --sig <compact-sig-hex> \
  --pubkey <serialized-pubkey-hex> \
  --msghash <32-byte-message-hash-hex>

# Parse a DER signature and emit DER again.
python3 -m pysecp256k1 ecdsa-signature-parse-der \
  --sig <der-sig-hex> \
  --der

# Normalize an ECDSA signature from DER input and emit compact hex.
python3 -m pysecp256k1 ecdsa-signature-normalize \
  --sig <der-sig-hex> \
  --input-der

# Compute a BIP-340 tagged hash.
python3 -m pysecp256k1 tagged-sha256 \
  --tag 746167 \
  --msg 6d657373616765

# Compute an ECDH shared secret from a secret key and the peer public key.
python3 -m pysecp256k1 ecdh \
  --seckey 97e07bd67fe1c532283581c9fe675f8d1b30ec77769af5fdae09f079dc195ade \
  --pubkey 02f008b4e5ade1236e97dc5d3d81eab7be8553ce88c5081cba7ce81143d3058029

# Create a recoverable ECDSA signature. Output is "<compact-sig-hex> <rec-id>".
python3 -m pysecp256k1 ecdsa-sign-recoverable \
  --seckey 97e07bd67fe1c532283581c9fe675f8d1b30ec77769af5fdae09f079dc195ade \
  --msghash 1111111111111111111111111111111111111111111111111111111111111111

# Recover a public key from a compact recoverable signature and message hash.
python3 -m pysecp256k1 ecdsa-recover \
  --sig <compact-sig-hex> \
  --rec-id <0..3> \
  --msghash <32-byte-message-hash-hex>

# Convert a recoverable signature to a normal DER ECDSA signature.
python3 -m pysecp256k1 ecdsa-recoverable-signature-convert \
  --sig <compact-sig-hex> \
  --rec-id <0..3> \
  --der

# Create a Schnorr signature over a message.
python3 -m pysecp256k1 schnorrsig-sign \
  --seckey 97e07bd67fe1c532283581c9fe675f8d1b30ec77769af5fdae09f079dc195ade \
  --msg 6d657373616765

# Verify a Schnorr signature.
python3 -m pysecp256k1 schnorrsig-verify \
  --sig <compact-schnorr-sig-hex> \
  --msg <message-hex> \
  --xonly-pubkey <32-byte-xonly-pubkey-hex>

# Aggregate MuSig signer public keys into an x-only aggregate public key and cache.
# Output is "<agg-xonly-pubkey-hex> <keyagg-cache-hex>".
python3 -m pysecp256k1 musig-pubkey-agg \
  --pubkey <signer-0-pubkey-hex> \
  --pubkey <signer-1-pubkey-hex> \
  --sort

# Round 1: each signer generates and saves a secret nonce, and shares the public nonce.
# Output is "<secnonce-hex> <pubnonce-hex>".
python3 -m pysecp256k1 musig-nonce-gen \
  --pubkey <this-signer-pubkey-hex> \
  --session-secrand <unique-32-byte-random-hex> \
  --seckey <this-signer-seckey-hex> \
  --msg <32-byte-message-hash-hex> \
  --keyagg-cache <keyagg-cache-hex>

# Aggregate public nonces from all signers.
python3 -m pysecp256k1 musig-nonce-agg \
  --pubnonce <signer-0-pubnonce-hex> \
  --pubnonce <signer-1-pubnonce-hex>

# Round 2 setup: create the session hex from the aggregate nonce.
python3 -m pysecp256k1 musig-nonce-process \
  --aggnonce <aggregate-nonce-hex> \
  --msg <32-byte-message-hash-hex> \
  -c <keyagg-cache-hex>

# Round 2: each signer creates a partial signature using the saved secret nonce.
python3 -m pysecp256k1 musig-partial-sign \
  --secnonce <this-signer-secnonce-hex> \
  --seckey <this-signer-seckey-hex> \
  --session <session-hex> \
  --keyagg-cache <keyagg-cache-hex>

# Optional: verify an individual signer's partial signature.
python3 -m pysecp256k1 musig-partial-sig-verify \
  --sig <signer-partial-sig-hex> \
  --pubnonce <signer-pubnonce-hex> \
  --pubkey <signer-pubkey-hex> \
  --session <session-hex> \
  -c <keyagg-cache-hex>

# Aggregate partial signatures into the final Schnorr signature.
python3 -m pysecp256k1 musig-partial-sig-agg \
  --session <session-hex> \
  --partial-sig <signer-0-partial-sig-hex> \
  --partial-sig <signer-1-partial-sig-hex>

# Convert a serialized public key to x-only form. Output is "<xonly-hex> <parity>".
python3 -m pysecp256k1 xonly-pubkey-from-pubkey \
  --pubkey 021b59c0eaa5365a0dbf1f38ffc11cb19c31be9a2292bdcb7e8fb42da32a5b1e93

# Get the x-only public key for a secret key. Output is "<xonly-hex> <parity>".
python3 -m pysecp256k1 keypair-xonly-pub \
  --seckey 97e07bd67fe1c532283581c9fe675f8d1b30ec77769af5fdae09f079dc195ade

# Tweak an x-only public key and emit the resulting compressed public key.
python3 -m pysecp256k1 xonly-pubkey-tweak-add \
  --xonly-pubkey 1b59c0eaa5365a0dbf1f38ffc11cb19c31be9a2292bdcb7e8fb42da32a5b1e93 \
  --tweak d48c88512f15c628c611ae55d0b5609bcfc35a3127ec835308829c3ace32dc81

# Tweak a keypair created from a secret key and emit the tweaked secret key.
python3 -m pysecp256k1 keypair-xonly-tweak-add \
  --seckey 97e07bd67fe1c532283581c9fe675f8d1b30ec77769af5fdae09f079dc195ade \
  --tweak d48c88512f15c628c611ae55d0b5609bcfc35a3127ec835308829c3ace32dc81
```
