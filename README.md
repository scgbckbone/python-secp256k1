# python-secp256k1

Naming convention:

private key:

bytes -> seckey
negated -> negated_seckey
tweaked -> tweaked_seckey

public key:

secp256k1_pubkey (this is the parsed version) -> pubkey
serialization (compressed, uncompressed, hybrid) -> pubkey_ser
xonly -> xonly_pubkey
xonly serialization -> xonly_pubkey_ser
tweaked  -> tweaked_xonly_pubkey

SIGNATURES:

secp256k1_ecdsa_recoverable_signature -> rec_sig
secp256k1_ecdsa_signature -> sig
compact-> compact_sig
DER -> der_sig


messages to be signed:

msghash<len> if len is unspecified just msghash


TODO : get rid of plain integers - use CONSTANTS

if return code is zero - raise Something ele than builtin python exceptions


unify imports - now it is a mess


DEPRECATED function are not added by design
ec_privkey_negate
ec_privkey_tweak_add
ec_privkey_tweak_mul

also scratch space related functions should be ignored imo
