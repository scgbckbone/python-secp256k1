import ctypes

PYSECP_SO = "PYSECP_SO"

SECP256K1_FLAGS_TYPE_CONTEXT = 1 << 0
SECP256K1_FLAGS_BIT_CONTEXT_SIGN = 1 << 9
SECP256K1_FLAGS_BIT_CONTEXT_VERIFY = 1 << 8
SECP256K1_CONTEXT_SIGN = SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_SIGN
SECP256K1_CONTEXT_VERIFY = (
    SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_VERIFY
)
SECP256K1_FLAGS_TYPE_COMPRESSION = 1 << 1
SECP256K1_FLAGS_BIT_COMPRESSION = 1 << 8
SECP256K1_EC_COMPRESSED = (
    SECP256K1_FLAGS_TYPE_COMPRESSION | SECP256K1_FLAGS_BIT_COMPRESSION
)
SECP256K1_EC_UNCOMPRESSED = SECP256K1_FLAGS_TYPE_COMPRESSION

SECKEY_LENGTH = 32
HASH32 = 32
PUBLIC_KEY_LENGTH = 65
XONLY_PUBKEY_LENGTH = 32
COMPRESSED_PUBLIC_KEY_LENGTH = 33
DER_SIGNATURE_LENGTH = 72
COMPACT_SIGNATURE_LENGTH = 64
VALID_RECOVERY_IDS = [0, 1, 2, 3]
VALID_PUBKEY_PARITY = [0, 1]
SCHNORRSIG_EXTRAPARAMS_MAGIC = bytes([0xDA, 0x6F, 0xB3, 0x8C])

INTERNAL_PUBKEY_LENGTH = 64
INTERNAL_SIGNATURE_LENGTH = 64
INTERNAL_KEYPAIR_LENGTH = 96
INTERNAL_RECOVERABLE_SIGNATURE_LENGTH = 65

# Opaque secp256k1 data structures
Secp256k1Context = ctypes.c_void_p
Secp256k1Pubkey = ctypes.c_char * INTERNAL_PUBKEY_LENGTH
Secp256k1ECDSASignature = ctypes.c_char * INTERNAL_SIGNATURE_LENGTH
Secp256k1XonlyPubkey = ctypes.c_char * INTERNAL_PUBKEY_LENGTH
Secp256k1Keypair = ctypes.c_char * INTERNAL_KEYPAIR_LENGTH
Secp256k1ECDSARecoverableSignature = (
    ctypes.c_char * INTERNAL_RECOVERABLE_SIGNATURE_LENGTH
)
