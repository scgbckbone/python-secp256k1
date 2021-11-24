import ctypes


secp256k1_ecdsa_recoverable_signature = ctypes.c_char * 65


# Parse a compact ECDSA signature (64 bytes + recovery id).
#
# Returns: 1 when the signature could be parsed, 0 otherwise
# Args: ctx:     a secp256k1 context object
# Out:  sig:     a pointer to a signature object
# In:   input64: a pointer to a 64-byte compact signature
#       recid:   the recovery id (0, 1, 2 or 3)
#
#SECP256K1_API int secp256k1_ecdsa_recoverable_signature_parse_compact(
#    const secp256k1_context* ctx,
#    secp256k1_ecdsa_recoverable_signature* sig,
#    const unsigned char *input64,
#    int recid
#) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);
def ecdsa_recoverable_signature_parse_compact():
    pass


# Convert a recoverable signature into a normal signature.
#
# Returns: 1
# Args: ctx:    a secp256k1 context object.
# Out:  sig:    a pointer to a normal signature.
# In:   sigin:  a pointer to a recoverable signature.
#
#SECP256K1_API int secp256k1_ecdsa_recoverable_signature_convert(
#    const secp256k1_context* ctx,
#    secp256k1_ecdsa_signature* sig,
#    const secp256k1_ecdsa_recoverable_signature* sigin
#) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);
def ecdsa_recoverable_signature_convert():
    pass


# Serialize an ECDSA signature in compact format (64 bytes + recovery id).
#
# Returns: 1
# Args: ctx:      a secp256k1 context object.
# Out:  output64: a pointer to a 64-byte array of the compact signature.
#       recid:    a pointer to an integer to hold the recovery id.
# In:   sig:      a pointer to an initialized signature object.
#
#SECP256K1_API int secp256k1_ecdsa_recoverable_signature_serialize_compact(
#    const secp256k1_context* ctx,
#    unsigned char *output64,
#    int *recid,
#    const secp256k1_ecdsa_recoverable_signature* sig
#) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);
def ecdsa_recoverable_signature_serialize_compact():
    pass


# Create a recoverable ECDSA signature.
#
# Returns: 1: signature created
#          0: the nonce generation function failed, or the secret key was invalid.
# Args:    ctx:       pointer to a context object, initialized for signing.
# Out:     sig:       pointer to an array where the signature will be placed.
# In:      msghash32: the 32-byte message hash being signed.
#          seckey:    pointer to a 32-byte secret key.
#          noncefp:   pointer to a nonce generation function. If NULL,
#                     secp256k1_nonce_function_default is used.
#          ndata:     pointer to arbitrary data used by the nonce generation function
#                     (can be NULL for secp256k1_nonce_function_default).
#
#SECP256K1_API int secp256k1_ecdsa_sign_recoverable(
#    const secp256k1_context* ctx,
#    secp256k1_ecdsa_recoverable_signature *sig,
#    const unsigned char *msghash32,
#    const unsigned char *seckey,
#    secp256k1_nonce_function noncefp,
#    const void *ndata
#) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);
def ecdsa_sign_recoverable():
    pass


# Recover an ECDSA public key from a signature.
#
# Returns: 1: public key successfully recovered (which guarantees a correct signature).
#          0: otherwise.
# Args:    ctx:       pointer to a context object, initialized for verification.
# Out:     pubkey:    pointer to the recovered public key.
# In:      sig:       pointer to initialized signature that supports pubkey recovery.
#          msghash32: the 32-byte message hash assumed to be signed.
#
#SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_ecdsa_recover(
#    const secp256k1_context* ctx,
#    secp256k1_pubkey *pubkey,
#    const secp256k1_ecdsa_recoverable_signature *sig,
#    const unsigned char *msghash32
#) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);
def ecdsa_recover():
    pass
