import argparse
import ctypes
import sys

import pysecp256k1 as secp
from pysecp256k1.low_level import (
    Libsecp256k1Exception,
    has_secp256k1_ecdh,
    has_secp256k1_extrakeys,
    has_secp256k1_musig,
    has_secp256k1_recovery,
    has_secp256k1_schnorrsig,
)
from pysecp256k1.low_level.constants import (
    INTERNAL_MUSIG_NONCE_LENGTH,
    INTERNAL_MUSIG_SESSION_LENGTH,
    MuSigKeyAggCache,
    SCHNORRSIG_EXTRAPARAMS_MAGIC,
)

if has_secp256k1_ecdh:
    import pysecp256k1.ecdh as ecdh_module

if has_secp256k1_extrakeys:
    import pysecp256k1.extrakeys as extrakeys

if has_secp256k1_recovery:
    import pysecp256k1.recovery as recovery

if has_secp256k1_schnorrsig:
    import pysecp256k1.schnorrsig as schnorrsig

if has_secp256k1_musig:
    import pysecp256k1.musig as musig


def _bytes_from_hex(value):
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc))


def _hex_or_ascii(value):
    try:
        return bytes.fromhex(value)
    except ValueError:
        return value.encode()


def _optional_hex(value):
    return _bytes_from_hex(value) if value is not None else None


class _CLIArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, "error: {}\n".format(message))


def _musig_pubkeys(values, sort_pubkeys=False):
    pubkeys = [secp.ec_pubkey_parse(_bytes_from_hex(value)) for value in values]
    if sort_pubkeys:
        pubkeys = secp.ec_pubkey_sort(pubkeys)
    return pubkeys


def _musig_keyagg_cache(value):
    raw = _bytes_from_hex(value)
    assert len(raw) == ctypes.sizeof(MuSigKeyAggCache)
    return ctypes.create_string_buffer(raw, ctypes.sizeof(MuSigKeyAggCache))


def _musig_secnonce(value):
    raw = _bytes_from_hex(value)
    assert len(raw) == INTERNAL_MUSIG_NONCE_LENGTH
    return ctypes.create_string_buffer(raw, INTERNAL_MUSIG_NONCE_LENGTH)


def _musig_session(value):
    raw = _bytes_from_hex(value)
    assert len(raw) == INTERNAL_MUSIG_SESSION_LENGTH
    return ctypes.create_string_buffer(raw, INTERNAL_MUSIG_SESSION_LENGTH)


def _handle_ec_pubkey_parse(args):
    pubkey = secp.ec_pubkey_parse(_bytes_from_hex(args.pubkey))
    print(secp.ec_pubkey_serialize(pubkey, compressed=args.compressed).hex())
    return 0


def _handle_ec_pubkey_sort(args):
    pubkeys = [secp.ec_pubkey_parse(_bytes_from_hex(pubkey)) for pubkey in args.pubkey]
    for pubkey in secp.ec_pubkey_sort(pubkeys):
        print(secp.ec_pubkey_serialize(pubkey).hex())
    return 0


def _handle_ec_pubkey_combine(args):
    pubkeys = [secp.ec_pubkey_parse(_bytes_from_hex(pubkey)) for pubkey in args.pubkey]
    print(secp.ec_pubkey_serialize(secp.ec_pubkey_combine(pubkeys)).hex())
    return 0


def _handle_ec_pubkey_create(args):
    pubkey = secp.ec_pubkey_create(_bytes_from_hex(args.seckey))
    print(secp.ec_pubkey_serialize(pubkey).hex())
    return 0


def _handle_ec_pubkey_negate(args):
    pubkey = secp.ec_pubkey_parse(_bytes_from_hex(args.pubkey))
    print(secp.ec_pubkey_serialize(secp.ec_pubkey_negate(pubkey)).hex())
    return 0


def _handle_ec_pubkey_tweak_add(args):
    pubkey = secp.ec_pubkey_parse(_bytes_from_hex(args.pubkey))
    tweak = _bytes_from_hex(args.tweak)
    print(secp.ec_pubkey_serialize(secp.ec_pubkey_tweak_add(pubkey, tweak)).hex())
    return 0


def _handle_ec_pubkey_tweak_mul(args):
    pubkey = secp.ec_pubkey_parse(_bytes_from_hex(args.pubkey))
    tweak = _bytes_from_hex(args.tweak)
    print(secp.ec_pubkey_serialize(secp.ec_pubkey_tweak_mul(pubkey, tweak)).hex())
    return 0


def _handle_ec_seckey_verify(args):
    secp.ec_seckey_verify(_bytes_from_hex(args.seckey))
    return 0


def _handle_ec_seckey_negate(args):
    print(secp.ec_seckey_negate(_bytes_from_hex(args.seckey)).hex())
    return 0


def _handle_ec_seckey_tweak_add(args):
    seckey = _bytes_from_hex(args.seckey)
    tweak = _bytes_from_hex(args.tweak)
    print(secp.ec_seckey_tweak_add(seckey, tweak).hex())
    return 0


def _handle_ec_seckey_tweak_mul(args):
    seckey = _bytes_from_hex(args.seckey)
    tweak = _bytes_from_hex(args.tweak)
    print(secp.ec_seckey_tweak_mul(seckey, tweak).hex())
    return 0


def _handle_ecdsa_sign(args):
    sig = secp.ecdsa_sign(_bytes_from_hex(args.seckey), _bytes_from_hex(args.msghash))
    if args.der:
        print(secp.ecdsa_signature_serialize_der(sig).hex())
    else:
        print(secp.ecdsa_signature_serialize_compact(sig).hex())
    return 0


def _handle_ecdsa_verify(args):
    sig_bytes = _bytes_from_hex(args.sig)
    if args.der:
        sig = secp.ecdsa_signature_parse_der(sig_bytes)
    else:
        sig = secp.ecdsa_signature_parse_compact(sig_bytes)
    pubkey = secp.ec_pubkey_parse(_bytes_from_hex(args.pubkey))
    ok = secp.ecdsa_verify(sig, pubkey, _bytes_from_hex(args.msghash))
    print(ok)
    return 0 if ok else 1


def _handle_ecdsa_signature_parse_compact(args):
    sig = secp.ecdsa_signature_parse_compact(_bytes_from_hex(args.sig))
    if args.der:
        print(secp.ecdsa_signature_serialize_der(sig).hex())
    else:
        print(secp.ecdsa_signature_serialize_compact(sig).hex())
    return 0


def _handle_ecdsa_signature_parse_der(args):
    sig = secp.ecdsa_signature_parse_der(_bytes_from_hex(args.sig))
    if args.der:
        print(secp.ecdsa_signature_serialize_der(sig).hex())
    else:
        print(secp.ecdsa_signature_serialize_compact(sig).hex())
    return 0


def _handle_ecdsa_signature_normalize(args):
    if args.input_der:
        sig = secp.ecdsa_signature_parse_der(_bytes_from_hex(args.sig))
    else:
        sig = secp.ecdsa_signature_parse_compact(_bytes_from_hex(args.sig))
    normalized = secp.ecdsa_signature_normalize(sig)
    if args.output_der:
        print(secp.ecdsa_signature_serialize_der(normalized).hex())
    else:
        print(secp.ecdsa_signature_serialize_compact(normalized).hex())
    return 0


def _handle_tagged_sha256(args):
    print(secp.tagged_sha256(_hex_or_ascii(args.tag), _hex_or_ascii(args.msg)).hex())
    return 0


def _handle_ecdh(args):
    pubkey = secp.ec_pubkey_parse(_bytes_from_hex(args.pubkey))
    print(ecdh_module.ecdh(_bytes_from_hex(args.seckey), pubkey).hex())
    return 0


def _handle_ecdsa_recoverable_signature_parse_compact(args):
    rec_sig = recovery.ecdsa_recoverable_signature_parse_compact(
        _bytes_from_hex(args.sig), args.rec_id
    )
    compact_sig, rec_id = recovery.ecdsa_recoverable_signature_serialize_compact(rec_sig)
    print("{} {}".format(compact_sig.hex(), rec_id))
    return 0


def _handle_ecdsa_recoverable_signature_convert(args):
    rec_sig = recovery.ecdsa_recoverable_signature_parse_compact(
        _bytes_from_hex(args.sig), args.rec_id
    )
    sig = recovery.ecdsa_recoverable_signature_convert(rec_sig)
    if args.der:
        print(secp.ecdsa_signature_serialize_der(sig).hex())
    else:
        print(secp.ecdsa_signature_serialize_compact(sig).hex())
    return 0


def _handle_ecdsa_sign_recoverable(args):
    rec_sig = recovery.ecdsa_sign_recoverable(
        _bytes_from_hex(args.seckey), _bytes_from_hex(args.msghash)
    )
    compact_sig, rec_id = recovery.ecdsa_recoverable_signature_serialize_compact(rec_sig)
    print("{} {}".format(compact_sig.hex(), rec_id))
    return 0


def _handle_ecdsa_recover(args):
    rec_sig = recovery.ecdsa_recoverable_signature_parse_compact(
        _bytes_from_hex(args.sig), args.rec_id
    )
    pubkey = recovery.ecdsa_recover(rec_sig, _bytes_from_hex(args.msghash))
    print(secp.ec_pubkey_serialize(pubkey, compressed=args.compressed).hex())
    return 0


def _handle_schnorrsig_sign(args):
    keypair = extrakeys.keypair_create(_bytes_from_hex(args.seckey))
    extraparams = None
    if args.aux_rand is not None:
        aux_rand = _bytes_from_hex(args.aux_rand)
        assert len(aux_rand) == 32
        extraparams = schnorrsig.SchnorrsigExtraparams(
            SCHNORRSIG_EXTRAPARAMS_MAGIC,
            None,
            ctypes.cast(ctypes.create_string_buffer(aux_rand), ctypes.c_void_p),
        )
    print(schnorrsig.schnorrsig_sign_custom(keypair, _hex_or_ascii(args.msg), extraparams).hex())
    return 0


def _handle_schnorrsig_verify(args):
    xonly_pubkey = extrakeys.xonly_pubkey_parse(_bytes_from_hex(args.xonly_pubkey))
    ok = schnorrsig.schnorrsig_verify(
        _bytes_from_hex(args.sig), _hex_or_ascii(args.msg), xonly_pubkey
    )
    print(ok)
    return 0 if ok else 1


def _handle_musig_pubnonce_parse(args):
    pubnonce = musig.musig_pubnonce_parse(_bytes_from_hex(args.pubnonce))
    print(musig.musig_pubnonce_serialize(pubnonce).hex())
    return 0


def _handle_musig_aggnonce_parse(args):
    aggnonce = musig.musig_aggnonce_parse(_bytes_from_hex(args.aggnonce))
    print(musig.musig_aggnonce_serialize(aggnonce).hex())
    return 0


def _handle_musig_partial_sig_parse(args):
    sig = musig.musig_partial_sig_parse(_bytes_from_hex(args.sig))
    print(musig.musig_partial_sig_serialize(sig).hex())
    return 0


def _handle_musig_pubkey_agg(args):
    pubkeys = _musig_pubkeys(args.pubkey, args.sort)
    cache = MuSigKeyAggCache()
    agg_pubkey = musig.musig_pubkey_agg(pubkeys, cache)
    print("{} {}".format(extrakeys.xonly_pubkey_serialize(agg_pubkey).hex(), cache.raw.hex()))
    return 0


def _handle_musig_pubkey_ec_tweak_add(args):
    cache = _musig_keyagg_cache(args.keyagg_cache)
    tweaked = musig.musig_pubkey_ec_tweak_add(_bytes_from_hex(args.tweak), cache)
    print("{} {}".format(secp.ec_pubkey_serialize(tweaked, compressed=args.compressed).hex(), cache.raw.hex()))
    return 0


def _handle_musig_pubkey_xonly_tweak_add(args):
    cache = _musig_keyagg_cache(args.keyagg_cache)
    tweaked = musig.musig_pubkey_xonly_tweak_add(_bytes_from_hex(args.tweak), cache)
    print("{} {}".format(secp.ec_pubkey_serialize(tweaked, compressed=args.compressed).hex(), cache.raw.hex()))
    return 0


def _handle_musig_nonce_gen(args):
    pubkey = secp.ec_pubkey_parse(_bytes_from_hex(args.pubkey))
    secnonce, pubnonce = musig.musig_nonce_gen(
        pubkey,
        _optional_hex(args.session_secrand),
        _optional_hex(args.seckey),
        _optional_hex(args.msg),
        _musig_keyagg_cache(args.keyagg_cache),
        _optional_hex(args.extra_input),
    )
    print("{} {}".format(secnonce.raw.hex(), musig.musig_pubnonce_serialize(pubnonce).hex()))
    return 0


def _handle_musig_nonce_gen_counter(args):
    keypair = extrakeys.keypair_create(_bytes_from_hex(args.seckey))
    secnonce, pubnonce = musig.musig_nonce_gen_counter(
        args.counter,
        keypair,
        _optional_hex(args.msg),
        _musig_keyagg_cache(args.keyagg_cache),
        _optional_hex(args.extra_input),
    )
    print("{} {}".format(secnonce.raw.hex(), musig.musig_pubnonce_serialize(pubnonce).hex()))
    return 0


def _handle_musig_nonce_agg(args):
    pubnonces = [musig.musig_pubnonce_parse(_bytes_from_hex(value)) for value in args.pubnonce]
    print(musig.musig_aggnonce_serialize(musig.musig_nonce_agg(pubnonces)).hex())
    return 0


def _handle_musig_nonce_process(args):
    cache = _musig_keyagg_cache(args.keyagg_cache)
    aggnonce = musig.musig_aggnonce_parse(_bytes_from_hex(args.aggnonce))
    session = musig.musig_nonce_process(aggnonce, _bytes_from_hex(args.msg), cache)
    print(session.raw.hex())
    return 0


def _handle_musig_partial_sign(args):
    cache = _musig_keyagg_cache(args.keyagg_cache)
    sig = musig.musig_partial_sign(
        _musig_secnonce(args.secnonce),
        extrakeys.keypair_create(_bytes_from_hex(args.seckey)),
        cache,
        _musig_session(args.session),
    )
    print(musig.musig_partial_sig_serialize(sig).hex())
    return 0


def _handle_musig_partial_sig_verify(args):
    cache = _musig_keyagg_cache(args.keyagg_cache)
    sig = musig.musig_partial_sig_parse(_bytes_from_hex(args.sig))
    pubnonce = musig.musig_pubnonce_parse(_bytes_from_hex(args.pubnonce))
    pubkey = secp.ec_pubkey_parse(_bytes_from_hex(args.signer_pubkey))
    ok = musig.musig_partial_sig_verify(sig, pubnonce, pubkey, cache, _musig_session(args.session))
    print(ok)
    return 0 if ok else 1


def _handle_musig_partial_sig_agg(args):
    partial_sigs = [musig.musig_partial_sig_parse(_bytes_from_hex(value)) for value in args.partial_sig]
    print(musig.musig_partial_sig_agg(_musig_session(args.session), partial_sigs).hex())
    return 0


def _handle_xonly_pubkey_parse(args):
    xonly_pubkey = extrakeys.xonly_pubkey_parse(_bytes_from_hex(args.xonly_pubkey))
    print(extrakeys.xonly_pubkey_serialize(xonly_pubkey).hex())
    return 0


def _handle_xonly_pubkey_from_pubkey(args):
    pubkey = secp.ec_pubkey_parse(_bytes_from_hex(args.pubkey))
    xonly_pubkey, parity = extrakeys.xonly_pubkey_from_pubkey(pubkey)
    print("{} {}".format(extrakeys.xonly_pubkey_serialize(xonly_pubkey).hex(), parity))
    return 0


def _handle_xonly_pubkey_tweak_add(args):
    xonly_pubkey = extrakeys.xonly_pubkey_parse(_bytes_from_hex(args.xonly_pubkey))
    tweak = _bytes_from_hex(args.tweak)
    print(secp.ec_pubkey_serialize(extrakeys.xonly_pubkey_tweak_add(xonly_pubkey, tweak)).hex())
    return 0


def _handle_xonly_pubkey_tweak_add_check(args):
    internal_pubkey = extrakeys.xonly_pubkey_parse(_bytes_from_hex(args.internal_pubkey))
    ok = extrakeys.xonly_pubkey_tweak_add_check(
        _bytes_from_hex(args.tweaked_pubkey),
        args.parity,
        internal_pubkey,
        _bytes_from_hex(args.tweak),
    )
    print(ok)
    return 0 if ok else 1


def _handle_keypair_xonly_pub(args):
    keypair = extrakeys.keypair_create(_bytes_from_hex(args.seckey))
    xonly_pubkey, parity = extrakeys.keypair_xonly_pub(keypair)
    print("{} {}".format(extrakeys.xonly_pubkey_serialize(xonly_pubkey).hex(), parity))
    return 0


def _handle_keypair_xonly_tweak_add(args):
    keypair = extrakeys.keypair_create(_bytes_from_hex(args.seckey))
    tweaked_keypair = extrakeys.keypair_xonly_tweak_add(keypair, _bytes_from_hex(args.tweak))
    print(extrakeys.keypair_sec(tweaked_keypair).hex())
    return 0


def build_parser():
    parser = _CLIArgumentParser(prog="pysecp256k1")
    subparsers = parser.add_subparsers(
        dest="command", parser_class=_CLIArgumentParser, required=True
    )
    seckey_help = "32-byte secret key hex"
    signer_seckey_help = "32-byte signer secret key hex"
    pubkey_help = "serialized public key hex"
    signer_pubkey_help = "serialized signer public key hex"
    tweak_help = "32-byte tweak hex"
    msghash_help = "32-byte message hash hex"
    msg_help = "message hex"
    sig_help = "signature hex"
    emit_der_help = "emit DER signature hex"
    compressed_help = "emit compressed public key hex"
    uncompressed_help = "emit uncompressed public key hex"
    sort_help = "sort pubkeys before aggregation"
    keyagg_cache_help = "197-byte raw internal key aggregation cache hex"
    session_help = "133-byte session hex from musig-nonce-process"

    p = subparsers.add_parser("ec-pubkey-parse")
    p.set_defaults(handler=_handle_ec_pubkey_parse)
    p.add_argument("-p", "--pubkey", required=True, help=pubkey_help)
    group = p.add_mutually_exclusive_group()
    group.add_argument("--compressed", dest="compressed", action="store_true",
                       default=True, help=compressed_help)
    group.add_argument("--uncompressed", dest="compressed", action="store_false",
                       help=uncompressed_help)

    p = subparsers.add_parser("ec-pubkey-sort")
    p.set_defaults(handler=_handle_ec_pubkey_sort)
    p.add_argument("-p", "--pubkey", action="append", required=True,
                   help="{}; repeat for multiple keys".format(pubkey_help))

    p = subparsers.add_parser("ec-pubkey-combine")
    p.set_defaults(handler=_handle_ec_pubkey_combine)
    p.add_argument("-p", "--pubkey", action="append", required=True,
                   help="{}; repeat for multiple keys".format(pubkey_help))

    p = subparsers.add_parser("ec-pubkey-create")
    p.set_defaults(handler=_handle_ec_pubkey_create)
    p.add_argument("-s", "--seckey", required=True, help=seckey_help)

    p = subparsers.add_parser("ec-pubkey-negate")
    p.set_defaults(handler=_handle_ec_pubkey_negate)
    p.add_argument("-p", "--pubkey", required=True, help=pubkey_help)

    p = subparsers.add_parser("ec-pubkey-tweak-add")
    p.set_defaults(handler=_handle_ec_pubkey_tweak_add)
    p.add_argument("-p", "--pubkey", required=True, help=pubkey_help)
    p.add_argument("--tweak", required=True, help=tweak_help)

    p = subparsers.add_parser("ec-pubkey-tweak-mul")
    p.set_defaults(handler=_handle_ec_pubkey_tweak_mul)
    p.add_argument("-p", "--pubkey", required=True, help=pubkey_help)
    p.add_argument("--tweak", required=True, help=tweak_help)

    p = subparsers.add_parser("ec-seckey-verify")
    p.set_defaults(handler=_handle_ec_seckey_verify)
    p.add_argument("-s", "--seckey", required=True, help=seckey_help)

    p = subparsers.add_parser("ec-seckey-negate")
    p.set_defaults(handler=_handle_ec_seckey_negate)
    p.add_argument("-s", "--seckey", required=True, help=seckey_help)

    p = subparsers.add_parser("ec-seckey-tweak-add")
    p.set_defaults(handler=_handle_ec_seckey_tweak_add)
    p.add_argument("-s", "--seckey", required=True, help=seckey_help)
    p.add_argument("--tweak", required=True, help=tweak_help)

    p = subparsers.add_parser("ec-seckey-tweak-mul")
    p.set_defaults(handler=_handle_ec_seckey_tweak_mul)
    p.add_argument("-s", "--seckey", required=True, help=seckey_help)
    p.add_argument("--tweak", required=True, help=tweak_help)

    p = subparsers.add_parser("ecdsa-sign")
    p.set_defaults(handler=_handle_ecdsa_sign)
    p.add_argument("-s", "--seckey", required=True, help=seckey_help)
    p.add_argument("--msghash", required=True, help=msghash_help)
    p.add_argument("--der", action="store_true", help=emit_der_help)

    p = subparsers.add_parser("ecdsa-verify")
    p.set_defaults(handler=_handle_ecdsa_verify)
    p.add_argument("--sig", required=True, help=sig_help)
    p.add_argument("-p", "--pubkey", required=True, help=pubkey_help)
    p.add_argument("--msghash", required=True, help=msghash_help)
    p.add_argument("--der", action="store_true", help="accept DER signature hex")

    p = subparsers.add_parser("ecdsa-signature-parse-compact")
    p.set_defaults(handler=_handle_ecdsa_signature_parse_compact)
    p.add_argument("--sig", required=True, help=sig_help)
    p.add_argument("--der", action="store_true", help=emit_der_help)

    p = subparsers.add_parser("ecdsa-signature-parse-der")
    p.set_defaults(handler=_handle_ecdsa_signature_parse_der)
    p.add_argument("--sig", required=True, help=sig_help)
    p.add_argument("--der", action="store_true", help=emit_der_help)

    p = subparsers.add_parser("ecdsa-signature-normalize")
    p.set_defaults(handler=_handle_ecdsa_signature_normalize)
    p.add_argument("--sig", required=True, help=sig_help)
    p.add_argument("--input-der", action="store_true", help="accept DER signature hex")
    p.add_argument("--output-der", action="store_true", help=emit_der_help)

    p = subparsers.add_parser("tagged-sha256")
    p.set_defaults(handler=_handle_tagged_sha256)
    p.add_argument("--tag", required=True, help="tag hex")
    p.add_argument("--msg", required=True, help=msg_help)

    if has_secp256k1_ecdh:
        p = subparsers.add_parser("ecdh")
        p.set_defaults(handler=_handle_ecdh)
        p.add_argument("-s", "--seckey", required=True, help=seckey_help)
        p.add_argument("-p", "--pubkey", required=True, help=pubkey_help)

    if has_secp256k1_recovery:
        p = subparsers.add_parser("ecdsa-recoverable-signature-parse-compact")
        p.set_defaults(handler=_handle_ecdsa_recoverable_signature_parse_compact)
        p.add_argument("--sig", required=True, help="64-byte compact signature hex")
        p.add_argument("--rec-id", required=True, type=int, help="recovery id, 0 through 3")

        p = subparsers.add_parser("ecdsa-recoverable-signature-convert")
        p.set_defaults(handler=_handle_ecdsa_recoverable_signature_convert)
        p.add_argument("--sig", required=True, help="64-byte compact recoverable signature hex")
        p.add_argument("--rec-id", required=True, type=int, help="recovery id, 0 through 3")
        p.add_argument("--der", action="store_true", help=emit_der_help)

        p = subparsers.add_parser("ecdsa-sign-recoverable")
        p.set_defaults(handler=_handle_ecdsa_sign_recoverable)
        p.add_argument("-s", "--seckey", required=True, help=seckey_help)
        p.add_argument("--msghash", required=True, help=msghash_help)

        p = subparsers.add_parser("ecdsa-recover")
        p.set_defaults(handler=_handle_ecdsa_recover)
        p.add_argument("--sig", required=True, help="64-byte compact recoverable signature hex")
        p.add_argument("--rec-id", required=True, type=int, help="recovery id, 0 through 3")
        p.add_argument("--msghash", required=True, help=msghash_help)
        group = p.add_mutually_exclusive_group()
        group.add_argument("--compressed", dest="compressed", action="store_true",
                           default=True, help=compressed_help)
        group.add_argument("--uncompressed", dest="compressed", action="store_false",
                           help=uncompressed_help)

    if has_secp256k1_schnorrsig and has_secp256k1_extrakeys:
        p = subparsers.add_parser("schnorrsig-sign")
        p.set_defaults(handler=_handle_schnorrsig_sign)
        p.add_argument("-s", "--seckey", required=True, help=seckey_help)
        p.add_argument("--msg", required=True, help="message hex or ASCII")
        p.add_argument("--aux-rand", help="optional 32-byte auxiliary randomness hex")

        p = subparsers.add_parser("schnorrsig-verify")
        p.set_defaults(handler=_handle_schnorrsig_verify)
        p.add_argument("--sig", required=True, help="64-byte Schnorr signature hex")
        p.add_argument("--msg", required=True, help=msg_help)
        p.add_argument("--xonly-pubkey", required=True, help="32-byte x-only public key hex")

    if has_secp256k1_musig and has_secp256k1_extrakeys:
        p = subparsers.add_parser("musig-pubnonce-parse")
        p.set_defaults(handler=_handle_musig_pubnonce_parse)
        p.add_argument("--pubnonce", required=True, help="66-byte public nonce hex")

        p = subparsers.add_parser("musig-aggnonce-parse")
        p.set_defaults(handler=_handle_musig_aggnonce_parse)
        p.add_argument("--aggnonce", required=True, help="66-byte aggregate nonce hex")

        p = subparsers.add_parser("musig-partial-sig-parse")
        p.set_defaults(handler=_handle_musig_partial_sig_parse)
        p.add_argument("--sig", required=True, help="32-byte partial signature hex")

        p = subparsers.add_parser("musig-pubkey-agg")
        p.set_defaults(handler=_handle_musig_pubkey_agg)
        p.add_argument("-p", "--pubkey", action="append", required=True,
                       help="{}; repeat for multiple keys".format(signer_pubkey_help))
        p.add_argument("--sort", action="store_true", help=sort_help)

        p = subparsers.add_parser("musig-pubkey-ec-tweak-add")
        p.set_defaults(handler=_handle_musig_pubkey_ec_tweak_add)
        p.add_argument("--keyagg-cache", required=True, help=keyagg_cache_help)
        p.add_argument("--tweak", required=True, help=tweak_help)
        group = p.add_mutually_exclusive_group()
        group.add_argument("--compressed", dest="compressed", action="store_true",
                           default=True, help=compressed_help)
        group.add_argument("--uncompressed", dest="compressed", action="store_false",
                           help=uncompressed_help)

        p = subparsers.add_parser("musig-pubkey-xonly-tweak-add")
        p.set_defaults(handler=_handle_musig_pubkey_xonly_tweak_add)
        p.add_argument("--keyagg-cache", required=True, help=keyagg_cache_help)
        p.add_argument("--tweak", required=True, help=tweak_help)
        group = p.add_mutually_exclusive_group()
        group.add_argument("--compressed", dest="compressed", action="store_true",
                           default=True, help=compressed_help)
        group.add_argument("--uncompressed", dest="compressed", action="store_false",
                           help=uncompressed_help)

        p = subparsers.add_parser("musig-nonce-gen")
        p.set_defaults(handler=_handle_musig_nonce_gen)
        p.add_argument("-p", "--pubkey", required=True, help=signer_pubkey_help)
        p.add_argument("--session-secrand", help="optional 32-byte secret nonce randomness hex")
        p.add_argument("-s", "--seckey", help="optional {}".format(signer_seckey_help))
        p.add_argument("--msg", help="optional {}".format(msghash_help))
        p.add_argument("--keyagg-cache", required=True, help=keyagg_cache_help)
        p.add_argument("--extra-input", help="optional 32-byte extra input hex")

        p = subparsers.add_parser("musig-nonce-gen-counter")
        p.set_defaults(handler=_handle_musig_nonce_gen_counter)
        p.add_argument("--counter", required=True, type=int, help="unique unsigned 64-bit counter")
        p.add_argument("-s", "--seckey", required=True, help=signer_seckey_help)
        p.add_argument("--msg", help="optional {}".format(msghash_help))
        p.add_argument("--keyagg-cache", required=True, help=keyagg_cache_help)
        p.add_argument("--extra-input", help="optional 32-byte extra input hex")

        p = subparsers.add_parser("musig-nonce-agg")
        p.set_defaults(handler=_handle_musig_nonce_agg)
        p.add_argument("--pubnonce", action="append", required=True,
                       help="66-byte public nonce hex; repeat for multiple signers")

        p = subparsers.add_parser("musig-nonce-process")
        p.set_defaults(handler=_handle_musig_nonce_process)
        p.add_argument("--aggnonce", required=True, help="66-byte aggregate nonce hex")
        p.add_argument("--msg", required=True, help=msghash_help)
        p.add_argument("--keyagg-cache", required=True, help=keyagg_cache_help)

        p = subparsers.add_parser("musig-partial-sign")
        p.set_defaults(handler=_handle_musig_partial_sign)
        p.add_argument("--secnonce", required=True, help="132-byte secret nonce hex from musig-nonce-gen")
        p.add_argument("-s", "--seckey", required=True, help=signer_seckey_help)
        p.add_argument("--session", required=True, help=session_help)
        p.add_argument("--keyagg-cache", required=True, help=keyagg_cache_help)

        p = subparsers.add_parser("musig-partial-sig-verify")
        p.set_defaults(handler=_handle_musig_partial_sig_verify)
        p.add_argument("--sig", required=True, help="32-byte partial signature hex")
        p.add_argument("--pubnonce", required=True, help="66-byte signer public nonce hex")
        p.add_argument("--signer-pubkey", required=True, help=signer_pubkey_help)
        p.add_argument("--session", required=True, help=session_help)
        p.add_argument("--keyagg-cache", required=True, help=keyagg_cache_help)

        p = subparsers.add_parser("musig-partial-sig-agg")
        p.set_defaults(handler=_handle_musig_partial_sig_agg)
        p.add_argument("--session", required=True, help=session_help)
        p.add_argument("--partial-sig", action="append", required=True,
                       help="32-byte partial signature hex; repeat for multiple signers")

    if has_secp256k1_extrakeys:
        p = subparsers.add_parser("xonly-pubkey-parse")
        p.set_defaults(handler=_handle_xonly_pubkey_parse)
        p.add_argument("--xonly-pubkey", required=True, help="32-byte x-only public key hex")

        p = subparsers.add_parser("xonly-pubkey-from-pubkey")
        p.set_defaults(handler=_handle_xonly_pubkey_from_pubkey)
        p.add_argument("-p", "--pubkey", required=True, help=pubkey_help)

        p = subparsers.add_parser("xonly-pubkey-tweak-add")
        p.set_defaults(handler=_handle_xonly_pubkey_tweak_add)
        p.add_argument("--xonly-pubkey", required=True, help="32-byte x-only public key hex")
        p.add_argument("--tweak", required=True, help=tweak_help)

        p = subparsers.add_parser("xonly-pubkey-tweak-add-check")
        p.set_defaults(handler=_handle_xonly_pubkey_tweak_add_check)
        p.add_argument("--tweaked-pubkey", required=True, help="32-byte tweaked x-only public key hex")
        p.add_argument("--parity", required=True, type=int, help="tweaked public key parity, 0 or 1")
        p.add_argument("--internal-pubkey", required=True, help="32-byte internal x-only public key hex")
        p.add_argument("--tweak", required=True, help=tweak_help)

        p = subparsers.add_parser("keypair-xonly-pub")
        p.set_defaults(handler=_handle_keypair_xonly_pub)
        p.add_argument("-s", "--seckey", required=True, help=seckey_help)

        p = subparsers.add_parser("keypair-xonly-tweak-add")
        p.set_defaults(handler=_handle_keypair_xonly_tweak_add)
        p.add_argument("-s", "--seckey", required=True, help=seckey_help)
        p.add_argument("--tweak", required=True, help=tweak_help)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except (AssertionError, Libsecp256k1Exception, argparse.ArgumentTypeError) as exc:
        print("error: {}".format(str(exc) or "invalid input"), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
