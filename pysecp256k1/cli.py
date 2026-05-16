import argparse
import sys

import pysecp256k1 as secp
from pysecp256k1.low_level import Libsecp256k1Exception


def _bytes_from_hex(value):
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc))


def _handle_ec_pubkey_parse(args):
    pubkey = secp.ec_pubkey_parse(_bytes_from_hex(args.pubkey))
    print(secp.ec_pubkey_serialize(pubkey, compressed=args.compressed).hex())
    return 0


def _handle_ec_pubkey_cmp(args):
    pubkey0 = secp.ec_pubkey_parse(_bytes_from_hex(args.pubkey0))
    pubkey1 = secp.ec_pubkey_parse(_bytes_from_hex(args.pubkey1))
    print(secp.ec_pubkey_cmp(pubkey0, pubkey1))
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
    if args.der:
        sig = secp.ecdsa_signature_parse_der(_bytes_from_hex(args.sig))
        print(secp.ecdsa_signature_serialize_der(secp.ecdsa_signature_normalize(sig)).hex())
    else:
        sig = secp.ecdsa_signature_parse_compact(_bytes_from_hex(args.sig))
        print(secp.ecdsa_signature_serialize_compact(secp.ecdsa_signature_normalize(sig)).hex())
    return 0


def _handle_context_randomize(args):
    seed = _bytes_from_hex(args.seed) if args.seed is not None else None
    secp.context_randomize(seed32=seed)
    return 0


def _handle_tagged_sha256(args):
    print(secp.tagged_sha256(_bytes_from_hex(args.tag), _bytes_from_hex(args.msg)).hex())
    return 0


def build_parser():
    parser = argparse.ArgumentParser(prog="pysecp256k1")
    subparsers = parser.add_subparsers(dest="command", required=True)

    p = subparsers.add_parser("ec-pubkey-parse")
    p.set_defaults(handler=_handle_ec_pubkey_parse)
    p.add_argument("--pubkey", required=True, help="serialized public key hex")
    group = p.add_mutually_exclusive_group()
    group.add_argument("--compressed", dest="compressed", action="store_true",
                       default=True, help="emit compressed public key hex")
    group.add_argument("--uncompressed", dest="compressed", action="store_false",
                       help="emit uncompressed public key hex")

    p = subparsers.add_parser("ec-pubkey-cmp")
    p.set_defaults(handler=_handle_ec_pubkey_cmp)
    p.add_argument("--pubkey0", required=True, help="first serialized public key hex")
    p.add_argument("--pubkey1", required=True, help="second serialized public key hex")

    for name, handler in (
        ("ec-pubkey-sort", _handle_ec_pubkey_sort),
        ("ec-pubkey-combine", _handle_ec_pubkey_combine),
    ):
        p = subparsers.add_parser(name)
        p.set_defaults(handler=handler)
        p.add_argument("--pubkey", action="append", required=True,
                       help="serialized public key hex; repeat for multiple keys")

    p = subparsers.add_parser("ec-pubkey-create")
    p.set_defaults(handler=_handle_ec_pubkey_create)
    p.add_argument("--seckey", required=True, help="32-byte secret key hex")

    for name, handler in (
        ("ec-pubkey-negate", _handle_ec_pubkey_negate),
        ("ec-pubkey-tweak-add", _handle_ec_pubkey_tweak_add),
        ("ec-pubkey-tweak-mul", _handle_ec_pubkey_tweak_mul),
    ):
        p = subparsers.add_parser(name)
        p.set_defaults(handler=handler)
        p.add_argument("--pubkey", required=True, help="serialized public key hex")
        if "tweak" in name:
            p.add_argument("--tweak", required=True, help="32-byte tweak hex")

    p = subparsers.add_parser("ec-seckey-verify")
    p.set_defaults(handler=_handle_ec_seckey_verify)
    p.add_argument("--seckey", required=True, help="32-byte secret key hex")

    for name, handler in (
        ("ec-seckey-negate", _handle_ec_seckey_negate),
        ("ec-seckey-tweak-add", _handle_ec_seckey_tweak_add),
        ("ec-seckey-tweak-mul", _handle_ec_seckey_tweak_mul),
    ):
        p = subparsers.add_parser(name)
        p.set_defaults(handler=handler)
        p.add_argument("--seckey", required=True, help="32-byte secret key hex")
        if "tweak" in name:
            p.add_argument("--tweak", required=True, help="32-byte tweak hex")

    p = subparsers.add_parser("ecdsa-sign")
    p.set_defaults(handler=_handle_ecdsa_sign)
    p.add_argument("--seckey", required=True, help="32-byte secret key hex")
    p.add_argument("--msghash", required=True, help="32-byte message hash hex")
    p.add_argument("--der", action="store_true", help="emit DER signature hex")

    p = subparsers.add_parser("ecdsa-verify")
    p.set_defaults(handler=_handle_ecdsa_verify)
    p.add_argument("--sig", required=True, help="signature hex")
    p.add_argument("--pubkey", required=True, help="serialized public key hex")
    p.add_argument("--msghash", required=True, help="32-byte message hash hex")
    p.add_argument("--der", action="store_true", help="accept DER signature hex")

    for name, handler in (
        ("ecdsa-signature-parse-compact", _handle_ecdsa_signature_parse_compact),
        ("ecdsa-signature-parse-der", _handle_ecdsa_signature_parse_der),
    ):
        p = subparsers.add_parser(name)
        p.set_defaults(handler=handler)
        p.add_argument("--sig", required=True, help="signature hex")
        p.add_argument("--der", action="store_true", help="emit DER signature hex")

    for name, handler in (
        ("ecdsa-signature-normalize", _handle_ecdsa_signature_normalize),
    ):
        p = subparsers.add_parser(name)
        p.set_defaults(handler=handler)
        p.add_argument("--sig", required=True, help="signature hex")
        p.add_argument("--der", action="store_true", help="accept DER signature hex")

    p = subparsers.add_parser("context-randomize")
    p.set_defaults(handler=_handle_context_randomize)
    p.add_argument("--seed", help="optional 32-byte random seed hex")

    p = subparsers.add_parser("tagged-sha256")
    p.set_defaults(handler=_handle_tagged_sha256)
    p.add_argument("--tag", required=True, help="tag hex")
    p.add_argument("--msg", required=True, help="message hex")

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except (AssertionError, Libsecp256k1Exception, argparse.ArgumentTypeError, ValueError) as exc:
        print("error: {}".format(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
