import contextlib
import io
import unittest

import pysecp256k1 as secp
from pysecp256k1 import cli
from pysecp256k1.low_level import (
    has_secp256k1_ecdh,
    has_secp256k1_extrakeys,
    has_secp256k1_musig,
    has_secp256k1_recovery,
    has_secp256k1_schnorrsig,
)
from tests import data

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


CLI_COMMANDS = [
    "ec-pubkey-parse",
    "ec-pubkey-sort",
    "ec-pubkey-combine",
    "ec-pubkey-create",
    "ec-pubkey-negate",
    "ec-pubkey-tweak-add",
    "ec-pubkey-tweak-mul",
    "ec-seckey-verify",
    "ec-seckey-negate",
    "ec-seckey-tweak-add",
    "ec-seckey-tweak-mul",
    "ecdsa-sign",
    "ecdsa-verify",
    "ecdsa-signature-parse-compact",
    "ecdsa-signature-parse-der",
    "ecdsa-signature-normalize",
    "tagged-sha256",
]

EXTRAKEYS_CLI_COMMANDS = [
    "xonly-pubkey-parse",
    "xonly-pubkey-from-pubkey",
    "xonly-pubkey-tweak-add",
    "xonly-pubkey-tweak-add-check",
    "keypair-xonly-pub",
    "keypair-xonly-tweak-add",
]

ECDH_CLI_COMMANDS = [
    "ecdh",
]

RECOVERY_CLI_COMMANDS = [
    "ecdsa-recoverable-signature-parse-compact",
    "ecdsa-recoverable-signature-convert",
    "ecdsa-sign-recoverable",
    "ecdsa-recover",
]

SCHNORRSIG_CLI_COMMANDS = [
    "schnorrsig-sign",
    "schnorrsig-verify",
]

MUSIG_CLI_COMMANDS = [
    "musig-pubnonce-parse",
    "musig-aggnonce-parse",
    "musig-partial-sig-parse",
    "musig-pubkey-agg",
    "musig-pubkey-ec-tweak-add",
    "musig-pubkey-xonly-tweak-add",
    "musig-nonce-gen",
    "musig-nonce-gen-counter",
    "musig-nonce-agg",
    "musig-nonce-process",
    "musig-partial-sign",
    "musig-partial-sig-verify",
    "musig-partial-sig-agg",
]


def run_cli(argv):
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        try:
            code = cli.main(argv)
        except SystemExit as exc:
            code = exc.code
    return code, stdout.getvalue(), stderr.getvalue()


class TestCLI(unittest.TestCase):
    def test_help_lists_subcommands_and_subcommand_help(self):
        code, out, err = run_cli(["--help"])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        for command in CLI_COMMANDS:
            self.assertIn(command, out)
        if has_secp256k1_ecdh:
            for command in ECDH_CLI_COMMANDS:
                self.assertIn(command, out)
        if has_secp256k1_extrakeys:
            for command in EXTRAKEYS_CLI_COMMANDS:
                self.assertIn(command, out)
        if has_secp256k1_recovery:
            for command in RECOVERY_CLI_COMMANDS:
                self.assertIn(command, out)
        if has_secp256k1_schnorrsig and has_secp256k1_extrakeys:
            for command in SCHNORRSIG_CLI_COMMANDS:
                self.assertIn(command, out)
        if has_secp256k1_musig and has_secp256k1_extrakeys:
            for command in MUSIG_CLI_COMMANDS:
                self.assertIn(command, out)
        for dropped in (
            "ec-pubkey-serialize",
            "ecdsa-signature-serialize-compact",
            "ecdsa-signature-serialize-der",
            "ecdsa-recoverable-signature-serialize-compact",
            "xonly-pubkey-serialize",
            "musig-pubnonce-serialize",
            "musig-aggnonce-serialize",
            "musig-partial-sig-serialize",
            "keypair-sec",
            "keypair-pub",
            "keypair-create",
            "context-randomize",
            "ec-pubkey-cmp",
            "xonly-pubkey-cmp",
            "musig-pubkey-get",
            "schnorrsig-sign32",
            "schnorrsig-sign-custom",
        ):
            self.assertNotIn(dropped, out)

        for command in CLI_COMMANDS:
            code, out, err = run_cli([command, "--help"])
            self.assertEqual(code, 0)
            self.assertEqual(err, "")
            self.assertIn("usage:", out)
        if has_secp256k1_ecdh:
            for command in ECDH_CLI_COMMANDS:
                code, out, err = run_cli([command, "--help"])
                self.assertEqual(code, 0)
                self.assertEqual(err, "")
                self.assertIn("usage:", out)
        if has_secp256k1_extrakeys:
            for command in EXTRAKEYS_CLI_COMMANDS:
                code, out, err = run_cli([command, "--help"])
                self.assertEqual(code, 0)
                self.assertEqual(err, "")
                self.assertIn("usage:", out)
        if has_secp256k1_recovery:
            for command in RECOVERY_CLI_COMMANDS:
                code, out, err = run_cli([command, "--help"])
                self.assertEqual(code, 0)
                self.assertEqual(err, "")
                self.assertIn("usage:", out)
        if has_secp256k1_schnorrsig and has_secp256k1_extrakeys:
            for command in SCHNORRSIG_CLI_COMMANDS:
                code, out, err = run_cli([command, "--help"])
                self.assertEqual(code, 0)
                self.assertEqual(err, "")
                self.assertIn("usage:", out)
        if has_secp256k1_musig and has_secp256k1_extrakeys:
            for command in MUSIG_CLI_COMMANDS:
                code, out, err = run_cli([command, "--help"])
                self.assertEqual(code, 0)
                self.assertEqual(err, "")
                self.assertIn("usage:", out)

    def test_seckey_and_pubkey_short_aliases(self):
        seckey = data.valid_seckeys[0]
        pubkey = secp.ec_pubkey_serialize(secp.ec_pubkey_create(seckey)).hex()

        code, out, err = run_cli(["ec-pubkey-create", "-s", seckey.hex()])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertEqual(out.strip(), pubkey)

        code, out, err = run_cli(["ec-pubkey-parse", "-p", pubkey])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertEqual(out.strip(), pubkey)

        code, out, err = run_cli(["ec-pubkey-sort", "-p", pubkey, "-p", pubkey])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertEqual(out.strip().splitlines(), [pubkey, pubkey])

    def test_ec_pubkey_create_matches_library(self):
        for seckey in data.valid_seckeys:
            code, out, err = run_cli(["ec-pubkey-create", "--seckey", seckey.hex()])
            expected = secp.ec_pubkey_serialize(secp.ec_pubkey_create(seckey)).hex()
            self.assertEqual(code, 0)
            self.assertEqual(err, "")
            self.assertEqual(out.strip(), expected)

    def test_ec_seckey_verify_success(self):
        code, out, err = run_cli([
            "ec-seckey-verify", "--seckey", data.valid_seckeys[0].hex()
        ])
        self.assertEqual(code, 0)
        self.assertEqual(out, "")
        self.assertEqual(err, "")

    def test_ec_pubkey_sort_matches_library(self):
        pubkeys = [
            secp.ec_pubkey_serialize(secp.ec_pubkey_create(seckey)).hex()
            for seckey in reversed(data.valid_seckeys[:3])
        ]
        raw_pubkeys = [secp.ec_pubkey_parse(bytes.fromhex(pubkey)) for pubkey in pubkeys]
        expected = [
            secp.ec_pubkey_serialize(pubkey).hex()
            for pubkey in secp.ec_pubkey_sort(raw_pubkeys)
        ]

        argv = ["ec-pubkey-sort"]
        for pubkey in pubkeys:
            argv.extend(["--pubkey", pubkey])
        code, out, err = run_cli(argv)
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertEqual(out.strip().splitlines(), expected)

    def test_tweak_commands_match_library(self):
        seckey = data.valid_seckeys[0]
        tweak = data.valid_seckeys[1]
        pubkey = secp.ec_pubkey_serialize(secp.ec_pubkey_create(seckey)).hex()
        raw_pubkey = secp.ec_pubkey_parse(bytes.fromhex(pubkey))

        code, out, err = run_cli([
            "ec-seckey-tweak-mul", "--seckey", seckey.hex(), "--tweak", tweak.hex()
        ])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertEqual(out.strip(), secp.ec_seckey_tweak_mul(seckey, tweak).hex())

        code, out, err = run_cli([
            "ec-pubkey-tweak-add", "--pubkey", pubkey, "--tweak", tweak.hex()
        ])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertEqual(
            out.strip(),
            secp.ec_pubkey_serialize(secp.ec_pubkey_tweak_add(raw_pubkey, tweak)).hex(),
        )

        code, out, err = run_cli([
            "ec-pubkey-tweak-mul", "--pubkey", pubkey, "--tweak", tweak.hex()
        ])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertEqual(
            out.strip(),
            secp.ec_pubkey_serialize(secp.ec_pubkey_tweak_mul(raw_pubkey, tweak)).hex(),
        )

    def test_ecdsa_sign_verify_round_trip(self):
        seckey = data.valid_seckeys[0]
        msg = b"\x11" * 32
        pubkey = secp.ec_pubkey_serialize(secp.ec_pubkey_create(seckey)).hex()

        code, out, err = run_cli([
            "ecdsa-sign", "--seckey", seckey.hex(), "--msghash", msg.hex()
        ])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        sig = out.strip()

        code, out, err = run_cli([
            "ecdsa-verify", "--sig", sig, "--pubkey", pubkey, "--msghash", msg.hex()
        ])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertEqual(out.strip(), "True")

        tampered = bytes([msg[0] ^ 1]) + msg[1:]
        code, out, err = run_cli([
            "ecdsa-verify", "--sig", sig, "--pubkey", pubkey,
            "--msghash", tampered.hex()
        ])
        self.assertEqual(code, 1)
        self.assertEqual(err, "")
        self.assertEqual(out.strip(), "False")

    def test_der_round_trip(self):
        der = data.valid_der_sig_serializations[0]
        code, out, err = run_cli([
            "ecdsa-signature-parse-der", "--sig", der.hex(), "--der"
        ])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertEqual(bytes.fromhex(out.strip()), der)

    def test_signature_normalize_input_and_output_der_flags(self):
        compact = data.valid_compact_sig_serializations[0]
        sig = secp.ecdsa_signature_parse_compact(compact)
        normalized = secp.ecdsa_signature_normalize(sig)
        expected_compact = secp.ecdsa_signature_serialize_compact(normalized)
        expected_der = secp.ecdsa_signature_serialize_der(normalized)

        code, out, err = run_cli([
            "ecdsa-signature-normalize", "--sig", compact.hex(), "--output-der"
        ])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertEqual(bytes.fromhex(out.strip()), expected_der)

        code, out, err = run_cli([
            "ecdsa-signature-normalize", "--sig", expected_der.hex(), "--input-der"
        ])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertEqual(bytes.fromhex(out.strip()), expected_compact)

    def test_compressed_and_uncompressed_pubkey_serialization(self):
        pubkey = data.serialized_pubkeys_compressed[0].hex()

        code, out, err = run_cli(["ec-pubkey-parse", "--pubkey", pubkey])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        compressed = bytes.fromhex(out.strip())
        self.assertEqual(len(compressed), 33)
        self.assertIn(compressed[0], (2, 3))

        code, out, err = run_cli([
            "ec-pubkey-parse", "--pubkey", pubkey, "--uncompressed"
        ])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        uncompressed = bytes.fromhex(out.strip())
        self.assertEqual(len(uncompressed), 65)
        self.assertEqual(uncompressed[0], 4)

    def test_negation_involutions(self):
        seckey = data.valid_seckeys[0]
        code, out, err = run_cli(["ec-seckey-negate", "--seckey", seckey.hex()])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        negated = out.strip()

        code, out, err = run_cli(["ec-seckey-negate", "--seckey", negated])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertEqual(out.strip(), seckey.hex())

        pubkey = data.serialized_pubkeys_compressed[0].hex()
        code, out, err = run_cli(["ec-pubkey-negate", "--pubkey", pubkey])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        negated_pubkey = out.strip()

        code, out, err = run_cli(["ec-pubkey-negate", "--pubkey", negated_pubkey])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertEqual(out.strip(), pubkey)

    def test_tweak_add_inverse_for_secret_key(self):
        seckey = data.valid_seckeys[0]
        tweak = data.valid_seckeys[1]
        neg_tweak = secp.ec_seckey_negate(tweak)

        code, out, err = run_cli([
            "ec-seckey-tweak-add", "--seckey", seckey.hex(), "--tweak", tweak.hex()
        ])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        tweaked = out.strip()

        code, out, err = run_cli([
            "ec-seckey-tweak-add", "--seckey", tweaked,
            "--tweak", neg_tweak.hex()
        ])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertEqual(out.strip(), seckey.hex())

    def test_combine_pubkey_with_negation_exits_two(self):
        pubkey = data.serialized_pubkeys_compressed[0].hex()
        code, out, err = run_cli(["ec-pubkey-negate", "--pubkey", pubkey])
        self.assertEqual(code, 0)
        negated = out.strip()

        code, out, err = run_cli([
            "ec-pubkey-combine", "--pubkey", pubkey, "--pubkey", negated
        ])
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertTrue(err.startswith("error:"))

    def test_error_contract(self):
        cases = [
            ["ec-pubkey-create"],
            ["ec-pubkey-create", "--seckey", "abc"],
            ["ec-pubkey-create", "--seckey", (b"\x01" * 31).hex()],
            ["ec-pubkey-create", "--seckey", data.invalid_seckeys[1].hex()],
            ["ec-pubkey-create", "--seckey", data.invalid_seckeys[0].hex()],
            ["ecdsa-signature-parse-compact", "--sig", (b"\x01" * 63).hex()],
        ]
        for argv in cases:
            with self.subTest(argv=argv):
                code, out, err = run_cli(argv)
                self.assertEqual(code, 2)
                self.assertEqual(out, "")
                self.assertTrue(err.startswith("error:"))
                self.assertNotEqual(err.strip(), "error:")

    def test_bare_assertion_errors_are_not_blank(self):
        code, out, err = run_cli(["ec-pubkey-create", "--seckey", "deadbeef"])
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertEqual(err.strip(), "error: invalid input")

    def test_ecdsa_verify_exit_codes(self):
        seckey = data.valid_seckeys[0]
        msg = b"\x22" * 32
        pubkey = secp.ec_pubkey_serialize(secp.ec_pubkey_create(seckey)).hex()
        sig = secp.ecdsa_signature_serialize_compact(secp.ecdsa_sign(seckey, msg)).hex()

        code, out, err = run_cli([
            "ecdsa-verify", "--sig", sig, "--pubkey", pubkey, "--msghash", msg.hex()
        ])
        self.assertEqual(code, 0)
        self.assertEqual(out.strip(), "True")
        self.assertEqual(err, "")

        tampered = b"\x23" + msg[1:]
        code, out, err = run_cli([
            "ecdsa-verify", "--sig", sig, "--pubkey", pubkey,
            "--msghash", tampered.hex()
        ])
        self.assertEqual(code, 1)
        self.assertEqual(out.strip(), "False")
        self.assertEqual(err, "")

        code, out, err = run_cli([
            "ecdsa-verify", "--sig", (b"\x01" * 63).hex(),
            "--pubkey", pubkey, "--msghash", msg.hex()
        ])
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertTrue(err.startswith("error:"))

    def test_tagged_sha256_deterministic(self):
        argv = ["tagged-sha256", "--tag", b"tag".hex(), "--msg", b"message".hex()]
        code0, out0, err0 = run_cli(argv)
        code1, out1, err1 = run_cli(argv)
        self.assertEqual(code0, 0)
        self.assertEqual(code1, 0)
        self.assertEqual(err0, "")
        self.assertEqual(err1, "")
        self.assertEqual(out0, out1)
        self.assertEqual(len(bytes.fromhex(out0.strip())), 32)

        code, out, err = run_cli(["tagged-sha256", "--tag", "tag", "--msg", "message"])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertEqual(out, out0)

    @unittest.skipUnless(has_secp256k1_ecdh, "secp256k1 is not compiled with module 'ecdh'")
    def test_ecdh_shared_secret_round_trip(self):
        seckey0 = data.valid_seckeys[0]
        seckey1 = data.valid_seckeys[1]
        pubkey0 = secp.ec_pubkey_serialize(secp.ec_pubkey_create(seckey0)).hex()
        pubkey1 = secp.ec_pubkey_serialize(secp.ec_pubkey_create(seckey1)).hex()

        code, out, err = run_cli([
            "ecdh", "--seckey", seckey0.hex(), "--pubkey", pubkey1
        ])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        shared0 = out.strip()
        self.assertEqual(
            shared0,
            ecdh_module.ecdh(seckey0, secp.ec_pubkey_parse(bytes.fromhex(pubkey1))).hex(),
        )

        code, out, err = run_cli([
            "ecdh", "--seckey", seckey1.hex(), "--pubkey", pubkey0
        ])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertEqual(out.strip(), shared0)
        self.assertEqual(len(bytes.fromhex(shared0)), 32)

    @unittest.skipUnless(has_secp256k1_ecdh, "secp256k1 is not compiled with module 'ecdh'")
    def test_ecdh_error_contract(self):
        cases = [
            [
                "ecdh", "--seckey", "abc",
                "--pubkey", data.serialized_pubkeys_compressed[0].hex(),
            ],
            [
                "ecdh", "--seckey", (b"\x01" * 31).hex(),
                "--pubkey", data.serialized_pubkeys_compressed[0].hex(),
            ],
            [
                "ecdh", "--seckey", data.invalid_seckeys[1].hex(),
                "--pubkey", data.serialized_pubkeys_compressed[0].hex(),
            ],
            [
                "ecdh", "--seckey", data.valid_seckeys[0].hex(),
                "--pubkey", (b"\x01" * 33).hex(),
            ],
        ]
        for argv in cases:
            with self.subTest(argv=argv):
                code, out, err = run_cli(argv)
                self.assertEqual(code, 2)
                self.assertEqual(out, "")
                self.assertTrue(err.startswith("error:"))

    @unittest.skipUnless(has_secp256k1_recovery, "secp256k1 is not compiled with module 'recovery'")
    def test_recovery_sign_convert_and_recover_round_trip(self):
        seckey = data.valid_seckeys[0]
        msg = b"\x33" * 32
        expected_pubkey = secp.ec_pubkey_serialize(secp.ec_pubkey_create(seckey)).hex()

        code, out, err = run_cli([
            "ecdsa-sign-recoverable", "--seckey", seckey.hex(), "--msghash", msg.hex()
        ])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        sig, rec_id = out.strip().split()
        self.assertEqual(len(bytes.fromhex(sig)), 64)
        self.assertIn(int(rec_id), (0, 1, 2, 3))

        code, out, err = run_cli([
            "ecdsa-recoverable-signature-parse-compact",
            "--sig", sig,
            "--rec-id", rec_id,
        ])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertEqual(out.strip(), "{} {}".format(sig, rec_id))

        code, out, err = run_cli([
            "ecdsa-recoverable-signature-convert",
            "--sig", sig,
            "--rec-id", rec_id,
        ])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        converted = out.strip()
        rec_sig = recovery.ecdsa_recoverable_signature_parse_compact(bytes.fromhex(sig), int(rec_id))
        expected = secp.ecdsa_signature_serialize_compact(
            recovery.ecdsa_recoverable_signature_convert(rec_sig)
        ).hex()
        self.assertEqual(converted, expected)

        code, out, err = run_cli([
            "ecdsa-recover",
            "--sig", sig,
            "--rec-id", rec_id,
            "--msghash", msg.hex(),
        ])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertEqual(out.strip(), expected_pubkey)

        code, out, err = run_cli([
            "ecdsa-recover",
            "--sig", sig,
            "--rec-id", rec_id,
            "--msghash", msg.hex(),
            "--uncompressed",
        ])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        recovered_uncompressed = bytes.fromhex(out.strip())
        self.assertEqual(len(recovered_uncompressed), 65)
        self.assertEqual(recovered_uncompressed[0], 4)

    @unittest.skipUnless(has_secp256k1_recovery, "secp256k1 is not compiled with module 'recovery'")
    def test_recoverable_convert_der(self):
        seckey = data.valid_seckeys[0]
        msg = b"\x44" * 32
        rec_sig = recovery.ecdsa_sign_recoverable(seckey, msg)
        sig, rec_id = recovery.ecdsa_recoverable_signature_serialize_compact(rec_sig)

        code, out, err = run_cli([
            "ecdsa-recoverable-signature-convert",
            "--sig", sig.hex(),
            "--rec-id", str(rec_id),
            "--der",
        ])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        parsed = secp.ecdsa_signature_parse_der(bytes.fromhex(out.strip()))
        expected = recovery.ecdsa_recoverable_signature_convert(rec_sig)
        self.assertEqual(parsed.raw, expected.raw)

    @unittest.skipUnless(has_secp256k1_recovery, "secp256k1 is not compiled with module 'recovery'")
    def test_recovery_error_contract(self):
        msg = b"\x55" * 32
        cases = [
            [
                "ecdsa-sign-recoverable", "--seckey", "abc",
                "--msghash", msg.hex(),
            ],
            [
                "ecdsa-sign-recoverable", "--seckey", data.invalid_seckeys[1].hex(),
                "--msghash", msg.hex(),
            ],
            [
                "ecdsa-sign-recoverable", "--seckey", data.valid_seckeys[0].hex(),
                "--msghash", (b"\x01" * 31).hex(),
            ],
            [
                "ecdsa-recoverable-signature-parse-compact",
                "--sig", (b"\x01" * 63).hex(),
                "--rec-id", "0",
            ],
            [
                "ecdsa-recoverable-signature-parse-compact",
                "--sig", (b"\x01" * 64).hex(),
                "--rec-id", "abc",
            ],
            [
                "ecdsa-recoverable-signature-parse-compact",
                "--sig", (b"\x01" * 64).hex(),
                "--rec-id", "4",
            ],
            [
                "ecdsa-recover",
                "--sig", (b"\x01" * 64).hex(),
                "--rec-id", "0",
                "--msghash", (b"\x01" * 31).hex(),
            ],
        ]
        for argv in cases:
            with self.subTest(argv=argv):
                code, out, err = run_cli(argv)
                self.assertEqual(code, 2)
                self.assertEqual(out, "")
                self.assertTrue(err.startswith("error:"))

    @unittest.skipUnless(
        has_secp256k1_schnorrsig and has_secp256k1_extrakeys,
        "secp256k1 is not compiled with modules 'schnorrsig' and 'extrakeys'",
    )
    def test_schnorrsig_sign_32_byte_message_round_trip(self):
        seckey = data.valid_seckeys[0]
        msg = b"\x66" * 32
        aux_rand = b"\x77" * 32
        keypair = extrakeys.keypair_create(seckey)
        xonly_pubkey, _ = extrakeys.keypair_xonly_pub(keypair)
        xonly_hex = extrakeys.xonly_pubkey_serialize(xonly_pubkey).hex()

        code, out, err = run_cli([
            "schnorrsig-sign",
            "--seckey", seckey.hex(),
            "--msg", msg.hex(),
            "--aux-rand", aux_rand.hex(),
        ])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        sig = out.strip()
        self.assertEqual(
            sig,
            schnorrsig.schnorrsig_sign32(keypair, msg, aux_rand).hex(),
        )
        self.assertEqual(len(bytes.fromhex(sig)), 64)

        code, out, err = run_cli([
            "schnorrsig-verify",
            "--sig", sig,
            "--msg", msg.hex(),
            "--xonly-pubkey", xonly_hex,
        ])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertEqual(out.strip(), "True")

        tampered = b"\x67" + msg[1:]
        code, out, err = run_cli([
            "schnorrsig-verify",
            "--sig", sig,
            "--msg", tampered.hex(),
            "--xonly-pubkey", xonly_hex,
        ])
        self.assertEqual(code, 1)
        self.assertEqual(err, "")
        self.assertEqual(out.strip(), "False")

    @unittest.skipUnless(
        has_secp256k1_schnorrsig and has_secp256k1_extrakeys,
        "secp256k1 is not compiled with modules 'schnorrsig' and 'extrakeys'",
    )
    def test_schnorrsig_sign_variable_length_message(self):
        seckey = data.valid_seckeys[0]
        msg = b"variable length schnorr message"
        keypair = extrakeys.keypair_create(seckey)
        xonly_pubkey, _ = extrakeys.keypair_xonly_pub(keypair)
        xonly_hex = extrakeys.xonly_pubkey_serialize(xonly_pubkey).hex()

        code, out, err = run_cli([
            "schnorrsig-sign",
            "--seckey", seckey.hex(),
            "--msg", msg.decode(),
        ])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        sig = out.strip()
        self.assertEqual(len(bytes.fromhex(sig)), 64)

        code, out, err = run_cli([
            "schnorrsig-verify",
            "--sig", sig,
            "--msg", msg.decode(),
            "--xonly-pubkey", xonly_hex,
        ])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertEqual(out.strip(), "True")

    @unittest.skipUnless(
        has_secp256k1_schnorrsig and has_secp256k1_extrakeys,
        "secp256k1 is not compiled with modules 'schnorrsig' and 'extrakeys'",
    )
    def test_schnorrsig_error_contract(self):
        xonly = data.serialized_pubkeys_compressed[0][1:].hex()
        cases = [
            [
                "schnorrsig-sign",
                "--seckey", "abc",
                "--msg", (b"\x01" * 32).hex(),
            ],
            [
                "schnorrsig-sign",
                "--seckey", data.invalid_seckeys[1].hex(),
                "--msg", (b"\x01" * 32).hex(),
            ],
            [
                "schnorrsig-sign",
                "--seckey", data.valid_seckeys[0].hex(),
                "--msg", (b"\x01" * 32).hex(),
                "--aux-rand", (b"\x01" * 31).hex(),
            ],
            [
                "schnorrsig-verify",
                "--sig", (b"\x01" * 63).hex(),
                "--msg", (b"\x01" * 32).hex(),
                "--xonly-pubkey", xonly,
            ],
            [
                "schnorrsig-verify",
                "--sig", (b"\x01" * 64).hex(),
                "--msg", (b"\x01" * 32).hex(),
                "--xonly-pubkey", (b"\x01" * 31).hex(),
            ],
        ]
        for argv in cases:
            with self.subTest(argv=argv):
                code, out, err = run_cli(argv)
                self.assertEqual(code, 2)
                self.assertEqual(out, "")
                self.assertTrue(err.startswith("error:"))

    @unittest.skipUnless(
        has_secp256k1_musig and has_secp256k1_extrakeys and has_secp256k1_schnorrsig,
        "secp256k1 is not compiled with modules 'musig', 'extrakeys', and 'schnorrsig'",
    )
    def test_musig_two_round_flow(self):
        seckeys = data.valid_seckeys[:2]
        pubkeys = [secp.ec_pubkey_serialize(secp.ec_pubkey_create(seckey)).hex()
                   for seckey in seckeys]
        msg = b"\x88" * 32
        session_secrands = [b"\x90" * 32, b"\x91" * 32]

        code, out, err = run_cli([
            "musig-pubkey-agg", "--sort",
            "--pubkey", pubkeys[0], "--pubkey", pubkeys[1],
        ])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        agg_xonly, keyagg_cache = out.strip().split()
        self.assertEqual(len(bytes.fromhex(agg_xonly)), 32)
        self.assertEqual(len(bytes.fromhex(keyagg_cache)), 197)

        secnonces = []
        pubnonces = []
        for seckey, pubkey, session_secrand in zip(seckeys, pubkeys, session_secrands):
            code, out, err = run_cli([
                "musig-nonce-gen",
                "--pubkey", pubkey,
                "--session-secrand", session_secrand.hex(),
                "--seckey", seckey.hex(),
                "--msg", msg.hex(),
                "-c", keyagg_cache,
            ])
            self.assertEqual(code, 0)
            self.assertEqual(err, "")
            secnonce, pubnonce = out.strip().split()
            self.assertEqual(len(bytes.fromhex(secnonce)), 132)
            self.assertEqual(len(bytes.fromhex(pubnonce)), 66)
            secnonces.append(secnonce)
            pubnonces.append(pubnonce)

        code, out, err = run_cli(["musig-pubnonce-parse", "--pubnonce", pubnonces[0]])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertEqual(out.strip(), pubnonces[0])

        code, out, err = run_cli([
            "musig-nonce-agg",
            "--pubnonce", pubnonces[0],
            "--pubnonce", pubnonces[1],
        ])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        aggnonce = out.strip()
        self.assertEqual(len(bytes.fromhex(aggnonce)), 66)

        code, out, err = run_cli(["musig-aggnonce-parse", "--aggnonce", aggnonce])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertEqual(out.strip(), aggnonce)

        code, out, err = run_cli([
            "musig-nonce-process",
            "--aggnonce", aggnonce,
            "--msg", msg.hex(),
            "-c", keyagg_cache,
        ])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        session = out.strip()
        self.assertEqual(len(bytes.fromhex(session)), 133)

        partial_sigs = []
        for seckey, secnonce in zip(seckeys, secnonces):
            code, out, err = run_cli([
                "musig-partial-sign",
                "--secnonce", secnonce,
                "--seckey", seckey.hex(),
                "--session", session,
                "-c", keyagg_cache,
            ])
            self.assertEqual(code, 0)
            self.assertEqual(err, "")
            partial_sig = out.strip()
            self.assertEqual(len(bytes.fromhex(partial_sig)), 32)
            partial_sigs.append(partial_sig)

        code, out, err = run_cli(["musig-partial-sig-parse", "--sig", partial_sigs[0]])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertEqual(out.strip(), partial_sigs[0])

        for partial_sig, pubnonce, pubkey in zip(partial_sigs, pubnonces, pubkeys):
            code, out, err = run_cli([
                "musig-partial-sig-verify",
                "--sig", partial_sig,
                "--pubnonce", pubnonce,
                "--pubkey", pubkey,
                "--session", session,
                "-c", keyagg_cache,
            ])
            self.assertEqual(code, 0)
            self.assertEqual(err, "")
            self.assertEqual(out.strip(), "True")

        code, out, err = run_cli([
            "musig-partial-sig-verify",
            "--sig", partial_sigs[0],
            "--pubnonce", pubnonces[1],
            "--pubkey", pubkeys[1],
            "--session", session,
            "-c", keyagg_cache,
        ])
        self.assertEqual(code, 1)
        self.assertEqual(err, "")
        self.assertEqual(out.strip(), "False")

        code, out, err = run_cli([
            "musig-partial-sig-agg",
            "--session", session,
            "--partial-sig", partial_sigs[0],
            "--partial-sig", partial_sigs[1],
        ])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        final_sig = out.strip()
        self.assertEqual(len(bytes.fromhex(final_sig)), 64)

        code, out, err = run_cli([
            "schnorrsig-verify",
            "--sig", final_sig,
            "--msg", msg.hex(),
            "--xonly-pubkey", agg_xonly,
        ])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertEqual(out.strip(), "True")

    @unittest.skipUnless(
        has_secp256k1_musig and has_secp256k1_extrakeys,
        "secp256k1 is not compiled with modules 'musig' and 'extrakeys'",
    )
    def test_musig_tweak_and_nonce_counter_commands(self):
        pubkeys = [
            secp.ec_pubkey_serialize(secp.ec_pubkey_create(data.valid_seckeys[0])).hex(),
            secp.ec_pubkey_serialize(secp.ec_pubkey_create(data.valid_seckeys[1])).hex(),
        ]
        tweak = data.valid_seckeys[2]
        msg = b"\x92" * 32

        code, out, err = run_cli([
            "musig-pubkey-agg",
            "--pubkey", pubkeys[0],
            "--pubkey", pubkeys[1],
            "--sort",
        ])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        _, keyagg_cache = out.strip().split()

        for command in ("musig-pubkey-ec-tweak-add", "musig-pubkey-xonly-tweak-add"):
            code, out, err = run_cli([
                command,
                "-c", keyagg_cache,
                "--tweak", tweak.hex(),
            ])
            self.assertEqual(code, 0)
            self.assertEqual(err, "")
            tweaked_pubkey, tweaked_cache = out.strip().split()
            self.assertEqual(len(bytes.fromhex(tweaked_pubkey)), 33)
            self.assertEqual(len(bytes.fromhex(tweaked_cache)), 197)

        code, out, err = run_cli([
            "musig-nonce-gen-counter",
            "--counter", "7",
            "--seckey", data.valid_seckeys[0].hex(),
            "--msg", msg.hex(),
            "-c", keyagg_cache,
        ])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        secnonce, pubnonce = out.strip().split()
        self.assertEqual(len(bytes.fromhex(secnonce)), 132)
        self.assertEqual(len(bytes.fromhex(pubnonce)), 66)

    @unittest.skipUnless(
        has_secp256k1_musig and has_secp256k1_extrakeys,
        "secp256k1 is not compiled with modules 'musig' and 'extrakeys'",
    )
    def test_musig_error_contract(self):
        pubkey = secp.ec_pubkey_serialize(secp.ec_pubkey_create(data.valid_seckeys[0])).hex()
        cases = [
            ["musig-pubnonce-parse", "--pubnonce", (b"\x01" * 65).hex()],
            ["musig-aggnonce-parse", "--aggnonce", (b"\x01" * 65).hex()],
            ["musig-partial-sig-parse", "--sig", (b"\x01" * 31).hex()],
            ["musig-pubkey-agg", "--pubkey", pubkey],
            [
                "musig-nonce-gen",
                "--pubkey", pubkey,
                "--session-secrand", (b"\x01" * 32).hex(),
                "--keyagg-cache", (b"\x01" * 196).hex(),
            ],
            [
                "musig-nonce-gen-counter",
                "--counter", "-1",
                "--seckey", data.valid_seckeys[0].hex(),
                "--keyagg-cache", (b"\x01" * 197).hex(),
            ],
            [
                "musig-partial-sign",
                "--secnonce", (b"\x01" * 131).hex(),
                "--seckey", data.valid_seckeys[0].hex(),
                "--session", (b"\x01" * 133).hex(),
                "--keyagg-cache", (b"\x01" * 197).hex(),
            ],
        ]
        for argv in cases:
            with self.subTest(argv=argv):
                code, out, err = run_cli(argv)
                self.assertEqual(code, 2)
                self.assertEqual(out, "")
                self.assertTrue(err.startswith("error:"))

    @unittest.skipUnless(has_secp256k1_extrakeys, "secp256k1 is not compiled with module 'extrakeys'")
    def test_xonly_pubkey_parse(self):
        xonly = data.serialized_pubkeys_compressed[0][1:]

        code, out, err = run_cli(["xonly-pubkey-parse", "--xonly-pubkey", xonly.hex()])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertEqual(out.strip(), xonly.hex())

    @unittest.skipUnless(has_secp256k1_extrakeys, "secp256k1 is not compiled with module 'extrakeys'")
    def test_xonly_pubkey_from_pubkey(self):
        pubkey = data.serialized_pubkeys_compressed[0]
        raw_pubkey = secp.ec_pubkey_parse(pubkey)
        expected_xonly, expected_parity = extrakeys.xonly_pubkey_from_pubkey(raw_pubkey)
        code, out, err = run_cli([
            "xonly-pubkey-from-pubkey", "--pubkey", pubkey.hex()
        ])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        xonly_hex, parity = out.strip().split()
        self.assertEqual(xonly_hex, extrakeys.xonly_pubkey_serialize(expected_xonly).hex())
        self.assertEqual(int(parity), expected_parity)

    @unittest.skipUnless(has_secp256k1_extrakeys, "secp256k1 is not compiled with module 'extrakeys'")
    def test_xonly_tweak_add_and_check(self):
        seckey = data.valid_seckeys[0]
        tweak = data.valid_seckeys[1]
        pubkey = secp.ec_pubkey_create(seckey)
        xonly_pubkey, _ = extrakeys.xonly_pubkey_from_pubkey(pubkey)
        xonly_hex = extrakeys.xonly_pubkey_serialize(xonly_pubkey).hex()

        code, out, err = run_cli([
            "xonly-pubkey-tweak-add", "--xonly-pubkey", xonly_hex,
            "--tweak", tweak.hex()
        ])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        tweaked_pubkey = secp.ec_pubkey_parse(bytes.fromhex(out.strip()))
        tweaked_xonly, parity = extrakeys.xonly_pubkey_from_pubkey(tweaked_pubkey)
        tweaked_xonly_hex = extrakeys.xonly_pubkey_serialize(tweaked_xonly).hex()

        code, out, err = run_cli([
            "xonly-pubkey-tweak-add-check",
            "--tweaked-pubkey", tweaked_xonly_hex,
            "--parity", str(parity),
            "--internal-pubkey", xonly_hex,
            "--tweak", tweak.hex(),
        ])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertEqual(out.strip(), "True")

        code, out, err = run_cli([
            "xonly-pubkey-tweak-add-check",
            "--tweaked-pubkey", tweaked_xonly_hex,
            "--parity", str(0 if parity else 1),
            "--internal-pubkey", xonly_hex,
            "--tweak", tweak.hex(),
        ])
        self.assertEqual(code, 1)
        self.assertEqual(err, "")
        self.assertEqual(out.strip(), "False")

    @unittest.skipUnless(has_secp256k1_extrakeys, "secp256k1 is not compiled with module 'extrakeys'")
    def test_keypair_commands(self):
        seckey = data.valid_seckeys[0]
        tweak = data.valid_seckeys[1]

        keypair = extrakeys.keypair_create(seckey)
        expected_xonly, expected_parity = extrakeys.keypair_xonly_pub(keypair)
        code, out, err = run_cli(["keypair-xonly-pub", "--seckey", seckey.hex()])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        xonly_hex, parity = out.strip().split()
        self.assertEqual(xonly_hex, extrakeys.xonly_pubkey_serialize(expected_xonly).hex())
        self.assertEqual(int(parity), expected_parity)

        code, out, err = run_cli([
            "keypair-xonly-tweak-add", "--seckey", seckey.hex(),
            "--tweak", tweak.hex()
        ])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertEqual(
            out.strip(),
            extrakeys.keypair_sec(extrakeys.keypair_xonly_tweak_add(keypair, tweak)).hex(),
        )

    @unittest.skipUnless(has_secp256k1_extrakeys, "secp256k1 is not compiled with module 'extrakeys'")
    def test_extrakeys_error_contract(self):
        cases = [
            ["xonly-pubkey-parse", "--xonly-pubkey", "abc"],
            ["xonly-pubkey-parse", "--xonly-pubkey", (b"\x01" * 31).hex()],
            ["xonly-pubkey-parse", "--xonly-pubkey", (b"\x00" * 32).hex()],
            [
                "xonly-pubkey-tweak-add-check",
                "--tweaked-pubkey", data.serialized_pubkeys_compressed[0][1:].hex(),
                "--parity", "2",
                "--internal-pubkey", data.serialized_pubkeys_compressed[0][1:].hex(),
                "--tweak", data.valid_seckeys[1].hex(),
            ],
        ]
        for argv in cases:
            with self.subTest(argv=argv):
                code, out, err = run_cli(argv)
                self.assertEqual(code, 2)
                self.assertEqual(out, "")
                self.assertTrue(err.startswith("error:"))


if __name__ == "__main__":
    unittest.main()
