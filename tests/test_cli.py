import contextlib
import io
import unittest

import pysecp256k1 as secp
from pysecp256k1 import cli
from pysecp256k1.low_level import has_secp256k1_ecdh, has_secp256k1_extrakeys
from tests import data

if has_secp256k1_ecdh:
    import pysecp256k1.ecdh as ecdh_module

if has_secp256k1_extrakeys:
    import pysecp256k1.extrakeys as extrakeys


CLI_COMMANDS = [
    "ec-pubkey-parse",
    "ec-pubkey-cmp",
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
    "context-randomize",
    "tagged-sha256",
]

EXTRAKEYS_CLI_COMMANDS = [
    "xonly-pubkey-parse",
    "xonly-pubkey-serialize",
    "xonly-pubkey-cmp",
    "xonly-pubkey-from-pubkey",
    "xonly-pubkey-tweak-add",
    "xonly-pubkey-tweak-add-check",
    "keypair-create",
    "keypair-sec",
    "keypair-pub",
    "keypair-xonly-pub",
    "keypair-xonly-tweak-add",
]

ECDH_CLI_COMMANDS = [
    "ecdh",
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
        for dropped in (
            "ec-pubkey-serialize",
            "ecdsa-signature-serialize-compact",
            "ecdsa-signature-serialize-der",
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

    def test_ec_pubkey_create_matches_library(self):
        for seckey in data.valid_seckeys:
            code, out, err = run_cli(["ec-pubkey-create", "--seckey", seckey.hex()])
            expected = secp.ec_pubkey_serialize(secp.ec_pubkey_create(seckey)).hex()
            self.assertEqual(code, 0)
            self.assertEqual(err, "")
            self.assertEqual(out.strip(), expected)

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

    @unittest.skipUnless(has_secp256k1_extrakeys, "secp256k1 is not compiled with module 'extrakeys'")
    def test_xonly_pubkey_parse_and_serialize(self):
        xonly = data.serialized_pubkeys_compressed[0][1:]

        for command in ("xonly-pubkey-parse", "xonly-pubkey-serialize"):
            code, out, err = run_cli([command, "--xonly-pubkey", xonly.hex()])
            self.assertEqual(code, 0)
            self.assertEqual(err, "")
            self.assertEqual(out.strip(), xonly.hex())

    @unittest.skipUnless(has_secp256k1_extrakeys, "secp256k1 is not compiled with module 'extrakeys'")
    def test_xonly_pubkey_cmp_and_from_pubkey(self):
        xonly0 = data.serialized_pubkeys_compressed[0][1:].hex()
        xonly1 = data.serialized_pubkeys_compressed[1][1:].hex()

        code, out, err = run_cli([
            "xonly-pubkey-cmp", "--xonly-pubkey0", xonly0, "--xonly-pubkey1", xonly1
        ])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertTrue(int(out.strip()) < 0)

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

        code, out, err = run_cli(["keypair-create", "--seckey", seckey.hex()])
        self.assertEqual(code, 0)
        self.assertEqual(out, "")
        self.assertEqual(err, "")

        code, out, err = run_cli(["keypair-sec", "--seckey", seckey.hex()])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertEqual(out.strip(), seckey.hex())

        code, out, err = run_cli(["keypair-pub", "--seckey", seckey.hex()])
        expected_pubkey = secp.ec_pubkey_serialize(secp.ec_pubkey_create(seckey)).hex()
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertEqual(out.strip(), expected_pubkey)

        code, out, err = run_cli([
            "keypair-pub", "--seckey", seckey.hex(), "--uncompressed"
        ])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertEqual(len(bytes.fromhex(out.strip())), 65)

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
            ["keypair-create", "--seckey", data.invalid_seckeys[1].hex()],
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
