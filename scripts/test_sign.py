#!/usr/bin/env python3
"""Unit tests for sign.py: no network, no cloud credentials.

    python3 -m unittest discover -s scripts -p 'test_*.py'
"""

import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sign  # noqa: E402

RELAYS = ["https://relay-a.example/relay", "https://relay-b.example/gateway"]
# Independently checked: printf 'https://relay-a.example/relay\nhttps://relay-b.example/gateway\n' | sha256sum
SET_HEX = "e681259aa06b7980"
MSG_HEX = (
    "7a6f646c2d6f687474702d72656c61792d776569676874732d7631"  # zodl-ohttp-relay-weights-v1
    "00" "746573746e6574" "00"                                  # 0x00 testnet 0x00
    "000000006553f100"                                          # seq 1700000000
    "000000006553efd4"                                          # not_before 1699999700
    "00000000657b7cd4"                                          # not_after 1702591700
    "02" "e681259aa06b7980" "461e"                              # n, set, weights 70 30
)
BLOCK_ID = "3bdfd5f1eb8e5ec9e2388b7b598845671ac8b37901bb62f2726aeeb78354b41d"


class Weights(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(sign.validate_weights({"weights": [50, 50]}), [50, 50])
        self.assertEqual(sign.validate_weights({"weights": [100]}), [100])
        self.assertEqual(sign.validate_weights({"weights": [100, 0, 0]}), [100, 0, 0])
        self.assertEqual(sign.validate_weights({"weights": [12] * 7 + [16]}), [12] * 7 + [16])

    def test_invalid(self):
        for doc in [
            {"weights": [50, 49]}, {"weights": [50, 51]}, {"weights": [True, 99]},
            {"weights": [50.0, 50]}, {"weights": ["50", 50]}, {"weights": [101, -1]},
            {"weights": []}, {"weights": [10] * 9 + [10]}, {"weights": [50, 50], "n": 2},
            {"w": [100]}, [50, 50], {"weights": 100}, {"weights": [None, 100]},
        ]:
            with self.subTest(doc=doc), self.assertRaises(sign.Refused):
                sign.validate_weights(doc)


class Relays(unittest.TestCase):
    def test_canonical_accepted(self):
        self.assertEqual(sign.check_relays({"relays": RELAYS}), RELAYS)
        self.assertEqual(sign.check_relays({"relays": ["https://r.example:8443/x"]}), ["https://r.example:8443/x"])
        self.assertEqual(sign.check_relays({"relays": ["https://r.example"]}), ["https://r.example"])

    def test_not_canonical_refused(self):
        for u in [
            "https://Relay.example/relay", "HTTPS://relay.example/relay", "https://relay.example:443/relay",
            "https://relay.example/relay/", "https://relay.example/relay?x=1", "https://relay.example/relay#f",
            "https://user@relay.example/relay", "http://relay.example/relay", "https://relay.example/a/../b",
            "https://relay.example/./b", " https://relay.example/relay", "https://relay.example/re lay",
            "https://relay.example/%zz", "https://[::1]/relay", "https://192.0.2.1:99999/x", "", 7,
            "https://relay.example:abc/x", "https://relay.example\\@evil.example/x", "https://relay.example//x",
            "https://relay.example/a//b", "https://relay.example/x\n", "https://relay.example/x\x7f",
            "https://relay_a.example/x", "https://relay.example./x", "https://.relay.example/x",
            "https://relay..example/x", "https://rel%61y.example/x",
        ]:
            with self.subTest(u=u), self.assertRaises(sign.Refused):
                sign.check_relays({"relays": [u]})

    def test_shape(self):
        for doc in [{"relays": []}, {"relays": RELAYS * 5}, {"relays": [RELAYS[0], RELAYS[0]]}, {}, [], {"relays": "x"}]:
            with self.subTest(doc=doc), self.assertRaises(sign.Refused):
                sign.check_relays(doc)

    def test_set(self):
        self.assertEqual(sign.relay_set(RELAYS).hex(), SET_HEX)
        self.assertNotEqual(sign.relay_set(list(reversed(RELAYS))).hex(), SET_HEX)


class Message(unittest.TestCase):
    def test_bytes_and_block_id(self):
        nb, na = sign.validity(1700000000)
        self.assertEqual((nb, na), (1699999700, 1702591700))
        msg = sign.message("testnet", 1700000000, nb, na, bytes.fromhex(SET_HEX), [70, 30])
        self.assertEqual(msg.hex(), MSG_HEX)
        self.assertEqual(sign.block_id(msg), BLOCK_ID)

    def test_network(self):
        with self.assertRaises(sign.Refused):
            sign.message("regtest", 1, 0, 2, bytes(8), [100])
        m = sign.message("mainnet", 1, 0, 2, bytes(8), [100])
        self.assertTrue(m.startswith(b"zodl-ohttp-relay-weights-v1\x00mainnet\x00"))

    def test_key_id(self):
        # SHA-256 of bytes 0x00..0x1f
        self.assertEqual(sign.key_id(bytes(range(32))), "630dcd29")

    def test_block_json(self):
        sig = bytes(range(64))
        body = sign.block_json("testnet", 1700000000, 1699999700, 1702591700, bytes.fromhex(SET_HEX), [70, 30],
                               "630dcd29", sig)
        self.assertEqual(body, '{"v":1,"network":"testnet","seq":1700000000,"not_before":1699999700,'
                               '"not_after":1702591700,"n":2,"set":"e681259aa06b7980","weights":[70,30],'
                               '"key_id":"630dcd29","sig":"' + base64.b64encode(sig).decode() + '"}')
        self.assertEqual(list(json.loads(body)), ["v", "network", "seq", "not_before", "not_after", "n", "set",
                                                   "weights", "key_id", "sig"])
        self.assertFalse(body.endswith("\n"))


class Log(unittest.TestCase):
    def write(self, d, text):
        p = os.path.join(d, "log.jsonl")
        with open(p, "w") as f:
            f.write(text)
        return p

    def test_last_seq(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "log.jsonl")
            self.assertEqual(sign.last_seq(p, "testnet", 100), 0)
            self.write(d, '{"network":"testnet","seq":5}\n{"network":"mainnet","seq":9}\n\n{"network":"testnet","seq":7}\n')
            self.assertEqual(sign.last_seq(p, "testnet", 100), 7)
            self.assertEqual(sign.last_seq(p, "mainnet", 100), 9)

    def test_malformed_refused(self):
        for text in ['{"network":"testnet","seq":5\n', '[1]\n', '{"network":"testnet"}\n',
                     '{"network":"testnet","seq":"5"}\n', '{"network":"testnet","seq":true}\n',
                     '{"network":"testnet","seq":5,"seq":6}\n', '{"seq":5}\n']:
            with self.subTest(text=text), tempfile.TemporaryDirectory() as d:
                p = self.write(d, text)
                with self.assertRaises(sign.Refused):
                    sign.last_seq(p, "testnet", 100)

    def test_future_seq_refused(self):
        with tempfile.TemporaryDirectory() as d:
            p = self.write(d, '{"network":"testnet","seq":161}\n')
            with self.assertRaises(sign.Refused):
                sign.last_seq(p, "testnet", 100)
            self.assertEqual(sign.last_seq(p, "mainnet", 100), 0)
            p = self.write(d, '{"network":"testnet","seq":160}\n')
            self.assertEqual(sign.last_seq(p, "testnet", 100), 160)


class Head(unittest.TestCase):
    def test_check_head(self):
        sha = "a" * 40
        sign.check_head(sha, "1", sha)
        for attempt, head in [("2", sha), ("", sha), ("1", "b" * 40), ("1", "")]:
            with self.subTest(attempt=attempt, head=head), self.assertRaises(sign.Refused):
                sign.check_head(sha, attempt, head)


class StrictJson(unittest.TestCase):
    def test_duplicate_keys(self):
        with self.assertRaises(sign.Refused):
            sign.loads_strict('{"weights":[100],"weights":[50,50]}', "weights file")
        with self.assertRaises(sign.Refused):
            sign.loads_strict('{"relays":["https://a.example"],"relays":[]}', "relay list")

    def test_not_json(self):
        for text in ["", "{", "[1,]", "NaN-", "\ud800"]:
            with self.subTest(text=text), self.assertRaises(sign.Refused):
                sign.loads_strict(text, "x")

    def test_ok(self):
        self.assertEqual(sign.loads_strict('{"weights":[50,50]}', "x"), {"weights": [50, 50]})


@unittest.skipUnless(shutil.which("openssl"), "openssl not installed")
class Verify(unittest.TestCase):
    """Sign with a throwaway openssl key, then check sign.verify against its raw public key."""

    def test_verify(self):
        with tempfile.TemporaryDirectory() as d:
            key = os.path.join(d, "k.pem")
            msgf = os.path.join(d, "m")
            sigf = os.path.join(d, "s")
            subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519", "-out", key], check=True, capture_output=True)
            der = subprocess.run(["openssl", "pkey", "-in", key, "-pubout", "-outform", "DER"],
                                 check=True, capture_output=True).stdout
            self.assertEqual(der[:12], sign.SPKI_PREFIX)
            raw = der[12:]
            msg = bytes.fromhex(MSG_HEX)
            open(msgf, "wb").write(msg)
            subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", key, "-rawin", "-in", msgf, "-out", sigf],
                           check=True, capture_output=True)
            sig = open(sigf, "rb").read()
            self.assertTrue(sign.verify(raw, msg, sig))
            self.assertFalse(sign.verify(raw, msg + b"\x00", sig))
            self.assertFalse(sign.verify(raw, msg, bytes([sig[0] ^ 1]) + sig[1:]))
            self.assertFalse(sign.verify(bytes(32), msg, sig))
            self.assertFalse(sign.verify(raw, msg, sig[:63]))


class CrossPlatformVector(unittest.TestCase):
    """The client library's published vector (relay-weights-test-vector.json, copied as is):
    set, message, block JSON and block id must match byte for byte."""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "relay-weights-test-vector.json")) as f:
            cls.v = json.load(f)

    def test_canonical(self):
        v = self.v
        self.assertEqual(sign.check_relays({"relays": v["relay_urls_canonical"]}), v["relay_urls_canonical"])
        self.assertEqual([sign.canonical_dns_url(u) for u in v["relay_urls_as_written"]], v["relay_urls_canonical"])
        with self.assertRaises(sign.Refused):
            sign.check_relays({"relays": [v["relay_urls_as_written"][0]]})

    def test_set_message_block(self):
        v = self.v
        set_bytes = sign.relay_set(v["relay_urls_canonical"])
        self.assertEqual(set_bytes.hex(), v["set"])
        self.assertEqual(sign.validity(v["seq"]), (v["not_before"], v["not_after"]))
        msg = sign.message(v["network"], v["seq"], v["not_before"], v["not_after"], set_bytes, v["weights"])
        self.assertEqual(msg.hex(), v["signed_message_hex"])
        self.assertEqual(sign.block_id(msg), v["block_id"])
        pub = bytes.fromhex(v["public_key_hex"])
        self.assertEqual(sign.key_id(pub), v["key_id"])
        sig = base64.b64decode(v["signature_base64"])
        body = sign.block_json(v["network"], v["seq"], v["not_before"], v["not_after"], set_bytes, v["weights"],
                               sign.key_id(pub), sig)
        self.assertEqual(body, v["block_json"])

    @unittest.skipUnless(shutil.which("openssl"), "openssl not installed")
    def test_signature(self):
        v = self.v
        msg = bytes.fromhex(v["signed_message_hex"])
        pub = bytes.fromhex(v["public_key_hex"])
        sig = base64.b64decode(v["signature_base64"])
        self.assertTrue(sign.verify(pub, msg, sig))
        self.assertFalse(sign.verify(pub, msg[:-1] + b"\x1f", sig))


class Main(unittest.TestCase):
    def test_refuses_other_events(self):
        env = dict(os.environ, GITHUB_EVENT_NAME="pull_request", GITHUB_SHA="0" * 40)
        r = subprocess.run([sys.executable, "-I", os.path.join(os.path.dirname(__file__), "sign.py")],
                           env=env, capture_output=True, text=True)
        self.assertEqual(r.returncode, 1)
        self.assertIn("refusing", r.stdout)

    def run_in_tree(self, weights_text, with_key, attempt="1"):
        root = tempfile.mkdtemp()
        try:
            os.makedirs(os.path.join(root, "scripts"))
            os.makedirs(os.path.join(root, "relay-weights"))
            shutil.copy(sign.__file__, os.path.join(root, "scripts", "sign.py"))
            with open(os.path.join(root, "relay-weights", "testnet.json"), "w") as f:
                f.write(weights_text)
            if with_key:
                os.makedirs(os.path.join(root, "keys"))
                with open(os.path.join(root, "keys", "testnet.pub"), "w") as f:
                    f.write("ab" * 32 + "\n")
            env = {k: v for k, v in os.environ.items() if not k.startswith(("AWS_", "ACTIONS_", "GIT_"))}
            env.update(GITHUB_EVENT_NAME="push", GITHUB_SHA="a" * 40, GITHUB_RUN_ATTEMPT=attempt)
            return subprocess.run([sys.executable, "-I", os.path.join(root, "scripts", "sign.py")],
                                  env=env, capture_output=True, text=True, cwd=root)
        finally:
            shutil.rmtree(root)

    def test_duplicate_weights_key_refused(self):
        r = self.run_in_tree('{"weights":[100],"weights":[50,50]}', with_key=False)
        self.assertEqual(r.returncode, 1)
        self.assertIn("duplicate JSON key", r.stdout)

    def test_not_head_of_main_refused(self):
        # No git repository with an origin here: ls-remote fails, nothing is signed.
        r = self.run_in_tree('{"weights":[50,50]}', with_key=True)
        self.assertEqual(r.returncode, 1)
        self.assertIn("testnet: refused: git ls-remote failed", r.stdout)
        self.assertEqual(r.stderr, "")

    def test_skips_without_key(self):
        root = tempfile.mkdtemp()
        try:
            os.makedirs(os.path.join(root, "scripts"))
            os.makedirs(os.path.join(root, "relay-weights"))
            shutil.copy(sign.__file__, os.path.join(root, "scripts", "sign.py"))
            with open(os.path.join(root, "relay-weights", "testnet.json"), "w") as f:
                f.write('{"weights":[50,50]}\n')
            env = {k: v for k, v in os.environ.items() if not k.startswith(("AWS_", "ACTIONS_"))}
            env.update(GITHUB_EVENT_NAME="push", GITHUB_SHA="a" * 40)
            r = subprocess.run([sys.executable, "-I", os.path.join(root, "scripts", "sign.py")],
                               env=env, capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn("testnet: no public key", r.stdout)
        finally:
            shutil.rmtree(root)


if __name__ == "__main__":
    unittest.main()
