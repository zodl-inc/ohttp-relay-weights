#!/usr/bin/env python3
"""Sign the relay weights block of each network (see README.md, "Format").

Run by .github/workflows/sign.yml on a push to main and on a weekly schedule. For each
network with a file relay-weights/<network>.json and a public key keys/<network>.pub:

  1. validate the weights,
  2. read the relay list (outside this repository) and compute n and set,
  3. choose seq and the validity window,
  4. sign the message with the network's sign-only key and verify the signature locally
     against keys/<network>.pub,
  5. append one line to log.jsonl on branch signing-log and push it,
  6. only then publish the block.

Standard library only, plus the aws CLI, git and openssl. Nothing about the
deployment (key, role, storage, relay list) is printed: command output is captured, and
values that must exist in memory are masked in the Actions log.
"""

import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request

DOMAIN = b"zodl-ohttp-relay-weights-v1"
NETWORKS = ("mainnet", "testnet")
MAX_RELAYS = 8
VALIDITY = 2592000  # 30 days
BACKDATE = 300
# Ed25519 SubjectPublicKeyInfo (RFC 8410) up to the 32-byte key.
SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
TRIGGERS = {"push": "merge", "schedule": "schedule"}
LOG_BRANCH = "signing-log"
LOG_FILE = "log.jsonl"


class Refused(Exception):
    """A check failed: nothing is signed or published for this run."""


# ---------------------------------------------------------------- pure functions (tested)

def validate_weights(doc):
    """doc = parsed relay-weights/<network>.json. Returns the list of weights."""
    if not isinstance(doc, dict) or set(doc) != {"weights"}:
        raise Refused('the weights file must be exactly {"weights": [...]}')
    w = doc["weights"]
    if not isinstance(w, list) or not 1 <= len(w) <= MAX_RELAYS:
        raise Refused(f"weights must be a list of 1..{MAX_RELAYS} integers")
    for x in w:
        if isinstance(x, bool) or not isinstance(x, int) or not 0 <= x <= 100:
            raise Refused("each weight must be an integer 0..100")
    if sum(w) != 100:
        raise Refused("weights must sum to exactly 100")
    return w


def canonical_dns_url(url):
    """The simple canonical form check for DNS hosts: lower-case scheme and host, no
    default port, no query/fragment/userinfo, one trailing slash removed."""
    if not isinstance(url, str) or not url or any(c.isspace() for c in url) or not url.isascii():
        raise Refused("relay list entry is not a URL")
    p = urllib.parse.urlsplit(url)
    if p.scheme.lower() != "https":
        raise Refused("relay list entry is not https")
    if p.query or p.fragment or "?" in url or "#" in url or "@" in p.netloc:
        raise Refused("relay list entry has a query, fragment or userinfo")
    host = (p.hostname or "").lower()
    if not host or host.startswith("[") or ":" in host:
        raise Refused("relay list entry has no DNS host")
    port = p.port
    netloc = host if port in (None, 443) else f"{host}:{port}"
    path = p.path
    segs = path.split("/")
    if "." in segs or ".." in segs:
        raise Refused("relay list entry has dot segments")
    if re.search(r"%(?![0-9A-F]{2})", path):
        raise Refused("relay list entry has non-normalized percent-encoding")
    if path.endswith("/"):
        path = path[:-1]
    return f"https://{netloc}{path}"


def check_relays(doc):
    """doc = parsed relay list {"relays": [url, ...]}. Returns the list, all canonical."""
    if not isinstance(doc, dict) or not isinstance(doc.get("relays"), list):
        raise Refused("relay list has the wrong shape")
    relays = doc["relays"]
    if not 1 <= len(relays) <= MAX_RELAYS:
        raise Refused(f"relay list must have 1..{MAX_RELAYS} entries")
    for u in relays:
        if canonical_dns_url(u) != u:
            raise Refused("relay list entry is not in canonical form")
    if len(set(relays)) != len(relays):
        raise Refused("relay list has a duplicate entry")
    return relays


def relay_set(relays):
    """set = first 8 bytes of SHA-256 over each canonical URL followed by LF."""
    return hashlib.sha256(b"".join(u.encode("ascii") + b"\n" for u in relays)).digest()[:8]


def key_id(raw_pub):
    return hashlib.sha256(raw_pub).digest()[:4].hex()


def message(network, seq, not_before, not_after, set_bytes, weights):
    if network not in NETWORKS:
        raise Refused("unknown network")
    if len(set_bytes) != 8 or not 1 <= len(weights) <= MAX_RELAYS:
        raise Refused("bad set or weights")
    return (DOMAIN + b"\x00" + network.encode("ascii") + b"\x00"
            + seq.to_bytes(8, "big") + not_before.to_bytes(8, "big") + not_after.to_bytes(8, "big")
            + bytes([len(weights)]) + set_bytes + bytes(weights))


def block_id(msg):
    return hashlib.sha256(msg).hexdigest()


def block_json(network, seq, not_before, not_after, set_bytes, weights, kid, sig):
    block = {
        "v": 1, "network": network, "seq": seq, "not_before": not_before, "not_after": not_after,
        "n": len(weights), "set": set_bytes.hex(), "weights": list(weights), "key_id": kid,
        "sig": base64.b64encode(sig).decode("ascii"),
    }
    return json.dumps(block, separators=(",", ":"))


def validity(seq):
    not_before = seq - BACKDATE
    return not_before, not_before + VALIDITY


def read_pub(path):
    text = open(path, encoding="ascii").read().strip()
    if not re.fullmatch(r"[0-9a-f]{64}", text):
        raise Refused(f"{path} must hold 64 lower-case hex characters")
    return bytes.fromhex(text)


def last_seq(log_path, network):
    best = 0
    if not os.path.exists(log_path):
        return best
    with open(log_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            if entry.get("network") == network:
                best = max(best, int(entry["seq"]))
    return best


def verify(raw_pub, msg, sig):
    """Ed25519 verification with openssl. Returns True only for a valid signature."""
    if len(raw_pub) != 32 or len(sig) != 64:
        return False
    pem = ("-----BEGIN PUBLIC KEY-----\n" + base64.b64encode(SPKI_PREFIX + raw_pub).decode()
           + "\n-----END PUBLIC KEY-----\n")
    with tempfile.TemporaryDirectory() as d:
        paths = {}
        for name, data in (("pub.pem", pem.encode()), ("msg", msg), ("sig", sig)):
            paths[name] = os.path.join(d, name)
            with open(paths[name], "wb") as f:
                f.write(data)
        r = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", paths["pub.pem"],
                            "-rawin", "-in", paths["msg"], "-sigfile", paths["sig"]],
                           capture_output=True)
        return r.returncode == 0


# ---------------------------------------------------------------- side effects (workflow)

def mask(value):
    if value:
        print(f"::add-mask::{value}", flush=True)


def run(step, args, env=None, stdin=None):
    """Run a command with all output captured; on failure print only the step name."""
    r = subprocess.run(args, capture_output=True, env=env, input=stdin)
    if r.returncode != 0:
        raise Refused(f"{step} failed (exit {r.returncode})")
    return r.stdout


def require_env(*names):
    values = {}
    for n in names:
        v = os.environ.get(n, "")
        if not v:
            raise Refused(f"missing setting {n}")
        values[n] = v
    return values


class Cloud:
    """Short-lived credentials from the workflow's OIDC token, never printed."""

    def __init__(self, network):
        prefix = network.upper()
        cfg = require_env("AWS_REGION", "CONFIG_BUCKET", f"{prefix}_ROLE_ARN",
                          f"{prefix}_KMS_KEY_ID", f"{prefix}_RELAYS_SECRET")
        for v in cfg.values():
            mask(v)
        self.region = cfg["AWS_REGION"]
        self.bucket = cfg["CONFIG_BUCKET"]
        self.key = cfg[f"{prefix}_KMS_KEY_ID"]
        self.relays_secret = cfg[f"{prefix}_RELAYS_SECRET"]
        role = cfg[f"{prefix}_ROLE_ARN"]
        parts = role.split(":")
        if len(parts) > 4:
            mask(parts[4])  # account id
        token = self._oidc_token()
        mask(token)
        env = self._base_env()
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write(token)
            token_file = f.name
        try:
            out = run("assume role", ["aws", "sts", "assume-role-with-web-identity",
                                      "--role-arn", role, "--role-session-name", f"sign-{network}",
                                      "--web-identity-token", f"file://{token_file}",
                                      "--duration-seconds", "900", "--output", "json"], env=env)
        finally:
            os.unlink(token_file)
        creds = json.loads(out)["Credentials"]
        for k in ("AccessKeyId", "SecretAccessKey", "SessionToken"):
            mask(creds[k])
        env.update(AWS_ACCESS_KEY_ID=creds["AccessKeyId"], AWS_SECRET_ACCESS_KEY=creds["SecretAccessKey"],
                   AWS_SESSION_TOKEN=creds["SessionToken"])
        self.env = env

    def _base_env(self):
        env = {k: v for k, v in os.environ.items()
               if not k.startswith("AWS_") and not k.startswith("ACTIONS_ID_TOKEN")}
        env.update(AWS_REGION=self.region, AWS_DEFAULT_REGION=self.region, AWS_PAGER="",
                   AWS_EC2_METADATA_DISABLED="true")
        return env

    @staticmethod
    def _oidc_token():
        url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL", "")
        bearer = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
        if not url or not bearer:
            raise Refused("no OIDC token available (id-token permission missing)")
        sep = "&" if "?" in url else "?"
        req = urllib.request.Request(url + sep + "audience=sts.amazonaws.com",
                                     headers={"Authorization": f"Bearer {bearer}"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.load(r)["value"]
        except Exception:
            raise Refused("OIDC token request failed") from None

    def relays(self):
        out = run("read relay list", ["aws", "secretsmanager", "get-secret-value", "--secret-id",
                                      self.relays_secret, "--query", "SecretString", "--output", "text"],
                  env=self.env)
        try:
            doc = json.loads(out)
        except ValueError:
            raise Refused("relay list is not JSON") from None
        for u in doc.get("relays", []) if isinstance(doc, dict) else []:
            mask(u)
        return check_relays(doc)

    def sign(self, msg):
        with tempfile.NamedTemporaryFile("wb", delete=False) as f:
            f.write(msg)
            path = f.name
        try:
            out = run("sign", ["aws", "kms", "sign", "--key-id", self.key, "--message", f"fileb://{path}",
                               "--message-type", "RAW", "--signing-algorithm", "ED25519_SHA_512",
                               "--query", "Signature", "--output", "text"], env=self.env)
        finally:
            os.unlink(path)
        return base64.b64decode(out.strip())

    def publish(self, network, body, trigger, bid, seq):
        with tempfile.NamedTemporaryFile("wb", delete=False) as f:
            f.write(body.encode("ascii"))
            path = f.name
        try:
            run("publish", ["aws", "s3api", "put-object", "--bucket", self.bucket,
                            "--key", f"{network}/relay-weights.json", "--body", path,
                            "--content-type", "application/json",
                            "--metadata", f"trigger={trigger},block-id={bid},seq={seq}"], env=self.env)
        finally:
            os.unlink(path)


def git(*args):
    step = "git " + next(a for a in args if not a.startswith("-") and "=" not in a and "/" not in a)
    return run(step, ["git", *args])


def open_log(repo_root):
    """Check out branch signing-log into a worktree; returns its path."""
    path = os.path.join(tempfile.mkdtemp(), "log")
    git("-C", repo_root, "fetch", "--quiet", "--no-tags", "--depth=50", "origin",
        f"+refs/heads/{LOG_BRANCH}:refs/remotes/origin/{LOG_BRANCH}")
    git("-C", repo_root, "worktree", "add", "--quiet", "-B", LOG_BRANCH, path, f"origin/{LOG_BRANCH}")
    return path


def append_log(log_dir, entry):
    with open(os.path.join(log_dir, LOG_FILE), "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, separators=(",", ":")) + "\n")
    who = ["-c", "user.name=github-actions[bot]",
           "-c", "user.email=41898282+github-actions[bot]@users.noreply.github.com"]
    git(*who, "-C", log_dir, "add", LOG_FILE)
    git(*who, "-C", log_dir, "commit", "--quiet", "-m",
        f"{entry['network']} seq {entry['seq']} block {entry['block_id']} ({entry['trigger']})")
    git("-C", log_dir, "push", "--quiet", "origin", f"HEAD:refs/heads/{LOG_BRANCH}")


def sign_network(network, repo_root, trigger, commit, state):
    weights_path = os.path.join(repo_root, "relay-weights", f"{network}.json")
    pub_path = os.path.join(repo_root, "keys", f"{network}.pub")
    if not os.path.exists(weights_path):
        return
    try:
        doc = json.load(open(weights_path, encoding="utf-8"))
    except ValueError:
        raise Refused("weights file is not JSON") from None
    weights = validate_weights(doc)
    if not os.path.exists(pub_path):
        print(f"{network}: no public key (keys/{network}.pub), skipped")
        return
    raw_pub = read_pub(pub_path)
    kid = key_id(raw_pub)

    cloud = Cloud(network)
    relays = cloud.relays()
    if len(relays) != len(weights):
        raise Refused(f"{len(weights)} weights for {len(relays)} relays")
    set_bytes = relay_set(relays)

    if "log_dir" not in state:
        state["log_dir"] = open_log(repo_root)
    log_dir = state["log_dir"]
    seq = int(time.time())
    if seq <= last_seq(os.path.join(log_dir, LOG_FILE), network):
        raise Refused(f"seq {seq} is not above the last logged seq")
    not_before, not_after = validity(seq)
    msg = message(network, seq, not_before, not_after, set_bytes, weights)
    sig = cloud.sign(msg)
    if not verify(raw_pub, msg, sig):
        raise Refused(f"signature does not verify against keys/{network}.pub")
    bid = block_id(msg)
    body = block_json(network, seq, not_before, not_after, set_bytes, weights, kid, sig)

    append_log(log_dir, {
        "network": network, "seq": seq, "not_before": not_before, "not_after": not_after,
        "n": len(weights), "set": set_bytes.hex(), "weights": weights, "block_id": bid,
        "key_id": kid, "trigger": trigger, "commit": commit,
    })
    cloud.publish(network, body, trigger, bid, seq)
    print(f"{network}: signed seq={seq} weights={weights} block_id={bid} trigger={trigger}")


def main():
    event = os.environ.get("GITHUB_EVENT_NAME", "")
    trigger = TRIGGERS.get(event)
    if trigger is None:
        print(f"refusing to sign on event {event!r}")
        return 1
    commit = os.environ.get("GITHUB_SHA", "")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        print("no commit id")
        return 1
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    state = {}
    failed = False
    for network in NETWORKS:
        try:
            sign_network(network, repo_root, trigger, commit, state)
        except Refused as e:
            print(f"{network}: refused: {e}")
            failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
