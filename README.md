# Relay weights

The application ships with a fixed, ordered list of relays, each run by an operator
independent of the gateway operator, and a default share of requests for each (equal
shares). For every request the client picks one of these relays at random according to
those shares.

The gateway operator may publish a small signed block that changes the shares, for example
to move traffic away from a relay that is slow, or to introduce a new relay gradually. The
block can do nothing else. It names no relay: it holds one number per position in the
application's own list, together with a fingerprint of that list, and a client whose list
differs in any way ignores the block. An invalid, expired or absent block means the
application uses its built-in shares.

There is one block for everyone. It travels inside the signed key configuration that every
client already fetches through a relay, so it adds no request and no identifier, and the
client never reports which block it holds.

It is signed with a non-exportable key, separate from the gateway's keys, that can only
sign. An automated job signs when a change to the weights is merged into this public
repository, and again every week with the same weights, so that a block is never valid for
more than 30 days. The history of this repository and its log file record every signed
block, and anyone can fetch the current one through a relay and compare it with the log;
the application shows the identifier of the block it is using.

Changing the shares does not change what any party can learn: each relay sees the addresses
of the clients that use it and never the content, and the gateway sees content and never
addresses. In the most extreme case, all requests through a single relay, the result is the
same as an application that ships with only that relay.

## Contents

| Path | What |
|---|---|
| `relay-weights/<network>.json` | `{"weights": [w1, ..., wn]}`: one integer 0..100 per relay position, sum 100 |
| `keys/<network>.pub` | the network's Ed25519 public key, 64 hex characters |
| `scripts/sign.py` | the signing job (tests: `scripts/test_sign.py`) |
| `.github/workflows/sign.yml` | runs `sign.py` on a merge to `main` and weekly |
| `log.jsonl` on branch `signing-log` | one line per signed block |

## Changing the weights

Open a pull request that edits `relay-weights/<network>.json`, for example
`{"weights":[70,30]}`. The number of weights must equal the number of relays in the
application's list. When it is merged, the job signs and publishes a new block. Deleting the
file stops the weekly signature, and the last block lapses within 30 days; clients then use
their built-in shares.

The job computes everything except the weights: it takes the relay list fingerprint from
the list it knows, sets `seq` to the signing time and the validity window itself, and refuses
weights that are not integers summing to 100.

## Log

Every signature appends one line to `log.jsonl` on branch `signing-log` before the block is
published:

```json
{"network":"testnet","seq":1700000000,"not_before":1699999700,"not_after":1702591700,"n":2,"set":"e681259aa06b7980","weights":[50,50],"block_id":"...","key_id":"...","trigger":"merge","commit":"<commit of main that was signed>"}
```

`trigger` is `merge` (a merge to `main`) or `schedule` (the weekly re-signature).

The log is a superset of the published blocks: a line is pushed before its block is uploaded,
so a logged block may have failed to upload, but no block is published without a log line. The
job signs only the current head of `main` and only on the first attempt of a run; a re-run of
an old run is refused. So a run that failed after its log line (an upload error, say) is not
retried: the next merge touching the signed paths, or the weekly run, signs again.

## Format

The block is one JSON object with exactly these fields, in this order:

```json
{"v":1,"network":"testnet","seq":S,"not_before":NB,"not_after":NA,"n":2,"set":"<16 hex>","weights":[50,50],"key_id":"<8 hex>","sig":"<base64>"}
```

- `v` = 1; `network` = `mainnet` or `testnet`.
- `n` = number of relays (1..8); `weights` = `n` integers 0..100 that sum to 100, in the
  order of the application's relay list.
- `seq` = signing time (unix seconds). Clients refuse a `seq` more than 60 s in the future, or
  lower than the highest they have accepted.
- `not_before` = `seq` - 300, `not_after` = `not_before` + 2592000 (30 days).
- `set` = hex of the first 8 bytes of SHA-256(U1 LF U2 LF ... Un LF), each `Ui` the
  canonical URL of relay `i` (`https://`, lower-case host, no `:443`, no trailing `/`, no
  query, fragment or user info).
- `key_id` = hex of the first 4 bytes of SHA-256 of the raw public key (informational).
- `sig` = Ed25519 (RFC 8032) signature, standard base64, over:

```
"zodl-ohttp-relay-weights-v1" 0x00 network 0x00 u64be(seq) u64be(not_before) u64be(not_after)
u8(n) set (8 raw bytes) u8(w1) ... u8(wn)
```

The block identifier is the hex SHA-256 of that message.

## Verifying a block

Save the block as `block.json`, then rebuild the message and check the signature with the
network's public key:

```sh
python3 - block.json <<'PY'
import base64, json, sys
sys.path.insert(0, "scripts")
import sign
b = json.load(open(sys.argv[1]))
msg = sign.message(b["network"], b["seq"], b["not_before"], b["not_after"], bytes.fromhex(b["set"]), b["weights"])
pub = sign.read_pub(f"keys/{b['network']}.pub")
print("block id", sign.block_id(msg))
print("signature", "OK" if sign.verify(pub, msg, base64.b64decode(b["sig"])) else "INVALID")
PY
```

Then look for the block id in `log.jsonl` on branch `signing-log`.

## License

AGPL-3.0-only, see [LICENSE](LICENSE).
