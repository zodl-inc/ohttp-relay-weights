# Public keys

`keys/<network>.pub` holds the raw 32-byte Ed25519 public key of that network's signing key
as 64 lower-case hex characters. The signing job verifies every signature against it before
anything is published, and anyone can use it to check a block (see the main README).

A network without a key file is not signed.
