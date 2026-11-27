# Protocol test vectors (v1)

`handshake_v1.json` pins every deterministic value in `docs/PROTOCOL.md`:
transcript hashes, ECDH output, HKDF keys, setup-code proof, encrypted records,
chunking, the signed-result digest, the site-profile envelope and the label QR.

* `generate.py` is an **independent reference implementation** in Python
  (`cryptography`). The Rust core (`keymaker-proto`) must reproduce the same bytes;
  two independent implementations agreeing is what makes the spec trustworthy.
* `inputs.json` holds the fixed inputs (ephemeral keys, nonces, setup code, …).
* `vector-device.key` / `vector-device.crt` is a fixed demo device (`Teton-3F9A2C`)
  issued by the demo CA in `demo/pki/`. Test-only, public on purpose.

ECDSA signatures are randomized, so the two signatures (device auth, result) are
created once, stored in `inputs.json`, and only verified afterwards.

```bash
python3 tests/vectors/generate.py --check   # CI: fails if anything would change
python3 tests/vectors/generate.py           # rewrite after an intentional spec change
python3 tests/vectors/generate.py --resign  # create new fixed signatures
```

Requires `python3-cryptography` (`sudo apt install python3-cryptography` on Ubuntu 24.04).
