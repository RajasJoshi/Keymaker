#!/usr/bin/env python3
"""Reference test-vector generator for docs/PROTOCOL.md (v1).

An *independent* implementation (Python `cryptography`) of every deterministic
step of the protocol. The Rust core must reproduce these values byte for byte.

    python3 generate.py            # (re)write handshake_v1.json
    python3 generate.py --check    # fail if handshake_v1.json would change (CI)
    python3 generate.py --resign   # create new fixed signatures in inputs.json

ECDSA signatures are randomized, so they are created once (--resign), stored in
inputs.json, and only *verified* afterwards.

Dev/test tool only; not shipped. Needs python3-cryptography (Ubuntu 24.04 apt
package is fine).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
LABEL = b"TETON-PROV-v1"
CURVE = ec.SECP256R1()


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def compact(obj: dict) -> bytes:
    # Fixed key order chosen by us; receivers never re-serialize (PROTOCOL §3).
    return json.dumps(obj, separators=(",", ":")).encode()


def th(ctx: bytes, *msgs: bytes) -> bytes:
    h = hashlib.sha256(LABEL + b"|" + ctx)
    for m in msgs:
        h.update(len(m).to_bytes(4, "big"))
        h.update(m)
    return h.digest()


def chunks(msg: bytes, mtu: int) -> list[bytes]:
    size = mtu - 3 - 1
    parts = [msg[i:i + size] for i in range(0, len(msg), size)] or [b""]
    out = []
    for i, p in enumerate(parts):
        hdr = (0x40 if i == 0 else 0) | (0x80 if i == len(parts) - 1 else 0)
        out.append(bytes([hdr]) + p)
    return out


def seal(key: bytes, direction: bytes, counter: int, th_: bytes, pt: bytes) -> bytes:
    nonce = direction + counter.to_bytes(8, "big")
    return AESGCM(key).encrypt(nonce, pt, LABEL + th_)


def uncompressed(pub: ec.EllipticCurvePublicKey) -> bytes:
    return pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--resign", action="store_true")
    args = ap.parse_args()

    inputs_path = HERE / "inputs.json"
    inp = json.loads(inputs_path.read_text())

    ca_cert = x509.load_pem_x509_certificate((ROOT / inp["ca_cert"]).read_bytes())
    dev_cert = x509.load_pem_x509_certificate((ROOT / inp["device_cert"]).read_bytes())
    dev_key = serialization.load_pem_private_key((ROOT / inp["device_key"]).read_bytes(), None)
    dev_pub = dev_cert.public_key()
    # Certificate is signed by the CA (sanity check of the fixture itself).
    ca_cert.public_key().verify(dev_cert.signature, dev_cert.tbs_certificate_bytes,
                                ec.ECDSA(dev_cert.signature_hash_algorithm))
    cert_der = dev_cert.public_bytes(serialization.Encoding.DER)

    eph_c = ec.derive_private_key(int(inp["eph_c_priv"], 16), CURVE)
    eph_d = ec.derive_private_key(int(inp["eph_d_priv"], 16), CURVE)
    nonce_c, nonce_d = bytes.fromhex(inp["nonce_c"]), bytes.fromhex(inp["nonce_d"])
    device_id = inp["device_id"]

    m1 = compact({"t": "hello", "v": 1, "nonce": b64(nonce_c), "epk": b64(uncompressed(eph_c.public_key()))})
    m2 = compact({"t": "hello", "v": 1, "device_id": device_id, "nonce": b64(nonce_d),
                  "epk": b64(uncompressed(eph_d.public_key())), "cert": b64(cert_der)})
    th2 = th(b"device-auth", m1, m2)

    if args.resign or "device_auth_sig" not in inp:
        inp["device_auth_sig"] = b64(dev_key.sign(th2, ec.ECDSA(hashes.SHA256())))
    sig = base64.b64decode(inp["device_auth_sig"])
    dev_pub.verify(sig, th2, ec.ECDSA(hashes.SHA256()))  # raises if wrong
    m3 = compact({"t": "device_auth", "sig": inp["device_auth_sig"]})
    th_ = th(b"session", m1, m2, m3)

    z = eph_c.exchange(ec.ECDH(), eph_d.public_key())
    assert z == eph_d.exchange(ec.ECDH(), eph_c.public_key())
    okm = HKDF(hashes.SHA256(), 96, salt=nonce_c + nonce_d, info=LABEL + b"|keys|" + th_).derive(z)
    k_c2d, k_d2c, k_auth = okm[:32], okm[32:64], okm[64:96]

    def proof(code: str) -> bytes:
        return hmac.new(k_auth, LABEL + b"|setup-code|" + code.encode(), hashlib.sha256).digest()

    auth_pt = compact({"t": "auth", "proof": b64(proof(inp["setup_code"]))})
    auth_ok_pt = compact({"t": "auth_ok"})
    set_wifi_pt = compact(inp["set_wifi"])
    rec_c1 = seal(k_c2d, b"C2D\x00", 1, th_, auth_pt)
    rec_d1 = seal(k_d2c, b"D2C\x00", 1, th_, auth_ok_pt)
    rec_c2 = seal(k_c2d, b"C2D\x00", 2, th_, set_wifi_pt)

    body = compact(inp["result_body"])
    result_digest = hashlib.sha256(LABEL + b"|result|" + th_ + body).digest()
    if args.resign or "result_sig" not in inp:
        inp["result_sig"] = b64(dev_key.sign(result_digest, ec.ECDSA(hashes.SHA256())))
    dev_pub.verify(base64.b64decode(inp["result_sig"]), result_digest, ec.ECDSA(hashes.SHA256()))

    sp = inp["site_profile"]
    salt, sp_nonce = bytes.fromhex(sp["salt"]), bytes.fromhex(sp["nonce"])
    sp_key = PBKDF2HMAC(hashes.SHA256(), 32, salt, sp["iterations"]).derive(sp["passphrase"].encode())
    sp_plain = compact(sp["profile"])
    sp_ct = AESGCM(sp_key).encrypt(sp_nonce, sp_plain, b"TETON-PROFILE-v1")
    envelope = "TETONPROFILE1:" + b64(salt + sp_nonce + sp_ct)

    out = {
        "_comment": "Generated by tests/vectors/generate.py from inputs.json - do not edit by hand.",
        "spec": "docs/PROTOCOL.md v1",
        "device_id": device_id,
        "setup_code": inp["setup_code"],
        "ca_cert_der_b64": b64(ca_cert.public_bytes(serialization.Encoding.DER)),
        "device_cert_der_b64": b64(cert_der),
        "eph_c_priv_hex": inp["eph_c_priv"],
        "eph_d_priv_hex": inp["eph_d_priv"],
        "eph_c_pub_hex": uncompressed(eph_c.public_key()).hex(),
        "eph_d_pub_hex": uncompressed(eph_d.public_key()).hex(),
        "nonce_c_hex": inp["nonce_c"],
        "nonce_d_hex": inp["nonce_d"],
        "m1_b64": b64(m1),
        "m2_b64": b64(m2),
        "m3_b64": b64(m3),
        "th2_hex": th2.hex(),
        "th_hex": th_.hex(),
        "z_hex": z.hex(),
        "k_c2d_hex": k_c2d.hex(),
        "k_d2c_hex": k_d2c.hex(),
        "k_auth_hex": k_auth.hex(),
        "proof_hex": proof(inp["setup_code"]).hex(),
        "proof_wrong_code_00000000_hex": proof("00000000").hex(),
        "auth_plaintext_b64": b64(auth_pt),
        "record_c2d_1_ct_b64": b64(rec_c1),
        "auth_ok_plaintext_b64": b64(auth_ok_pt),
        "record_d2c_1_ct_b64": b64(rec_d1),
        "set_wifi_plaintext_b64": b64(set_wifi_pt),
        "record_c2d_2_ct_b64": b64(rec_c2),
        "result_body_b64": b64(body),
        "result_digest_hex": result_digest.hex(),
        "result_sig_b64": inp["result_sig"],
        "chunks_m2_mtu23_b64": [b64(c) for c in chunks(m2, 23)],
        "chunks_m2_mtu185_b64": [b64(c) for c in chunks(m2, 185)],
        "chunks_m1_mtu517_b64": [b64(c) for c in chunks(m1, 517)],
        "site_profile_passphrase": sp["passphrase"],
        "site_profile_iterations": sp["iterations"],
        "site_profile_key_hex": sp_key.hex(),
        "site_profile_plaintext_b64": b64(sp_plain),
        "site_profile_envelope": envelope,
        "label_qr": f"TETON:1;ID={device_id};CODE={inp['setup_code']};",
    }

    target = HERE / "handshake_v1.json"
    text = json.dumps(out, indent=2) + "\n"
    if args.check:
        if not target.exists() or target.read_text() != text:
            print("handshake_v1.json is out of date: run tests/vectors/generate.py", file=sys.stderr)
            return 1
        print("vectors up to date")
        return 0
    inputs_path.write_text(json.dumps(inp, indent=2) + "\n")
    target.write_text(text)
    print(f"wrote {target.relative_to(ROOT)} ({len(out)} values)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
