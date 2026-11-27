# Demo PKI — NOT FOR PRODUCTION

> **The private key in this folder is public.** Anyone can use it to mint a
> "genuine" Teton device certificate. It exists only so that the demo can be
> reproduced by anyone. It provides **no security**.

| File | What it is |
|---|---|
| `teton-demo-root-ca.key` | P-256 private key of the demo root CA (intentionally committed) |
| `teton-demo-root-ca.crt` | Self-signed demo root certificate: `CA:TRUE, pathlen:0`, 20 years |

The demo build of the Ubuntu configurator pins `teton-demo-root-ca.crt` (and
shows a "DEMO TRUST" banner). A production build must pin a real Teton root
whose key lives in an offline HSM; CI fails a production build that contains
this demo CA.

## How these were created

```bash
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out teton-demo-root-ca.key
openssl req -x509 -new -key teton-demo-root-ca.key -sha256 -days 7300 \
  -subj "/O=Teton (DEMO)/CN=Teton Demo Root CA - NOT FOR PRODUCTION" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out teton-demo-root-ca.crt
```

## Device certificate profile

Issued by `keymaker-factory personalize` on the gateway (the key is generated on
the device and never leaves it):

| Field | Value |
|---|---|
| Key | P-256, `/var/lib/keymaker/device.key`, mode 0600 |
| Subject | `O=Teton (DEMO), CN=Teton-<ID>, serialNumber=<ID>` (`<ID>` = 6 uppercase hex) |
| Extensions | `basicConstraints=critical,CA:FALSE`, `keyUsage=critical,digitalSignature`, `extendedKeyUsage=clientAuth` |
| Validity | 10 years |

Check one by hand:

```bash
openssl verify -CAfile teton-demo-root-ca.crt device.crt
```

## GitHub secret scanning

GitHub may flag `teton-demo-root-ca.key`. That is expected: close the alert as
"used in tests".
