# Keymaker

**Secure, offline Wi-Fi provisioning for Teton gateways over Bluetooth Low Energy.**
Keymaker brings new gateways onto the network; Agent Smith (fleet management)
looks after them once they are there.

A technician uses the Keymaker configurator on Ubuntu (GUI or CLI) to send Wi-Fi credentials to a gateway over Bluetooth Low Energy.
The gateway proves it is genuine with a device certificate, the technician
proves physical access with the setup code on the label, and the credentials
travel only inside AES-256-GCM. The gateway then joins a real WPA2/WPA3 network
and returns a signed result.

## Components (planned)

| Package | Runs on | Purpose |
|---|---|---|
| `keymaker-gateway` | each Teton gateway (Ubuntu, x86-64 or Raspberry Pi arm64) | BLE provisioning agent (BlueZ + NetworkManager), systemd service |
| `keymaker` | technician laptop (Ubuntu) | configurator: GUI wizard + CLI |
| `keymaker-factory` | factory / demo setup | device keys + certificates, labels, site profiles |

> **Work in progress.** Built in stages; this README is completed in stage 8.

| Stage | Content | Status |
|---|---|---|
| 1 | Protocol spec, demo PKI, test vectors | ✅ |
| 2 | Rust protocol core + simulated transport | ⏳ |
| 3 | Gateway agent (BlueZ, NetworkManager) | ⏳ |
| 4 | Configurator CLI | ⏳ |
| 5 | Configurator GUI, site profiles, CSV export, receipt verification | ⏳ |
| 6 | `.deb` packaging + GitHub Actions | ⏳ |
| 7 | Security / failure tests, evidence | ⏳ |
| 8 | Documentation, release | ⏳ |

## Stage 1 test gate (Ubuntu 24.04)

```bash
sudo apt install -y openssl python3-cryptography
openssl verify -CAfile demo/pki/teton-demo-root-ca.crt tests/vectors/vector-device.crt   # → OK
python3 tests/vectors/generate.py --check                                               # → vectors up to date
```

## Documents

* Protocol: [`docs/PROTOCOL.md`](docs/PROTOCOL.md)
* Demo keys (public on purpose): [`demo/pki/`](demo/pki/README.md)
* Test vectors: [`tests/vectors/`](tests/vectors/README.md)

License: Apache-2.0.
