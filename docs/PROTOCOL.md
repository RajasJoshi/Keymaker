# Teton BLE Provisioning Protocol — v1

Status: **v1, frozen for the demo.** Any change to bytes on the wire bumps the
version and regenerates `tests/vectors/`.

This document is the single source of truth. The Rust core (`keymaker-proto`),
shared by the gateway and the Ubuntu configurator (CLI + GUI), implements it.
`tests/vectors/` pins every deterministic value.

Notation: `||` is concatenation, `u32be(x)` / `u64be(x)` are big-endian
integers, strings are ASCII/UTF-8 bytes without terminator, `b64()` is
standard Base64 (RFC 4648 §4) **with** padding.

---

## 1. Roles and goals

| Role | Who | Proves | With |
|---|---|---|---|
| **Device** | Teton gateway (Ubuntu, BLE + Wi-Fi) | it is a genuine Teton device | P-256 key + certificate chained to the Teton CA |
| **Configurator** | Ubuntu configurator (CLI or GUI) | physical access to *this* device | 8-digit setup code printed on the device label |

Properties:

* Nothing is trusted because of the radio link. BLE pairing/bonding is **not** used.
* The configurator sends nothing secret until the device has proven its identity.
* Wi-Fi credentials travel only inside AES-256-GCM records keyed from an
  ephemeral ECDH exchange (forward secrecy).
* The setup code cannot be brute-forced offline; online guesses are rate limited
  by the device, with the counter persisted across reboots.
* The device returns a signed, session-bound result (a receipt).

---

## 2. BLE transport

### 2.1 Advertising
* Only while the device is **unprovisioned** (factory-new or after `reset`).
* Advertisement data: Flags + complete list of 128-bit service UUIDs (the service below).
* Scan response: Complete Local Name `Teton-<ID>` where `<ID>` is 6 uppercase hex characters.

### 2.2 GATT
Service `6e5f0001-b2c4-4d1e-9a3f-7465746f6e01`

| Characteristic | UUID | Properties | Direction / content |
|---|---|---|---|
| RX | `6e5f0002-b2c4-4d1e-9a3f-7465746f6e01` | Write (with response) | configurator → device chunks |
| TX | `6e5f0003-b2c4-4d1e-9a3f-7465746f6e01` | Notify | device → configurator chunks |
| INFO | `6e5f0004-b2c4-4d1e-9a3f-7465746f6e01` | Read | plaintext JSON `{"device_id":"3F9A2C","state":"unprovisioned","v":1}` |

No characteristic requires encryption or authentication at the BLE layer, so no
OS pairing dialog appears.

### 2.3 Sessions
* One configurator at a time. A second connection receives `error/busy` and is dropped.
* Limits: handshake complete within **30 s**, idle timeout **120 s**, total session **10 min**.
* Configurators SHOULD request ATT MTU 517.

### 2.4 Chunking
Every message is split into chunks that each fit one ATT write/notification:

```
chunk = header(1 byte) || payload
header bit 6 (0x40) = START   first chunk of a message
header bit 7 (0x80) = FINAL   last chunk of a message
other bits                     must be 0
payload length            <= ATT_MTU - 3 - 1
```

* A single-chunk message has header `0xC0`.
* A START chunk discards any partial message being reassembled.
* A continuation without a preceding START, a reserved bit set, an empty chunk,
  or a reassembled message larger than **8192 bytes** is a protocol error.

---

## 3. Message encoding

* Each message is a UTF-8 JSON object with a string field `"t"` (type).
* Unknown fields MUST be ignored; unknown `"t"` values are protocol errors.
* **Transcripts hash the exact bytes received/sent.** Implementations never
  re-serialize JSON before hashing (key order and spacing differ between libraries).

---

## 4. Handshake

```
M1  C→D  {"t":"hello","v":1,"nonce":b64(32 bytes),"epk":b64(65 bytes)}
M2  D→C  {"t":"hello","v":1,"device_id":"3F9A2C","nonce":b64(32 bytes),"epk":b64(65 bytes),"cert":b64(DER)}
M3  D→C  {"t":"device_auth","sig":b64(DER ECDSA signature)}
```

* `epk` is an ephemeral P-256 public key, SEC1 **uncompressed** (`0x04 || X || Y`, 65 bytes).
  Receivers MUST reject points not on the curve and the identity point.
* `cert` is the device's X.509 certificate, DER.
* The device sends M2 and M3 back to back after receiving M1.

### 4.1 Transcript hashes

```
TH(ctx, m1, …, mk) = SHA-256( "TETON-PROV-v1|" || ctx || u32be(len(m1)) || m1 || … || u32be(len(mk)) || mk )

TH2 = TH("device-auth", M1, M2)
TH  = TH("session",     M1, M2, M3)
```

### 4.2 Device signature (M3)
`sig = ECDSA-P256-SHA256(device_private_key, TH2)` — i.e. the 32-byte TH2 is the
*message* passed to ECDSA with SHA-256 (it is hashed again by ECDSA).
Signatures are DER-encoded. Verifiers MUST accept both low-S and high-S values.

### 4.3 Configurator checks — in this order, before sending anything secret
1. `v == 1` in M2; `epk` valid.
2. Certificate signature verifies under the pinned Teton CA public key, and the
   current time is within its validity period.
3. Profile: `basicConstraints CA:FALSE`; `keyUsage` contains `digitalSignature`;
   public key is P-256.
4. Subject `CN == "Teton-" || device_id` **and** `device_id` equals the ID read
   from the device label (QR or typed).
5. Certificate serial number is not on the configurator's denylist (empty in the demo).
6. `sig` verifies over TH2 with the certificate's public key.

Any failure → abort and disconnect **without** sending the setup-code proof.

### 4.4 Key schedule

```
Z    = ECDH(configurator_ephemeral, device_ephemeral)      32 bytes, the shared X coordinate
OKM  = HKDF-SHA256(IKM = Z,
                   salt = nonce_c || nonce_d,               64 bytes
                   info = "TETON-PROV-v1|keys|" || TH,
                   L = 96)
k_c2d  = OKM[0..32]     configurator → device AES-256-GCM key
k_d2c  = OKM[32..64]    device → configurator AES-256-GCM key
k_auth = OKM[64..96]    setup-code proof key
```

---

## 5. Encrypted records

After M3 every message is wrapped:

```
{"t":"enc","n":<counter>,"ct":b64(ciphertext || 16-byte tag)}

key   = k_c2d (C→D) or k_d2c (D→C)
nonce = dir || u64be(counter)              dir = "C2D\0" (43 32 44 00) or "D2C\0" (44 32 43 00)
AAD   = "TETON-PROV-v1" || TH
pt    = the inner JSON message bytes
```

* Counters start at **1** in each direction and increase by exactly 1.
  A receiver accepts only `n == last_received + 1`; anything else ends the session.
* A record that fails authentication ends the session.

---

## 6. Setup-code proof

First encrypted message from the configurator:

```
C→D  {"t":"auth","proof":b64(HMAC-SHA256(k_auth, "TETON-PROV-v1|setup-code|" || code))}
     code = the 8 ASCII digits, separators removed ("1234-5678" → "12345678")

D→C  {"t":"auth_ok"}
  or {"t":"error","code":"auth_failed","attempts_left":N}   then the device disconnects
```

Device rules:
* Before comparing, increment the persisted failure counter and write it to disk
  (atomically). Reset to 0 only after a successful comparison (constant time).
* After **5** consecutive failures the device is locked for 30 s; each further
  failure doubles the lock, capped at 1 h. The lock survives reboots.
* While locked, the device answers M1 with plaintext
  `{"t":"error","code":"locked_out","retry_after":<seconds>}`.
* Before `auth_ok`, the only accepted encrypted message is `auth`.

---

## 7. Requests (encrypted, after `auth_ok`)

### 7.1 Scan
```
C→D  {"t":"scan"}
D→C  {"t":"networks","networks":[{"ssid":"StMarys-Devices","signal":84,"security":"wpa2"}, …]}
```
`signal` is 0–100. `security` ∈ `wpa2`, `wpa3`, `wpa2/wpa3`, `open`, `enterprise`, `wep`.
Hidden networks and other `Teton-*` devices are omitted.

### 7.2 Set Wi-Fi
```
C→D  {"t":"set_wifi","ssid":"…","psk":"…","security":"wpa2","hidden":false,"country":"US"}
D→C  {"t":"status","state":"connecting"}             (zero or more progress messages)
D→C  {"t":"result","body":b64(result JSON),"sig":b64(DER ECDSA)}
```

| Field | Rule |
|---|---|
| `ssid` | 1–32 bytes UTF-8 |
| `security` | `wpa2` → NM `wpa-psk`; `wpa3` → NM `sae`; `wpa2/wpa3` → `sae` if the adapter supports SAE, else `wpa-psk`; `open` → no security. `enterprise`/`wep` → result `unsupported_security`. |
| `psk` | `wpa2`: 8–63 chars or exactly 64 hex digits. `wpa3`: 1–128 chars. `open`: must be empty. |
| `hidden` | optional, default `false`; when true the device probes for the SSID. |
| `country` | optional ISO 3166-1 alpha-2 regulatory domain, applied before connecting. |

A failed `set_wifi` may be repeated in the same session (e.g. after a wrong password).

### 7.3 Signed result
```
body (success) = {"ok":true,"device_id":"3F9A2C","ssid":"…","ip":"192.168.50.23","gateway":"192.168.50.1",
                  "gateway_reachable":true,"boot_id":"…","uptime_s":1234}
body (failure) = {"ok":false,"device_id":"3F9A2C","ssid":"…","reason":"wrong_password","boot_id":"…","uptime_s":1234}
reason ∈ wrong_password | network_not_found | no_ip | timeout | unsupported_security | device_error

sig = ECDSA-P256-SHA256(device_private_key, SHA-256("TETON-PROV-v1|result|" || TH || body_bytes))
```
`body_bytes` are the decoded bytes of `body`. The device has no trusted clock, so
it reports `boot_id` and `uptime_s`; the configurator adds its own timestamp when
exporting. Binding to `TH` makes a result unusable in any other session.

### 7.4 Finish
```
C→D  {"t":"finish"}
D→C  {"t":"bye"}
```
If the device is now provisioned it removes its GATT service, stops advertising
and powers the Bluetooth adapter off.

---

## 8. Plaintext errors (before keys exist)

`{"t":"error","code":<code>, …}` with `code` ∈ `version`, `busy`, `locked_out`
(+`retry_after`), `protocol`. After keys exist, errors are sent inside records.

---

## 9. Device states

| State | BLE | Wi-Fi |
|---|---|---|
| `unprovisioned` | advertising, accepts sessions | not configured |
| `provisioned` | **off** | connected / auto-reconnecting |
| `offline` | **off** | lost for longer than the retry window (default 24 h); stays offline |

`keymaker-gateway reset` → `unprovisioned`: deletes the Wi-Fi profile and the
provisioning state, keeps the device identity (key, certificate, setup code).

---

## 10. Label QR

```
TETON:1;ID=3F9A2C;CODE=12345678;
```
The configurator accepts this string in its input field (typed, pasted, or
entered by a USB 2D barcode scanner, which behaves like a keyboard), or the ID
and code typed separately.

---

## 11. Site profile

IT prepares a site profile once; technicians import it into the configurator as
a file. The passphrase is given out separately. The envelope is plain text, so a
future mobile configurator could carry the same envelope in a QR code.

```
profile JSON = {"v":1,"name":"St Marys Wing 4","ssid":"…","security":"wpa2","psk":"…",
                "hidden":false,"country":"US"}

envelope text = "TETONPROFILE1:" || b64( salt(16) || nonce(12) || ciphertext || tag(16) )
key  = PBKDF2-HMAC-SHA256(passphrase UTF-8, salt, 600000 iterations, 32 bytes)
AES-256-GCM(key, nonce, plaintext = profile JSON, AAD = "TETON-PROFILE-v1")
```

File extension: `.tetonprofile` (contains the envelope text).

---

## 12. Constants

| Name | Value |
|---|---|
| Protocol label | `TETON-PROV-v1` |
| Nonce length | 32 bytes |
| Max message | 8192 bytes |
| Max setup-code failures before lock | 5 |
| Lock duration | 30 s doubling, max 3600 s |
| Handshake / idle / session timeout | 30 s / 120 s / 600 s |
| Wi-Fi retry window before `offline` | 24 h (configurable) |

---

## 13. Security notes (demo scope)

* The demo CA private key is in this repository on purpose; demo trust is public.
* Device keys are software keys (`/var/lib/keymaker/device.key`, mode 0600). Production
  would use a TPM or secure element.
* Residual risk: anyone holding a device label can point that device at a network
  of their choice. Technician authorization is out of scope for v1.
