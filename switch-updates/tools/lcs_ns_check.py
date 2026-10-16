#!/usr/bin/env python3
"""Check switchlcs.delivery against `ns`'s own DeliveryInfo checks, run under unicorn.

    python ../pokeldn/tools/switch/nso_read.py <ns exefs>/main ns.bin
    python tools/lcs_ns_check.py ns.bin                 # POKELDN_SOURCE: a pokeldn checkout, else ../pokeldn

Firmware 20.5.0 addresses: the HMAC 0x31a80, the system validator 0x13fa5c (HMAC, protocol versions,
version floor at ctx+0x40), the application HMAC 0x141304 and protocol check 0x1412c0. The settings
readers 0x9780c / 0x97850 / 0x97894 are patched to return the retail defaults (1, 1, 0).
docs/lcs.md "DeliveryInfo and the join gate".
"""
import hashlib
import hmac
import os
import struct
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
SOURCE = os.environ.get("POKELDN_SOURCE") or os.path.join(ROOT, "..", "pokeldn")
sys.path.insert(0, os.path.join(SOURCE, "tools", "switch"))         # nso_run: pokeldn's unicorn harness
sys.path.insert(0, ROOT)
from nso_run import Runner, SCRATCH                                       # noqa: E402
from switchlcs import delivery as d                                      # noqa: E402

MAC, VALIDATE_SYSTEM, APP_MAC, APP_PROTOCOL = 0x31a80, 0x13fa5c, 0x141304, 0x1412c0
SETTINGS = {0x9780c: 1, 0x97850: 1, 0x97894: 0}
RET = 0xD65F03C0


def mov_w0(value):
    return 0x52800000 | (value << 5)


def main(argv=None):
    path = (argv or sys.argv[1:])[0]
    r = Runner(path)
    img = bytes(r.img)
    if img[0x2c3340:0x2c3360] != d.SYSTEM_KEY or img[0x2c3360:0x2c3380] != d.APPLICATION_KEY:
        sys.exit(f"{path}: the keys are not at 20.5.0's addresses; this tool is pinned to 20.5.0")
    for addr, value in SETTINGS.items():
        r.write(addr, struct.pack("<II", mov_w0(value), RET))
    blob_at, ctx_at, out_at = SCRATCH + 0x1000, SCRATCH + 0x2000, SCRATCH + 0x3000

    failures = 0
    for trial in range(4):
        data = os.urandom(0xE0)
        key = d.SYSTEM_KEY if trial % 2 else d.APPLICATION_KEY
        r.write(blob_at, data)
        r.write(ctx_at, key)
        r.call(MAC, (out_at, 0x20, blob_at, 0xE0, ctx_at, 0x20))
        same = bytes(r.uc.mem_read(out_at, 0x20)) == hmac.new(key, data, hashlib.sha256).digest()
        failures += not same
        print(f"ns 0x31a80 vs HMAC-SHA256, random input {trial}: {'same' if same else 'DIFFERENT'}")

    base = d.SystemDeliveryInfo(system_update_version=d.system_version(20, 5, 0, 100))
    cases = [("built, 20.5.0", base.pack(), 0)]
    tampered = bytearray(base.pack())
    tampered[0x0C] ^= 1
    cases.append(("one byte changed after signing", bytes(tampered), 0))
    for name, field, value in (("system protocol 0", "system_delivery_protocol_version", 0),
                               ("system protocol 2", "system_delivery_protocol_version", 2),
                               ("application protocol 2", "application_delivery_protocol_version", 2),
                               ("reserved bytes set", "reserved", b"\xff" * 0xB8),
                               ("system update id 0", "system_update_id", 0)):
        info = d.SystemDeliveryInfo(**{**base.__dict__, field: value})
        cases.append((name, info.pack(), 0))
    floor_cases = [("version floor 20.5.1 over 20.5.0", base.pack(), d.system_version(20, 5, 1)),
                   ("version floor equal", base.pack(), d.system_version(20, 5, 0, 100))]
    for name, blob, floor in cases + floor_cases:
        r.write(blob_at, blob)
        r.write(ctx_at, bytes(0x40) + struct.pack("<I", floor))
        got, _ = r.call(VALIDATE_SYSTEM, (ctx_at, blob_at))
        want = d.verify_system(blob, required_system_version=floor)
        failures += (got & 0xFFFFFFFF) != want
        print(f"system   {name:34s} ns {got & 0xFFFFFFFF:#07x} ({d.error_code(got) if got else 'ok'})"
              f"  pokeldn {want:#07x}  {'same' if (got & 0xFFFFFFFF) == want else 'DIFFERENT'}")

    app = d.ApplicationDeliveryInfo(application_id=0x01008F6008C5E000, application_version=786432)
    app_cases = [("built", app.pack()),
                 ("signed with the system key", app.pack(key=d.SYSTEM_KEY)),
                 ("protocol 2", d.ApplicationDeliveryInfo(**{**app.__dict__,
                  "application_delivery_protocol_version": 2}).pack())]
    for name, blob in app_cases:
        r.write(blob_at, blob)
        got, _ = r.call(APP_MAC, (blob_at,))
        if not got:
            got, _ = r.call(APP_PROTOCOL, (blob_at,))
        got &= 0xFFFFFFFF
        want = d.verify_application(blob)
        failures += got != want
        print(f"app      {name:34s} ns {got:#07x} ({d.error_code(got) if got else 'ok'})"
              f"  pokeldn {want:#07x}  {'same' if got == want else 'DIFFERENT'}")
    print("all agree" if not failures else f"{failures} DISAGREE")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
