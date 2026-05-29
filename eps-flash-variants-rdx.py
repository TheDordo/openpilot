#!/usr/bin/env python3
"""
Flash TJB RDX EPS with multiple 0xC000 / 0x74000 .rwd variants until
CHECK_PROGRAMMING_DEPENDENCIES succeeds.

Mirrors nrdr/openpilot eps-update.py (erase, key, download, dependency, reset)
but loops over candidate files. Each attempt performs a full erase + flash cycle.

After a failed dependency check the ECU often stays in programming session;
the next F181 read then returns NRC 0x31 unless you hard-reset and wait.
This script calls ecuReset(HARD) + ~15s wait between variants by default.

Usage on comma (ignition ON, flat dir with tjb_sa_key.py + .rwd files):

  python eps-flash-variants-rdx.py --bus 1 --danger

  python eps-flash-variants-rdx.py --bus 1 --danger --rwd-dir rwd_zstart_sweep

Requires --danger (refuses mutating UDS without it).
"""

from __future__ import annotations

import argparse
import os
import struct
import sys
import time
import traceback
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

# Default order: best checksum hypothesis first (see tools/build_74000_checksum_variants.py)
DEFAULT_VARIANTS = [
    "stock_tjb_a030_zstart_0c000_74000_base4000_trailer.rwd",
    "stock_tjb_a030_zstart_0c000_74000_eps32_base4000.rwd",
    "stock_tjb_a030_zstart_0c000_74000_plain.rwd",
    "stock_tjb_a030_zstart_0c000_74000_base4000_trailer_neg16.rwd",
    "stock_tjb_a030_zstart_0c000_74000_eps32_base4000_neg16.rwd",
    "stock_tjb_a030_zstart_0c000_74000_cs.rwd",
    "stock_tjb_a030_zstart_0c000_74000_cs_eps32.rwd",
    "stock_tjb_a030_zstart_0c000_74000_stock.rwd",
]

DEFAULT_RWD_DIR = os.path.join(_HERE, "rwd_zstart_sweep")
DEFAULT_LOG = os.path.join(_HERE, "eps-flash-results-rdx.txt")


def import_uds_stack():
    from panda import Panda

    for mod in ("opendbc.car.uds", "panda.python.uds"):
        try:
            uds_mod = __import__(mod, fromlist=[
                "UdsClient",
                "SESSION_TYPE",
                "ACCESS_TYPE",
                "ROUTINE_CONTROL_TYPE",
                "ROUTINE_IDENTIFIER_TYPE",
                "DATA_IDENTIFIER_TYPE",
                "RESET_TYPE",
                "NegativeResponseError",
            ])
            return (
                Panda,
                uds_mod.UdsClient,
                uds_mod.SESSION_TYPE,
                uds_mod.ACCESS_TYPE,
                uds_mod.ROUTINE_CONTROL_TYPE,
                uds_mod.ROUTINE_IDENTIFIER_TYPE,
                uds_mod.DATA_IDENTIFIER_TYPE,
                uds_mod.RESET_TYPE,
                uds_mod.NegativeResponseError,
                mod,
            )
        except ImportError:
            continue
    raise ImportError("Could not import UdsClient (opendbc.car.uds or panda.python.uds)")


def set_elm327_safety(panda) -> None:
    try:
        from opendbc.car.structs import CarParams
        panda.set_safety_mode(CarParams.SafetyModel.elm327)
        return
    except ImportError:
        pass
    panda.set_safety_mode(3)


def make_uds_client(UdsClient, panda, addr: int, bus: int, uds_module: str):
    if uds_module == "opendbc.car.uds":
        return UdsClient(panda, addr, bus=bus)
    return UdsClient(panda, addr, bus=bus)


def load_x5a(path: str):
    from panda.format.x5a import x5a
    with open(path, "rb") as f:
        return x5a(f.read())


def get_can_address(fw) -> int:
    return 0x18DA00F1 | (struct.unpack("!B", fw.file_headers[2].values[0].value)[0] << 8)


def get_seed_secret(fw, app_id: bytes) -> bytes:
    headers = fw.file_headers
    for i in range(len(headers[4].values)):
        if headers[3].values[i].value == app_id:
            return headers[4].values[i].value
    raise RuntimeError(f"No SA key in RWD for app_id {app_id!r}")


def calculate_session_key(const_bytes: bytes, seed_bytes: bytes) -> bytes:
    k0, k1, k2 = struct.unpack("!HHH", const_bytes)
    seed = struct.unpack("!H", seed_bytes)[0]
    if k2 == 0:
        k2 = 0x10000
    key = ((seed + k0) ^ (seed * k1) % k2) & 0xFFFF
    return struct.pack("!H", key)


def transfer_progress(total: int, label: str):
    try:
        import tqdm
        return tqdm.tqdm(total=total, unit="B", unit_scale=True, desc=label)
    except ImportError:
        return None


def is_comm_error(exc: BaseException) -> bool:
    name = type(exc).__name__
    if name in ("PandaSpiNackResponse", "PandaUsbException", "PandaException"):
        return True
    mod = type(exc).__module__ or ""
    return "panda" in mod and "Nack" in name


def reconnect_panda(
    Panda,
    UdsClient,
    *,
    can_addr: int,
    bus: int,
    uds_module: str,
    emit,
) -> tuple:
    emit("  reconnect: opening new panda handle ...")
    time.sleep(3)
    panda = Panda(disable_checks=True)
    try:
        panda.can_clear(0xFFFF)
    except Exception as e:
        emit(f"  reconnect: can_clear warn {e!r}")
    set_elm327_safety(panda)
    uds = make_uds_client(UdsClient, panda, can_addr, bus, uds_module)
    time.sleep(1)
    try:
        uds.tester_present()
    except Exception as e:
        emit(f"  reconnect: tester_present warn {e!r}")
    emit("  reconnect: done")
    return panda, uds


def read_app_id_with_retry(
    uds,
    *,
    SESSION_TYPE,
    DATA_IDENTIFIER_TYPE,
    NegativeResponseError,
    emit,
    retries: int = 8,
    retry_delay: float = 2.0,
) -> bytes:
    """F181 read fails (NRC 0x31) if ECU is left in programming session after a bad flash."""
    last_err: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            uds.tester_present()
            if hasattr(SESSION_TYPE, "DEFAULT"):
                try:
                    uds.diagnostic_session_control(SESSION_TYPE.DEFAULT)
                except NegativeResponseError:
                    pass
            uds.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
            return uds.read_data_by_identifier(
                DATA_IDENTIFIER_TYPE.APPLICATION_SOFTWARE_IDENTIFICATION
            )
        except NegativeResponseError as e:
            last_err = e
            emit(f"  F181 read attempt {attempt}/{retries}: NRC 0x{e.error_code:02X}")
            if attempt < retries:
                time.sleep(retry_delay)
        except Exception as e:
            last_err = e
            emit(f"  F181 read attempt {attempt}/{retries}: comm {e!r}")
            if attempt < retries:
                time.sleep(retry_delay)
    assert last_err is not None
    raise last_err


def recover_ecu(
    uds,
    panda,
    *,
    Panda,
    UdsClient,
    can_addr: int,
    bus: int,
    uds_module: str,
    SESSION_TYPE,
    RESET_TYPE,
    NegativeResponseError,
    emit,
    wait_s: float,
) -> tuple:
    """Hard-reset, wait, reconnect panda if bus died. Returns (panda, uds)."""
    emit("  recover: ecuReset(HARD) ...")
    try:
        uds.ecu_reset(RESET_TYPE.HARD)
    except NegativeResponseError as e:
        emit(f"  recover: reset NRC 0x{e.error_code:02X} (continuing anyway)")
    except Exception as e:
        emit(f"  recover: reset comm error {e!r} (continuing)")

    emit(f"  recover: waiting {wait_s:.0f}s for ECU boot ...")
    time.sleep(wait_s)

    try:
        panda.can_clear(0xFFFF)
    except Exception as e:
        emit(f"  recover: can_clear failed ({e!r}) — reconnecting panda")
        return reconnect_panda(
            Panda, UdsClient, can_addr=can_addr, bus=bus, uds_module=uds_module, emit=emit
        )

    bus_ok = False
    for i in range(8):
        try:
            uds.tester_present()
            bus_ok = True
        except NegativeResponseError:
            bus_ok = True
            break
        except Exception:
            pass
        time.sleep(0.5)

    if not bus_ok:
        emit("  recover: no tester_present — reconnecting panda")
        return reconnect_panda(
            Panda, UdsClient, can_addr=can_addr, bus=bus, uds_module=uds_module, emit=emit
        )

    try:
        if hasattr(SESSION_TYPE, "DEFAULT"):
            uds.diagnostic_session_control(SESSION_TYPE.DEFAULT)
    except Exception:
        pass

    return panda, uds


def flash_one(
    uds,
    fw,
    *,
    SESSION_TYPE,
    ACCESS_TYPE,
    ROUTINE_CONTROL_TYPE,
    ROUTINE_IDENTIFIER_TYPE,
    DATA_IDENTIFIER_TYPE,
    RESET_TYPE,
    NegativeResponseError,
    skip_dependency: bool,
    f181_retries: int,
    emit,
) -> str:
    app_id = read_app_id_with_retry(
        uds,
        SESSION_TYPE=SESSION_TYPE,
        DATA_IDENTIFIER_TYPE=DATA_IDENTIFIER_TYPE,
        NegativeResponseError=NegativeResponseError,
        emit=emit,
        retries=f181_retries,
    )
    emit(f"  app_id (F181) = {app_id!r}")

    uds.tester_present()
    uds.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
    seed_resp = uds.security_access(ACCESS_TYPE.REQUEST_SEED)
    secret = get_seed_secret(fw, app_id)
    key = calculate_session_key(secret, seed_resp[-2:])
    uds.security_access(ACCESS_TYPE.SEND_KEY, key)
    uds.diagnostic_session_control(SESSION_TYPE.PROGRAMMING)

    emit("  eraseMemory ...")
    uds.routine_control(ROUTINE_CONTROL_TYPE.START, ROUTINE_IDENTIFIER_TYPE.ERASE_MEMORY)
    uds.tester_present()

    emit(f"  FLASH_DECRYPTION_KEY = {fw.keys.hex().upper()}")
    uds.write_data_by_identifier(DATA_IDENTIFIER_TYPE.FLASH_DECRYPTION_KEY, fw.keys)

    assert len(fw.firmware_blocks) == 1
    block = fw.firmware_blocks[0]
    start, length = block["start"], block["length"]
    emit(f"  requestDownload(0x{start:X}, 0x{length:X}) ...")
    max_chunk = uds.request_download(start, length)
    max_chunk -= 2

    enc = fw.firmware_encrypted[0]
    bar = transfer_progress(length, "transfer")
    cursor = 0
    seq = 1
    while cursor < length:
        n = min(max_chunk, length - cursor)
        uds.transfer_data(seq, enc[cursor : cursor + n])
        seq = (seq + 1) & 0xFF
        cursor += n
        if bar is not None:
            bar.update(n)
    if bar is not None:
        bar.close()

    emit("  requestTransferExit ...")
    uds.request_transfer_exit()

    if skip_dependency:
        emit("  skip dependency (--skip-dependency)")
        return "ok"

    emit("  CHECK_PROGRAMMING_DEPENDENCIES ...")
    try:
        uds.tester_present()
        uds.routine_control(
            ROUTINE_CONTROL_TYPE.START,
            ROUTINE_IDENTIFIER_TYPE.CHECK_PROGRAMMING_DEPENDENCIES,
        )
    except NegativeResponseError as e:
        emit(f"  DEPENDENCY FAIL: {e} (NRC 0x{e.error_code:02X})")
        try:
            uds.ecu_reset(RESET_TYPE.HARD)
        except Exception as re:
            emit(f"  post-fail reset: {re!r}")
        return "dependency_fail"
    except Exception as e:
        # ECU often resets or drops CAN during dependency check → PandaSpiNackResponse
        emit(f"  DEPENDENCY COMM LOST: {type(e).__name__}: {e!r}")
        emit("  (transfer completed; ECU may have reset during dependency — not a script crash)")
        return "dependency_comm_fail"

    emit("  dependency OK — ecuReset(HARD)")
    try:
        uds.ecu_reset(RESET_TYPE.HARD)
    except Exception as e:
        emit(f"  post-success reset: {e!r}")
    return "ok"


def load_manifest(manifest_path: str) -> list[str] | None:
    if not os.path.isfile(manifest_path):
        return None
    names: list[str] = []
    with open(manifest_path, encoding="utf-8") as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if not line or line.startswith("#"):
                continue
            token = line.split()[0]
            if token.endswith(".rwd"):
                names.append(token)
    return names if names else None


def discover_variants(rwd_dir: str, manifest: str | None) -> list[str]:
    if manifest:
        path = manifest if os.path.isabs(manifest) else os.path.join(rwd_dir, manifest)
        names = load_manifest(path)
        if names:
            return names
    # MANIFEST.txt in rwd-dir
    for candidate in (
        os.path.join(rwd_dir, "MANIFEST.txt"),
        os.path.join(_HERE, "rwd_zstart_sweep", "bruteforce", "MANIFEST.txt"),
    ):
        names = load_manifest(candidate)
        if names:
            return names
    # All bf_*.rwd sorted
    bf: list[str] = []
    for base in (rwd_dir, _HERE, os.path.join(_HERE, "rwd_zstart_sweep", "bruteforce")):
        if not os.path.isdir(base):
            continue
        for fn in sorted(os.listdir(base)):
            if fn.startswith("bf_") and fn.endswith(".rwd"):
                bf.append(fn)
        if bf:
            return bf
    return DEFAULT_VARIANTS


def resolve_rwd(path: str, rwd_dir: str) -> str | None:
    candidates = [
        path,
        os.path.join(rwd_dir, path),
        os.path.join(_HERE, path),
        os.path.join(_HERE, "rwd_zstart_sweep", path),
        os.path.join(_HERE, "rwd_zstart_sweep", "bruteforce", path),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--bus", type=int, required=True, help="CAN bus (e.g. 1)")
    p.add_argument(
        "--danger",
        action="store_true",
        help="Required: allow erase/flash/reset (mutating UDS)",
    )
    p.add_argument(
        "--rwd-dir",
        default=".",
        help="Directory containing .rwd variants (default: current dir; also searches rwd_zstart_sweep/)",
    )
    p.add_argument(
        "--variants",
        nargs="*",
        default=None,
        help="RWD filenames to try (default: built-in ordered list)",
    )
    p.add_argument(
        "--manifest",
        default=None,
        help="MANIFEST.txt path (default: auto-detect MANIFEST.txt in --rwd-dir)",
    )
    p.add_argument("--skip-dependency", action="store_true", help="Stop after transfer exit (debug)")
    p.add_argument("--skip-missing", action="store_true", default=True, help="Skip missing RWD files")
    p.add_argument(
        "--pause",
        type=float,
        default=5.0,
        help="Extra seconds to wait after recover (default: 5)",
    )
    p.add_argument(
        "--recover-wait",
        type=float,
        default=15.0,
        help="Seconds to wait after ecuReset before next attempt (default: 15)",
    )
    p.add_argument(
        "--f181-retries",
        type=int,
        default=8,
        help="F181 read retries per attempt after session setup (default: 8)",
    )
    p.add_argument(
        "--no-recover",
        action="store_true",
        help="Do not hard-reset between failed variants (not recommended)",
    )
    p.add_argument(
        "--start-at",
        type=int,
        default=1,
        metavar="N",
        help="Start at variant N in the list (1-based, for resume after crash)",
    )
    p.add_argument("--out", default=DEFAULT_LOG, help="Log file path")
    args = p.parse_args()

    if not args.danger:
        print("Refusing to run without --danger (this script erases and flashes the EPS).", file=sys.stderr)
        return 2

    variants = args.variants if args.variants else discover_variants(args.rwd_dir, args.manifest)
    log = open(args.out, "w", buffering=1)

    def emit(msg: str) -> None:
        print(msg)
        log.write(msg + "\n")

    emit("=" * 72)
    emit(f"  EPS FLASH VARIANT SWEEP — TJB RDX  {datetime.now(timezone.utc).isoformat()}")
    emit(f"  bus={args.bus}  rwd_dir={args.rwd_dir}")
    emit(f"  variants={len(variants)}  (from manifest/discovery)")
    emit("=" * 72)

    (
        Panda,
        UdsClient,
        SESSION_TYPE,
        ACCESS_TYPE,
        ROUTINE_CONTROL_TYPE,
        ROUTINE_IDENTIFIER_TYPE,
        DATA_IDENTIFIER_TYPE,
        RESET_TYPE,
        NegativeResponseError,
        uds_module,
    ) = import_uds_stack()

    try:
        panda = Panda(disable_checks=True)
    except Exception as e:
        emit(f"[fatal] no panda: {e}")
        log.close()
        return 2

    panda.can_clear(0xFFFF)
    set_elm327_safety(panda)

    # CAN address from first available RWD
    can_addr = 0x18DA30F1
    for name in variants:
        rp = resolve_rwd(name, args.rwd_dir)
        if rp:
            can_addr = get_can_address(load_x5a(rp))
            break
    emit(f"[setup] CAN 0x{can_addr:08X}  UDS={uds_module}")

    uds = make_uds_client(UdsClient, panda, can_addr, args.bus, uds_module)

    for idx, name in enumerate(variants, 1):
        if idx < args.start_at:
            continue
        rwd_path = resolve_rwd(name, args.rwd_dir)
        emit("")
        emit("-" * 72)
        emit(f"[{idx}/{len(variants)}] {name}")
        if rwd_path is None:
            msg = "  SKIP: file not found"
            emit(msg)
            if not args.skip_missing:
                log.close()
                return 1
            continue

        emit(f"  path: {rwd_path}")
        try:
            fw = load_x5a(rwd_path)
            block = fw.firmware_blocks[0]
            emit(
                f"  Z-block start=0x{block['start']:X} len=0x{block['length']:X}  "
                f"key={fw.keys.hex()}"
            )
            status = flash_one(
                uds,
                fw,
                SESSION_TYPE=SESSION_TYPE,
                ACCESS_TYPE=ACCESS_TYPE,
                ROUTINE_CONTROL_TYPE=ROUTINE_CONTROL_TYPE,
                ROUTINE_IDENTIFIER_TYPE=ROUTINE_IDENTIFIER_TYPE,
                DATA_IDENTIFIER_TYPE=DATA_IDENTIFIER_TYPE,
                RESET_TYPE=RESET_TYPE,
                NegativeResponseError=NegativeResponseError,
                skip_dependency=args.skip_dependency,
                f181_retries=args.f181_retries,
                emit=emit,
            )
        except NegativeResponseError as e:
            emit(f"  ERROR (NRC 0x{e.error_code:02X}): {e}")
            status = "error"
        except Exception as e:
            if is_comm_error(e):
                emit(f"  COMM ERROR: {type(e).__name__}: {e!r}")
            else:
                emit(f"  ERROR:\n{traceback.format_exc()}")
            status = "error"

        if status == "ok":
            emit("")
            emit("=" * 72)
            emit(f"  SUCCESS with {name}")
            emit("=" * 72)
            log.close()
            return 0

        if idx < len(variants):
            if not args.no_recover:
                try:
                    panda, uds = recover_ecu(
                        uds,
                        panda,
                        Panda=Panda,
                        UdsClient=UdsClient,
                        can_addr=can_addr,
                        bus=args.bus,
                        uds_module=uds_module,
                        SESSION_TYPE=SESSION_TYPE,
                        RESET_TYPE=RESET_TYPE,
                        NegativeResponseError=NegativeResponseError,
                        emit=emit,
                        wait_s=args.recover_wait,
                    )
                except Exception as e:
                    emit(f"  recover failed ({e!r}), forcing panda reconnect ...")
                    panda, uds = reconnect_panda(
                        Panda,
                        UdsClient,
                        can_addr=can_addr,
                        bus=args.bus,
                        uds_module=uds_module,
                        emit=emit,
                    )
            if args.pause > 0:
                emit(f"  waiting {args.pause:.0f}s before next variant ...")
                time.sleep(args.pause)

    emit("")
    emit("=" * 72)
    emit("  ALL VARIANTS FAILED (dependency or error on every attempt)")
    emit("=" * 72)
    log.close()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
