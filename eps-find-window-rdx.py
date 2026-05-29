"""eps-find-window-rdx.py - find accepted RequestDownload window on TJB RDX EPS.

Probes RequestDownload (0x34) across page-aligned (start, size) combinations on
**39990-TJB-A030** (2019-2021 Acura RDX SH-2A EPS). Same safety contract as
``eps-find-window.py`` (Accord TVA / x31): **never sends TransferData (0x36)**.

Differences from ``eps-find-window.py`` (Accord):
  - 512 KiB map (``FLASH_TOP = 0x80000``), not 1 MiB TVA
  - Decryption key DID ``0xF101`` = ``01 02 03`` (not x31 ``BF 10 9E``)
  - Honda openpilot SA constants (``011101121120``), not ``tva_sa_key``
  - Favored starts from TJB cal layout / rwd_zstart_sweep

Usage
-----
    python eps-find-window-rdx.py --bus 1

    python eps-find-window-rdx.py --bus 1 --start-min 0x4000 --start-max 0x80000

    python eps-find-window-rdx.py --bus 1 --erase-first

    # Load SA + cipher key from a reference .rwd on disk:
    python eps-find-window-rdx.py --bus 1 --reference-rwd tools/rwd_zstart_sweep/39990-TJB-A030-Stock.rwd
"""

from __future__ import annotations

import argparse
import os
import struct
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from tjb_sa_key import TJB_A030_SA_CONST, calculate_honda_session_key, hex_to_sa_const

DEFAULT_ADDR = 0x18DA30F1
# TJB / openpilot eps-update (bin_to_rwd 39990-TJB-A030)
CIPHER_KEY = bytes([0x01, 0x02, 0x03])
FLASH_TOP = 0x80000  # 512 KiB user.bin linear image
PAGE = 0x1000
NRC_OUT_OF_RANGE = 0x31

# Cal layout + rwd_zstart_sweep candidates (most likely first)
TJB_FAVORED_STARTS = [
    0x4000,   # cal file origin / model default
    0x8000,   # flash = file + 0x4000 at cal base
    0x10000,  # eps-update NRC 0x31 workaround
    0xC000,   # TY2/TY3 OEM window style
    0x58000,  # config-A flash bundle
    0x58100,  # first programmed cal (typical stock dump)
    0x5C100,  # first programmed @ flash-mapped
    0x00000,  # image base
]


def parse_x5a_headers(raw: bytes) -> list[list[bytes]]:
    if raw[0:1] != b"\x5a":
        raise ValueError("not a Z-format RWD")
    idx = 3
    headers: list[list[bytes]] = []
    for _ in range(6):
        cnt = raw[idx]
        idx += 1
        vals: list[bytes] = []
        for _ in range(cnt):
            length = raw[idx]
            idx += 1
            vals.append(raw[idx : idx + length])
            idx += length
        headers.append(vals)
    return headers


def sa_const_from_rwd(path: str) -> bytes:
    """Use first security-access record in Z header (one per supported version)."""
    raw = open(path, "rb").read()
    headers = parse_x5a_headers(raw)
    if len(headers) < 5 or not headers[4]:
        raise ValueError(f"no SA keys in RWD header: {path}")
    const = headers[4][0]
    if len(const) != 6:
        raise ValueError(f"unexpected SA key length {len(const)} in {path}")
    return const


def cipher_key_from_rwd(path: str) -> bytes:
    raw = open(path, "rb").read()
    headers = parse_x5a_headers(raw)
    if len(headers) < 6 or not headers[5]:
        raise ValueError(f"no cipher key in RWD header: {path}")
    key = headers[5][0]
    if len(key) != 3:
        raise ValueError(f"unexpected cipher key length {len(key)} in {path}")
    return key


def ordered_starts(start_min: int, start_max: int, page: int) -> list[int]:
    allp = list(range(start_min, start_max, page))
    seq = [s for s in TJB_FAVORED_STARTS if start_min <= s < start_max]
    seq += [s for s in allp if s not in seq]
    return seq


def import_uds_stack():
    """
    openpilot/comma: ``opendbc.car.uds`` (same as eps-update.py).
    Standalone panda tree: ``panda.python.uds``.
    """
    from panda import Panda

    uds_errors: list[str] = []
    for mod in ("opendbc.car.uds", "panda.python.uds"):
        try:
            uds_mod = __import__(mod, fromlist=[
                "UdsClient",
                "SESSION_TYPE",
                "ACCESS_TYPE",
                "DATA_IDENTIFIER_TYPE",
                "ROUTINE_CONTROL_TYPE",
                "ROUTINE_IDENTIFIER_TYPE",
                "NegativeResponseError",
            ])
            return (
                Panda,
                uds_mod.UdsClient,
                uds_mod.SESSION_TYPE,
                uds_mod.ACCESS_TYPE,
                uds_mod.DATA_IDENTIFIER_TYPE,
                uds_mod.ROUTINE_CONTROL_TYPE,
                uds_mod.ROUTINE_IDENTIFIER_TYPE,
                uds_mod.NegativeResponseError,
                mod,
            )
        except ImportError as e:
            uds_errors.append(f"{mod}: {e}")
    raise ImportError(
        "Could not import UDS client. Tried:\n  " + "\n  ".join(uds_errors)
    )


def set_elm327_safety(panda) -> None:
    try:
        from opendbc.car.structs import CarParams
        panda.set_safety_mode(CarParams.SafetyModel.elm327)
        return
    except ImportError:
        pass
    if not hasattr(panda, "SAFETY_ELM327"):
        # Panda.SAFETY_ELM327 = 3 on older bindings
        from panda import Panda as PandaCls
        if hasattr(PandaCls, "SAFETY_ELM327"):
            panda.set_safety_mode(PandaCls.SAFETY_ELM327)
            return
    panda.set_safety_mode(3)


def make_uds_client(UdsClient, panda, addr: int, bus: int, debug: bool, uds_module: str):
    """``opendbc.car.uds.UdsClient`` (openpilot) has no ``debug=`` kwarg; legacy panda.python.uds does."""
    if uds_module == "opendbc.car.uds":
        return UdsClient(panda, addr, bus=bus)
    return UdsClient(panda, addr, debug=debug, bus=bus)


def main() -> int:
    p = argparse.ArgumentParser(
        description="Find TJB RDX EPS bootloader accepted download window (no 0x36)"
    )
    p.add_argument("--bus", type=int, required=True)
    p.add_argument("--addr", type=lambda s: int(s, 0), default=DEFAULT_ADDR)
    p.add_argument("--page", type=lambda s: int(s, 0), default=PAGE)
    p.add_argument("--start-min", type=lambda s: int(s, 0), default=0x00000)
    p.add_argument("--start-max", type=lambda s: int(s, 0), default=FLASH_TOP)
    p.add_argument(
        "--flash-top",
        type=lambda s: int(s, 0),
        default=FLASH_TOP,
        help="Upper bound for full-size probe (default 0x80000)",
    )
    p.add_argument(
        "--erase-first",
        action="store_true",
        help="issue eraseMemory(0xFF00) before probing",
    )
    p.add_argument(
        "--sa-const",
        default=None,
        metavar="HEX",
        help="6-byte SA constant as hex (default TJB A030 011101121120)",
    )
    p.add_argument(
        "--reference-rwd",
        default=None,
        help="Optional .rwd to read SA const + cipher key from Z header",
    )
    p.add_argument(
        "--out",
        default=os.path.join(_HERE, "eps-window-scan-results-rdx.txt"),
    )
    p.add_argument("--debug", action="store_true")
    args = p.parse_args()

    sa_const = TJB_A030_SA_CONST
    cipher_key = CIPHER_KEY
    if args.reference_rwd:
        sa_const = sa_const_from_rwd(args.reference_rwd)
        cipher_key = cipher_key_from_rwd(args.reference_rwd)
    if args.sa_const is not None:
        sa_const = hex_to_sa_const(args.sa_const)

    log = open(args.out, "w", buffering=1)

    def emit(msg: str) -> None:
        print(msg)
        log.write(msg + "\n")

    emit("=" * 70)
    emit("  EPS DOWNLOAD-WINDOW FINDER — TJB RDX (39990-TJB-A030)")
    emit("  Issues 0x34/0x37 only; NEVER 0x36 (no flash write)")
    emit(f"  addr=0x{args.addr:08X} bus={args.bus} page=0x{args.page:X} "
         f"flash_top=0x{args.flash_top:X} erase_first={args.erase_first}")
    emit(f"  start range [0x{args.start_min:X}, 0x{args.start_max:X})")
    emit(f"  SA const={sa_const.hex().upper()}  cipher={cipher_key.hex().upper()}")
    emit("=" * 70)

    try:
        (
            Panda,
            UdsClient,
            SESSION_TYPE,
            ACCESS_TYPE,
            DATA_IDENTIFIER_TYPE,
            ROUTINE_CONTROL_TYPE,
            ROUTINE_IDENTIFIER_TYPE,
            NegativeResponseError,
            uds_module,
        ) = import_uds_stack()
    except ImportError as e:
        emit(f"[fatal] {e}")
        log.close()
        return 2
    emit(f"[setup] UDS module: {uds_module}")

    try:
        panda = Panda(disable_checks=True)
    except Exception as e:
        emit(f"[fatal] no real panda ({type(e).__name__}: {e}); refusing to mock.")
        log.close()
        return 2
    panda.can_clear(0xFFFF)
    set_elm327_safety(panda)
    uds = make_uds_client(UdsClient, panda, args.addr, args.bus, args.debug, uds_module)

    try:
        uds.tester_present()
        app_id = uds.read_data_by_identifier(
            DATA_IDENTIFIER_TYPE.APPLICATION_SOFTWARE_IDENTIFICATION
        )
        emit(f"[setup] app id (0xF181) = {app_id!r}")
        uds.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
        seed = uds.security_access(ACCESS_TYPE.REQUEST_SEED)[-2:]
        key = calculate_honda_session_key(sa_const, seed)
        uds.security_access(ACCESS_TYPE.SEND_KEY, key)
        emit(f"[setup] SA ok (seed 0x{seed.hex().upper()} -> key 0x{key.hex().upper()})")
        uds.diagnostic_session_control(SESSION_TYPE.PROGRAMMING)
        uds.tester_present()
        if args.erase_first:
            emit("[setup] --erase-first: issuing eraseMemory(0xFF00)")
            uds.routine_control(
                ROUTINE_CONTROL_TYPE.START, ROUTINE_IDENTIFIER_TYPE.ERASE_MEMORY
            )
            uds.tester_present()
        uds.write_data_by_identifier(DATA_IDENTIFIER_TYPE.FLASH_DECRYPTION_KEY, cipher_key)
        emit(f"[setup] wrote decryption key {cipher_key.hex().upper()}")
    except NegativeResponseError as e:
        emit(
            f"[fatal] setup failed: {e} (NRC 0x{e.error_code:02X}). "
            "If conditionsNotCorrect (0x22), retry --erase-first."
        )
        log.close()
        return 3

    def try_download(start: int, size: int):
        try:
            max_chunk = uds.request_download(start, size)
            try:
                uds.request_transfer_exit()
            except NegativeResponseError:
                pass
            return ("ok", max_chunk)
        except NegativeResponseError as e:
            return ("nrc", e.error_code)

    starts = ordered_starts(args.start_min, args.start_max, args.page)
    emit(f"[scan] probing {len(starts)} page-aligned starts...")
    found = None
    nrc_hist: dict[int, int] = {}
    t0 = time.time()

    for i, start in enumerate(starts):
        remaining = min(args.flash_top, args.start_max) - start
        if remaining <= 0:
            continue
        res_full = try_download(start, remaining)
        if res_full[0] == "ok":
            emit(
                f"[FOUND] start=0x{start:X} accepts FULL size=0x{remaining:X} "
                f"(max_chunk=0x{res_full[1]:X})"
            )
            found = (start, start + remaining, remaining, res_full[1])
            break
        res_page = try_download(start, args.page)
        if res_page[0] == "ok":
            emit(f"[hit]   start=0x{start:X} accepts 0x{args.page:X}; binary-searching max size")
            lo_pages = 1
            hi_pages = remaining // args.page
            best = args.page
            best_chunk = res_page[1]
            while lo_pages + 1 < hi_pages:
                mid = (lo_pages + hi_pages) // 2
                size = mid * args.page
                r = try_download(start, size)
                if r[0] == "ok":
                    lo_pages, best, best_chunk = mid, size, r[1]
                else:
                    hi_pages = mid
                    nrc_hist[r[1]] = nrc_hist.get(r[1], 0) + 1
            emit(
                f"[FOUND] start=0x{start:X} max size=0x{best:X} "
                f"-> [0x{start:X}, 0x{start + best:X}) (max_chunk=0x{best_chunk:X})"
            )
            found = (start, start + best, best, best_chunk)
            break
        code = res_full[1]
        nrc_hist[code] = nrc_hist.get(code, 0) + 1
        if i < 8 or code != NRC_OUT_OF_RANGE:
            emit(f"[scan]  start=0x{start:08X}: rejected NRC 0x{code:02X}")
        if i % 32 == 31:
            uds.tester_present()
            emit(
                f"[scan]  ...{i + 1}/{len(starts)} starts ({time.time() - t0:.0f}s) "
                f"NRC: { {hex(k): v for k, v in nrc_hist.items()} }"
            )

    emit("=" * 70)
    if found:
        start, end, size, chunk = found
        emit("  RESULT: ACCEPTED WINDOW FOUND")
        emit(f"    start = 0x{start:X}")
        emit(f"    end   = 0x{end:X}  (size 0x{size:X}, {size} bytes)")
        emit(f"    ECU max transfer chunk = 0x{chunk:X}")
        emit("  No flash written (no 0x36 sent).")
        emit("  Build matching RWD with bin_to_rwd.py / tools/build_stock_rwd_zstart_sweep.py:")
        emit(f"    --rwd-x5a-start 0x{start:X} --payload-length 0x{size:X}")
        emit("  For brick recovery (cal+tail), also try:")
        emit("    python tools/build_rwd_flash_4000_7ffff.py --encrypt-backend panda")
        if size == 0x6C000 and start == 0x4000:
            emit("  -> matches stock cal-only TJB layout")
        elif size == 0x7C000 and start == 0x4000:
            emit("  -> matches wide flash 0x4000..0x7FFFF layout")
    else:
        emit("  RESULT: NO accepted window in scanned range.")
        emit(f"    NRC histogram: { {hex(k): v for k, v in nrc_hist.items()} }")
        emit("  All 0x31 -> try other starts or programming session / erase state.")
        emit("  All 0x22 -> retry --erase-first.")
    emit("=" * 70)
    emit(f"  {len(starts)} starts in {time.time() - t0:.0f}s -> {args.out}")
    log.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
