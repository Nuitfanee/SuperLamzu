"""Read-only LAMZU APP queries and offline sparse HEX inspection.

Firmware installation and stock recovery use the matching executable in flasher/.
"""
import argparse
import json
import sys
from pathlib import Path

from . import target


def inspect_image(path):
    # Sparse parsing needs only the standard library; no assembler, emulation or HID.
    from .hexfile import Image
    image = Image(Path(path))
    mem = image.mem
    if not mem:
        raise ValueError("HEX contains no data bytes")
    addresses = sorted(mem)
    start = previous = addresses[0]
    ranges = []
    for addr in addresses[1:]:
        if addr != previous + 1:
            ranges.append((start, previous + 1))
            start = addr
        previous = addr
    ranges.append((start, previous + 1))
    low, end = addresses[0], addresses[-1] + 1
    vectors = bytes(mem[a] for a in range(low, low + 8)) if all(a in mem for a in range(low, low + 8)) else None
    sp = int.from_bytes(vectors[:4], "little") if vectors else None
    reset = int.from_bytes(vectors[4:], "little") if vectors else None
    vectors_match = (low, sp, reset) == (target.BASE, target.SP, target.RESET)
    target_matches = vectors_match and end - low == target.SPAN
    return {"path": str(Path(path).resolve()), "base": low, "end": end,
            "span_bytes": end - low, "data_bytes": len(mem),
            "gap_bytes": end - low - len(mem), "data_ranges": ranges,
            "initial_sp": sp, "reset_vector": reset,
            "target_vectors_match": vectors_match,
            "flash_available": False, "bootloader_protocol_verified": target_matches,
            "write_entry_point": "flasher/SuperLAMZU THORN V2-0.1.0-windows-x64.exe" if target_matches else None,
            "verified_bootloader": "b0.00.05.01 (37B0:0041)" if target_matches else None,
            "erase_supported": False}


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m superlamzu fw", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for command in ("inspect", "dry-run"):
        p = sub.add_parser(command, help="offline sparse HEX inspection; no USB access or writes")
        p.add_argument("file", type=Path)
        p.add_argument("--json", action="store_true")
    sub.add_parser("receiver-info", help="offline Thorn Receiver B two-core inventory and checked hook preimages")
    for command in ("list", "info"):
        p = sub.add_parser(command, help="read-only APP access; does not enter/query bootloader")
        p.add_argument("--backend", choices=("auto", "hidraw", "hidapi"))
        if command == "info":
            p.add_argument("--node")
    a = ap.parse_args(argv)
    if a.cmd == "receiver-info":
        from .receiver import inventory
        try:
            print(json.dumps(inventory(), indent=2))
        except (OSError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        return 0
    if a.cmd in ("list", "info"):
        from . import cfg
        options = (["--backend", a.backend] if a.backend else [])
        if getattr(a, "node", None):
            options += ["--node", a.node]
        return cfg.main([*options, a.cmd])
    try:
        report = inspect_image(a.file)
    except (OSError, ValueError, IndexError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if a.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"{report['path']}\n"
              f"address range: 0x{report['base']:08X}..0x{report['end'] - 1:08X}\n"
              f"data: {report['data_bytes']} bytes; span: {report['span_bytes']} bytes; "
              f"undefined gaps: {report['gap_bytes']} bytes\n"
              f"LAMZU vector match: {report['target_vectors_match']}\n"
              "Sparse gaps are undefined, not padded. Offline inspection only; flash/dump/erase unavailable.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
