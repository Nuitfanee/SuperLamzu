"""Sparse Intel HEX parsing shared by offline build, inspection and verification."""
import struct
from functools import cached_property
from pathlib import Path


class Image:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.mem = {}
        upper = 0
        self.entry = None
        self.records = []
        eof = False
        for lineno, line in enumerate(self.path.read_text("ascii").splitlines(), 1):
            if eof:
                raise ValueError((lineno, "record after EOF"))
            if not line.startswith(":"):
                raise ValueError((lineno, "not Intel HEX"))
            try:
                b = bytes.fromhex(line[1:])
            except ValueError:
                raise ValueError((lineno, "invalid hexadecimal record")) from None
            if len(b) < 5:
                raise ValueError((lineno, "short Intel HEX record"))
            n, lo, typ = b[0], int.from_bytes(b[1:3], "big"), b[3]
            if len(b) != n + 5 or sum(b) & 255:
                raise ValueError((lineno, "length/checksum"))
            lengths = {1: 0, 2: 2, 4: 2, 5: 4}
            if typ in lengths and (n != lengths[typ] or lo != 0):
                raise ValueError((lineno, "invalid control record", typ))
            if typ == 0 and lo + n > 0x10000:
                raise ValueError((lineno, "data crosses 64 KiB record boundary"))
            data = b[4:-1]
            self.records.append((upper + lo, typ, data))
            if typ == 0:
                for i, x in enumerate(data):
                    a = upper + lo + i
                    if a in self.mem:
                        raise ValueError((lineno, "overlap", hex(a)))
                    self.mem[a] = x
            elif typ == 4:
                upper = int.from_bytes(data, "big") << 16
            elif typ == 2:
                upper = int.from_bytes(data, "big") << 4
            elif typ == 5:
                self.entry = int.from_bytes(data, "big")
            elif typ == 1:
                eof = True
            else:
                raise ValueError((lineno, "unsupported record", typ))
        if not eof:
            raise ValueError("missing EOF")
        if not self.mem:
            raise ValueError("HEX contains no data bytes")
        self.base, self.end = min(self.mem), max(self.mem) + 1

    @cached_property
    def data(self):
        # Offline inspection only needs defined bytes. Do not allocate the
        # potentially enormous undefined span of an otherwise tiny sparse HEX.
        return bytes(self.mem.get(a, 255) for a in range(self.base, self.end))

    def get(self, addr, size):
        return self.data[addr - self.base : addr - self.base + size]

    def u32(self, addr):
        return struct.unpack("<I", self.get(addr, 4))[0]
