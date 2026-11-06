"""Guarded sparse Intel HEX editing and Thumb assembly for the exact target."""
from pathlib import Path

from . import target as T

from .hexfile import Image


def assemble(source, address):
    import re
    from collections import Counter
    from keystone import Ks, KS_ARCH_ARM, KS_MODE_THUMB, KS_MODE_LITTLE_ENDIAN
    if not isinstance(source, str):
        source = "\n".join(source)
    data, _ = Ks(KS_ARCH_ARM, KS_MODE_THUMB | KS_MODE_LITTLE_ENDIAN).asm(source, addr=address)
    if data is None:
        raise ValueError(f"assembly returned no bytes at {address:#x}: {source}")
    data = bytes(data)
    # Fixed dev applies this guard too: Keystone can widen a forward label
    # branch without re-resolving an earlier absolute BL/B.W operand. Reject
    # the resulting +2 target rather than emit an untested instruction entry.
    wanted = Counter(int(m.group(1), 0) & ~1 for m in re.finditer(
        r"(?im)^\s*b(?:l|\.w)\s+#(0x[0-9a-f]+|[0-9]+)\s*$", source))
    if wanted:
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
        decoded = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS).disasm(data, address)
        actual = Counter(int(i.op_str[1:], 0) & ~1 for i in decoded
                         if i.mnemonic in ('bl', 'b.w') and i.op_str.startswith('#'))
        missing = wanted - actual
        if missing:
            raise ValueError(f"assembler changed absolute branch targets at {address:#x}: "
                             f"{[hex(v) for v in missing]}; use explicit wide label branches")
    return data


def literal_addresses(source):
    """Share immutable address constants within a generated Thumb helper."""
    import re
    source = source.splitlines() if isinstance(source, str) else list(source)
    result, index = [], 0
    while index < len(source):
        low = re.fullmatch(r'movw (\w+),#(\d+)', source[index])
        high = (re.fullmatch(r'movt (\w+),#(\d+)', source[index + 1])
                if index + 1 < len(source) else None)
        if low and high and low[1] == high[1]:
            result.append(f'ldr {low[1]},={int(low[2]) | int(high[2]) << 16:#x}')
            index += 2
        else:
            result.append(source[index])
            index += 1
    return result + ['.ltorg']


class Builder:
    def __init__(self, source=T.STOCK, *, target=T):
        self.target = target
        self.source = Path(source).resolve()
        self.image = Image(self.source)
        expected = Image(target.STOCK)
        if self.image.mem != expected.mem or self.image.entry != expected.entry:
            raise ValueError(f"input is not the supplied {getattr(target, 'NAME', 'LAMZU 00.00.01.16')} image")
        if self.image.base != target.BASE or len(self.image.data) != target.SPAN:
            raise ValueError("unexpected firmware address span")
        if self.image.u32(target.BASE) != target.SP or self.image.u32(target.BASE + 4) != target.RESET:
            raise ValueError("unexpected target vectors")
        self.changes = {}
        self.reasons = {}
        self.pools = []
        self.allocations = []
        self.symbols = {}

    def edit(self, address, data, reason):
        address = getattr(self, 'target', T).flash_source(address)
        for i, value in enumerate(bytes(data)):
            a = address + i
            if a not in self.image.mem:
                raise ValueError(f"cannot write unowned HEX gap {a:#x}")
            if a in self.changes and self.changes[a] != value:
                raise ValueError(f"conflicting edits at {a:#x}: {self.reasons[a]} / {reason}")
            if value != self.image.mem[a]:
                self.changes[a] = value
                self.reasons[a] = reason

    def add_pool(self, start, end):
        if any(not (end <= a or start >= b) for a, b in self.pools):
            raise ValueError("overlapping pools")
        self.pools.append((start, end))
        self.pools.sort()

    def alloc(self, name, data_bytes, alignment=2):
        if name in self.symbols:
            raise ValueError(f"duplicate symbol {name}")
        data_bytes = bytes(data_bytes)
        for i, (a, end) in enumerate(self.pools):
            start = (a + alignment - 1) & -alignment
            if start + len(data_bytes) <= end:
                self.edit(start, data_bytes, name)
                self.pools[i] = (start + len(data_bytes), end)
                self.symbols[name] = start
                self.allocations.append(dict(name=name, address=f"0x{start:08X}", bytes=len(data_bytes)))
                return start
        raise ValueError(f"no proven pool fits {name} ({len(data_bytes)} bytes)")

    def code(self, name, source):
        if name in self.symbols:
            raise ValueError(f"duplicate symbol {name}")
        if not isinstance(source, str):
            source = list(source)
        compact = literal_addresses(source)
        for i, (a, end) in enumerate(self.pools):
            a = (a + 1) & ~1
            data = assemble(source, a)
            compressed = assemble(compact, a)
            if len(compressed) < len(data):
                data = compressed
            if a + len(data) <= end:
                self.edit(a, data, name)
                self.pools[i] = (a + len(data), end)
                self.symbols[name] = a
                self.allocations.append(dict(name=name, address=f"0x{a:08X}", bytes=len(data)))
                return a
        raise ValueError(f"no proven code pool fits {name}")

    def bl(self, runtime_callsite, target, reason):
        old = self.image.get(getattr(self, 'target', T).flash_source(runtime_callsite), 4)
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
        ins = next(Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS).disasm(old, runtime_callsite), None)
        if ins is None or ins.mnemonic not in ("bl", "blx"):
            raise ValueError(f"not a call at {runtime_callsite:#x}")
        data = assemble(f"bl #{target:#x}", runtime_callsite)
        if len(data) != 4:
            raise ValueError("call size changed")
        decoded = next(Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS).disasm(data, runtime_callsite))
        if int(decoded.op_str.lstrip('#'), 0) != target & ~1:
            raise ValueError(f"Thumb BL target out of range: {runtime_callsite:#x}->{target:#x}")
        self.edit(runtime_callsite, data, reason)

    def branch(self, runtime_entry, target, reason):
        data = assemble(f"b.w #{target:#x}", runtime_entry)
        if len(data) != 4:
            raise ValueError("branch size changed")
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
        decoded = next(Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS).disasm(data, runtime_entry))
        if int(decoded.op_str.lstrip('#'), 0) != target & ~1:
            raise ValueError(f"Thumb B target out of range: {runtime_entry:#x}->{target:#x}")
        self.edit(runtime_entry, data, reason)

    def output_image(self):
        data = bytearray(self.image.data)
        for a, v in self.changes.items():
            data[a - self.image.base] = v
        return bytes(data)

    def write(self, destination):
        destination = Path(destination).resolve()
        target = getattr(self, 'target', T)
        protected = {self.source, T.STOCK.resolve(), target.STOCK.resolve()}
        protected.update(Path(p).resolve() for p in getattr(target, 'PROTECTED_SOURCES', ()))
        if destination in protected:
            raise ValueError("refusing to overwrite original firmware")
        lines, upper, touched = [], 0, set()
        for line in self.source.read_bytes().splitlines(keepends=True):
            body = line.rstrip(b"\r\n")
            term = line[len(body):]
            record = bytearray.fromhex(body[1:].decode("ascii"))
            n, lo, kind = record[0], int.from_bytes(record[1:3], "big"), record[3]
            if kind == 4:
                upper = int.from_bytes(record[4:-1], "big") << 16
            elif kind == 2:
                upper = int.from_bytes(record[4:-1], "big") << 4
            elif kind == 0:
                changed = False
                for i in range(n):
                    a = upper + lo + i
                    if a in self.changes:
                        record[4 + i] = self.changes[a]
                        touched.add(a)
                        changed = True
                if changed:
                    record[-1] = -sum(record[:-1]) & 255
                    rendered = record.hex()
                    if body == body.upper():
                        rendered = rendered.upper()
                    line = b":" + rendered.encode("ascii") + term
            lines.append(line)
        if touched != set(self.changes):
            raise ValueError("not all patches found in source data records")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(b"".join(lines))
        check = Image(destination)
        wanted = dict(self.image.mem)
        wanted.update(self.changes)
        if check.mem != wanted or check.entry != self.image.entry:
            raise AssertionError("written HEX differs from requested sparse edits")
        return destination

    def manifest(self, profile):
        target = getattr(self, 'target', T)
        return dict(target=getattr(target, 'NAME', 'LAMZU Thorn V2 00.00.01.16'), profile=profile,
                    source=str(self.source), base=hex(target.BASE), span=target.SPAN,
                    changed_bytes=len(self.changes), allocations=self.allocations,
                    symbols={k:hex(v) for k,v in self.symbols.items()},
                    edits=[dict(address=hex(a), old=self.image.mem[a], new=v,
                                reason=self.reasons[a]) for a,v in sorted(self.changes.items())])
