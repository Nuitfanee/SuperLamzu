"""Offline Thumb execution helpers. SPI and external services are explicit stubs.

These checks execute firmware instructions; physical peripherals and the stock
MPU are not implicitly emulated. Protection checks are added by snapshot tests.
"""
import gc
import struct
from dataclasses import dataclass

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_MCLASS, UC_HOOK_CODE
import unicorn.arm_const as C
from unicorn.arm_const import (
    UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
    UC_ARM_REG_R12, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC,
)

from . import target as T
from .hexfile import Image


@dataclass(frozen=True)
class MemoryLayout:
    """Explicit target fixture; mapped emulator RAM is not an ownership proof."""
    ram_regions: tuple
    stack: int
    stop: int
    copies: tuple = ()
    delays: tuple = ()
    site_exclusions: tuple = ()


THORN_LAYOUT = MemoryLayout(
    ram_regions=((0x23000000, 0x40000),), stack=0x23030000, stop=0x2303F000,
    copies=((T.RAM_SRC, T.RAM_RUN, T.RAM_LEN),
            (T.RAM_DATA_SRC, T.RAM_DATA_RUN, T.RAM_DATA_LEN)),
    delays=(0x0E086F46,), site_exclusions=((0x23005618, 0x23005840),))


def _load_memory(uc, image, layout, mapped):
    base = image.base & ~0xFFF
    end = (image.end + 0xFFF) & ~0xFFF
    uc.mem_map(base, end - base)
    uc.mem_write(image.base, image.data)
    for start, size in layout.ram_regions:
        uc.mem_map(start, size)
    if mapped:
        for source, destination, size in layout.copies:
            uc.mem_write(destination, image.get(source, size))


class Arm:
    def __init__(self, image=None, *, layout=THORN_LAYOUT):
        self.image = Image(T.STOCK) if image is None else image
        self.layout = layout
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
        _load_memory(self.uc, self.image, layout, True)
        self.stubs = {}
        self.calls = []
        self.stop = layout.stop
        self.ends = set()
        self._hooks = []
        self.add_hook(UC_HOOK_CODE, self._hook)

    def add_hook(self, kind, callback, **options):
        """Own every callback so a verification case can release its engine."""
        handle = self.uc.hook_add(kind, callback, **options)
        self._hooks.append(handle)
        return handle

    def close(self):
        if self.uc is None:
            return
        for handle in self._hooks:
            self.uc.hook_del(handle)
        self._hooks.clear()
        self.stubs.clear()
        self.uc = None
        # ctypes callback objects can retain the Uc engine even after hook_del.
        # Native allocations are invisible to Python's GC thresholds. Collect
        # at the actual ownership boundary, not after later HEX allocations fail.
        gc.collect()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.close()

    def reg(self, name):
        return self.uc.reg_read(getattr(C, "UC_ARM_REG_" + name.upper()))

    def setreg(self, name, value):
        self.uc.reg_write(getattr(C, "UC_ARM_REG_" + name.upper()), value)

    def byte(self, addr):
        return self.uc.mem_read(addr, 1)[0]

    def u32(self, addr):
        return struct.unpack("<I", self.uc.mem_read(addr, 4))[0]

    def put32(self, addr, value):
        self.uc.mem_write(addr, struct.pack("<I", value & 0xFFFFFFFF))

    def stub(self, addr, value=0, effect=None):
        self.stubs[addr] = (value, effect)

    def _hook(self, uc, addr, size, _):
        if addr in self.ends:
            uc.emu_stop()
            return
        if addr not in self.stubs:
            return
        self.calls.append((addr, self.reg("r0"), self.reg("r1")))
        value, effect = self.stubs[addr]
        if effect:
            result = effect(self)
            if result is not None:
                value = result
        self.setreg("r0", value)
        self.setreg("pc", self.reg("lr"))

    def run(self, entry, *args, count=20000):
        self.setreg("sp", self.layout.stack)
        self.setreg("lr", self.stop | 1)
        for k, value in enumerate(args):
            self.setreg(f"r{k}", value)
        self.uc.emu_start(entry | 1, self.stop, count=count)
        if self.reg("pc") != self.stop and self.reg("pc") not in self.ends:
            raise AssertionError(f"instruction limit, PC={self.reg('pc'):#x}")
        return self.reg("r0")

    def preempt(self, first, second, at, nth=1):
        """Reuse dev's stop/context/second-stack/resume instruction interleave.

        Both calls are (entry, args). The caller selects a real unmasked
        instruction boundary; this helper does not model NVIC priorities.
        Memory changes survive the interrupt, register/stack context does not.
        """
        from unicorn.arm_const import UC_ARM_REG_PRIMASK
        if at in self.stubs:
            raise ValueError('preempt at a real callsite, before its service stub')
        seen = 0
        interrupted = False

        def hit(uc, address, size, user):
            nonlocal seen, interrupted
            seen += 1
            if seen == nth:
                interrupted = True
                uc.emu_stop()

        handle = self.uc.hook_add(UC_HOOK_CODE, hit, begin=at, end=at)
        entry, args = first
        self.setreg('sp', self.layout.stack)
        self.setreg('lr', self.stop | 1)
        for index, value in enumerate(args):
            self.setreg(f'r{index}', value)
        try:
            self.uc.emu_start(entry | 1, self.stop, count=100000)
        finally:
            self.uc.hook_del(handle)
        if not interrupted:
            assert self.reg('pc') == self.stop, 'first call exceeded instruction budget'
            return False
        assert not self.uc.reg_read(UC_ARM_REG_PRIMASK), 'cannot preempt a masked IRQ boundary'
        context = self.uc.context_save()
        resume = self.reg('pc')
        entry, args = second
        self.setreg('sp', self.layout.stack - 0x8000)
        self.setreg('lr', self.stop | 1)
        for index, value in enumerate(args):
            self.setreg(f'r{index}', value)
        try:
            self.uc.emu_start(entry | 1, self.stop, count=100000)
            assert self.reg('pc') == self.stop, 'interrupt exceeded instruction budget'
        finally:
            self.uc.context_restore(context)
        self.uc.emu_start(resume | 1, self.stop, count=100000)
        assert self.reg('pc') == self.stop, 'resumed call exceeded instruction budget'
        return True


def sensor_run(image, entry, wr, rd, rd_value=0xA5, args=(), mapped=False, *, layout=THORN_LAYOUT):
    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
    _load_memory(uc, image, layout, mapped)
    write_sites = {wr} if isinstance(wr, int) else set(wr)
    read_sites = {rd} if isinstance(rd, int) else set(rd)
    stop = layout.stop
    uc.reg_write(UC_ARM_REG_SP, layout.stack)
    uc.reg_write(UC_ARM_REG_LR, stop | 1)
    for r, arg in zip((UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2), args):
        uc.reg_write(r, arg)
    state = {"page": 0, "last_site": entry}
    log = []

    def hook(u, addr, size, _):
        r, v = u.reg_read(UC_ARM_REG_R0), u.reg_read(UC_ARM_REG_R1)
        if addr in write_sites:
            r, v = r & 255, v & 255
            if r == 0x7F:
                state["page"] = v
            log.append({"site": f"0x{state['last_site']:08X}",
                        "op": "write", "page": state["page"], "reg": r, "value": v})
        elif addr in read_sites:
            u.mem_write(v, bytes([rd_value]))
            log.append({"site": f"0x{state['last_site']:08X}",
                        "op": "read", "page": state["page"], "reg": r & 255, "value": rd_value})
        elif mapped and addr in layout.delays:
            # Vendor delay helper. Timing is irrelevant to the ordered SPI log.
            pass
        else:
            # Keep the true call/branch site, including tail branches. LR-4
            # would incorrectly point at the test return sentinel for tail calls.
            if not (mapped and any(lo <= addr < hi for lo, hi in layout.site_exclusions)):
                state["last_site"] = addr
            return
        for reg, value in [(UC_ARM_REG_R0, 1), (UC_ARM_REG_R1, 0xDEADBEEF),
                           (UC_ARM_REG_R2, 0xCAFEF00D), (UC_ARM_REG_R3, 0xBAD),
                           (UC_ARM_REG_R12, 0x12121212)]:
            u.reg_write(reg, value)
        u.reg_write(UC_ARM_REG_PC, u.reg_read(UC_ARM_REG_LR))

    handle = uc.hook_add(UC_HOOK_CODE, hook)
    try:
        uc.emu_start(entry | 1, stop, count=200000)
        if uc.reg_read(UC_ARM_REG_PC) != stop:
            raise RuntimeError(f"recipe did not return: {entry:#x}")
    finally:
        uc.hook_del(handle)
        uc = None
        gc.collect()
    return log
