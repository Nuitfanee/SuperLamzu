"""Focused real-Thumb clock ownership checks; hardware transitions are explicit.

The target request/spec resolver, onoff manager, cancel, release and notify code
execute unchanged. Only hardware transition callbacks and scheduler services are
substituted. Tests use owned fixture RAM, never the user's device or calibration.
"""

import struct

from . import native_clock as N, target as T
from .common import assemble
from .verify import arm, patched_image


HEAP, TRANSITIONS = 0x23024000, 0x23026000
START, STOP, RESET, OFF_CALL = 0x23026100, 0x23026120, 0x23026140, 0x23026160


class NativeClockFixture:
    def __init__(self, b, *, state=2, refs=1):
        from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_WRITE
        self.b, self.entries = b, b.native_clock
        self.a = arm(patched_image(b))
        self.a.uc.mem_map(0x53000000, 0x100000)
        self.clock = HEAP + N.OFFSET
        data = b.image.u32(T.NATIVE_CLOCK_DEVICE + 16)
        self.manager = data + 0x40
        self.events = []
        self.callbacks = []
        self.a.uc.mem_write(HEAP, b'\xa5' * T.SNAPSHOT_STORAGE_BYTES)
        self.a.uc.mem_write(self.clock, bytes(N.BYTES))
        self.a.uc.mem_write(T.NATIVE_CLOCK_READY, b'\x01')
        self.a.uc.mem_write(self.manager, bytes(36))
        self.a.put32(self.manager + 16, TRANSITIONS)
        self.a.uc.mem_write(self.manager + 24, struct.pack('<HH', state, refs))
        self.a.uc.mem_write(TRANSITIONS, struct.pack('<III', START | 1, STOP | 1, RESET | 1))
        for address, kind in ((START, 'start'), (STOP, 'stop'), (RESET, 'reset')):
            def transition(a, kind=kind):
                self.events.append((kind, a.reg('r0'), a.reg('r1')))
                self.callbacks.append((a.reg('r1'), a.reg('r0')))
                return 0
            self.a.stub(address, effect=transition)
        self.a.uc.mem_write(OFF_CALL, assemble([
            'push {r4,lr}', f'movw r4,#{HEAP & 65535}', f'movt r4,#{HEAP >> 16}',
            'mov r0,r4', 'movs r1,#0',
            *N._addr('r3', self.entries['intent'] | 1), 'blx r3',
            'mov r0,r4', *N._addr('r3', self.entries['reconcile'] | 1),
            'blx r3', 'pop {r4,pc}',
        ], OFF_CALL))
        self.instructions = 0
        self.executed = set()
        self.writes = []
        self.lowest_sp = self.a.layout.stack
        def trace(uc, address, size, user):
            self.instructions += 1
            self.executed.add(address)
            sp = self.a.reg('sp')
            if self.a.layout.stack - 0x1000 <= sp <= self.a.layout.stack:
                self.lowest_sp = min(self.lowest_sp, sp)
        self.a.add_hook(UC_HOOK_CODE, trace)
        def write(uc, access, address, size, value, user):
            self.writes.append((address, size, value))
            allowed = ((self.clock, self.clock + N.BYTES),
                       (self.manager, self.manager + 36),
                       (self.a.layout.stack - 0x1000, self.a.layout.stack),
                       (self.a.layout.stack - 0x9000, self.a.layout.stack - 0x8000))
            assert any(lo <= address and address + size <= hi for lo, hi in allowed), hex(address)
        self.write_guard = self.a.add_hook(UC_HOOK_MEM_WRITE, write)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.a.close()

    def call(self, name, *args):
        return self.a.run(self.entries[name], HEAP, *args, count=100000)

    def complete(self, result=0):
        callback, manager = self.callbacks.pop(0)
        return self.a.run(callback, manager, result & 0xffffffff, count=100000)

    def phase(self):
        return self.a.byte(self.clock + N.PHASE)

    def flags(self):
        return self.a.byte(self.clock + N.FLAGS)

    def refs(self):
        return int.from_bytes(self.a.uc.mem_read(self.manager + 26, 2), 'little')

    def error(self):
        return int.from_bytes(self.a.uc.mem_read(self.clock + N.ERROR, 2), 'little', signed=True)


class IntegratedClockFixture(NativeClockFixture):
    """Production wrappers plus native timer bodies and the native clock core."""
    def __init__(self, b, **kwargs):
        from unicorn import UC_HOOK_MEM_WRITE
        super().__init__(b, **kwargs)
        self.a.uc.hook_del(self.write_guard)
        self.a._hooks.remove(self.write_guard)
        self.a.uc.mem_map(0x5f900000, 0x100000)
        self.a.uc.mem_map(0xe000e000, 0x1000)
        self.a.uc.mem_map(T.ADV_STORAGE & ~4095, 4096)
        self.a.uc.mem_write(T.ADV_STORAGE, b'\xff' * T.ADV_STORAGE_BYTES)
        self.a.uc.mem_write(T.SNAPSHOT_POINTER, bytes(3))
        self.a.put32(0x2300a63c, 1)
        for address in (0x0e075150, 0x0e075178, 0x0e075134):
            self.a.stub(address)
        self.allocations = []
        self.allocation_result = HEAP - 4
        def malloc(a):
            self.allocations.append((a.reg('r0'), a.reg('r1')))
            return self.allocation_result
        self.a.stub(0x0e07fad4, effect=malloc)
        self.a.stub(T.SET_SENSOR_MODE)
        # Keep a native HFXO manager reference after the application's OFF.
        hfxo = 0x23009f00
        self.a.uc.mem_write(hfxo, bytes(104))
        self.a.put32(hfxo + 16, TRANSITIONS + 64)
        self.a.uc.mem_write(TRANSITIONS + 64, struct.pack('<III', 0x0e08376f, 0x0e083759, 0))
        self.a.uc.mem_write(hfxo + 24, struct.pack('<HH', 2, 2))
        self.a.put32(0x5301e490, 0x21)
        def write(uc, access, address, size, value, user):
            allowed = ((HEAP - 4, HEAP + T.SNAPSHOT_STORAGE_BYTES),
                       (self.manager, self.manager + 36), (hfxo, hfxo + 104),
                       (0x2300d83b, 0x2300d83b + 7 * 298),
                       (0x2300a63c, 0x2300a640),
                       (T.NATIVE_CLOCK_READY, T.NATIVE_CLOCK_READY + 4),
                       (T.REPORT_TIMER, T.REPORT_TIMER + 0x1000),
                       (0x53000000, 0x53100000), (0xe000e000, 0xe000f000),
                       (self.a.layout.stack - 0x1000, self.a.layout.stack),
                       (self.a.layout.stack - 0x9000, self.a.layout.stack - 0x8000))
            assert any(lo <= address and address + size <= hi for lo, hi in allowed), hex(address)
        self.integration_guard = self.a.add_hook(UC_HOOK_MEM_WRITE, write)

    def queue(self, number=0):
        return self.a.run(self.b.symbols['advanced_queue_init'], number, count=100000)

    def hook(self, name):
        return self.a.run(self.entries[name], count=100000)


def integration_check(b):
    """Exercise each installed BL, queue rebuild, USB and native START/STOP."""
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
    cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS)
    image = patched_image(b)
    for site, name in ((*((site, 'timer_start') for site in T.REPORT_TIMER_INIT_CALLS),
                        (T.REPORT_TIMER_STOP_CALL, 'timer_stop'),
                        (T.HFXO_OFF_CALL, 'hfxo_off'))):
        ins = next(cs.disasm(image.get(site, 4), site))
        assert ins.mnemonic == 'bl' and int(ins.op_str[1:], 0) == b.native_clock[name]
    cases = 4
    with IntegratedClockFixture(b) as f:
        f.hook('timer_start')
        assert not f.allocations and f.refs() == 1 and f.flags() == 0
        assert f.a.byte(T.NATIVE_CLOCK_READY) == 1
        assert f.a.u32(T.REPORT_TIMER + 0x200) == 1
        assert f.a.u32(T.REPORT_TIMER + 0x304) == 0x10000
        assert f.a.u32(T.REPORT_TIMER + 0x508) == 3
        assert f.a.u32(T.REPORT_TIMER + 0x510) == 4
        f.queue()
        assert f.phase() == N.HELD and f.refs() == 2 and len(f.allocations) == 1
        assert f.a.u32(f.clock + N.SPEC) == 0 and f.a.u32(f.clock + N.SPEC + 4) == 30
        client = bytes(f.a.uc.mem_read(f.clock, N.BYTES))
        f.a.uc.mem_write(T.MOTION_STATE, bytes((f.a.byte(T.MOTION_STATE) | 0x70,)))
        f.a.uc.mem_write(HEAP, b'\xa5' * 28)
        f.a.uc.mem_write(HEAP + 308, b'\xa5' * 36)
        f.queue()
        assert bytes(f.a.uc.mem_read(f.clock, N.BYTES)) == client
        assert bytes(f.a.uc.mem_read(T.SNAPSHOT_POINTER, 3)) == struct.pack('<I', HEAP)[:3]
        assert bytes(f.a.uc.mem_read(HEAP, 28)) == b'\1' + bytes(27)
        assert bytes(f.a.uc.mem_read(HEAP + 308, 36)) == bytes(36)
        assert f.refs() == 2 and len(f.allocations) == 1
        for queue in (1, 2, 3):
            before = bytes(f.a.uc.mem_read(HEAP, T.SNAPSHOT_STORAGE_BYTES))
            f.queue(queue)
            assert bytes(f.a.uc.mem_read(HEAP, T.SNAPSHOT_STORAGE_BYTES)) == before
        f.hook('timer_stop')
        assert f.phase() == N.EMPTY and f.refs() == 1 and not f.flags() & N.WANTED
        assert f.a.byte(T.NATIVE_CLOCK_READY) == 0
        assert f.a.u32(T.REPORT_TIMER + 0x200) == 0
        assert f.a.u32(T.REPORT_TIMER + 0x540) == 0
        f.hook('timer_stop')
        assert f.refs() == 1
        f.hook('timer_start')
        assert f.phase() == N.HELD and f.refs() == 2 and len(f.allocations) == 1
        assert f.hook('hfxo_off') == 1
        assert f.phase() == N.EMPTY and f.refs() == 1
        assert f.a.u32(0x5301e490) == 1
        assert 0x0e06d824 in f.executed and 0x0e0837dc in f.executed
        cases += 22
    for snapshot in (False, True):
        with IntegratedClockFixture(b) as f:
            f.a.uc.mem_write(T.NATIVE_CLOCK_READY, b'\0')
            if snapshot:
                assert f.a.run(b.symbols['advanced_snapshot_storage']) == HEAP
            f.hook('timer_start')
            assert f.refs() == 1 and f.flags() == 0
            assert len(f.allocations) == int(snapshot)
            # Snapshot-only USB storage never implies the wireless lifetime.
            f.queue()
            assert f.phase() == N.HELD and f.refs() == 2 and len(f.allocations) == 1
            cases += 3
    with IntegratedClockFixture(b) as f:
        f.allocation_result = 0
        f.queue()
        assert bytes(f.a.uc.mem_read(T.SNAPSHOT_POINTER, 3)) == bytes(3)
        assert f.refs() == 1 and f.flags() == 0
        f.allocation_result = HEAP - 4
        f.queue()
        assert f.phase() == N.HELD and f.refs() == 2
        cases += 2
    return cases


def hook_interleave_check(b):
    """Publish real PM OFF while queue allocation, START or request is active."""
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
    cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS)
    storage = next(v for v in b.allocations if v['name'] == 'advanced_snapshot_storage')
    instructions = cs.disasm(patched_image(b).get(int(storage['address'], 16), storage['bytes']),
                            int(storage['address'], 16))
    after_malloc = next(i.address + i.size for i in instructions
                        if i.mnemonic == 'bl' and int(i.op_str[1:], 0) == T.NATIVE_ALLOC)
    cases = 0
    with IntegratedClockFixture(b) as f:
        assert f.a.preempt((b.symbols['advanced_queue_init'], (0,)),
                           (b.native_clock['timer_stop'], ()), after_malloc)
        assert f.flags() & N.INITIALIZED and not f.flags() & N.WANTED
        assert f.phase() == N.EMPTY and f.refs() == 1
        f.hook('timer_start')
        assert f.phase() == N.HELD and f.refs() == 2
        cases += 2
    with IntegratedClockFixture(b) as f:
        f.queue()
        f.hook('timer_stop')
        assert f.a.preempt((b.native_clock['timer_start'], ()),
                           (b.native_clock['timer_stop'], ()), 0x0e06d164)
        assert not f.flags() & N.WANTED and f.phase() == N.EMPTY and f.refs() == 1
        cases += 1
    reconcile = next(v for v in b.allocations if v['name'] == 'native_clock_reconcile')
    entry = int(reconcile['address'], 16)
    instructions = cs.disasm(patched_image(b).get(entry, reconcile['bytes']), entry)
    after_request = next(i.address + i.size for i in instructions
                         if i.mnemonic == 'bl' and int(i.op_str[1:], 0) == T.NATIVE_CLOCK_REQUEST)
    for boundary in ('timer_stop', 'hfxo_off'):
        with IntegratedClockFixture(b) as f:
            assert f.a.preempt((b.symbols['advanced_queue_init'], (0,)),
                               (b.native_clock[boundary], ()), after_request)
            assert not f.flags() & N.WANTED and f.phase() == N.EMPTY and f.refs() == 1
            cases += 1
    return cases


def combined_layout_check(b):
    """Only held native clocks admit split; PM withdraws layout before release."""
    if not hasattr(b, 'native_plock'):
        return 0
    from unicorn import UC_HOOK_CODE
    from . import native_plock as P
    cases = 0
    for state, refs in ((2, 1), (0, 0)):
        with IntegratedClockFixture(b, state=state, refs=refs) as f:
            f.a.uc.mem_write(T.TRANSPORT_STATE, b'\1')
            f.a.uc.mem_write(T.TICKS_PER_MS, b'\4')
            f.a.uc.mem_write(T.REPORT_DIVIDER, b'\1')
            f.a.put32(T.REPORT_TIMER + 0x200, 1)
            f.a.put32(T.REPORT_TIMER + 0x540, 250)
            f.queue()
            f.a.uc.mem_write(T.ADV_RAM + 2, b'\1')
            f.a.uc.mem_write(T.ADV_RAM + 4, struct.pack('<H', 80))
            f.a.run(b.native_plock['configure'])
            if state == 0:
                assert f.phase() == N.PENDING and f.a.u32(T.REPORT_TIMER + 0x200) == 1
                f.complete()
                assert f.phase() == N.PENDING and f.a.u32(T.REPORT_TIMER + 0x200) == 1
                f.a.run(b.native_plock['configure'])
            assert f.phase() == N.HELD
            assert f.a.u32(T.REPORT_TIMER + 0x200) == 2
            assert f.a.u32(T.REPORT_TIMER + 0x540) == 170
            assert f.a.u32(T.REPORT_TIMER + 0x544) == 250
            assert f.a.byte(HEAP + P.CONTROL_OFFSET + P.FLAGS) & P.SPLIT
            release_layouts = []
            def release(uc, address, size, user):
                release_layouts.append((f.a.u32(T.REPORT_TIMER + 0x200),
                                        f.a.byte(HEAP + P.CONTROL_OFFSET + P.FLAGS)))
            f.a.add_hook(UC_HOOK_CODE, release, begin=T.NATIVE_CLOCK_RELEASE, end=T.NATIVE_CLOCK_RELEASE)
            f.hook('timer_stop')
            assert release_layouts and all(shorts != 2 and not flags & P.SPLIT
                                          for shorts, flags in release_layouts)
            assert f.phase() == N.EMPTY and f.refs() == refs
            f.hook('timer_start')
            if state == 0:
                while f.callbacks:
                    f.complete()
                f.a.run(b.native_plock['configure'])
            assert f.phase() == N.HELD and f.a.u32(T.REPORT_TIMER + 0x200) == 2
            release_layouts.clear()
            f.hook('hfxo_off')
            assert release_layouts and all(shorts == 1 and not flags & P.SPLIT
                                          for shorts, flags in release_layouts)
            assert f.phase() == N.EMPTY and f.refs() == refs
            cases += 9
    # An allocation retry bootstraps only an established wireless lifetime.
    for queue_ready, transport in ((False, 1), (True, 0), (True, 1)):
        with IntegratedClockFixture(b) as f:
            f.a.uc.mem_write(T.TRANSPORT_STATE, bytes((transport,)))
            f.a.uc.mem_write(T.ADV_RAM + 2, b'\1')
            if queue_ready:
                f.allocation_result = 0
                f.queue()
                f.allocation_result = HEAP - 4
                f.a.uc.mem_write(T.ADV_RAM + 2, b'\1')
            f.a.run(b.native_plock['configure'])
            enabled = queue_ready and transport == 1
            assert bool(f.flags() & N.INITIALIZED) == enabled
            assert f.refs() == (2 if enabled else 1)
            cases += 2
    # Native completion detached the pending client before PM can cancel it.
    with IntegratedClockFixture(b, state=0, refs=0) as f:
        f.queue()
        callback, manager = f.callbacks.pop(0)
        assert f.a.preempt((callback, (manager, 0)),
                           (b.native_clock['hfxo_off'], ()), 0x0e07ff02)
        assert f.phase() == N.DRAINING and f.refs() == 0
        assert f.a.u32(f.clock + 8) == 0
        f.a.run(b.native_plock['configure'])
        assert f.phase() == N.EMPTY and f.refs() == 0
        cases += 2
    return cases


def ownership_check(b):
    cases = 0
    with NativeClockFixture(b) as f:
        assert f.call('bootstrap') == 1
        assert f.phase() == N.HELD and f.refs() == 2
        assert f.a.u32(f.clock + 8) == 0
        for _ in range(3):
            assert f.call('bootstrap') == 1 and f.refs() == 2
            cases += 1
        assert f.a.run(OFF_CALL) == 0
        assert f.phase() == N.EMPTY and f.refs() == 1
        assert f.call('reconcile') == 0 and f.refs() == 1
        generation = f.call('intent', 2, 0)
        f.call('intent', 1, generation)
        assert f.call('reconcile') == 1 and f.refs() == 2
        assert f.a.run(OFF_CALL) == 0 and f.refs() == 1
        for at in (T.NATIVE_CLOCK_REQUEST, T.NATIVE_CLOCK_MANAGER,
                   T.NATIVE_CLOCK_CANCEL, T.NATIVE_CLOCK_RELEASE,
                   0x0e07fd3c, 0x0e07feec, 0x0e07fdea):
            assert at in f.executed, hex(at)
        assert bytes(f.a.uc.mem_read(HEAP, N.OFFSET)) == b'\xa5' * N.OFFSET
        assert bytes(f.a.uc.mem_read(HEAP + 60, T.SNAPSHOT_STORAGE_BYTES - 60)) == b'\xa5' * (T.SNAPSHOT_STORAGE_BYTES - 60)
        cases += 9
    with NativeClockFixture(b, state=0, refs=0) as f:
        assert f.call('bootstrap') == 0
        assert f.phase() == N.PENDING and f.a.u32(f.clock + 8) == 1
        assert f.a.u32(f.manager) == f.clock
        f.complete()
        assert f.a.u32(f.clock + 8) == 0 and f.refs() == 1
        assert f.call('reconcile') == 1 and f.phase() == N.HELD
        f.a.run(OFF_CALL)
        assert f.phase() == N.EMPTY and f.refs() == 0
        assert f.events[-1][0] == 'stop'
        f.complete()
        assert f.a.u32(f.manager + 24) & 7 == 0
        cases += 8
    with NativeClockFixture(b, state=0, refs=0) as f:
        f.call('bootstrap')
        f.a.run(OFF_CALL)
        assert f.phase() == N.EMPTY and f.a.u32(f.clock + 8) == 1
        assert f.a.u32(f.manager) == 0 and f.refs() == 0
        f.complete()
        assert f.phase() == N.EMPTY and f.a.u32(f.clock + 8) == 1
        assert f.events[-1][0] == 'stop'
        f.complete()
        generation = f.call('intent', 2, 0)
        f.call('intent', 1, generation)
        f.call('reconcile')
        assert f.phase() == N.PENDING
        f.complete()
        assert f.call('reconcile') == 1 and f.refs() == 1
        cases += 7
    return cases


def failure_check(b):
    cases = 0
    with NativeClockFixture(b, state=2, refs=65535) as f:
        assert f.call('bootstrap') == 0
        assert f.phase() == N.EMPTY and f.error() == -11 and f.refs() == 65535
        cases += 1
    with NativeClockFixture(b, state=0, refs=0) as f:
        f.call('bootstrap')
        f.complete(-5)
        assert f.call('reconcile') == 0
        assert f.phase() == N.EMPTY and f.error() == -5 and f.refs() == 0
        f.a.run(OFF_CALL)
        assert f.phase() == N.EMPTY and f.refs() == 0
        cases += 3
    with NativeClockFixture(b) as f:
        f.call('bootstrap')
        f.a.stub(T.NATIVE_CLOCK_CANCEL, value=-22)
        f.a.run(OFF_CALL)
        assert f.phase() == N.CLEANUP_ERROR and f.error() == -22 and f.refs() == 2
        del f.a.stubs[T.NATIVE_CLOCK_CANCEL]
        assert f.call('reconcile') == 0
        assert f.phase() == N.EMPTY and f.refs() == 1
        cases += 3
    with NativeClockFixture(b) as f:
        f.call('bootstrap')
        f.a.stub(T.NATIVE_CLOCK_RELEASE, value=-134)
        f.a.run(OFF_CALL)
        assert f.phase() == N.CLEANUP_ERROR and f.error() == -134 and f.refs() == 2
        del f.a.stubs[T.NATIVE_CLOCK_RELEASE]
        f.call('reconcile')
        assert f.phase() == N.EMPTY and f.refs() == 1
        cases += 3
    with NativeClockFixture(b) as f:
        f.call('bootstrap')
        f.a.stub(T.NATIVE_CLOCK_MANAGER, value=0)
        f.a.run(OFF_CALL)
        assert f.phase() == N.CLEANUP_ERROR and f.error() == -22 and f.refs() == 2
        del f.a.stubs[T.NATIVE_CLOCK_MANAGER]
        f.call('reconcile')
        assert f.phase() == N.EMPTY and f.refs() == 1
        cases += 3
    with NativeClockFixture(b) as f:
        f.a.uc.mem_write(T.NATIVE_CLOCK_READY, b'\x00')
        assert f.call('bootstrap') == 0 and f.refs() == 1
        f.call('intent', 1, 0)
        assert not f.flags() & N.WANTED
        assert f.a.run(b.native_clock['bootstrap'], 0) == 0
        assert f.a.run(b.native_clock['reconcile'], 0) == 0
        cases += 4
    with NativeClockFixture(b) as f:
        f.call('bootstrap')
        f.a.uc.mem_write(T.NATIVE_CLOCK_READY, b'\x00')
        assert f.call('bootstrap') == 0
        assert f.phase() == N.EMPTY and f.refs() == 1 and not f.flags() & N.WANTED
        cases += 2
    return cases


def interleave_check(b):
    cases = 0
    # Execute OFF at each unmasked instruction of one real request path.
    with NativeClockFixture(b) as trace:
        trace.call('bootstrap')
        sites = sorted(at for at in trace.executed
                       if any(int(v['address'], 16) <= at < int(v['address'], 16) + v['bytes']
                              for v in b.allocations if v['name'].startswith('native_clock_')))
    from unicorn.arm_const import UC_ARM_REG_PRIMASK
    for site in sites:
        with NativeClockFixture(b) as f:
            reached = [False]
            def boundary(uc, address, size, user):
                if address == site and not uc.reg_read(UC_ARM_REG_PRIMASK):
                    reached[0] = True
                    uc.emu_stop()
            from unicorn import UC_HOOK_CODE
            handle = f.a.uc.hook_add(UC_HOOK_CODE, boundary, begin=site, end=site)
            f.a.setreg('sp', f.a.layout.stack)
            f.a.setreg('lr', f.a.stop | 1)
            f.a.setreg('r0', HEAP)
            f.a.uc.emu_start(b.native_clock['bootstrap'] | 1, f.a.stop, count=100000)
            f.a.uc.hook_del(handle)
            if not reached[0]:
                continue
            context, resume = f.a.uc.context_save(), f.a.reg('pc')
            f.a.setreg('sp', f.a.layout.stack - 0x8000)
            f.a.setreg('lr', f.a.stop | 1)
            f.a.uc.emu_start(OFF_CALL | 1, f.a.stop, count=100000)
            f.a.uc.context_restore(context)
            f.a.uc.emu_start(resume | 1, f.a.stop, count=100000)
            assert f.a.reg('pc') == f.a.stop, hex(site)
            if f.flags() & N.INITIALIZED and not f.flags() & N.WANTED:
                assert f.phase() == N.EMPTY and f.refs() == 1, (hex(site), f.phase(), f.refs())
            cases += 1
    # Native notify has detached the node but has not published flags=0.
    for result in (0, -5):
        with NativeClockFixture(b, state=0, refs=0) as f:
            f.call('bootstrap')
            callback, manager = f.callbacks.pop(0)
            assert f.a.preempt((callback, (manager, result & 0xffffffff)),
                               (OFF_CALL, ()), 0x0e07ff02)
            if result == 0:
                assert f.phase() == N.DRAINING and f.refs() == 0
            else:
                assert f.phase() == N.CLEANUP_ERROR and f.refs() == 0
            assert f.a.u32(f.clock + 8) == 0
            f.call('reconcile')
            assert f.phase() == N.EMPTY and f.refs() == 0
            cases += 2
    return cases


def generation_check(b):
    cases = 0
    with NativeClockFixture(b) as f:
        f.call('bootstrap')
        old = f.call('intent', 2, 0)
        f.call('intent', 0, 0)
        f.call('intent', 1, old)
        assert not f.flags() & N.WANTED
        new = f.call('intent', 2, 0)
        assert new != old
        f.call('intent', 1, new)
        assert f.flags() & N.WANTED and f.flags() & N.STALE
        assert f.call('reconcile') == 0 and f.refs() == 1
        assert f.call('reconcile') == 1 and f.refs() == 2
        cases += 5
    # Preempt exactly after native request returns: OFF then a newer ON must
    # discharge the old operation before a later application can request anew.
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
    allocation = next(v for v in b.allocations if v['name'] == 'native_clock_reconcile')
    entry, length = int(allocation['address'], 16), allocation['bytes']
    instructions = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS).disasm(
        patched_image(b).get(entry, length), entry)
    at = next(i.address + i.size for i in instructions
              if i.mnemonic == 'bl' and int(i.op_str[1:], 0) == T.NATIVE_CLOCK_REQUEST)
    with NativeClockFixture(b) as f:
        second = OFF_CALL + 0x80
        f.a.uc.mem_write(second, assemble([
            'push {r4,lr}', *N._addr('r4', HEAP), 'mov r0,r4', 'movs r1,#0',
            *N._addr('r3', b.native_clock['intent'] | 1), 'blx r3',
            'mov r2,r0', 'mov r0,r4', 'movs r1,#1',
            *N._addr('r3', b.native_clock['intent'] | 1), 'blx r3',
            'mov r0,r4', *N._addr('r3', b.native_clock['reconcile'] | 1), 'blx r3',
            'pop {r4,pc}',
        ], second))
        assert f.a.preempt((b.native_clock['bootstrap'], (HEAP,)), (second, ()), at)
        assert f.phase() == N.EMPTY and f.refs() == 1 and f.flags() & N.WANTED
        assert f.call('reconcile') == 1 and f.refs() == 2
        cases += 3
    return cases


def phase_boundary_check(b):
    """Repeat OFF while notify is suspended after a successful release."""
    from unicorn import UC_HOOK_CODE
    with NativeClockFixture(b, state=0, refs=0) as f:
        f.call('bootstrap')
        callback, manager = f.callbacks.pop(0)
        stopped = [False]
        def pause(uc, address, size, user):
            stopped[0] = True
            uc.emu_stop()
        handle = f.a.uc.hook_add(UC_HOOK_CODE, pause, begin=0x0e07ff02, end=0x0e07ff02)
        f.a.setreg('sp', f.a.layout.stack)
        f.a.setreg('lr', f.a.stop | 1)
        f.a.setreg('r0', manager)
        f.a.setreg('r1', 0)
        f.a.uc.emu_start(callback | 1, f.a.stop, count=100000)
        f.a.uc.hook_del(handle)
        assert stopped[0]
        context = f.a.uc.context_save()
        for _ in range(3):
            f.a.setreg('sp', f.a.layout.stack - 0x8000)
            f.a.setreg('lr', f.a.stop | 1)
            f.a.uc.emu_start(OFF_CALL | 1, f.a.stop, count=100000)
            assert f.phase() == N.DRAINING and f.refs() == 0
        f.a.uc.context_restore(context)
        f.a.uc.emu_start(0x0e07ff03, f.a.stop, count=100000)
        assert f.call('reconcile') == 0 and f.phase() == N.EMPTY and f.refs() == 0
    return 4


def native_power_check(b):
    """Run native source and power owners, with completed-transition stimuli.

    This checks the concrete FLL/HFXO register writers in addition to onoff
    ownership. Analog crystal settling and workqueue scheduling remain external.
    """
    from unicorn import UC_HOOK_MEM_WRITE
    from unicorn.arm_const import UC_ARM_REG_PRIMASK, UC_ARM_REG_BASEPRI
    cases = 0
    for primask, basepri in ((0, 0), (1, 0x60)):
        with arm(patched_image(b)) as a:
            a.uc.mem_map(0x53000000, 0x100000)
            fll, hfxo, lrc = 0x2300c334, 0x23009f00, 0x5301e000
            a.uc.mem_write(fll, bytes(128))
            a.uc.mem_write(hfxo, bytes(104))
            a.uc.mem_write(0x2300bff0, bytes(20))
            a.put32(lrc + 0x490, 0x20)
            a.put32(lrc + 0x444, 0xf0)
            writes = []
            def record(uc, access, address, size, value, user):
                if lrc <= address < lrc + 0x500:
                    writes.append((address - lrc, value))
            a.add_hook(UC_HOOK_MEM_WRITE, record)
            a.uc.reg_write(UC_ARM_REG_PRIMASK, primask)
            a.uc.reg_write(UC_ARM_REG_BASEPRI, basepri)
            # Original HFXO transition acquires its own MAIN node and starts XO.
            a.run(0x0e078ad0, hfxo)
            assert a.u32(lrc + 0x490) == 0x21
            assert a.u32(0x2300bffc) == hfxo + 0x58
            assert a.u32(lrc + 0x50) == 1
            a.run(0x0e078994, fll, 2)
            assert a.u32(lrc + 0x444) == 0xf2
            assert a.u32(0x2300c000) == fll + 0x74
            assert a.u32(hfxo + 0x58) == fll + 0x74
            assert a.u32(lrc) == 1
            # The app gives back one of two manager refs; this must not stop XO.
            a.put32(hfxo + 16, TRANSITIONS)
            a.uc.mem_write(TRANSITIONS, struct.pack('<III', 0x0e08376f, 0x0e083759, 0))
            a.uc.mem_write(hfxo + 24, struct.pack('<HH', 2, 2))
            a.run(0x0e06d824)
            assert int.from_bytes(a.uc.mem_read(hfxo + 26, 2), 'little') == 1
            assert a.u32(lrc + 0x490) == 1
            assert a.u32(lrc + 0x54) == 0
            # Complete the FLL driver's lower-option actions using its real
            # release and mode-switch functions in the observed native order.
            a.run(0x0e0837dc, 0x0e087c78, 0)
            assert a.u32(lrc + 0x54) == 1
            assert a.u32(lrc + 0x490) == 1
            assert a.u32(0x2300bffc) == fll + 0x74
            a.run(0x0e078994, fll, 0)
            assert a.u32(lrc + 0x444) == 0xf0
            assert a.u32(lrc + 0x490) == 0
            assert a.u32(0x2300bffc) == 0 and a.u32(0x2300c000) == 0
            source = [v for off, v in writes if off == 0x444]
            power = [v for off, v in writes if off == 0x490]
            assert source == [0xf2, 0xf0]
            assert power == [0x21, 1, 0]
            assert a.uc.reg_read(UC_ARM_REG_PRIMASK) == primask
            assert a.uc.reg_read(UC_ARM_REG_BASEPRI) == basepri
            cases += 12
    return cases


def abi_check(b):
    from unicorn.arm_const import UC_ARM_REG_PRIMASK, UC_ARM_REG_BASEPRI
    cases = 0
    for primask in (0, 1):
        for basepri in (0, 0x40, 0x60):
            with NativeClockFixture(b) as f:
                f.a.uc.reg_write(UC_ARM_REG_PRIMASK, primask)
                f.a.uc.reg_write(UC_ARM_REG_BASEPRI, basepri)
                saved = {f'r{i}': 0x14000000 + i for i in range(4, 12)}
                for name, value in saved.items():
                    f.a.setreg(name, value)
                assert f.call('bootstrap') == 1
                assert all(f.a.reg(name) == value for name, value in saved.items())
                assert f.a.reg('sp') == f.a.layout.stack
                assert f.a.uc.reg_read(UC_ARM_REG_PRIMASK) == primask
                assert f.a.uc.reg_read(UC_ARM_REG_BASEPRI) == basepri
                generation = f.call('intent', 2, 0)
                f.call('intent', 0, 0)
                f.call('intent', 1, generation)
                assert not f.flags() & N.WANTED
                f.call('reconcile')
                assert f.phase() == N.EMPTY and f.refs() == 1
                assert f.a.uc.reg_read(UC_ARM_REG_PRIMASK) == primask
                assert f.a.uc.reg_read(UC_ARM_REG_BASEPRI) == basepri
                cases += 3
    return cases


def stack_check(b):
    peak = 0
    for state, refs in ((2, 1), (0, 0)):
        with IntegratedClockFixture(b, state=state, refs=refs) as f:
            f.queue()
            f.hook('timer_stop')
            f.hook('hfxo_off')
            f.hook('timer_start')
            peak = max(peak, f.a.layout.stack - f.lowest_sp)
    assert peak <= 1024, peak
    return dict(observed_bytes=peak, native_pm_stack_bytes=1024,
                boundary='generated hooks and native manager; transition services explicit')


def verify(b):
    return dict(ownership=ownership_check(b), failure=failure_check(b),
                interleavings=interleave_check(b), generation=generation_check(b),
                draining=phase_boundary_check(b), native_power=native_power_check(b), abi=abi_check(b),
                integration=integration_check(b), hook_interleavings=hook_interleave_check(b),
                combined_layout=combined_layout_check(b), stack=stack_check(b))
