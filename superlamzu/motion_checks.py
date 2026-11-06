"""Target-specific real Thumb checks for dev's thread/direct selection."""
import itertools
import struct

from . import advanced as A, protocol as P, target as T
from .checks import fresh
from .motion import DIRECT, OWNER
from .verify import request


def verify(b):
    from unicorn.arm_const import UC_ARM_REG_PRIMASK
    cases = 0
    for path, via, count, waiter, busy, callback in (
        (0, 1, 0, 1, 0, 1), (1, 0, 0, 1, 0, 1), (1, 1, 0, 1, 0, 1),
        (1, 1, 1, 0, 0, 1), (1, 1, 0, 0, 0, 1), (1, 1, 0, 1, 1, 1),
        (1, 1, 0, 1, 0, 0),
    ):
        with fresh(b) as a:
            state = 2 | path * DIRECT | busy * OWNER
            a.uc.mem_write(T.MOTION_STATE, bytes((state,)))
            a.uc.mem_write(T.TRANSPORT_STATE, bytes((via,)))
            a.uc.mem_write(T.ADV_RAM, b'\1\1')
            a.uc.mem_write(T.MOTION_SAMPLE, b'\1\0\x13\0\xf9\xff')
            a.put32(T.MOTION_DONE_QUEUE, 0x2300A328 if waiter else T.MOTION_DONE_QUEUE)
            a.put32(T.MOTION_DONE_QUEUE+32, count)
            a.put32(T.MOTION_CALLBACK, b.symbols['advanced_motion'] | 1 if callback else 0)
            seen = []
            def native(cpu):
                assert cpu.byte(T.MOTION_STATE) & OWNER
                assert cpu.reg('r0') == T.MOTION_SAMPLE
                seen.append(bytes(cpu.uc.mem_read(cpu.reg('r0'), 6)))
            a.stub(T.MOTION_NATIVE, effect=native)
            a.stub(T.MOTION_POST, -35)
            for i in range(4, 12):
                a.setreg(f'r{i}', 0x1100+i)
            a.uc.reg_write(UC_ARM_REG_PRIMASK, cases % 2)
            result = a.run(b.symbols['motion_post'], T.MOTION_DONE_QUEUE, 0x23025000, 0, 0)
            direct = path and via == 1 and not count and waiter and not busy and callback
            assert result == (0 if direct else 0xFFFFFFDD)
            assert bool(seen) == bool(direct)
            assert a.byte(T.MOTION_STATE) == state
            assert a.uc.reg_read(UC_ARM_REG_PRIMASK) == cases % 2
            assert all(a.reg(f'r{i}') == 0x1100+i for i in range(4, 12))
            counted=int(bool(direct) and b.advanced.get('telemetry',True))
            assert a.u32(T.ADV_RAM+A.OFF['samples']) == counted
            assert a.u32(T.ADV_RAM+A.OFF['samples_motion']) == counted
            if not direct:
                assert a.calls[-1] == (T.MOTION_POST, T.MOTION_DONE_QUEUE, 0x23025000)
            cases += 1
    # Execute decode from its native entry through the installed callsite.
    with fresh(b) as a:
        a.uc.mem_write(T.SENSOR_READY, b'\1')
        a.uc.mem_write(T.MOTION_STATE, bytes((DIRECT,)))
        a.uc.mem_write(T.TRANSPORT_STATE, b'\1')
        a.uc.mem_write(0x23025000, b'\x80\xb7\x13\0\xf9\xff')
        a.put32(T.MOTION_DONE_QUEUE, 0x2300A328)
        a.put32(T.MOTION_CALLBACK, b.symbols['advanced_motion'] | 1)
        a.stub(0x0E086F6C)
        samples = []
        a.stub(T.MOTION_NATIVE, effect=lambda c: samples.append(bytes(c.uc.mem_read(c.reg('r0'), 6))))
        a.run(0x0E07E600, 0x23025000, 1)
        assert samples == [b'\1\0\x13\0\xf9\xff']
        assert a.byte(T.MOTION_STATE) == DIRECT
        cases += 1
    for via, state, expected in ((1, DIRECT|OWNER, 0), (1, DIRECT, 1),
                                 (1, OWNER, 0), (0, DIRECT|OWNER, 0),
                                 (0, OWNER, 0), (0, 0, 1)):
        with fresh(b) as a:
            a.uc.mem_write(T.MOTION_STATE, bytes((state,)))
            a.uc.mem_write(T.TRANSPORT_STATE, bytes((via,)))
            seen = []
            a.stub(T.REPORT_NATIVE, effect=lambda c: seen.append(c.byte(T.MOTION_STATE)))
            a.run(b.symbols['motion_report'])
            assert len(seen) == expected and all(v & OWNER for v in seen)
            assert a.byte(T.MOTION_STATE) == state
            cases += 1
    # Native motion callback -> real op9 -> native radio queue, in ISR context.
    # Only memcpy backend, sleep notification and lift semaphores are stubbed.
    from unicorn.arm_const import UC_ARM_REG_IPSR
    with fresh(b) as a:
        def memcpy(cpu):
            cpu.uc.mem_write(cpu.reg('r0'), bytes(cpu.uc.mem_read(cpu.reg('r1'), cpu.reg('r2'))))
            return cpu.reg('r0')
        a.stub(0x0E0877E0, effect=memcpy)
        a.run(b.symbols['advanced_queue_init'], 0)
        a.run(0x0E073F0C, 2)
        a.uc.mem_write(T.MOTION_STATE, bytes((DIRECT,)))
        a.uc.mem_write(T.TRANSPORT_STATE, b'\1')
        a.uc.mem_write(A.RSTATE, b'\1\1')
        a.uc.mem_write(T.MOTION_SAMPLE, b'\1\0\x13\0\xf9\xff')
        a.put32(T.MOTION_DONE_QUEUE, 0x2300A328)
        a.put32(T.MOTION_CALLBACK, b.symbols['advanced_motion'] | 1)
        for service in (0x0E06CA2C, 0x0E068E38, 0x0E068E70):
            a.stub(service)
        a.uc.reg_write(UC_ARM_REG_IPSR, 20)
        a.run(b.symbols['motion_post'], T.MOTION_DONE_QUEUE, 0x23025000, 0, 0)
        assert bytes(a.uc.mem_read(A.Q2+10, 4)) == b'\x13\0\xf9\xff'
        assert a.byte(A.Q2+2) == 1
        assert bytes(a.uc.mem_read(0x2300CAD4, 4)) == bytes(4)
        assert a.byte(T.MOTION_STATE) == DIRECT
        cases += 1
    with fresh(b) as a:
        for path in (1, 0, 1):
            a.uc.mem_write(T.MOTION_STATE, bytes((OWNER|2,)))
            assert request(a, P.SET, (0, P.MOTION_PATH, path)) == (0xA0, bytes((0, 10, path)))
            assert a.byte(T.MOTION_STATE) == OWNER | 2 | path*DIRECT
            assert request(a, P.GET, (0, P.MOTION_PATH)) == (0xA0, bytes((0, 10, path)))
            if b.advanced.get('telemetry',True):
                request(a, P.SET, (0, P.STATS, 2))
            assert a.byte(T.MOTION_STATE) == OWNER | 2 | path*DIRECT
            cases += 1
        for command, payload in ((P.GET,(0,10,0)), (P.GET,(1,10)),
                                 (P.SET,(0,10)), (P.SET,(0,10,2)), (P.SET,(1,10,1))):
            assert request(a, command, payload)[0] == 0xA2
            cases += 1
    # Pointer tags survive allocating the existing native-heap snapshot.
    with fresh(b) as a:
        snap = 0x23024004
        a.uc.mem_write(T.MOTION_STATE, bytes((DIRECT,)))
        assert request(a, P.GET, (0, P.SENSOR_SNAPSHOT)) == (0xA0, bytes((0, 6, 1))+bytes(23))
        a.uc.mem_write(T.SENSOR_READY, b'\1')
        a.stub(0x0E07FAD4, snap-4)
        a.stub(T.MOTION_POST)
        assert request(a, P.SET, (0, P.SENSOR_SNAPSHOT, 1, 0))[0] == 0xA0
        assert bytes(a.uc.mem_read(T.SNAPSHOT_POINTER, 3)) == bytes((4, 0x40, 2 | DIRECT))
        assert request(a, P.GET, (0, P.SENSOR_SNAPSHOT))[1][2:4] == b'\1\1'
        assert request(a, P.SET, (0, P.MOTION_PATH, 0))[0] == 0xA0
        assert bytes(a.uc.mem_read(T.SNAPSHOT_POINTER, 3)) == struct.pack('<I', snap)[:3]
        cases += 1
    cases += ownership_interleaves(b)
    cases += callback_report_interleaves(b)
    cases += callback_tail_check(b)
    cases += tail_switch_check(b)
    return cases + registered_report_check(b)


def registered_report_check(b):
    """Real driver-table report delegation, including native readiness gates.

    SPI start is the explicit peripheral boundary; Thorn completes SPI later,
    unlike MAYA's synchronous burst. LDA substitutions are emulator-only.
    """
    from .common import assemble
    from .verify import patched_image
    from unicorn.arm_const import UC_ARM_REG_PRIMASK
    image = patched_image(b)
    assert image.u32(T.REPORT_DRIVER_TABLE+0x43) == (b.symbols.get('advanced_tick', T.SENSOR_TICK)|1)
    cases = 0
    counting = (0, 1) if b.advanced.get('telemetry', True) else (0,)
    for via, path, stats, gate in itertools.product((0,1), (0,DIRECT), counting,
                                                   ('ready','not_ready','worker','burst','owner','divider')):
        with fresh(b) as a:
            a.put32(T.REPORT_DRIVER, T.REPORT_DRIVER_TABLE)
            a.uc.mem_write(T.SENSOR_READY, bytes((gate!='not_ready',)))
            a.uc.mem_write(0x2300E073, b'\xb7\0')
            a.put32(0x2300CA64, int(gate=='worker'))
            a.put32(0x2300CA6C, int(gate=='burst'))
            a.uc.mem_write(T.REPORT_DIVIDER, bytes((3 if gate=='divider' else 1,)))
            state = path | (OWNER if gate=='owner' else 0)
            a.uc.mem_write(T.MOTION_STATE, bytes((state,)))
            a.uc.mem_write(T.TRANSPORT_STATE, bytes((via,)))
            a.uc.mem_write(T.ADV_RAM, bytes((1,stats)))
            for site, original, instruction in T.SENSOR_TICK_LDA:
                assert bytes(a.uc.mem_read(site,4)) == original
                a.uc.mem_write(site, assemble([instruction],site))
            a.stub(0x0E086F6C, effect=lambda c:c.put32(c.reg('r0'),c.reg('r1')))
            bursts=[]
            a.stub(0x0E06CFE8, effect=lambda c:bursts.append((c.reg('r0'),c.reg('r1'))) or 1)
            a.run(b.symbols['motion_report'])
            assert bursts == ([(22,6)] if gate=='ready' else []), (via,path,stats,gate,bursts)
            if gate=='divider':
                a.run(b.symbols['motion_report']); a.run(b.symbols['motion_report'])
                assert bursts == [(22,6)]
            assert a.byte(T.MOTION_STATE) == state
            assert a.uc.reg_read(UC_ARM_REG_PRIMASK) == 0
            cases += 1
    return cases


def ownership_interleaves(b):
    """Preempt real ownership windows, rather than seed a synthetic busy byte."""
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
    from .verify import patched_image
    image = patched_image(b)
    cases = 0
    for report_first in (False, True):
        with fresh(b) as a:
            a.uc.mem_write(T.MOTION_STATE, bytes((DIRECT,)))
            a.uc.mem_write(T.TRANSPORT_STATE, b'\1')
            a.put32(T.MOTION_DONE_QUEUE, 0x2300A328)
            a.put32(T.MOTION_CALLBACK, b.symbols['advanced_motion'] | 1)
            a.stub(T.MOTION_NATIVE)
            a.stub(T.REPORT_NATIVE)
            a.stub(T.MOTION_POST)
            post = (b.symbols['motion_post'], (T.MOTION_DONE_QUEUE, 0x23025000, 0, 0))
            report = (b.symbols['motion_report'], ())
            first, second = (report, post) if report_first else (post, report)
            symbol = 'motion_report' if report_first else 'advanced_motion'
            native = T.REPORT_NATIVE if report_first else T.MOTION_NATIVE
            allocation = next(v for v in b.allocations if v['name'] == symbol)
            instructions = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS).disasm(
                image.get(b.symbols[symbol], allocation['bytes']), b.symbols[symbol])
            boundary = next(v.address for v in instructions if v.mnemonic == 'bl'
                            and int(v.op_str.lstrip('#'),0) == native)
            # Stop before the native service executes. The first callback has
            # claimed OWNER and restored PRIMASK; the other real wrapper runs.
            assert a.preempt(first, second, boundary)
            assert a.byte(T.MOTION_STATE) == DIRECT
            assert sum(c[0] == T.MOTION_NATIVE for c in a.calls) == int(not report_first)
            assert sum(c[0] == T.REPORT_NATIVE for c in a.calls) == int(report_first)
            assert sum(c[0] == T.MOTION_POST for c in a.calls) == int(report_first)
            cases += 1
    return cases


def callback_report_interleaves(b):
    """Thread and wired callbacks also own the same native XY accumulators."""
    from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_MCLASS
    from .verify import patched_image
    image=patched_image(b)
    allocation=next(v for v in b.allocations if v['name']=='advanced_motion')
    instructions=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_MCLASS).disasm(
        image.get(b.symbols['advanced_motion'],allocation['bytes']),b.symbols['advanced_motion'])
    boundary=next(v.address for v in instructions if v.mnemonic=='bl'
                  and int(v.op_str.lstrip('#'),0)==T.MOTION_NATIVE)
    cases=0
    for path,via in itertools.product((0,DIRECT),(0,1)):
        with fresh(b) as a:
            a.uc.mem_write(T.MOTION_STATE,bytes((path,)))
            a.uc.mem_write(T.TRANSPORT_STATE,bytes((via,)))
            a.stub(T.MOTION_NATIVE);a.stub(T.REPORT_NATIVE)
            assert a.preempt((b.symbols['advanced_motion'],(0x23025000,)),
                             (b.symbols['motion_report'],()),boundary)
            assert sum(c[0]==T.MOTION_NATIVE for c in a.calls)==1
            assert not any(c[0]==T.REPORT_NATIVE for c in a.calls)
            assert a.byte(T.MOTION_STATE)==path
            cases+=1
    # Pause after native X read but before the sum is committed. A report at
    # this boundary used to clear both accumulators under a stale X load.
    allocation=next(v for v in b.allocations if v['name']=='abs_total')
    instructions=list(Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_MCLASS).disasm(
        image.get(b.symbols['abs_total'],allocation['bytes']),b.symbols['abs_total']))
    boundary=next(v.address for v in instructions
                  if v.mnemonic in ('strh','strh.w') and v.op_str=='r3, [r2, #2]')
    with fresh(b) as a:
        a.uc.mem_write(T.MOTION_STATE,b'\0')
        a.uc.mem_write(T.TRANSPORT_STATE,b'\0')
        a.uc.mem_write(T.MOTION_SAMPLE,b'\1\0\x0a\0\x14\0')
        a.uc.mem_write(T.MOTION_ACC_X,struct.pack('<H',100))
        a.uc.mem_write(T.MOTION_ACC_Y,struct.pack('<H',200))
        a.uc.mem_write(T.REPORT_DIVIDER,b'\1')
        a.stub(0x0E071CBC);a.stub(0x0E06F530,0);a.stub(0x0E07F786,0)
        a.stub(0x0E068E38)
        reports=[]
        def usb(c):
            reports.append(bytes(c.uc.mem_read(c.reg('r1'),8)))
            return 1
        a.stub(0x0E06D2C4,effect=usb)
        assert a.preempt((b.symbols['advanced_motion'],(T.MOTION_SAMPLE,)),
                         (b.symbols['motion_report'],()),boundary)
        assert len(reports)==1,reports
        assert struct.unpack('<hh',reports[0][2:6])==(110,220),reports
        assert a.byte(T.MOTION_STATE)==0
        cases+=1
    return cases


def scheduled_callback_reports(b, *, path=DIRECT, via=1, lift=0, absolute=False,
                               reports=64, native_queue=False, done_thread=False):
    """A busy transport leaves XY pending, then lift wakeup switches threads."""
    from unicorn import UC_HOOK_CODE
    from unicorn.arm_const import UC_ARM_REG_IPSR, UC_ARM_REG_BASEPRI
    with fresh(b) as a:
        a.uc.mem_map(0xE000E000, 4096)  # Native PendSV request, not a scheduler model.
        if absolute:
            from .optical_checks import initialize, HEAP
            initialize(a)
            a.uc.mem_write(T.MOTION_STATE, bytes((path | 0x42,)))
        else:
            a.uc.mem_write(T.MOTION_STATE, bytes((path,)))
        a.uc.mem_write(T.TRANSPORT_STATE, bytes((via,)))
        a.uc.mem_write(T.MOTION_SAMPLE, bytes((1, lift, 10, 0, 20, 0)))
        a.uc.mem_write(T.MOTION_ACC_X, struct.pack('<H', 100))
        a.uc.mem_write(T.MOTION_ACC_Y, struct.pack('<H', 200))
        a.uc.mem_write(T.REPORT_DIVIDER, b'\1')
        a.uc.mem_write(T.SETTINGS+4, b'\0')
        a.uc.mem_write(T.SETTINGS+0x1B, b'\1')
        a.stub(0x0E071CBC)  # Coordinate transform: fixed, already-native XY.
        a.stub(0x0E06F530, via)
        a.stub(0x0E0879D0, 8)
        a.stub(0x0E07F786, 0)  # No wheel/button flags.
        a.stub(0x0E06CA2C)  # Activity timeout is independent of lift wakeup.
        # Existing emulator does not implement the target's LDA/LDAEX forms.
        a.stub(0x0E07F4B8, effect=lambda c: c.u32(c.reg('r0')))
        a.stub(0x0E07F4BE, effect=lambda c: c.put32(c.reg('r0'), c.reg('r1')))
        a.put32(0x2300A4FC, int(not lift))
        # A real semaphore waiter; ready-list helpers are the scheduler service
        # boundary, not the callback, semaphore or scheduling decision itself.
        sem, waiter = 0x23007BFC, 0x23022000
        a.put32(sem, waiter)
        a.put32(sem+4, waiter)
        a.put32(waiter, sem)
        a.put32(waiter+4, sem)
        a.stub(0x0E084E0A)
        a.stub(0x0E084C48)
        a.put32(0x2300C92C, 0x23022100)
        a.put32(0x2300C93C, waiter)
        sends = []

        if native_queue:
            assert via == 1
            def memcpy(c):
                c.uc.mem_write(c.reg('r0'), bytes(c.uc.mem_read(c.reg('r1'), c.reg('r2'))))
                return c.reg('r0')
            a.stub(0x0E0877E0, effect=memcpy)
            a.run(0x0E073F0C, 2)
            a.uc.mem_write(A.RSTATE, b'\1\1')
            a.uc.mem_write(0x23026000, bytes(12))
            for _ in range(8):
                assert a.run(0x0E0879D8, 9, 0x23026000) == 1
            assert a.byte(A.Q2) == 1

        def submit(c):
            # The callback initially encounters a busy downstream queue. Once
            # suspended, report IRQs can retry the still-pending accumulated XY.
            offset = 4 if via else 2
            xy = struct.unpack('<hh', bytes(c.uc.mem_read(c.reg('r1')+offset, 4)))
            sends.append(xy)
            return int(len(sends) > 1)

        if native_queue:
            a.add_hook(UC_HOOK_CODE, lambda uc, address, size, user: submit(a),
                       begin=0x0E0879D8, end=0x0E0879D8)
        else:
            a.stub(0x0E0879D8 if via else 0x0E06D2C4, effect=submit)
        entry, callback_end = b.symbols['advanced_motion'], a.stop
        if done_thread:
            def copy_notification(c):
                c.uc.mem_write(c.reg('r0'), bytes(c.uc.mem_read(c.reg('r1'), c.reg('r2'))))
                return c.reg('r0')
            a.stub(0x0E0877E0, effect=copy_notification)
            a.run(0x0E0847DE, T.MOTION_DONE_QUEUE, 0x2300C984, 4, 8)
            a.put32(T.MOTION_CALLBACK, b.symbols['advanced_motion'] | 1)
            a.uc.mem_write(T.SENSOR_READY, b'\1')
            a.stub(0x0E086F6C)
            a.uc.mem_write(0x23025000, bytes((0x80 | (8 if lift else 0), 0xB7, 10, 0, 20, 0)))
            a.uc.reg_write(UC_ARM_REG_IPSR, 20)
            a.run(0x0E07E600, 0x23025000, 1)
            assert a.u32(T.MOTION_DONE_QUEUE+32) == 1
            assert not sends  # Direct must fall back: no waiting done thread.
            a.uc.reg_write(UC_ARM_REG_IPSR, 0)
            entry, callback_end = 0x0E07E684, 0x0E07E6A6
            a.ends.add(callback_end)
        a.setreg('sp', a.layout.stack)
        a.setreg('lr', a.stop | 1)
        a.setreg('r0', T.MOTION_SAMPLE)
        boundary = 0x0E07D43C  # PendSV requested and BASEPRI restored to zero.
        paused = []

        def stop(uc, address, size, user):
            paused.append(address)
            uc.emu_stop()

        handle = a.uc.hook_add(UC_HOOK_CODE, stop, begin=boundary, end=boundary)
        try:
            a.uc.emu_start(entry | 1, a.stop, count=30000)
        finally:
            a.uc.hook_del(handle)
        assert paused, f'callback did not reach native scheduler: {a.reg("pc"):#x}'
        assert a.u32(0xE000ED04) & (1 << 28)
        assert a.uc.reg_read(UC_ARM_REG_BASEPRI) == 0
        assert a.uc.reg_read(UC_ARM_REG_IPSR) == 0
        assert a.reg('sp') < a.layout.stack
        assert len(sends) == 1 and sends[0] == (110, 220), sends
        state_at_switch = a.byte(T.MOTION_STATE)
        context = a.uc.context_save()
        a.uc.reg_write(UC_ARM_REG_IPSR, 20)
        a.uc.reg_write(UC_ARM_REG_BASEPRI, 0)
        if native_queue:
            # A radio IRQ frees one actual queue entry while the done thread
            # is switched out. Use a separate stack, as for report IRQs below.
            a.setreg('sp', a.layout.stack-0x8000)
            a.setreg('lr', a.stop | 1)
            for i, value in enumerate((2, 0x23026000, 12)):
                a.setreg(f'r{i}', value)
            a.uc.emu_start(0x23003A8D, a.stop, count=30000)
            assert a.reg('pc') == a.stop and a.reg('r0') == 1
            assert a.byte(A.Q2) == 0
        for _ in range(reports):
            a.setreg('sp', a.layout.stack-0x8000)
            a.setreg('lr', a.stop | 1)
            a.uc.emu_start(b.symbols['motion_report'] | 1, a.stop, count=30000)
            assert a.reg('pc') == a.stop
        submitted_while_suspended = len(sends)-1
        pending = (struct.unpack('<h', bytes(a.uc.mem_read(T.MOTION_ACC_X, 2)))[0],
                   struct.unpack('<h', bytes(a.uc.mem_read(T.MOTION_ACC_Y, 2)))[0])
        accepted_payload = (struct.unpack('<hh', bytes(a.uc.mem_read(A.Q2+10, 4)))
                            if native_queue and submitted_while_suspended else None)
        a.uc.context_restore(context)
        a.uc.emu_start(boundary | 1, a.stop, count=30000)
        assert a.reg('pc') == callback_end
        a.ends.discard(callback_end)
        expected_state = path | (0x42 if absolute else 0)
        assert a.byte(T.MOTION_STATE) == expected_state
        if absolute:
            assert bytes(a.uc.mem_read(HEAP+24, 4)) == struct.pack('<hh', 10, 20)
        if done_thread:
            assert a.u32(T.MOTION_DONE_QUEUE+32) == 0
        a.run(b.symbols['motion_report'])
        return dict(path=path, transport=via, lift=lift, absolute=absolute,
                    native_queue=native_queue, done_thread=done_thread,
                    accepted_payload=accepted_payload,
                    state_at_switch=state_at_switch,
                    owner_at_switch=bool(state_at_switch & OWNER),
                    report_calls_while_suspended=reports,
                    submitted_while_suspended=submitted_while_suspended,
                    pending_while_suspended=pending,
                    submissions=sends, final_state=a.byte(T.MOTION_STATE))


def callback_tail_check(b):
    """Report progress must not depend on a descheduled done thread resuming."""
    from unicorn.arm_const import UC_ARM_REG_PRIMASK
    from .optical_checks import initialize, HEAP
    from .common import assemble
    cases = 0
    for path, via, lift, absolute in itertools.product((0, DIRECT), (0, 1), (0, 1), (False, True)):
        result = scheduled_callback_reports(b, path=path, via=via, lift=lift, absolute=absolute)
        assert not result['owner_at_switch'], result
        assert result['submitted_while_suspended'] == 1, result
        assert result['pending_while_suspended'] == (0, 0), result
        # First submission failed; exactly one later successful submission.
        assert result['submissions'] == [(110, 220), (110, 220)], result
        cases += 1
    for path, lift, absolute in itertools.product((0, DIRECT), (0, 1), (False, True)):
        result = scheduled_callback_reports(b, path=path, lift=lift, absolute=absolute,
                                            native_queue=True)
        assert not result['owner_at_switch'], result
        assert result['submitted_while_suspended'] == 1, result
        assert result['pending_while_suspended'] == (0, 0), result
        assert result['accepted_payload'] == ((10, 20) if absolute else (110, 220)), result
        assert result['submissions'] == [(110, 220), (110, 220)], result
        cases += 1
    for path, lift, absolute in itertools.product((0, DIRECT), (0, 1), (False, True)):
        result = scheduled_callback_reports(b, path=path, lift=lift, absolute=absolute,
                                            native_queue=True, done_thread=True)
        assert not result['owner_at_switch'], result
        assert result['submitted_while_suspended'] == 1, result
        assert result['accepted_payload'] == ((10, 20) if absolute else (110, 220)), result
        assert result['submissions'] == [(110, 220), (110, 220)], result
        cases += 1
    # The new exit must preserve every pointer/path/ABS tag and incoming
    # interrupt mask; it must consume lift before another sample can replace it.
    for primask, lift in itertools.product((0, 1), (0, 1)):
        with fresh(b) as a:
            initialize(a)
            state = 2 | DIRECT | OWNER | 0x40
            a.uc.mem_write(T.MOTION_STATE, bytes((state,)))
            a.uc.mem_write(T.MOTION_SAMPLE+1, bytes((lift,)))
            a.setreg('r5', T.MOTION_SAMPLE)
            a.uc.reg_write(UC_ARM_REG_PRIMASK, primask)
            seen = []
            a.stub(0x0E068E38, effect=lambda c: seen.append((1, c.byte(T.MOTION_STATE))))
            a.stub(0x0E068E70, effect=lambda c: seen.append((0, c.byte(T.MOTION_STATE))))
            # Common epilogue expects the native callback's 0x48-byte local
            # area and six saved registers. Execute the real prologue first.
            a.uc.mem_write(T.MOTION_SAMPLE, b'\0')
            a.stub(0x0E06F530, 2)  # No transport activity in this ABI check.
            for reg in range(4, 12):
                a.setreg(f'r{reg}', 0x1100+reg)
            a.run(b.symbols['advanced_motion'], T.MOTION_SAMPLE)
            assert seen == [(lift, state & ~OWNER)], seen
            # owned_call restores its caller's OWNER; other tags never change.
            assert a.byte(T.MOTION_STATE) == state
            assert bytes(a.uc.mem_read(T.SNAPSHOT_POINTER, 2)) == bytes((4, 0x40))
            assert a.uc.reg_read(UC_ARM_REG_PRIMASK) == primask
            assert all(a.reg(f'r{reg}') == 0x1100+reg for reg in range(4, 12))
            cases += 1
    # The instruction immediately after release is still in the callback,
    # but must permit a timer. A replaced sample must not change this callback's
    # captured lift choice or cause a second XY application.
    for lift in (0, 1):
        with fresh(b) as a:
            a.uc.mem_write(T.MOTION_STATE, bytes((DIRECT,)))
            a.uc.mem_write(T.TRANSPORT_STATE, b'\1')
            a.uc.mem_write(T.MOTION_SAMPLE, bytes((1, lift, 10, 0, 20, 0)))
            a.uc.mem_write(T.REPORT_DIVIDER, b'\1')
            a.stub(0x0E071CBC)
            a.stub(0x0E06F530, 1)
            a.stub(0x0E0879D0, 8)
            a.stub(0x0E07F786, 0)
            a.stub(0x0E06CA2C)
            sent, tails = [], []
            def submit(c):
                sent.append(struct.unpack('<hh', bytes(c.uc.mem_read(c.reg('r1')+4, 4))))
                return int(len(sent) > 1)
            a.stub(0x0E0879D8, effect=submit)
            a.stub(0x0E068E38, effect=lambda c: tails.append(1))
            a.stub(0x0E068E70, effect=lambda c: tails.append(0))
            replacement = 0x23026000
            a.uc.mem_write(replacement, assemble([
                'push {r4,lr}', *A.addr('r4', T.MOTION_SAMPLE+1),
                f'movs r0,#{1-lift}', 'strb r0,[r4]',
                *A.addr('r12', b.symbols['motion_report'] | 1),
                'blx r12', 'pop {r4,pc}'], replacement))
            assert a.preempt((b.symbols['advanced_motion'], (T.MOTION_SAMPLE,)),
                             (replacement, ()), T.MOTION_TAIL_SITE+4)
            assert sent == [(10, 20), (10, 20)], sent
            assert tails == [lift], tails
            assert a.byte(T.MOTION_STATE) == DIRECT
            cases += 1
    return cases


def tail_switch_check(b):
    """An active done thread keeps new callbacks queued after SET direct."""
    from unicorn import UC_HOOK_CODE
    from .common import assemble

    cases = 0
    for via in (1, 0):
        with fresh(b) as a:
            def memcpy(c):
                c.uc.mem_write(c.reg('r0'), bytes(c.uc.mem_read(c.reg('r1'), c.reg('r2'))))
                return c.reg('r0')
            a.stub(0x0E0877E0, effect=memcpy)
            a.run(0x0E0847DE, T.MOTION_DONE_QUEUE, 0x2300C984, 4, 8)
            a.uc.mem_write(T.MOTION_STATE, b'\0')
            a.uc.mem_write(T.TRANSPORT_STATE, b'\1')
            a.uc.mem_write(T.SENSOR_READY, b'\1')
            a.put32(T.MOTION_CALLBACK, b.symbols['advanced_motion'] | 1)
            a.uc.mem_write(T.SETTINGS+4, b'\0')
            a.uc.mem_write(T.SETTINGS+0x1B, b'\1')
            a.put32(0x2300A4FC, 1)
            for service in (0x0E071CBC, 0x0E06CA2C, 0x0E086F6C, 0x0E07CEA0):
                a.stub(service)
            a.stub(0x0E0879D0, 8)
            a.stub(0x0E07F786, 0)
            # LDA forms are an emulator boundary; both native lift helpers run.
            a.stub(0x0E07F4B8, effect=lambda c: c.u32(c.reg('r0')))
            a.stub(0x0E07F4BE, effect=lambda c: c.put32(c.reg('r0'), c.reg('r1')))
            events = []

            def wireless(c):
                assert c.reg('r0') == 9
                events.append(('wireless', struct.unpack('<hh', bytes(c.uc.mem_read(c.reg('r1')+4, 4)))))
                return 1

            def wired(c):
                events.append(('wired', struct.unpack('<hh', bytes(c.uc.mem_read(c.reg('r1')+2, 4)))))
                return 1

            def lift(uc, address, size, user):
                if address in (0x0E068E38, 0x0E068E70):
                    events.append(('lift', int(address == 0x0E068E38)))

            a.stub(0x0E0879D8, effect=wireless)
            a.stub(0x0E06D2C4, effect=wired)
            a.add_hook(UC_HOOK_CODE, lift, begin=0x0E068E38, end=0x0E068E70)
            # Decode and receive the old notification exactly as the done
            # thread does before entering its registered callback.
            a.uc.mem_write(0x23025000, b'\x88\xb7'+struct.pack('<hh', 10, 20))
            a.run(0x0E07E600, 0x23025000, 1)
            assert a.u32(T.MOTION_DONE_QUEUE+32) == 1 and not events
            assert a.run(0x0E07CBE4, T.MOTION_DONE_QUEUE, 0x23025020, 0, 0) == 0
            assert a.u32(T.MOTION_DONE_QUEUE+32) == 0
            assert a.u32(T.MOTION_DONE_QUEUE) == T.MOTION_DONE_QUEUE
            assert bytes(a.uc.mem_read(T.MOTION_SAMPLE, 6)) == b'\1\1'+struct.pack('<hh', 10, 20)
            packet = bytearray(64)
            packet[0] = 0xA0
            packet[3:6] = bytes((3, 1, P.SET))
            packet[6:9] = bytes((0, P.MOTION_PATH, 1))
            a.uc.mem_write(T.PACKET, bytes(packet))
            a.uc.mem_write(0x23025000, b'\x80\xb7'+struct.pack('<hh', 3, 4))
            switch = 0x23026000
            def call(destination):
                return A.addr('r12', destination | 1)+['blx r12']
            a.uc.mem_write(switch, assemble([
                'push {r4,lr}', *call(T.GROUP1),
                *A.addr('r4', T.TRANSPORT_STATE), f'movs r0,#{via}', 'strb r0,[r4]',
                *A.addr('r0', 0x23025000), 'movs r1,#1',
                *call(0x0E07E600), 'pop {r4,pc}'], switch))
            # OWNER is released and old lift is captured, but the real queue
            # has no waiter until this callback and its done-thread loop finish.
            assert a.preempt((b.symbols['advanced_motion'], (T.MOTION_SAMPLE,)),
                             (switch, ()), T.MOTION_TAIL_SITE+4)
            assert a.byte(T.PACKET) == 0xA0
            assert a.byte(T.MOTION_STATE) == DIRECT
            assert events == [('wireless', (10, 20)), ('lift', 1)], events
            assert a.u32(T.MOTION_DONE_QUEUE+32) == 1
            assert a.u32(0x2300A4FC) == 1
            # Consume the new notification through the native done-thread
            # entry, callback pointer and native lift-down helper.
            a.ends.add(0x0E07E6A6)
            a.run(0x0E07E684, count=100000)
            a.ends.discard(0x0E07E6A6)
            assert events == [('wireless', (10, 20)), ('lift', 1),
                              ('wireless' if via else 'wired', (3, 4)), ('lift', 0)], events
            assert a.u32(T.MOTION_DONE_QUEUE+32) == 0
            assert a.u32(0x2300A4FC) == 0
            assert bytes(a.uc.mem_read(T.MOTION_ACC_X, 4)) == bytes(4)
            assert a.byte(T.MOTION_STATE) == DIRECT
            cases += 1
    return cases


def ownership_boundary_sweep(b):
    """Interrupt every executed, unmasked boundary on the shared XY paths.

    This reuses Arm.preempt, not an NVIC/elapsed-time model. A report may
    interrupt a callback or decoder; a decoder may interrupt a report. These
    are separate priority-order stress cases, not a simultaneous NVIC setup.
    The decoder's fallback notification is serviced only after the interrupted
    IRQ returns.
    Lift and peripheral services are explicit stubs; native decode, XY, ABS,
    enqueue decisions, report divider and generated ownership code execute.
    """
    from collections import Counter
    from unicorn import UC_HOOK_CODE
    from unicorn.arm_const import UC_ARM_REG_PRIMASK
    from .optical_checks import initialize, HEAP

    def fixture(via, path):
        a = fresh(b)
        initialize(a)
        state = 2 | path | 0x40
        a.uc.mem_write(T.MOTION_STATE, bytes((state,)))
        a.uc.mem_write(T.TRANSPORT_STATE, bytes((via,)))
        a.uc.mem_write(T.SENSOR_READY, b'\1')
        a.uc.mem_write(T.MOTION_SAMPLE, b'\1\0\x0a\0\x14\0')
        a.uc.mem_write(0x23025000, b'\x80\xb7\x0a\0\x14\0')
        a.uc.mem_write(T.MOTION_ACC_X, struct.pack('<h', 100))
        a.uc.mem_write(T.MOTION_ACC_Y, struct.pack('<h', 200))
        a.uc.mem_write(T.REPORT_DIVIDER, b'\1')
        a.put32(T.MOTION_DONE_QUEUE, 0x2300A328)
        a.put32(T.MOTION_CALLBACK, b.symbols['advanced_motion'] | 1)
        for service in (0x0E071CBC, 0x0E06CA2C, 0x0E068E38,
                        0x0E068E70, 0x0E086F6C, T.MOTION_POST):
            a.stub(service)
        a.stub(0x0E06F530, via)
        a.stub(0x0E0879D0, 8)
        a.stub(0x0E07F786, 0)
        submitted = []
        def submit(c):
            offset = 4 if via else 2
            submitted.append(struct.unpack('<hh', bytes(
                c.uc.mem_read(c.reg('r1') + offset, 4))))
            return 1
        a.stub(0x0E0879D8 if via else 0x0E06D2C4, effect=submit)
        for reg in range(4, 12):
            a.setreg(f'r{reg}', 0x1100 + reg)
        return a, state, submitted

    symbols = {'advanced_motion', 'motion_post', 'motion_report', 'motion_tail_release',
               'abs_total', 'abs_pointer'}
    ranges = [(b.symbols[v['name']], b.symbols[v['name']] + v['bytes'])
              for v in b.allocations if v['name'] in symbols]
    ranges += [(T.MOTION_NATIVE, 0x0E071FB0), (T.REPORT_NATIVE, 0x0E071C94),
               (0x0E07E600, 0x0E07E666)]
    cases = 0
    for direction, via, path in itertools.product(
            ('callback_report', 'report_decode', 'decode_report'), (0, 1), (0, DIRECT)):
        callback = (b.symbols['advanced_motion'], (T.MOTION_SAMPLE,))
        report = (b.symbols['motion_report'], ())
        decode = (0x0E07E600, (0x23025000, 1))
        first, second = {'callback_report': (callback, report),
                         'report_decode': (report, decode),
                         'decode_report': (decode, report)}[direction]
        a, _, _ = fixture(via, path)
        boundaries, visits = [], Counter()
        with a:
            def trace(uc, address, size, user):
                if any(lo <= address < hi for lo, hi in ranges):
                    visits[address] += 1
                    if not a.uc.reg_read(UC_ARM_REG_PRIMASK):
                        boundaries.append((address, visits[address]))
            a.add_hook(UC_HOOK_CODE, trace)
            a.run(first[0], *first[1])
        assert boundaries
        for boundary, nth in boundaries:
            a, state, submitted = fixture(via, path)
            with a:
                assert a.preempt(first, second, boundary, nth=nth)
                queued = sum(c[0] == T.MOTION_POST for c in a.calls)
                if queued:
                    assert direction != 'callback_report'
                    assert queued == 1
                    a.run(callback[0], *callback[1])
                assert tuple(map(sum, zip(*submitted))) == (110, 220), (
                    direction, via, path, hex(boundary), nth, submitted)
                assert bytes(a.uc.mem_read(T.MOTION_ACC_Y, 4)) == bytes(4)
                assert bytes(a.uc.mem_read(HEAP + 24, 4)) == struct.pack('<hh', 10, 20)
                assert a.byte(T.MOTION_STATE) == state
                assert a.uc.reg_read(UC_ARM_REG_PRIMASK) == 0
                assert all(a.reg(f'r{reg}') == 0x1100 + reg for reg in range(4, 12))
                cases += 1
    return cases
