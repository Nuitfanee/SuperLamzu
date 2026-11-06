"""Real THORN sample publication and native radio-frame consumption checks."""
import itertools
import struct

from . import native_plock as P, target as T
from .common import assemble
from .motion import DIRECT
from .native_clock_checks import IntegratedClockFixture, HEAP
from .native_plock_checks import Timeline


class SampleFixture(IntegratedClockFixture):
    """Reuse the existing Arm, peripheral services and native queue fixtures."""
    def __init__(self, b, *, split, direct, absolute):
        from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_WRITE
        super().__init__(b)
        a = self.a
        a.uc.hook_del(self.integration_guard)
        a._hooks.remove(self.integration_guard)
        def readonly(uc, access, address, size, value, user):
            raise AssertionError(f'write to native MPU read-only code at {address:#x}')
        a.add_hook(UC_HOOK_MEM_WRITE, readonly, begin=0x23000c60, end=0x2300583f)
        self.events, self.bursts, self.consumed = [], [], []
        self.slot_identities = {}
        self.now, self.identity, self.accept_start = 0, None, True
        self.direct, self.absolute = direct, absolute
        def memcpy(cpu):
            cpu.uc.mem_write(cpu.reg('r0'), bytes(cpu.uc.mem_read(cpu.reg('r1'), cpu.reg('r2'))))
            return cpu.reg('r0')
        for fn in (0x0e0877e0, T.RADIO_MEMCPY):
            a.stub(fn, effect=memcpy)
        for q in range(7):
            a.run(0x0e073f0c, q)
        self.queue()
        a.uc.mem_write(T.TRANSPORT_STATE, b'\1')
        a.uc.mem_write(T.RADIO_STATE, b'\1\1\1')
        a.uc.mem_write(T.TICKS_PER_MS, b'\4')
        a.uc.mem_write(T.REPORT_DIVIDER, b'\1')
        a.uc.mem_write(T.ADV_RAM + 2, b'\1')
        a.uc.mem_write(T.ADV_RAM + 4, struct.pack('<H', 80))
        a.uc.mem_write(T.MOTION_STATE, bytes((2 | (DIRECT if direct else 0) | (64 if absolute else 0),)))
        a.uc.mem_write(T.SENSOR_READY, b'\1')
        a.uc.mem_write(0x2300e073, b'\xb7\0')
        a.put32(0x2300ca64, 0)
        a.put32(0x2300ca6c, 0)
        a.put32(T.REPORT_DRIVER, T.REPORT_DRIVER_TABLE)
        a.put32(T.MOTION_CALLBACK, b.symbols['advanced_motion'] | 1)
        a.run(0x0e0847de, T.MOTION_DONE_QUEUE, 0x2300c984, 4, 8)
        if direct:
            a.put32(T.MOTION_DONE_QUEUE, 0x2300a328)
        for site, original, instruction in T.SENSOR_TICK_LDA:
            assert bytes(a.uc.mem_read(site, 4)) == original
            a.uc.mem_write(site, assemble([instruction], site))
        for fn in (0x0e086f6c, 0x0e06ca2c, 0x0e068e38, 0x0e068e70,
                   0x0e0751a8, 0x0e074ce8):
            a.stub(fn)
        a.stub(0x23002134, 1)
        a.stub(0x0e071cbc)
        def burst(cpu):
            assert (cpu.reg('r0'), cpu.reg('r1')) == (22, 6)
            self.bursts.append(self.identity)
            self.events.append(dict(event='spi_start', sample=self.identity, time=self.now))
            return int(self.accept_start)
        a.stub(0x0e06cfe8, effect=burst)
        a.put32(T.REPORT_TIMER + 0x200, 1)
        a.put32(T.REPORT_TIMER + 0x540, 250)
        a.put32(T.REPORT_TIMER + 0x544, 0)
        self.timer = Timeline(a, T.REPORT_TIMER)
        def capture_time(uc, access, address, size, value, user):
            if value:
                assert self.timer.count == self.timer.now - self.timer.origin
        a.add_hook(UC_HOOK_MEM_WRITE, capture_time,
                   begin=T.REPORT_TIMER + 0x48, end=T.REPORT_TIMER + 0x4c)
        if split:
            a.run(b.native_plock['configure'])
            assert a.u32(T.REPORT_TIMER + 0x200) == 2
        def frame(cpu, address, size, user):
            self.frame_destination = cpu.reg('r0')
            q, head = T.RADIO_QUEUE2, cpu.byte(T.RADIO_QUEUE2 + 3)
            if not cpu.byte(q + 1):
                xy = list(struct.unpack('<HH' if absolute else '<hh', cpu.uc.mem_read(q + 10 + head * 12, 4)))
                self.consumed.append(xy)
                self.events.append(dict(event='consume', frame=len(self.consumed),
                                        sample=self.slot_identities.pop(head), xy=xy, time=self.now))
        a.add_hook(UC_HOOK_CODE, lambda u, ad, sz, us: frame(a, ad, sz, us),
                   begin=T.ABS_FRAME_NATIVE, end=T.ABS_FRAME_NATIVE)

    def read(self, identity, *, pending=True, busy=False, fail_start=False):
        from unicorn.arm_const import UC_ARM_REG_IPSR
        self.identity = identity
        self.accept_start = not fail_start
        self.a.put32(0x2300ca6c, int(busy))
        if pending:
            self.a.put32(T.REPORT_TIMER + 0x140, 1)
        self.events.append(dict(event='compare', sample=identity, time=self.now, busy=busy))
        self.a.uc.reg_write(UC_ARM_REG_IPSR, 434)
        self.a.run(0x0e06d09c, count=100000)
        self.a.uc.reg_write(UC_ARM_REG_IPSR, 0)
        self.a.put32(0x2300ca6c, 0)

    def complete(self, dx, dy, *, valid=True):
        from unicorn.arm_const import UC_ARM_REG_IPSR
        a = self.a
        before = a.byte(T.RADIO_QUEUE2 + 2)
        raw = 0x23025000
        a.uc.mem_write(raw, b'\xa0\xb7' + struct.pack('<hh', dx, dy))
        a.uc.reg_write(UC_ARM_REG_IPSR, 437)
        a.run(0x0e07e600, raw, int(valid), count=100000)
        a.uc.reg_write(UC_ARM_REG_IPSR, 0)
        if not self.direct and valid:
            assert a.u32(T.MOTION_DONE_QUEUE + 32) == 1
            a.ends.add(0x0e07e6a6)
            a.run(0x0e07e684, count=100000)
            a.ends.discard(0x0e07e6a6)
            assert a.u32(T.MOTION_DONE_QUEUE + 32) == 0
        after = a.byte(T.RADIO_QUEUE2 + 2)
        if after != before:
            xy = list(struct.unpack('<HH' if self.absolute else '<hh',
                                   a.uc.mem_read(T.RADIO_QUEUE2 + 10 + before * 12, 4)))
            self.events.append(dict(event='publish', sample=self.identity, xy=xy, time=self.now))
            self.slot_identities[before] = self.identity
        return before != after

    def radio(self):
        a = self.a
        a.put32(0x2300bf7c, 10000)
        a.uc.mem_write(T.RADIO_STATE + 0x186, b'\10')
        a.put32(T.RADIO_EVENT, 1)
        self.timer.advance(self.now)
        count = len(self.consumed)
        a.run(self.b.symbols['advanced_radio_irq'], count=200000)
        if len(self.consumed) != count:
            actual = list(struct.unpack('<HH' if self.absolute else '<hh',
                                        a.uc.mem_read(self.frame_destination + 4, 4)))
            assert actual == self.consumed[-1], (actual, self.consumed[-1])
            assert a.byte(self.frame_destination + 2) & 15 == (10 if self.absolute else 2)
        return len(self.consumed) != count


def sample_frames(b):
    records = []
    source = ((19, -7), (-19, 7), (0, 0), (-2, 30), (7, -9), (3, -5)) * 2
    for direct, absolute, backlog in itertools.product((False, True), repeat=3):
        runs = []
        for split in (False, True):
            with SampleFixture(b, split=split, direct=direct, absolute=absolute) as f:
                xy = [0, 0]
                expected, scheduled = [], []
                acquired = completed = reads = 0
                f.timer.now = f.timer.origin = f.timer.count = 0
                f.timer.fired = None
                f.timer.reads.clear()
                for now in range(1, 10001):
                    f.now = now
                    f.timer.advance(now)
                    if len(f.timer.reads) > reads:
                        reads = len(f.timer.reads)
                        assert acquired < len(source), (split, direct, absolute, backlog, acquired)
                        identity = acquired
                        f.read(identity, pending=False)
                        assert f.bursts[-1] == identity
                        prior = len(f.bursts)
                        f.read(identity, pending=False)
                        assert len(f.bursts) == prior
                        scheduled.append((now + 20, identity))
                        acquired += 1
                    if scheduled and scheduled[0][0] == now:
                        _, identity = scheduled.pop(0)
                        f.identity = identity
                        dx, dy = source[identity]
                        published = f.complete(dx, dy)
                        completed += 1
                        xy = [(xy[0] + dx) & 65535, (xy[1] + dy) & 65535]
                        if published:
                            expected.append(xy[:] if absolute else [dx, dy])
                    # Both controllers see the same native wireless slot times.
                    if now >= (725 if backlog else 100) and (now - 100) % 125 == 0:
                        f.radio()
                    if completed == len(source) and f.a.byte(T.RADIO_QUEUE2 + 1):
                        break
                else:
                    raise AssertionError('native sample queue did not drain')
                assert completed == acquired == len(source)
                assert f.consumed == expected, (split, direct, absolute, backlog, f.consumed, expected)
                for order, event in enumerate(f.events):
                    event['order'] = order
                published = [e for e in f.events if e['event'] == 'publish']
                consumed = [e for e in f.events if e['event'] == 'consume']
                assert len(published) == len(consumed)
                for frame, (pub, con) in enumerate(zip(published, consumed), 1):
                    assert pub['sample'] == con['sample'] and pub['xy'] == con['xy'] and pub['order'] < con['order'] and pub['time'] <= con['time'], (
                        split, direct, absolute, backlog, pub, con)
                    assert con['frame'] == frame
                if absolute:
                    assert bytes(f.a.uc.mem_read(HEAP + 24, 4)) == struct.pack('<HH', *xy)
                if split:
                    flags = f.a.byte(HEAP + P.CONTROL_OFFSET + P.FLAGS)
                    assert flags & P.CALIBRATED, flags
                    assert f.timer.tasks.count(12) > 1, f.timer.tasks
                runs.append(dict(split=split, events=f.events, output=f.consumed,
                                 clear_tasks=f.timer.tasks.count(12),
                                 compare_times=f.timer.reads))
        assert runs[0]['output'] == runs[1]['output']
        old = [event for event in runs[0]['events'] if event['event'] == 'consume']
        new = [event for event in runs[1]['events'] if event['event'] == 'consume']
        assert [event['sample'] for event in old] == [event['sample'] for event in new]
        assert all(current['time'] <= previous['time'] for previous, current in zip(old, new)), (
            direct, absolute, backlog, [event['time'] for event in old],
            [event['time'] for event in new])
        records.append(dict(direct=direct, absolute=absolute, backlog=backlog, runs=runs))
    return records


def pending_and_failure(b):
    results = []
    for direct in (False, True):
        with SampleFixture(b, split=False, direct=direct, absolute=True) as f:
            f.a.put32(T.REPORT_TIMER + 0x140, 1)
            # The real configuration migration preserves an already-due read.
            f.a.run(b.native_plock['configure'])
            assert f.a.u32(T.REPORT_TIMER + 0x140) == 1
            f.read(0, pending=False)
            assert f.bursts == [0] and f.a.u32(T.REPORT_TIMER + 0x140) == 0
            f.read(0, pending=False)
            assert f.bursts == [0]
            f.now = 20
            assert f.complete(11, -3)
            f.now = 70
            assert f.radio()
            count = len(f.consumed)
            f.now = 170
            f.read(1, busy=True)
            assert f.bursts == [0]
            f.now = 270
            f.read(2)
            assert f.bursts == [0, 2]
            assert f.complete(23, 17, valid=False) is False
            f.now = 320
            f.radio()
            assert len(f.consumed) == count
            assert bytes(f.a.uc.mem_read(HEAP + 24, 4)) == struct.pack('<hh', 11, -3)
            f.now = 670
            f.read(4)
            f.now = 690
            assert f.complete(-11, 3)
            f.now = 725
            assert f.radio()
            assert f.consumed[-1] == [0, 0]
            results.append(dict(direct=direct, events=f.events, output=f.consumed))
        with SampleFixture(b, split=True, direct=direct, absolute=True) as f:
            f.read(0, fail_start=True)
            assert f.bursts == [0]
            assert f.a.u32(T.REPORT_TIMER + 0x140) == 0
            f.now = 100
            assert not f.radio()
            assert bytes(f.a.uc.mem_read(HEAP + 24, 4)) == bytes(4)
            results.append(dict(direct=direct, failure='SPI start rejected',
                                events=f.events, output=f.consumed))
    return results


def verify(b):
    from .mouse_abs_checks import retransmit_order_check
    samples = sample_frames(b)
    pending = pending_and_failure(b)
    return dict(sample_scenarios=len(samples) * 2, pending_failure_scenarios=len(pending),
                retransmit_order=retransmit_order_check(b),
                service_boundary='existing timer MMIO advances actual compare/CLEAR state; async SPI completion is +20 fixture units; native report, decode, queue, slot and frame execute',
                samples=samples, pending=pending, result='PASS')
