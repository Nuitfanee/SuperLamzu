"""SUPER production timer/configuration hooks and real sampled frame ordering."""
import struct
import unittest

from unicorn import UC_HOOK_MEM_WRITE
from unicorn.arm_const import UC_ARM_REG_PRIMASK

from MAYA_X_V2 import target as T
from MAYA_X_V2.full import build_pair
from MAYA_X_V2.sensor import LAYOUT
from superlamzu import native_plock as P, native_plock_checks as C, protocol
from superlamzu.emulation import Arm
from superlamzu.verify import patched_image, request


HEAP = T.NATIVE_HEAP_START + 0x404


class NativeTimingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.builder, cls.receiver = build_pair('SUPER')
        cls.changed = patched_image(cls.builder)
        cls.control = cls.builder.advanced['hooks']['plock']
        cls.timing = cls.builder.advanced['hooks']['timing']

    def cpu(self):
        cpu = Arm(self.changed, layout=LAYOUT)
        cpu.uc.mem_map(0xE000E000, 0x1000)
        cpu.uc.mem_map(0x50080000, 0x10000)
        cpu.uc.mem_map(T.REPORT_TIMER, 0x1000)
        cpu.uc.mem_write(T.SETTINGS, self.changed.get(T.SETTINGS_DEFAULT, T.SETTINGS_BYTES))
        cpu.uc.mem_write(T.SNAPSHOT_POINTER, (HEAP & 0xFFFFF).to_bytes(3, 'little'))
        cpu.uc.mem_write(T.ADV_RAM, b'\1' + bytes(187))
        cpu.uc.mem_write(T.REPORT_TRANSPORT, b'\1')
        cpu.uc.mem_write(T.REPORT_DIVIDER, b'\1')
        cpu.uc.mem_write(T.TICKS_PER_MS, b'\4')
        cpu.put32(T.REPORT_TIMER_POINTER, T.REPORT_TIMER)
        cpu.put32(T.REPORT_IRQ_ENABLE, T.REPORT_IRQ_MASK)
        cpu.put32(T.REPORT_TIMER + 0x200, 1)
        cpu.put32(T.REPORT_TIMER + 0x540, 250)
        cpu.put32(T.REPORT_TIMER + 0x304, 1 << 16)

        # The native NVIC helpers execute. Only MMIO's write-one clear action
        # needs an explicit fixture because Unicorn treats it as ordinary RAM.
        def nvic(uc, access, address, size, value, user):
            if address == T.REPORT_IRQ_ENABLE + 0x80:
                cpu.put32(T.REPORT_IRQ_ENABLE, cpu.u32(T.REPORT_IRQ_ENABLE) & ~value)
        cpu.add_hook(UC_HOOK_MEM_WRITE, nvic, begin=T.REPORT_IRQ_ENABLE + 0x80,
                     end=T.REPORT_IRQ_ENABLE + 0x83)
        cpu.timeline = C.Timeline(cpu, T.REPORT_TIMER)
        return cpu

    def test_installed_shared_thumb_phase_and_timer_contracts(self):
        counts = C.run_checks(self.builder, self.control, target=T, layout=LAYOUT)
        self.assertEqual(counts, dict(apply=245, phase=42, radio=5, timeline=19, native_layouts=3))
        self.assertEqual(C.native_radio_check(self.builder, self.control, target=T, layout=LAYOUT), 5)

    def test_real_set_eligibility_edges_and_repeated_apply(self):
        for period in (250, 500, 1000):
            for lead in (0, 1, period // 2 - 9, period // 2 - 8,
                         period // 2 - 7, period // 2 - 1, period // 2, 499):
                if lead > 499:
                    continue
                for mask in (0, 1):
                    with self.subTest(period=period, lead=lead, mask=mask), self.cpu() as cpu:
                        cpu.uc.reg_write(UC_ARM_REG_PRIMASK, mask)
                        cpu.uc.mem_write(T.TICKS_PER_MS, bytes((1000 // period,)))
                        cpu.put32(T.REPORT_TIMER + 0x540, period)
                        cpu.put32(T.REPORT_TIMER + 0x140, 1)
                        result = request(cpu, protocol.SET, (0, 3, 1, lead & 255, lead >> 8), target=T)
                        self.assertEqual(result[0], 0xA0)
                        split = (lead or 80) <= period // 2 - 8
                        self.assertEqual(cpu.u32(T.REPORT_TIMER + 0x200), 2 if split else 1)
                        self.assertEqual(bool(cpu.byte(HEAP + P.CONTROL_OFFSET + 7) & P.SPLIT), split)
                        self.assertEqual(cpu.u32(T.REPORT_TIMER + 0x140), 1)
                        self.assertEqual(cpu.uc.reg_read(UC_ARM_REG_PRIMASK), mask)
                        before = bytes(cpu.uc.mem_read(HEAP + P.CONTROL_OFFSET, 8))
                        tasks = len(cpu.timeline.tasks)
                        request(cpu, protocol.SET, (0, 3, 1, lead & 255, lead >> 8), target=T)
                        self.assertEqual(len(cpu.timeline.tasks), tasks)
                        self.assertEqual(bytes(cpu.uc.mem_read(HEAP + P.CONTROL_OFFSET, 8)), before)
                        self.assertEqual(request(cpu, protocol.SET, (0, 3, 0, 80, 0), target=T)[0], 0xA0)
                        self.assertEqual(cpu.u32(T.REPORT_TIMER + 0x200), 1)
                        self.assertEqual(cpu.u32(T.REPORT_TIMER + 0x540), period)
                        self.assertEqual(cpu.u32(T.REPORT_TIMER + 0x140), 1)

    def test_native_timer_veneers_zero_rate_8k_stop_and_restart(self):
        with self.cpu() as cpu:
            for mask in (0, 1):
                cpu.uc.reg_write(UC_ARM_REG_PRIMASK, mask)
                self.assertEqual(request(cpu, protocol.SET, (0, 3, 1, 80, 0), target=T)[0], 0xA0)
                for period in (0, 125, 250, 333, 500, 1000):
                    before = len(cpu.timeline.tasks)
                    self.assertEqual(cpu.run(T.REPORT_RATE_VENEER, period), period)
                    if not period:
                        self.assertEqual(len(cpu.timeline.tasks), before)
                        continue
                    split = period in (250, 500, 1000)
                    self.assertEqual(cpu.u32(T.REPORT_TIMER + 0x540),
                                     period - 80 if split else 120 if period == 125 else period)
                    self.assertEqual(cpu.u32(T.REPORT_TIMER + 0x200), 2 if split else 1)
                    self.assertEqual(cpu.byte(T.TICKS_PER_MS), 1000 // period)
                    self.assertEqual(cpu.uc.reg_read(UC_ARM_REG_PRIMASK), mask)
                    if period == 333:
                        before = len(cpu.timeline.tasks)
                        request(cpu, protocol.SET, (0, 3, 1, 80, 0), target=T)
                        self.assertEqual(len(cpu.timeline.tasks), before)
                        self.assertEqual(cpu.u32(T.REPORT_TIMER + 0x540), 333)
                cpu.run(T.REPORT_STOP_VENEER)
                self.assertEqual(cpu.u32(T.REPORT_IRQ_ENABLE) & T.REPORT_IRQ_MASK, 0)
                self.assertFalse(cpu.timeline.running)
                self.assertEqual(cpu.u32(T.REPORT_TIMER + 0x540), 0)
                self.assertEqual(bytes(cpu.uc.mem_read(HEAP + P.CONTROL_OFFSET, 8)), bytes(8))
                cpu.run(self.timing['setting'])
                self.assertFalse(cpu.timeline.running)
                cpu.run(T.REPORT_INIT_VENEER)
                self.assertEqual(cpu.u32(T.REPORT_TIMER + 0x200), 2)
                self.assertEqual(cpu.u32(T.REPORT_TIMER + 0x540), 920)
                self.assertEqual(cpu.u32(T.REPORT_TIMER + 0x544), 1000)
                self.assertEqual(cpu.u32(T.REPORT_TIMER + 0x508), 0)
                self.assertEqual(cpu.u32(T.REPORT_TIMER + 0x510), 4)
                self.assertEqual(cpu.u32(T.REPORT_TIMER + 0x304), 1 << 16)
                self.assertTrue(cpu.timeline.running)
                self.assertEqual(cpu.uc.reg_read(UC_ARM_REG_PRIMASK), mask)

    def test_wired_configuration_restores_legacy_without_changing_saved_lock(self):
        with self.cpu() as cpu:
            request(cpu, protocol.SET, (0, 3, 1, 80, 0), target=T)
            self.assertEqual(cpu.u32(T.REPORT_TIMER + 0x200), 2)
            cpu.uc.mem_write(T.REPORT_TRANSPORT, b'\0')
            cpu.run(T.REPORT_RATE_VENEER, 250)
            self.assertEqual(cpu.u32(T.REPORT_TIMER + 0x200), 1)
            self.assertEqual(cpu.u32(T.REPORT_TIMER + 0x540), 250)
            self.assertEqual(cpu.byte(T.ADV_RAM + 2), 1)
            cpu.uc.mem_write(T.REPORT_TRANSPORT, b'\1')
            cpu.run(T.REPORT_RATE_VENEER, 250)
            self.assertEqual(cpu.u32(T.REPORT_TIMER + 0x200), 2)

    def test_repeated_queue0_reuses_heap_and_done_runtime_and_restores_layout(self):
        with self.cpu() as cpu:
            cpu.uc.mem_map(0x110000, 0x1000)
            cpu.uc.mem_write(T.ADV_STORAGE, b'\xff' * 16)
            request(cpu, protocol.SET, (0, 3, 1, 80, 0), target=T)
            self.assertEqual(cpu.u32(T.REPORT_TIMER + 0x200), 2)
            cpu.uc.mem_write(HEAP, b'\xa5' * T.SNAPSHOT_STORAGE_BYTES)
            cpu.put32(HEAP + T.MOTION_RING_OFFSET + 4, 0x20020000)
            cpu.uc.mem_write(T.MOTION_STATE, bytes((cpu.byte(T.MOTION_STATE) | 0xf0,)))
            cpu.stub(T.NATIVE_ALLOC, effect=lambda c: self.fail('published heap was lost'))
            cpu.stub(T.SET_SENSOR_MODE)
            cpu.run(self.builder.advanced['init'], 0, count=100000)
            self.assertEqual(int.from_bytes(cpu.uc.mem_read(T.SNAPSHOT_POINTER, 3), 'little') & 0xfffff,
                             HEAP & 0xfffff)
            self.assertEqual(cpu.byte(T.MOTION_STATE) & 0xf0, 0x10)
            self.assertEqual(bytes(cpu.uc.mem_read(HEAP, 28)), b'\1' + bytes(27))
            self.assertEqual(bytes(cpu.uc.mem_read(HEAP + P.CONTROL_OFFSET, 8)), bytes(8))
            self.assertEqual(bytes(cpu.uc.mem_read(HEAP + T.CHAN_OFFSET, T.CHAN_BYTES)), bytes(T.CHAN_BYTES))
            self.assertEqual(cpu.u32(HEAP + T.MOTION_RING_OFFSET), 0)
            self.assertEqual(cpu.u32(HEAP + T.MOTION_RING_OFFSET + 4), 0x20020000)
            self.assertEqual(bytes(cpu.uc.mem_read(HEAP + 28, 280)), b'\xa5' * 280)
            self.assertEqual(cpu.u32(T.REPORT_TIMER + 0x200), 1)
            self.assertEqual(cpu.u32(T.REPORT_TIMER + 0x540), 250)

    def test_pending_read_survives_set_and_real_irq_consumes_once(self):
        from MAYA_X_V2.tests.test_motion import MotionTests
        fixture = MotionTests()
        fixture.builder, fixture.changed = self.builder, self.changed
        with fixture.registered_cpu(1, 1, 'xy') as cpu:
            cpu.uc.mem_map(0xE000E000, 0x1000)
            cpu.uc.mem_map(T.REPORT_TIMER, 0x1000)
            cpu.put32(T.REPORT_TIMER_POINTER, T.REPORT_TIMER)
            cpu.put32(T.REPORT_IRQ_ENABLE, T.REPORT_IRQ_MASK)
            cpu.uc.mem_write(T.REPORT_TRANSPORT, b'\1')
            cpu.uc.mem_write(T.TICKS_PER_MS, b'\4')
            cpu.put32(T.REPORT_TIMER + 0x540, 250)
            cpu.put32(T.REPORT_TIMER + 0x200, 1)
            cpu.put32(T.REPORT_TIMER + 0x140, 1)
            request(cpu, protocol.SET, (0, 3, 1, 80, 0), target=T)
            self.assertEqual(cpu.u32(T.REPORT_TIMER + 0x140), 1)
            cpu.run(0x2007B008, count=100000)
            self.assertEqual(cpu.u32(T.REPORT_TIMER + 0x140), 0)
            self.assertEqual([v['xy'] for v in cpu.submits], [(123, -45)])
            cpu.run(0x2007B008, count=100000)
            self.assertEqual([v['xy'] for v in cpu.submits], [(123, -45)])
            self.assertEqual(len(cpu.bursts), 1)

    def test_storage_failure_keeps_active_legacy_lock(self):
        with self.cpu() as cpu:
            cpu.uc.mem_write(T.SNAPSHOT_POINTER, b'\0\0\x10')
            cpu.stub(0x3089E, 0)
            self.assertEqual(request(cpu, protocol.SET, (0, 3, 1, 80, 0), target=T)[0], 0xA0)
            self.assertEqual(cpu.u32(T.REPORT_TIMER + 0x200), 1)
            cpu.uc.mem_write(T.RADIO_STATE, b'\1\1\1')
            cpu.uc.mem_write(T.RADIO_STATE + 0x186, b'\10')
            cpu.put32(T.RADIO_EVENT, 1)
            cpu.timeline.count = 40
            cpu.stub(T.RADIO_IRQ, effect=lambda c: c.uc.mem_write(T.RADIO_STATE + 0x186, b'\4') or 0)
            before = len(cpu.calls)
            cpu.run(self.builder.symbols['advanced_radio_irq'])
            self.assertEqual(cpu.u32(T.REPORT_TIMER + 0x540), 210)
            self.assertEqual(cpu.byte(T.ADV_RAM + 12), 1)
            self.assertFalse(any(fn in (T.NATIVE_ALLOC, 0x3089E) for fn, _, _ in cpu.calls[before:]))

    def test_native_read_irq_publishes_before_actual_wireless_frame_consumes(self):
        from MAYA_X_V2.tests.test_motion import MotionTests
        from unicorn import UC_HOOK_CODE
        fixture = MotionTests()
        fixture.builder, fixture.changed = self.builder, self.changed
        for direct in (0, 1):
            for absolute, dual in ((False, False), (True, False), (False, True), (True, True)):
                with self.subTest(direct=direct, absolute=absolute, dual=dual), fixture.registered_cpu(1, direct, 'xy') as cpu:
                    cpu.uc.mem_map(0xE000E000, 0x1000)
                    cpu.uc.mem_map(0x50080000, 0x10000)
                    cpu.uc.mem_map(T.REPORT_TIMER, 0x1000)
                    cpu.put32(T.REPORT_TIMER_POINTER, T.REPORT_TIMER)
                    cpu.put32(0x200064F8, T.RADIO_TIMER)
                    cpu.put32(T.REPORT_IRQ_ENABLE, T.REPORT_IRQ_MASK)
                    cpu.put32(0x2000C3E8, 10000)
                    cpu.uc.mem_write(T.REPORT_TRANSPORT, b'\1')
                    cpu.uc.mem_write(T.TICKS_PER_MS, b'\4')
                    cpu.uc.mem_write(T.RADIO_STATE, b'\1\1\1')
                    cpu.uc.mem_write(0x2000EA51, b'\x10' if dual else b'\1')
                    cpu.uc.mem_write(T.MOTION_STATE, bytes((cpu.byte(T.MOTION_STATE) | (64 if absolute else 0),)))
                    cpu.stubs.pop(T.RADIO_SEND)
                    cpu.stub(T.NATIVE_MEMCPY, effect=lambda c: c.uc.mem_write(c.reg('r0'),
                             bytes(c.uc.mem_read(c.reg('r1'), c.reg('r2')))) or c.reg('r0'))
                    for q in range(7):
                        cpu.run(T.QUEUE_INIT, q)
                    cpu.put32(T.REPORT_TIMER + 0x540, 250)
                    cpu.put32(T.REPORT_TIMER + 0x200, 1)
                    timeline = C.Timeline(cpu, T.REPORT_TIMER)
                    self.assertEqual(request(cpu, protocol.SET, (0, 3, 1, 80, 0), target=T)[0], 0xA0)
                    self.assertEqual(cpu.u32(T.REPORT_TIMER + 0x200), 2)
                    events, frames = [], []
                    def event(uc, address, size, user):
                        if address == T.RADIO_SEND:
                            events.append(('publish', timeline.now))
                        elif address == T.ABS_FRAME_NATIVE:
                            events.append(('frame', timeline.now))
                    cpu.add_hook(UC_HOOK_CODE, event)
                    samples = 2 if dual else 1
                    for i in range(6):
                        for j in range(samples):
                            read_at = timeline.origin + cpu.u32(T.REPORT_TIMER + 0x540)
                            while read_at <= timeline.now:
                                read_at += 250
                            timeline.advance(read_at)
                            self.assertEqual(cpu.u32(T.REPORT_TIMER + 0x140), 1)
                            cpu.run(0x2007B008, count=100000)
                            self.assertEqual(cpu.u32(T.REPORT_TIMER + 0x140), 0)
                            if not direct:
                                cpu.run(self.builder.motion['drain'], count=100000)
                            self.assertEqual(cpu.run(T.QUEUE_COUNT, 2), j + 1)
                        timeline.advance(230 + 250 * (samples * (i + 1) - 1))
                        cpu.uc.mem_write(T.RADIO_STATE + 0x186, b'\10')
                        cpu.put32(T.RADIO_EVENT, 1)
                        cpu.run(self.changed.u32(T.RADIO_VECTOR) & ~1, count=200000)
                        self.assertEqual(cpu.byte(T.RADIO_STATE + 0x186), 4)
                        self.assertEqual(cpu.run(T.QUEUE_COUNT, 2), 0)
                        frame = bytes(cpu.uc.mem_read(T.ABS_FRAME_BUFFER, 4 + 4 * samples))
                        frames.extend(struct.unpack('<HH' if absolute else '<hh', frame[4 + 4 * j:8 + 4 * j])
                                      for j in range(samples))
                    expected = [((123 * (i + 1)) & 65535, (-45 * (i + 1)) & 65535)
                                if absolute else (123, -45) for i in range(6 * samples)]
                    self.assertEqual(frames, expected)
                    self.assertEqual([kind for kind, now in events], (['publish'] * samples + ['frame']) * 6)
                    self.assertTrue(all(events[(samples + 1) * i + j][1] <
                                        events[(samples + 1) * i + samples][1]
                                        for i in range(6) for j in range(samples)))
                    gaps = [b - a for a, b in zip(timeline.reads, timeline.reads[1:])]
                    self.assertTrue(all(170 <= gap < 420 for gap in gaps))
                    self.assertEqual(len(cpu.bursts), 6 * samples)
                    self.assertTrue(cpu.byte(HEAP + P.CONTROL_OFFSET + 7) & P.CALIBRATED)


if __name__ == '__main__':
    unittest.main()
