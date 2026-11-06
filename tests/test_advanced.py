"""Discover the same FULL verification checks used by the builder."""
import unittest

from superlamzu.patch import build
from superlamzu.checks import (
    queue_boundary_check,
    initialization_check,
    native_send_check,
    protocol_check,
    fps_check,
    fps_publish_interleaves,
    fps_readback_failure_check,
    custom_fps_check,
    sensor_snapshot_check,
    sensor_snapshot_cpi_check,
    worker_check,
    tick_check,
    lock_check,
    idle_tracking_check,
    lock_release_check,
    radio_check,
    native_radio_check,
    wrapper_check,
)


class AdvancedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.b=build('SUPER')
    def test_initialization(self):initialization_check(self.b)
    def test_queue_boundary(self):queue_boundary_check(self.b)
    def test_protocol(self):protocol_check(self.b)
    def test_fps(self):fps_check(self.b)
    def test_fps_atomic_publication(self):fps_publish_interleaves(self.b)
    def test_preset_fps_readback_failures_and_retry(self):
        self.assertEqual(fps_readback_failure_check(self.b), 24)
    def test_custom_fps(self):custom_fps_check(self.b)
    def test_sensor_snapshot(self):sensor_snapshot_check(self.b)
    def test_sensor_snapshot_preserves_native_cpi_axes(self):
        self.assertEqual(sensor_snapshot_cpi_check(self.b), 4)
    def test_snapshot_reply_word_copy_is_atomic_bounded_and_mask_preserving(self):
        from unicorn import UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
        from unicorn.arm_const import UC_ARM_REG_PRIMASK
        from superlamzu import protocol as P, target as T
        from superlamzu.checks import fresh
        from superlamzu.verify import request
        from tools.audit_hotpaths import measure

        snap = 0x23024004
        record = bytes((i * 17 + 3) & 255 for i in range(24))
        for profile, builder in (('SUPER', self.b),):
            for present in (False, True):
                for mask in (0, 1):
                    with self.subTest(profile=profile, present=present, mask=mask), fresh(builder) as cpu:
                        cpu.uc.mem_write(T.SNAPSHOT_POINTER,
                            ((snap & 0xFFFFF) if present else 0).to_bytes(3, 'little'))
                        cpu.uc.mem_write(snap - 4, b'\xa5' * 4 + record + b'\xa5' * 4)
                        cpu.uc.reg_write(UC_ARM_REG_PRIMASK, mask)
                        reads, writes = [], []
                        def observed(uc, access, address, size, value, user):
                            self.assertEqual(uc.reg_read(UC_ARM_REG_PRIMASK), 1)
                            (reads if snap <= address < snap + 24 else writes).append((address, size))
                        cpu.add_hook(UC_HOOK_MEM_READ, observed, begin=snap, end=snap + 23)
                        cpu.add_hook(UC_HOOK_MEM_WRITE, observed, begin=T.PACKET + 8, end=T.PACKET + 31)
                        expected = record if present else b'\1' + bytes(23)
                        self.assertEqual(request(cpu, P.GET, (0, 6)), (0xA0, b'\0\6' + expected))
                        self.assertEqual(reads, [(snap + off, 4) for off in range(0, 24, 4)] if present else [])
                        expected_writes = [(T.PACKET + 8 + off, 4) for off in range(0, 24, 4)]
                        if not present:expected_writes.append((T.PACKET + 8, 1))
                        self.assertEqual(writes, expected_writes)
                        self.assertEqual(cpu.uc.reg_read(UC_ARM_REG_PRIMASK), mask)
                        self.assertEqual(bytes(cpu.uc.mem_read(snap - 4, 32)), b'\xa5' * 4 + record + b'\xa5' * 4)
                        reads.clear();writes.clear()
                        for body in ((1, 6), (0, 6, 0)):
                            self.assertEqual(request(cpu, P.GET, body)[0], 0xA2)
                        self.assertEqual((reads, writes), ([], []))
                        if mask == 0:
                            packet = bytearray(64)
                            packet[0] = 0xA0
                            packet[3:8] = bytes((2, 1, P.GET, 0, 6))
                            cpu.uc.mem_write(T.PACKET, bytes(packet))
                            result = measure(cpu, T.GROUP1)
                            self.assertLessEqual(result['longest_masked_instruction_run'], 40)
    def test_lock(self):lock_check(self.b)
    def test_super_lock_off_skips_frame_preserving_native_irq_contract(self):
        from unicorn import UC_HOOK_CODE
        from unicorn.arm_const import UC_ARM_REG_PRIMASK
        from superlamzu import advanced as A, target as T
        from superlamzu.checks import fresh, Timer
        from tools.audit_hotpaths import measure

        builder = build('SUPER')
        for mask in (0, 1):
            for tracking in (0, 1):
                with self.subTest(mask=mask, tracking=tracking), fresh(builder) as cpu:
                    cpu.uc.mem_write(T.SMOOTHING_STATE, bytes((tracking << 7,)))
                    cpu.uc.reg_write(UC_ARM_REG_PRIMASK, mask)
                    calls, entered = [], []
                    def native(c):
                        calls.append((c.reg('r0'), c.reg('sp')))
                        return 0x12345678
                    cpu.stub(A.IRQ, effect=native)
                    cpu.add_hook(UC_HOOK_CODE,
                        lambda uc, address, size, user: entered.append(address))
                    for reg in range(4, 12):
                        cpu.setreg(f'r{reg}', 0xA000 + reg)
                    cost = measure(cpu, builder.symbols['advanced_radio_irq'])
                    self.assertEqual(calls, [(0, cpu.layout.stack)])
                    self.assertEqual(cpu.reg('r0'), 0x12345678)
                    self.assertEqual(cpu.reg('sp'), cpu.layout.stack)
                    self.assertEqual([cpu.reg(f'r{reg}') for reg in range(4, 12)],
                                     [0xA000 + reg for reg in range(4, 12)])
                    self.assertEqual(cpu.uc.reg_read(UC_ARM_REG_PRIMASK), mask)
                    self.assertNotIn(builder.symbols['advanced_phase_lock'], entered)
                    self.assertLessEqual(cost['instructions'], 8)
        with fresh(builder) as cpu:
            cpu.uc.mem_write(A.ADV_RAM, b'\1\0\1\0' + bytes(184))
            cpu.uc.mem_write(A.ADV_RAM + 4, (80).to_bytes(2, 'little'))
            cpu.uc.mem_write(A.RSTATE + 1, b'\1\1')
            cpu.uc.mem_write(A.RSTATE + 0x186, b'\x08')
            cpu.uc.mem_write(A.DIVIDER, b'\1')
            cpu.uc.mem_write(A.TPMS, b'\4')
            cpu.put32(A.RADIO_EVENT, 1)
            cpu.put32(A.REPORT_TIMER + 0x540, 250)
            timer = Timer(cpu)
            timer.count = 100
            cpu.stub(A.IRQ,
                effect=lambda c: c.uc.mem_write(A.RSTATE + 0x186, b'\4') or 0)
            cost = measure(cpu, builder.symbols['advanced_radio_irq'])
            self.assertEqual(timer.captures, 1)
    def test_idle_tracking(self):idle_tracking_check(self.b)
    def test_radio(self):radio_check(self.b)
    def test_wrappers(self):
        for name in ('advanced_burst', 'advanced_spi_done', 'advanced_reinit'):
            self.assertNotIn(name, self.b.symbols)
    def test_native_send(self):native_send_check(self.b)
    def test_worker_paths(self):worker_check(self.b)
    def test_tick(self):self.assertNotIn('advanced_tick', self.b.symbols)
    def test_native_radio(self):native_radio_check(self.b)
    def test_lock_disable(self):lock_release_check(self.b)


if __name__=='__main__':unittest.main()
