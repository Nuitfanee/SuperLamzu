"""Reuse FULL timing acceptance; compare MAYA's real native IRQ effects."""
from functools import partial
from types import SimpleNamespace
import struct
import unittest

from unicorn.arm_const import UC_ARM_REG_PRIMASK

from MAYA_X_V2 import target as T
from MAYA_X_V2.advanced import build_radio_settings
from MAYA_X_V2.sensor import LAYOUT
from superlamzu import advanced as A, checks, protocol as P
from superlamzu.emulation import Arm
from superlamzu.verify import patched_image, request


class RadioTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.builder = build_radio_settings()
        cls.changed = patched_image(cls.builder)
        cls.addresses = SimpleNamespace(**{name: getattr(T, name) for name in (
            'ADV_RAM', 'REPORT_TIMER')}, DIVIDER=T.REPORT_DIVIDER,
            TPMS=T.TICKS_PER_MS, RSTATE=T.RADIO_STATE, OFF=A.OFF)

    def fresh(self, builder=None):
        cpu = Arm(self.changed, layout=LAYOUT)
        for base, size in ((0x50080000, 0x10000), (0x500CA000, 0x1000)):
            cpu.uc.mem_map(base, size)
        cpu.uc.mem_map(0xE000E000, 0x1000)
        cpu.uc.mem_write(T.SETTINGS, self.changed.get(T.SETTINGS_DEFAULT, T.SETTINGS_BYTES))
        return cpu

    def test_existing_full_lock_acceptance_matrix(self):
        self.assertEqual(checks.lock_check(self.builder, A=self.addresses, fresh=self.fresh), 9216)

    def test_existing_full_idle_tracking_acceptance_matrix(self):
        self.assertEqual(checks.idle_tracking_check(self.builder, A=self.addresses, T=T,
            fresh=self.fresh, request=partial(request, target=T)), 1125)

    def test_existing_full_release_acceptance_matrix(self):
        self.assertEqual(checks.lock_release_check(self.builder, A=self.addresses,
            fresh=self.fresh, request=partial(request, target=T)), 32)

    def test_native_8k_exception_remains_120_and_cannot_be_owned(self):
        for native in (T.REPORT_RATE_NATIVE, T.REPORT_RATE_FLASH):
            with self.fresh() as cpu:
                cpu.put32(0x200062B0, T.REPORT_TIMER)
                for interval in (125, 250, 500, 1000):
                    cpu.run(native, interval)
                    self.assertEqual(cpu.u32(T.REPORT_TIMER+0x540), 120 if interval==125 else interval)
                    self.assertEqual(cpu.byte(T.TICKS_PER_MS), 1000//interval)
                cpu.run(native, 125)
                cpu.uc.mem_write(T.ADV_RAM+12, b'\1')
                cpu.uc.mem_write(T.REPORT_DIVIDER, b'\1')
                cpu.run(self.builder.symbols['advanced_lock_release'])
                self.assertEqual(cpu.u32(T.REPORT_TIMER+0x540), 120)

    def test_native_irq_events_registers_and_stack_equivalence(self):
        for event in (0, 0x14C, 0x150, 0x154, 0x158):
            results=[]
            for wrapped in (False, True):
                with self.fresh() as cpu:
                    cpu.uc.mem_write(T.ADV_RAM, b'\1'+bytes(187))
                    # Keep the real IRQ and real slot-end. Inactive radio is a
                    # native path; no invented transition or ACK return stub.
                    cpu.uc.mem_write(T.RADIO_STATE, bytes(8))
                    cpu.put32(0x200064F8, T.RADIO_TIMER)
                    if event:
                        cpu.put32(T.RADIO_TIMER+event, 1)
                    for i in range(4,12):
                        cpu.setreg(f'r{i}', 0xA000+i)
                    entry=self.builder.symbols['maya_radio_irq_entry'] if wrapped else 0x20005A60
                    ret=cpu.run(entry)
                    results.append((ret, bytes(cpu.uc.mem_read(T.RADIO_TIMER,0x600)),
                        bytes(cpu.uc.mem_read(T.RADIO_STATE,0x190)),
                        [cpu.reg(f'r{i}') for i in range(4,12)], cpu.reg('sp')))
            self.assertEqual(results[0],results[1],hex(event))

    def test_disabled_radio_bypasses_helpers_with_tracking_selected(self):
        from tools.audit_hotpaths import measure
        for tracking in (0, 1):
            with self.fresh() as cpu:
                cpu.uc.mem_write(T.SMOOTHING_STATE, bytes((tracking << 7,)))
                cpu.stub(T.RADIO_IRQ, 0x12345678)
                entered=[]
                from unicorn import UC_HOOK_CODE
                cpu.add_hook(UC_HOOK_CODE,lambda u,ea,size,user:entered.append(ea))
                result = measure(cpu, self.builder.symbols['advanced_radio_irq'])
                self.assertEqual(cpu.reg('r0'), 0x12345678)
                self.assertEqual(cpu.reg('sp'), T.SP)
                # FULL is diagnostic: count instructions without a speed gate.
                for name in ('advanced_phase_lock', 'advanced_radio_count'):
                    if name in self.builder.symbols:
                        self.assertNotIn(self.builder.symbols[name],entered)

    def test_tracking_protocol_and_primask_preserve_smoothing(self):
        with self.fresh() as cpu:
            cpu.run(self.builder.symbols['advanced_queue_init'],0)
            for mask in (0,1):
                cpu.uc.reg_write(UC_ARM_REG_PRIMASK, mask)
                for selected in (1,0):
                    cpu.uc.mem_write(T.SMOOTHING_STATE,b'\x47')
                    self.assertEqual(request(cpu,P.SET,(0,9,selected),target=T),
                                     (0xA0,bytes((0,9,selected))))
                    self.assertEqual(cpu.byte(T.SMOOTHING_STATE), 0x47|selected<<7)
                    self.assertEqual(cpu.uc.reg_read(UC_ARM_REG_PRIMASK),mask)
            before=bytes(cpu.uc.mem_read(T.SNAPSHOT_POINTER,192))
            for packet in ((1,9),(0,9,2),(0,9,0,0)):
                self.assertEqual(request(cpu,P.SET,packet,target=T)[0],0xA2)
                self.assertEqual(bytes(cpu.uc.mem_read(T.SNAPSHOT_POINTER,192)),before)
            caps=P.decode_capabilities(request(cpu,P.GET,(0,0),target=T)[1])
            self.assertTrue(caps['flags'] & P.F_LOCK)
            self.assertTrue(caps['flags'] & P.F_IDLE_TRACKING)
            self.assertFalse(caps['flags'] & P.F_STATS)

    def test_super_lock_off_skips_stack_frame_and_all_lock_helpers(self):
        from MAYA_X_V2.full import build_pair
        from tools.audit_hotpaths import measure
        builder, _ = build_pair('SUPER')
        for mask in (0, 1):
            with Arm(patched_image(builder), layout=LAYOUT) as cpu:
                cpu.uc.reg_write(UC_ARM_REG_PRIMASK, mask)
                observed = []
                cpu.stub(T.RADIO_IRQ, 0x12345678,
                         effect=lambda c: observed.append((c.reg('sp'), c.reg('r0'))))
                for i in range(4, 12):
                    cpu.setreg(f'r{i}', 0xA000+i)
                result = measure(cpu, builder.symbols['advanced_radio_irq'])
                self.assertEqual(observed, [(T.SP, 0)])
                self.assertEqual(cpu.reg('r0'), 0x12345678)
                self.assertEqual(cpu.reg('sp'), T.SP)
                self.assertEqual(cpu.uc.reg_read(UC_ARM_REG_PRIMASK), mask)
                self.assertEqual([cpu.reg(f'r{i}') for i in range(4, 12)],
                                 [0xA000+i for i in range(4, 12)])
                self.assertLess(result['instructions'], 13)


if __name__ == '__main__':
    unittest.main()
