"""Resource ownership checks; no hardware, no skipped instruction checks."""
import gc
import unittest
import weakref
from unittest.mock import patch

from unicorn import Uc, UcError, UC_HOOK_MEM_WRITE

from superlamzu.emulation import Arm, sensor_run
from superlamzu.hexfile import Image
from superlamzu import target


class EmulationLifetimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = Image(target.STOCK)

    def test_context_releases_engine_and_all_hooks(self):
        with Arm(self.image) as cpu:
            engine = weakref.ref(cpu.uc)
            cpu.add_hook(UC_HOOK_MEM_WRITE, lambda *args: None,
                         begin=0x23000000, end=0x23000003)
            self.assertIs(cpu.image, self.image)
        self.assertIsNone(cpu.uc)
        self.assertIsNone(engine())
        cpu.close()  # Explicit cleanup is safe after context exit.

    def test_exception_also_releases_engine(self):
        with self.assertRaisesRegex(ValueError, 'case failed'):
            with Arm(self.image) as cpu:
                engine = weakref.ref(cpu.uc)
                raise ValueError('case failed')
        self.assertIsNone(engine())

    def test_repeated_cases_do_not_need_automatic_gc(self):
        was_enabled = gc.isenabled()
        gc.disable()
        try:
            for _ in range(12):
                with Arm(self.image) as cpu:
                    engine = weakref.ref(cpu.uc)
                    cpu.stub(target.WR, 1)
                    self.assertEqual(cpu.run(target.WR), 1)
                self.assertIsNone(engine())
        finally:
            if was_enabled:
                gc.enable()

    def test_spi_runner_releases_success_and_failure(self):
        engines = []
        def create(*args, **kwargs):
            uc = Uc(*args, **kwargs)
            engines.append(weakref.ref(uc))
            return uc
        with patch('superlamzu.emulation.Uc', side_effect=create):
            log = sensor_run(self.image, target.WR, target.WR, target.RD)
            self.assertEqual(len(log), 1)
            self.assertIsNone(engines[-1]())
            with self.assertRaises(UcError):
                sensor_run(self.image, 0, target.WR, target.RD)
            self.assertIsNone(engines[-1]())

    def test_preempt_uses_another_stack_and_restores_registers(self):
        from superlamzu.common import assemble
        first, second = 0x23026000, 0x23026100
        with Arm(self.image) as cpu:
            cpu.uc.mem_write(first,assemble(['push {r4,lr}','movs r4,#17',
                'nop','mov r0,r4','pop {r4,pc}'],first))
            cpu.uc.mem_write(second,assemble(['push {r4,lr}','movs r4,#29',
                'str r4,[r0]','pop {r4,pc}'],second))
            cpu.setreg('r4',0x12345678)
            self.assertTrue(cpu.preempt((first,()),(second,(0x23026200,)),first+4))
            self.assertEqual(cpu.reg('r0'),17)
            self.assertEqual(cpu.reg('r4'),0x12345678)
            self.assertEqual(cpu.reg('sp'),0x23030000)
            self.assertEqual(cpu.u32(0x23026200),29)
            self.assertFalse(cpu.preempt((first,()),(second,()),first+0x40))

    def test_preempt_rejects_masked_or_stub_boundaries(self):
        from superlamzu.common import assemble
        from unicorn.arm_const import UC_ARM_REG_PRIMASK
        entry=0x23026000
        with Arm(self.image) as cpu:
            cpu.uc.mem_write(entry,assemble(['nop','bx lr'],entry))
            cpu.uc.reg_write(UC_ARM_REG_PRIMASK,1)
            with self.assertRaisesRegex(AssertionError,'masked'):
                cpu.preempt((entry,()),(entry,()),entry)
            cpu.uc.reg_write(UC_ARM_REG_PRIMASK,0)
            self.assertEqual(cpu.run(entry),cpu.reg('r0'))
            cpu.stub(entry)
            with self.assertRaisesRegex(ValueError,'callsite'):
                cpu.preempt((entry,()),(entry,()),entry)

    def test_preempt_respects_non_thorn_memory_layout(self):
        from superlamzu.common import assemble
        from superlamzu.emulation import MemoryLayout
        layout=MemoryLayout(ram_regions=((0x20000000,0x40000),),
                            stack=0x20016AF0,stop=0x2003F000)
        first,second,result=0x20010000,0x20010100,0x20010200
        with Arm(self.image,layout=layout) as cpu:
            cpu.uc.mem_write(first,assemble(['push {r4,lr}','movs r4,#17',
                'nop','mov r0,r4','pop {r4,pc}'],first))
            cpu.uc.mem_write(second,assemble(['mov r1,sp','str r1,[r0]',
                'bx lr'],second))
            self.assertTrue(cpu.preempt((first,()),(second,(result,)),first+4))
            self.assertEqual(cpu.reg('r0'),17)
            self.assertEqual(cpu.reg('sp'),layout.stack)
            self.assertEqual(cpu.u32(result),layout.stack-0x8000)
