"""Real MAYA SOF -> cross-domain DPPI -> TIMER20 CLEAR instructions.

No phase sampler is transplanted: stock hardware clears the timer on SOF.
MMIO stores are observed, not claimed to model USB electrical timing.
"""
import unittest

from unicorn import UC_HOOK_MEM_WRITE

from MAYA_X_V2 import receiver as R
from superlamzu.emulation import Arm
from superlamzu.verify import patched_image

TIMER, USB = 0x500CA000, 0x5005A000


class SofTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.builder=R.build_absolute_stage()
        cls.changed=patched_image(cls.builder)

    def cpu(self,patched):
        cpu=Arm(self.changed if patched else self.builder.image,layout=R.LAYOUT)
        cpu.uc.mem_map(0x50000000,0x200000)
        cpu.uc.mem_map(0xE000E000,0x2000)
        cpu.writes=[]
        cpu.add_hook(UC_HOOK_MEM_WRITE,
            lambda uc,a,ad,s,v,u:cpu.writes.append((ad,s,v)),
            begin=0x50000000,end=0x501FFFFF)
        return cpu

    def test_real_native_allocation_bridge_publish_and_timer_clear_subscription(self):
        results=[]
        for patched in (False,True):
            with self.cpu(patched) as cpu:
                # Real firmware descriptors, channel pools and bridge writes;
                # no stubs at any DPPI allocator/enable boundary.
                self.assertEqual(cpu.run(0x1ABE0,count=200000),0)
                self.assertEqual(cpu.run(0x2007AC8C,count=200000),1)
                self.assertEqual(cpu.u32(USB+0x180),0x8000000F)
                self.assertEqual(cpu.u32(TIMER+0x8C),0x8000000F)
                self.assertEqual(cpu.u32(TIMER+0xCC),0)  # Not CAPTURE[3].
                self.assertEqual(cpu.u32(TIMER),1)
                self.assertEqual(cpu.byte(0x200034D8+12),2)
                self.assertTrue(any(ad not in (USB+0x180,TIMER+0x8C,TIMER)
                                    for ad,_,_ in cpu.writes))
                results.append((cpu.writes,cpu.u32(0x20006B18),cpu.reg('sp')))
        self.assertEqual(results[0],results[1])

    def test_sof_class_resume_idle_and_real_timer_irq_divider(self):
        results=[]
        for patched in (False,True):
            with self.cpu(patched) as cpu:
                cpu.run(0x1ABE0,count=200000)
                cpu.run(0x2007AE3C,count=200000)
                # Scheduler exit/clock-service boundaries only. IRQ and
                # compare state transitions remain original instructions.
                cpu.stub(0x2007B7B0);cpu.stub(0x2007B7D8);cpu.stub(0x2007B810)
                reports=[]
                cpu.stub(0x20000E64,effect=lambda c:reports.append(c.byte(0x20008314)))
                cpu.uc.mem_write(0x20009003,b'\2')
                cpu.run(0x2007AD1C)
                self.assertEqual((cpu.u32(TIMER+0x540),cpu.u32(TIMER+0x544)),(75,200))
                self.assertEqual(cpu.byte(0x20008310),1)
                self.assertEqual(cpu.u32(TIMER+0x200),0)
                for _ in range(17):
                    cpu.put32(TIMER+0x140,1)
                    cpu.run(0x2007AC04,count=100000)
                self.assertEqual(reports,[i%8 for i in range(17)])
                self.assertEqual(cpu.byte(0x2000830F),1)
                cpu.put32(TIMER+0x144,1)
                cpu.run(0x2007AC04,count=100000)
                self.assertEqual(cpu.byte(0x20008310),0)
                self.assertEqual((cpu.u32(TIMER+0x540),cpu.u32(TIMER+0x544)),(125,0))
                self.assertEqual(cpu.u32(TIMER+0x200),1)
                cpu.uc.mem_write(0x20009003,b'\1')
                before=len(cpu.writes);cpu.run(0x2007AD1C)
                self.assertEqual(len(cpu.writes),before)
                cpu.uc.mem_write(0x20009003,b'\2');cpu.run(0x2007AD1C)
                self.assertEqual(cpu.byte(0x20008310),1)
                self.assertEqual(cpu.reg('sp'),R.SP)
                results.append(cpu.writes)
        self.assertEqual(results[0],results[1])


if __name__=='__main__':unittest.main()
