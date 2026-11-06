"""Native split LOCK executes through the existing target Arm runner."""
import unittest
import sys
from pathlib import Path
from types import SimpleNamespace

from superlamzu.patch import build
from superlamzu import native_plock
from superlamzu.native_plock_checks import run_checks,native_radio_check


class NativePlockTests(unittest.TestCase):
    def test_thorn_super_real_thumb(self):
        b=build('SUPER')
        control=b.native_plock
        result=run_checks(b,control)
        self.assertGreater(result['apply'],200)
        self.assertGreater(result['phase'],30)
        self.assertEqual(result['timeline'],19)
        self.assertEqual(result['native_layouts'],3)
        self.assertEqual(native_radio_check(b,control),12)

    def test_thorn_native_samples_reach_frames(self):
        from superlamzu.native_sample_checks import verify
        result=verify(build('SUPER'))
        self.assertEqual(result['sample_scenarios'],16)
        self.assertEqual(result['pending_failure_scenarios'],4)
        self.assertEqual(result['retransmit_order'],9)

    def test_timer_stop_preserves_count_without_counting_paused_time(self):
        from superlamzu import target as T
        from superlamzu.common import assemble
        from superlamzu.emulation import Arm
        from superlamzu.native_plock_checks import Timeline
        from superlamzu.verify import patched_image
        with Arm(patched_image(build('SUPER'))) as cpu:
            cpu.uc.mem_map(T.REPORT_TIMER,0x1000)
            cpu.put32(T.REPORT_TIMER+0x540,250)
            cpu.put32(T.REPORT_TIMER+0x200,1)
            tm=Timeline(cpu,T.REPORT_TIMER)
            task=cpu.layout.stack-0x100
            cpu.uc.mem_write(task,assemble(
                ['movs r1,#1','str r1,[r0]','bx lr'],task))
            tm.advance(170)
            cpu.run(task,T.REPORT_TIMER+4)
            tm.advance(1170)
            self.assertEqual(tm.count,170)
            self.assertEqual(tm.reads,[])
            cpu.run(task,T.REPORT_TIMER)
            tm.advance(1250)
            self.assertEqual(tm.count,0)
            self.assertEqual(tm.reads,[1250])
            cpu.run(task,T.REPORT_TIMER+4)
            tm.advance(2250)
            cpu.run(task,T.REPORT_TIMER)
            tm.advance(2500)
            self.assertEqual(tm.reads,[1250,2500])

    def test_maya_super_real_thumb(self):
        sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
        from MAYA_X_V2.full import build_pair
        from MAYA_X_V2 import target
        from MAYA_X_V2.sensor import LAYOUT
        b,_=build_pair('SUPER')
        t=SimpleNamespace(**dict(vars(target),REPORT_TIMER_POINTER=0x200062B0))
        control=b.advanced['hooks']['plock']
        result=run_checks(b,control,target=t,layout=LAYOUT)
        self.assertGreater(result['phase'],30)
        self.assertEqual(result['timeline'],19)
        self.assertEqual(result['native_layouts'],3)
        self.assertEqual(native_radio_check(b,control,target=t,layout=LAYOUT),5)


if __name__=='__main__':
    unittest.main()
