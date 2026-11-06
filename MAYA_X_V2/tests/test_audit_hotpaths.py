"""A lower whole-window budget cannot hide a slower individual radio phase."""
import unittest

from MAYA_X_V2.tests.audit_hotpaths import nontelemetry_stage_review


class HotpathAcceptanceTests(unittest.TestCase):
    def test_normal_tick_audit_matches_successful_complete_startup(self):
        from unittest.mock import patch
        from MAYA_X_V2 import target as T
        from MAYA_X_V2.full import build_pair
        from MAYA_X_V2.tests import audit_hotpaths as audit
        from MAYA_X_V2.tests.test_persistence import PersistenceTests
        from MAYA_X_V2.tests.test_motion import HEAP
        from superlamzu.verify import patched_image

        builder,_=build_pair('SUPER')
        fixture=PersistenceTests();fixture.builder=builder;fixture.changed=patched_image(builder)
        with fixture.cpu() as cpu:
            cpu.stub(0x3089E,HEAP-4)
            cpu.run(0x30530,count=100000)
            self.assertEqual(int.from_bytes(cpu.uc.mem_read(T.SNAPSHOT_POINTER,3),'little')&0xFFFFF,
                             HEAP&0xFFFFF)
            cpu.stub(T.SENSOR_TICK,1)
            expected=audit.measure(cpu,builder.symbols['advanced_tick'])
        self.assertLessEqual(expected['instructions'],22)

        class FirstTickMeasured(Exception):pass
        observed={}
        measure=audit.measure
        def first_tick(cpu,entry,args=()):
            self.assertEqual(int.from_bytes(cpu.uc.mem_read(T.SNAPSHOT_POINTER,3),'little')&0xFFFFF,
                             HEAP&0xFFFFF)
            observed.update(measure(cpu,entry,args))
            raise FirstTickMeasured
        with patch.object(audit,'measure',side_effect=first_tick),self.assertRaises(FirstTickMeasured):
            audit.mouse_hotpaths(builder)
        self.assertEqual(observed,expected)

    def samples(self,tx=69,receive=114,timeout=120):
        return {f'radio_window.{phase}.stats0.chan0.heap{heap}':dict(instructions=count)
                for phase,count in (('state4_tx',tx),('state6_receive',receive),
                                    ('state6_timeout',timeout))
                for heap in (0,1)}

    def test_faster_total_still_blocks_slower_receive_and_timeout(self):
        result=nontelemetry_stage_review(self.samples(),self.samples(30,119,126))
        self.assertEqual(result['result'],'FAIL')
        self.assertFalse(result['instruction_budget_passed'])
        self.assertEqual(sorted(v['delta'] for v in result['regressions'].values()),[5,5,6,6])

    def test_equal_or_faster_each_phase_passes_instruction_budget_only(self):
        for current in (self.samples(),self.samples(30,113,119)):
            result=nontelemetry_stage_review(self.samples(),current)
            self.assertEqual(result['result'],'PASS')
            self.assertTrue(result['instruction_budget_passed'])
            self.assertEqual(result['regressions'],{})

    def test_missing_phase_cannot_report_pass(self):
        for partial in ({},self.samples()):
            if partial:partial.pop(next(iter(partial)))
            with self.assertRaises(ValueError):
                nontelemetry_stage_review(self.samples(),partial)


if __name__=='__main__':unittest.main()
