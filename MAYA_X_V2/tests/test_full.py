"""Run existing feature acceptance against one complete paired candidate.

Stage tests keep their own incomplete-capability assertions. Their actual
feature scenarios are reused here, with only the candidate builder replaced.
"""
import ast
import struct
import unittest

from MAYA_X_V2 import target as T
from MAYA_X_V2.full import build_pair,FLAGS
from superlamzu.verify import patched_image,request
from superlamzu import protocol as P

from MAYA_X_V2.tests.test_absolute import AbsoluteTests
from MAYA_X_V2.tests.test_advanced import AdvancedTests
from MAYA_X_V2.tests.test_channels import ChannelTests
from MAYA_X_V2.tests.test_configuration import ConfigurationTests
from MAYA_X_V2.tests.test_motion import MotionTests
from MAYA_X_V2.tests.test_optical import OpticalTests
from MAYA_X_V2.tests.test_persistence import PersistenceTests
from MAYA_X_V2.tests.test_radio import RadioTests
from MAYA_X_V2.tests.test_receiver import ReceiverTests
from MAYA_X_V2.tests.test_sensor import SensorTests
from MAYA_X_V2.tests.test_sof import SofTests
from MAYA_X_V2.tests.test_stats import StatisticsTests


class FullTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mouse,cls.receiver=build_pair()

    def test_existing_feature_scenarios_against_full_not_only_intermediate_stages(self):
        omitted={
            AdvancedTests:{'test_capabilities_and_init_do_not_claim_radio_or_persistence'},
            ChannelTests:{'test_host_uses_real_maya_thumb_handler_and_legacy_decode'},
            ConfigurationTests:{'test_capabilities_only_advertise_implemented_features'},
            PersistenceTests:{'test_bad_records_and_unimplemented_fields_never_enable_stub_capabilities',
                              'test_all_versions_migrate_without_nvm_rewrite_and_only_queue0_loads'},
            RadioTests:{'test_tracking_protocol_and_primask_preserve_smoothing'},
            SensorTests:{'test_nine_recipes_share_existing_interpreter'},
        }
        total=0
        classes=(AbsoluteTests,AdvancedTests,ChannelTests,ConfigurationTests,MotionTests,
                 OpticalTests,PersistenceTests,RadioTests,ReceiverTests,SensorTests,SofTests,StatisticsTests)
        if not self.mouse.advanced.get('telemetry',True):
            classes=tuple(c for c in classes if c not in (ChannelTests,StatisticsTests))
        for cls in classes:
            builder=self.receiver if cls in (ReceiverTests,SofTests) else self.mouse
            for name in unittest.defaultTestLoader.getTestCaseNames(cls):
                if name in omitted.get(cls,set()):continue
                with self.subTest(feature=cls.__name__,scenario=name):
                    case=cls(name);case.builder=builder;case.changed=patched_image(builder)
                    if cls is PersistenceTests:
                        original_cpu=case.cpu
                        def full_cpu():
                            cpu=original_cpu()
                            cpu.stub(0x3089E,effect=lambda c:T.NATIVE_HEAP_START+0x400
                                if c.reg('r1')==T.SNAPSHOT_STORAGE_BYTES+4 else T.NATIVE_HEAP_START+0x800)
                            return cpu
                        case.cpu=full_cpu
                    if cls is RadioTests:
                        # Preserve the established target-address fixture.
                        from types import SimpleNamespace
                        from superlamzu import advanced as A
                        case.addresses=SimpleNamespace(ADV_RAM=T.ADV_RAM,REPORT_TIMER=T.REPORT_TIMER,
                            DIVIDER=T.REPORT_DIVIDER,TPMS=T.TICKS_PER_MS,RSTATE=T.RADIO_STATE,OFF=A.OFF)
                    getattr(case,name)()
                    total+=1
        self.assertGreaterEqual(total,45 if not self.mouse.advanced.get('telemetry',True) else 55)

    def test_complete_capabilities_and_all_optional_settings_are_live(self):
        fixture=MotionTests();fixture.builder=self.mouse;fixture.changed=patched_image(self.mouse)
        with fixture.cpu() as cpu:
            caps=P.decode_capabilities(request(cpu,P.GET,(0,0),target=T)[1])
            self.assertEqual(caps,dict(api=1,flags=FLAGS,profiles=3,cpi_max=40000,stats_bytes=188,preset_count=38))
            self.assertTrue(caps['flags'] & P.F_RADIO_OUTCOMES)
            self.assertFalse(caps['flags'] & P.F_OPTICAL_CLICK)
            self.assertEqual(request(cpu,P.GET,(0,P.OPTICAL_CLICK),target=T)[0],0xA2)
            self.assertEqual(request(cpu,P.SET,(0,P.OPTICAL_CLICK,1),target=T)[0],0xA2)
            for op in (P.MOTION_PATH,P.ABS_MOTION,P.IDLE_TRACKING):
                self.assertEqual(request(cpu,P.SET,(0,op,1),target=T)[0],0xA0)
                self.assertEqual(request(cpu,P.GET,(0,op),target=T)[1][2],1)

    def test_paired_full_real_decode_worker_report_radio_parser_usb(self):
        from MAYA_X_V2.tests.test_motion import HEAP
        mf=MotionTests();mf.builder=self.mouse;mf.changed=patched_image(self.mouse)
        rf=ReceiverTests();rf.builder=self.receiver;rf.changed=patched_image(self.receiver)
        for direct in (0,1):
            with self.subTest(direct=direct),mf.cpu() as mouse,rf.radio_cpu() as rx:
                mouse.uc.mem_map(0x50080000,0x10000)
                mouse.uc.mem_map(T.REPORT_TIMER,0x1000)
                mouse.stubs.pop(T.MOTION_NATIVE)
                for a in (0x20005D10,0x20002E48,0x20002E80,0x20005CB8):mouse.stub(a)
                mouse.stub(0x200052D4,8)
                mouse.uc.mem_write(T.RADIO_STATE,b'\1\1')
                for q in range(7):mouse.run(T.QUEUE_INIT,q)
                mouse.uc.mem_write(T.SNAPSHOT_POINTER,(HEAP&0xFFFFF).to_bytes(3,'little'))
                self.assertEqual(request(mouse,P.SET,(0,P.ABS_MOTION,1),target=T)[0],0xA0)
                self.assertEqual(request(mouse,P.SET,(0,P.MOTION_PATH,direct),target=T)[0],0xA0)
                mouse.uc.mem_write(T.SENSOR_READY,b'\1')
                mouse.uc.mem_write(T.SETTINGS+705,b'\1')
                mouse.uc.mem_write(0x2000D234,b'\xb7\0')
                mouse.uc.mem_write(T.REPORT_DIVIDER,b'\1')
                mouse.run(0x16130)
                mouse.put32(T.REPORT_DRIVER,T.REPORT_DRIVER_TABLE)
                mouse.put32(T.MOTION_CALLBACK,mf.changed.u32(T.MOTION_CALLBACK_POINTER))
                for i,(x,y) in enumerate(((100,200),(10,-10),(15,30))):
                    def burst(c):
                        self.assertEqual(c.reg('r2'),6)
                        c.uc.mem_write(c.reg('r1'),b'\xa4\xb7'+struct.pack('<hh',x,y))
                        return 1
                    mouse.stub(T.SENSOR_BURST,effect=burst)
                    mouse.run(self.mouse.motion['report'],count=100000)
                    if not direct:
                        # Execute the real binary take and installed independent
                        # consumer, rather than bypassing its wake with drain.
                        mf.run_done(mouse)
                        self.assertEqual(mouse.u32(T.SENSOR_QUEUE+32),0)
                    self.assertEqual(mouse.run(T.QUEUE_COUNT,2),1)
                    self.assertEqual(mouse.run(T.ABS_FRAME_NATIVE,T.ABS_FRAME_BUFFER,1),1)
                    n=mouse.byte(T.ABS_FRAME_BUFFER)
                    raw=bytes(mouse.uc.mem_read(T.ABS_FRAME_BUFFER+2,n-1))
                    self.assertEqual(raw[0],10)
                    self.assertEqual(rf.radio_frame(rx,i&1,raw),1)
                rf.flush_usb(rx)
                self.assertEqual([struct.unpack('<hh',p[2:6]) for p in rx.usb],[(0,0),(10,-10),(15,30)])

    def test_production_never_imports_test_or_analysis_implementations(self):
        for path in T.ROOT.glob('*.py'):
            tree=ast.parse(path.read_text(encoding='utf-8'))
            for node in ast.walk(tree):
                names=[node.module or ''] if isinstance(node,ast.ImportFrom) else (
                    [x.name for x in node.names] if isinstance(node,ast.Import) else [])
                for name in names:
                    self.assertFalse({'tests','analysis'} & set(name.split('.')),str(path))

    def test_backlog_retry_preserves_each_usb_step_not_only_final_sum(self):
        from MAYA_X_V2.tests.test_absolute import HEAP
        mf=AbsoluteTests();mf.builder=self.mouse;mf.changed=patched_image(self.mouse)
        rf=ReceiverTests();rf.builder=self.receiver;rf.changed=patched_image(self.receiver)
        with mf.cpu() as mouse,rf.radio_cpu() as rx:
            mouse.uc.mem_write(T.RADIO_STATE,b'\1\1')
            rf.radio_packet(rx,0,10,[(0,0)])
            for x in (10,20,30,40,50):
                mouse.uc.mem_write(HEAP+24,struct.pack('<HH',x,0))
                mouse.uc.mem_write(0x20016000,bytes(8))
                self.assertEqual(mouse.run(T.RADIO_SEND,9,0x20016000),1)
            self.assertEqual(mouse.run(T.ABS_FRAME_NATIVE,T.ABS_TX_BUFFER,1),1)
            # The first transmission is lost; deliver its state4 retry.
            mouse.uc.mem_write(T.RADIO_STATE+0x186,b'\4')
            mouse.run(self.mouse.absolute['copy'],T.ABS_DMA_BUFFER,T.ABS_TX_BUFFER,12)
            rf.radio_frame(rx,1,bytes(mouse.uc.mem_read(T.ABS_DMA_BUFFER+2,10)))
            for head in (0,1):
                self.assertEqual(mouse.run(T.ABS_FRAME_NATIVE,T.ABS_FRAME_BUFFER,1),1)
                n=mouse.byte(T.ABS_FRAME_BUFFER)
                rf.radio_frame(rx,head,bytes(mouse.uc.mem_read(T.ABS_FRAME_BUFFER+2,n-1)))
            rf.flush_usb(rx)
            self.assertEqual([struct.unpack('<hh',p[2:6]) for p in rx.usb],[(0,0)]+[(10,0)]*5)

    def test_candidate_structure_sparse_gaps_storage_mpu_and_output_guards(self):
        from MAYA_X_V2.verify import structure
        from MAYA_X_V2.build import validate_destinations
        report=structure(self.mouse,self.receiver)
        self.assertEqual(report['receiver']['absolute_tail_aliases'],[])
        self.assertEqual(report['mouse']['storage']['storage'],0x1102D0)
        for directory in (T.WORKSPACE/'firmware'/'MAYA_X_V2',
                          T.WORKSPACE/'backups',T.WORKSPACE/'references'/'hyperdrako-dev'):
            with self.assertRaises(ValueError):validate_destinations(directory)


def load_tests(loader,tests,pattern):
    # Imported TestCase classes are reuse sources, not additional discovery.
    return loader.loadTestsFromTestCase(FullTests)


if __name__=='__main__':unittest.main()
