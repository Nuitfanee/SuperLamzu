"""Same complete feature scenarios on SUPER; telemetry hooks are absent."""
import unittest

from MAYA_X_V2 import target as T
from MAYA_X_V2.full import build_pair,flags
from MAYA_X_V2.tests.test_full import FullTests
from MAYA_X_V2.tests.test_motion import MotionTests
from superlamzu import protocol as P
from superlamzu.verify import patched_image,request


class SuperTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mouse,cls.receiver=build_pair('SUPER')

    test_all_preserved_feature_scenarios=FullTests.test_existing_feature_scenarios_against_full_not_only_intermediate_stages
    test_paired_decode_to_usb=FullTests.test_paired_full_real_decode_worker_report_radio_parser_usb
    test_sparse_storage_mpu=FullTests.test_candidate_structure_sparse_gaps_storage_mpu_and_output_guards
    test_backlog_retry_to_usb=FullTests.test_backlog_retry_preserves_each_usb_step_not_only_final_sum

    def test_no_telemetry_hooks_and_native_receive_dispatch(self):
        image=patched_image(self.mouse)
        for site,size in ((T.RADIO_RX_ACCEPT_SITE,len(T.RADIO_RX_ACCEPT_PREIMAGE)),
                          (T.RADIO_SLOT_DISPATCH_SITE,len(T.RADIO_SLOT_DISPATCH_PREIMAGE)),
                          (T.SENSOR_BURST_POINTER,4),(0x177F8,4),(0x1784C,4)):
            source=T.flash_source(site)
            self.assertEqual(image.get(source,size),self.mouse.image.get(source,size),hex(site))
        forbidden=('maya_stats_','maya_radio_outcomes_','channels_','advanced_burst',
                   'advanced_reinit','advanced_radio_count')
        self.assertFalse(any(n.startswith(forbidden) for n in self.mouse.symbols))
        fixture=MotionTests();fixture.builder=self.mouse;fixture.changed=image
        with fixture.cpu() as cpu:
            caps=P.decode_capabilities(request(cpu,P.GET,(0,P.CAPS),target=T)[1])
            self.assertEqual(caps['flags'],flags('SUPER'))
            self.assertEqual(caps['stats_bytes'],0)
            for op in (P.STATS,P.CHANNELS):
                for cmd,body in [(P.GET,(0,op)),(P.GET,(0,op,0))]+[(P.SET,(0,op,k)) for k in (0,1,2)]:
                    before=bytes(cpu.uc.mem_read(T.ADV_RAM,188))
                    self.assertEqual(request(cpu,cmd,body,target=T)[0],0xA2)
                    self.assertEqual(bytes(cpu.uc.mem_read(T.ADV_RAM,188)),before)

    def test_saved_v1_to_v5_settings_migrate_without_rewrite(self):
        from superlamzu.settings import encode_record
        from MAYA_X_V2.tests.test_persistence import PersistenceTests
        fixture=PersistenceTests();fixture.builder=self.mouse;fixture.changed=patched_image(self.mouse)
        with fixture.cpu() as cpu:
            cpu.stub(0x3089E,effect=lambda c:T.NATIVE_HEAP_START+0x400
                if c.reg('r1')==T.SNAPSHOT_STORAGE_BYTES+4 else T.NATIVE_HEAP_START+0x800)
            for version in range(1,6):
                record=encode_record(37,1,80,(60,1,1),1,int(version>1),version=version,
                    motion_path=int(version>=3),abs_motion=int(version>=4),optical_click=int(version>=5))
                cpu.uc.mem_write(T.ADV_STORAGE,record)
                # Use the installed startup chain, including settings load.
                cpu.run(self.mouse.symbols['motion_queue_init'],0)
                self.assertEqual(bytes(cpu.uc.mem_read(T.ADV_STORAGE,16)),record)
                self.assertEqual(request(cpu,P.GET,(0,P.MOTION_PATH),target=T)[1][2],int(version>=3))
                self.assertEqual(request(cpu,P.GET,(0,P.ABS_MOTION),target=T)[1][2],int(version>=4))


def load_tests(loader,tests,pattern):
    return loader.loadTestsFromTestCase(SuperTests)
