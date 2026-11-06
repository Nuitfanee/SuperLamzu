"""Actual host adapter + generated ARM handler, with USB/NVM boundaries stubbed."""
import struct
import unittest
from unittest.mock import patch

from superlamzu import cfg, protocol as P, target as T
from superlamzu.common import Builder
from superlamzu.patch import build
from superlamzu.verify import arm, patched_image


class FirmwareDevice:
    def __init__(self,builder):
        self.builder=builder
        self.cpu=arm(patched_image(builder))
        self.cpu.uc.mem_map(T.ADV_STORAGE & ~4095,4096)
        self.cpu.uc.mem_write(T.ADV_STORAGE,b'\xff'*16)
        self.cpu.stub(T.SCHEDULE_SAVE)
        self.cpu.uc.mem_write(0x2300BE10,b'\x04')
        self.posted=[]
        self.cpu.stub(0x0E07E568,effect=lambda a:self.posted.append(a.reg('r0')))
        self.cpu.stub(0x0E07FAD4, 0x23024000)
        if 'advanced_queue_init' in builder.symbols:
            self.cpu.run(builder.symbols['advanced_queue_init'],0)
        self.reply=bytes(64)
        self.auto_snapshot = False

    def set_report(self,packet):
        a=self.cpu
        a.uc.mem_write(T.PACKET,packet)
        a.uc.mem_write(T.PACKET,b'\xA0')
        a.run(T.GROUP1 if packet[4]==1 else 0x0E0710E0)
        result=bytearray(a.uc.mem_read(T.PACKET,64))
        if result[0]==0xA0:result[0]=0xA1
        self.reply=bytes(result)
        if self.auto_snapshot and packet[4:8] == bytes((1, P.SET, 0, P.SENSOR_SNAPSHOT)):
            self.cpu.run(self.builder.symbols['advanced_snapshot_worker'])

    def get_report(self):return b'\0'+self.reply
    def close(self):self.cpu.close()

    def sensor_worker(self,mode=6,variant=2):
        """Run the installed worker hook, stubbing only SPI and vendor delay."""
        writes=[]
        page = [0]; regs = {}
        def write(a):
            r, v = a.reg('r0'), a.reg('r1')
            writes.append((r, v))
            if r == 127: page[0] = v
            else: regs[page[0], r] = v
            return 1
        self.cpu.stub(T.WR,effect=write)
        def read(a):
            a.uc.mem_write(a.reg('r1'),bytes([regs.get((page[0], a.reg('r0')), 0xA5)]))
            return 1
        self.cpu.stub(T.RD,effect=read)
        self.cpu.stub(0x0E086F46)
        self.cpu.run(self.builder.symbols['advanced_recipe_dispatch'],mode,variant,count=100000)
        return writes


class IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.build=build('SUPER')

    def setUp(self):
        self.sleep=patch.object(cfg.native.time,'sleep');self.sleep.start()
        self.dev=FirmwareDevice(self.build)
        self.mouse=cfg.Mouse(cfg.Link(self.dev,delay=0),0,1)

    def tearDown(self):
        self.dev.close()
        self.sleep.stop()

    def test_native_profile_fields_from_host(self):
        self.assertEqual(self.mouse.capabilities()['flags'],
                         P.F_DB|P.F_B|P.F_FPS|P.F_LOCK|P.F_FPS_CUSTOM|P.F_SENSOR_SNAPSHOT|P.F_ADV_SAVED|P.F_SMOOTHING|P.F_IDLE_TRACKING|P.F_MOTION_PATH|P.F_ABS)
        self.assertEqual(self.mouse.debounce_values(),P.DB_FACTORY)
        self.mouse.set_debounce((0,5,10,30))
        self.assertEqual(self.mouse.debounce_values(),(0,5,10,30))
        self.assertEqual(bytes(self.dev.cpu.uc.mem_read(0x2300CC50,4)),bytes([0,5,10,30]))

    def test_native_panel_pre_changes_only_pre(self):
        self.mouse.set_debounce((0,5,10,30))
        self.mouse.set_panel_debounce(7)
        self.assertEqual(self.mouse.debounce_values(),(7,5,10,30))

    def test_inactive_profile_does_not_reload_live_profile(self):
        self.dev.cpu.run(T.RELOAD_DB)
        other=cfg.Mouse(cfg.Link(self.dev,delay=0),0,3)
        other.set_debounce((1,2,3,4))
        self.assertEqual(self.mouse.debounce_values(),P.DB_FACTORY)
        self.assertEqual(other.debounce_values(),(1,2,3,4))
        self.assertEqual(bytes(self.dev.cpu.uc.mem_read(0x2300CC50,4)),bytes(P.DB_FACTORY))

    def test_stock_firmware_extension_rejection(self):
        dev=FirmwareDevice(Builder())
        self.addCleanup(dev.close)
        m=cfg.Mouse(cfg.Link(dev,delay=0),0,1)
        with self.assertRaises(cfg.Unsupported):m.capabilities()


class AdvancedIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.build=build('SUPER')

    def setUp(self):
        self.sleep=patch.object(cfg.native.time,'sleep');self.sleep.start()
        self.dev=FirmwareDevice(self.build)
        self.mouse=cfg.Mouse(cfg.Link(self.dev,delay=0),0,3)
        self.dev.cpu.uc.mem_write(0x2300E07D,b'\x06')

    def tearDown(self):
        self.dev.close()
        self.sleep.stop()

    def test_super_discovery_and_fps_worker_completion(self):
        caps=self.mouse.capabilities()
        self.assertEqual(caps['flags'],P.F_DB|P.F_B|P.F_FPS|P.F_LOCK|P.F_FPS_CUSTOM|P.F_SENSOR_SNAPSHOT|P.F_ADV_SAVED|P.F_SMOOTHING|P.F_IDLE_TRACKING|P.F_MOTION_PATH|P.F_ABS)
        self.assertEqual(caps['stats_bytes'],0)
        self.assertEqual(len(self.mouse.fps_presets()['presets']),caps['preset_count'])
        self.assertNotEqual(caps['preset_count'],0)
        result=self.mouse.fps_set(1)
        self.assertEqual((result['requested'],result['applied'],result['pending']),(1,0,True))
        self.assertEqual(self.dev.posted,[6])
        writes=self.dev.sensor_worker()
        self.assertEqual(writes[-6:],[(127,6),(83,2),(98,2),(127,7),(66,20),(127,0)])
        result=self.mouse.fps_status()
        self.assertEqual((result['requested'],result['applied'],result['pending']),(1,1,False))
        self.assertIn('current power session',self.mouse.advanced_persistence())

    def test_compiled_out_stats_and_channels_are_rejected(self):
        for operation in (self.mouse.stats, self.mouse.channels,
                          lambda:self.mouse.channels('on')):
            with self.assertRaises(cfg.Unsupported):
                operation()

    def test_custom_injection_independent_spi_readback_and_reset(self):
        value = dict(unit=47, slow=1, fast=1)
        queued = self.mouse.fps_custom_set(value)
        self.assertTrue(queued['pending'])
        self.assertFalse(queued['readback_valid'])
        self.assertEqual(self.dev.posted, [6])
        self.dev.sensor_worker()
        status = self.mouse.fps_custom_status()
        self.assertEqual(status['recipe'], value)
        self.assertEqual(status['readback'], value)
        self.assertTrue(status['readback_matches'])
        self.assertFalse(status['pending'])
        self.assertEqual(self.mouse.fps_status()['applied'], 255)
        with self.assertRaises(cfg.Unsupported):
            self.mouse.stats_reset()
        self.assertEqual(self.mouse.fps_custom_status(), status)
        # A DPI/mode recipe must reapply the exact live recipe, not a table ID.
        self.dev.sensor_worker(3, 1)
        self.assertEqual(self.mouse.fps_custom_status(), status)
        self.mouse.fps_set(0); self.dev.sensor_worker()
        self.assertEqual(self.mouse.fps_status()['applied'], 0)

    def test_fresh_snapshot_without_reapplying_stock_or_custom_mode(self):
        self.mouse.fps_custom_set(dict(unit=31, slow=3, fast=3))
        self.dev.sensor_worker(4, 3)
        self.dev.cpu.uc.mem_write(0x2300E07D, b'\x04')
        self.dev.cpu.uc.mem_write(0x2300E07C, b'\x03')
        self.dev.cpu.uc.mem_write(0x2300E07E, b'\x01')
        messages = []
        self.dev.cpu.stub(0x0E086F68, effect=lambda a: messages.append(
            bytes(a.uc.mem_read(a.reg('r1'), 12))) or 0)
        self.dev.auto_snapshot = True
        previous_posts = list(self.dev.posted)
        custom = self.mouse.fps_custom_status()
        result = self.mouse.sensor_snapshot()
        self.assertTrue(result['fresh'] and result['valid'])
        self.assertEqual(result['recipe'], dict(unit=31, slow=3, fast=3))
        self.assertEqual((result['mode'], result['variant'], result['fps_applied']), (4, 3, 255))
        self.assertEqual(self.dev.posted, previous_posts)
        self.assertEqual(self.mouse.fps_custom_status(), custom)
        second = self.mouse.sensor_snapshot()
        self.assertNotEqual(result['request_token'], second['request_token'])
        self.assertEqual(messages, [struct.pack('<III', 11, 0, 0)]*2)
        self.assertFalse(self.mouse.sensor_snapshot_status()['fresh'])

    def test_lock_little_endian_is_global_not_profile_storage(self):
        before=bytes(self.dev.cpu.uc.mem_read(T.SETTINGS,704))
        result=self.mouse.set_lock(True,499)
        self.assertEqual(result,dict(enabled=True,lead_us=499,effective_lead_us=499))
        self.assertEqual(bytes(self.dev.cpu.uc.mem_read(T.ADV_RAM+4,2)),struct.pack('<H',499))
        other=cfg.Mouse(cfg.Link(self.dev,delay=0),0,1)
        self.assertEqual(other.lock_status(),result)
        self.assertEqual(bytes(self.dev.cpu.uc.mem_read(T.SETTINGS,704)),before)

    @unittest.skip('STATS counters and reset are compiled out of SUPER')
    def test_stats_actual_pages_decode_and_counter_only_reset(self):
        self.mouse.stats_switch(True)
        self.mouse.set_lock(True,249)
        self.mouse.fps_set(3)
        self.dev.sensor_worker()
        self.dev.cpu.stub(0x0E071DC0,0)
        self.dev.cpu.uc.mem_write(0x23025000,b'\x01'+bytes(5))
        self.dev.cpu.run(self.build.symbols['advanced_motion'],0x23025000)
        stats=self.mouse.stats()
        self.assertEqual(stats['record_bytes'],188)
        self.assertEqual(stats['counters']['samples'],1)
        self.assertEqual(stats['counters']['samples_motion'],1)
        self.assertEqual(stats['counters']['fps_apply'],1)
        self.assertTrue(stats['counting_enabled'])
        self.assertTrue(stats['lock_enabled'])
        self.assertEqual((stats['fps_requested'],stats['fps_applied'],stats['lead_us']),(3,3,249))
        self.assertEqual(len(self.mouse.stats_page(5)),28)
        self.assertTrue(self.mouse.stats_reset())
        reset=self.mouse.stats()
        self.assertTrue(all(v==0 for v in reset['counters'].values()))
        for field in ('counting_enabled','lock_enabled','fps_requested','fps_applied','lead_us'):
            self.assertEqual(stats[field],reset[field])

    def test_runtime_powerup_defaults_do_not_erase_native_db(self):
        self.mouse.set_debounce((0,5,20,30))
        self.mouse.fps_set(2)
        self.mouse.set_lock(True,80)
        self.assertEqual(self.mouse.tracking_set(True), dict(enabled=True))
        with self.assertRaises(cfg.Unsupported):
            self.mouse.stats_switch(True)
        self.dev.cpu.run(self.build.symbols['advanced_queue_init'],0)
        self.assertEqual(self.mouse.debounce_values(),(0,5,20,30))
        self.assertEqual(self.mouse.fps_status()['requested'],0)
        self.assertEqual(self.mouse.lock_status()['enabled'],False)
        self.assertFalse(self.mouse.tracking_status()['enabled'])

    def test_motion_path_host_save_reload_and_snapshot_coexist(self):
        self.assertEqual(self.mouse.motion_path(), 'thread')
        self.assertEqual(self.mouse.motion_path('direct'), 'direct')
        self.dev.cpu.stub(0x0E0877E0, effect=lambda a: a.uc.mem_write(
            a.reg('r0'), bytes(a.uc.mem_read(a.reg('r1'), a.reg('r2')))) or a.reg('r0'))
        saved = self.mouse.save_advanced()
        self.assertEqual(saved['settings']['motion_path'], 1)
        self.dev.cpu.run(self.build.symbols['advanced_queue_init'], 0)
        self.assertEqual(self.mouse.motion_path(), 'direct')
        with self.assertRaises(cfg.Unsupported):
            self.mouse.stats_reset()
        self.assertEqual(self.mouse.motion_path(), 'direct')
        self.assertEqual(self.mouse.motion_path('thread'), 'thread')
        self.assertEqual(self.mouse.saved_advanced()['settings']['motion_path'], 1)
        with self.assertRaises(cfg.CfgError):
            self.mouse.motion_path('fast')
        with self.assertRaises(cfg.Unsupported):
            self.mouse.stats()

    def test_saved_custom_lock_and_smoothing_survive_runtime_init(self):
        a=self.dev.cpu
        def memcpy(a):
            a.uc.mem_write(a.reg('r0'),bytes(a.uc.mem_read(a.reg('r1'),a.reg('r2'))))
            return a.reg('r0')
        a.stub(0x0E0877E0,effect=memcpy)
        self.mouse.fps_custom_set(dict(unit=60,slow=1,fast=1))
        self.mouse.set_lock(True,80)
        self.assertEqual(self.mouse.tracking_set(True), dict(enabled=True))
        self.mouse._global_extension(P.SMOOTHING,(1,),write=True,reply_length=3)
        self.dev.sensor_worker(6,3)
        self.assertEqual(self.mouse.smoothing_status()['register_value'],2)
        saved=self.mouse.save_advanced()
        self.assertEqual(saved['settings'],dict(fps=255,lock=1,lead=80,custom=(60,1,1),smoothing=1,tracking=1,motion_path=0,abs_motion=0,optical_click=0))
        a.run(self.build.symbols['advanced_queue_init'],0)
        self.dev.sensor_worker(7,2)
        self.assertEqual(self.mouse.smoothing_status()['requested'],'reduced')
        self.assertEqual(self.mouse.smoothing_status()['register_value'],2)
        self.assertEqual(self.mouse.fps_custom_status()['readback'],dict(unit=60,slow=1,fast=1))
        self.assertTrue(self.mouse.lock_status()['enabled'])
        self.assertTrue(self.mouse.tracking_status()['enabled'])
        self.mouse._global_extension(P.SMOOTHING,(0,),write=True,reply_length=3)
        self.dev.sensor_worker(7,2)
        self.assertEqual(self.mouse.smoothing_status()['register_value'],0x27)
        self.assertEqual(self.mouse.saved_advanced(),saved)
        self.assertTrue(self.mouse.tracking_status()['enabled'])
        self.mouse.tracking_set(False)
        self.assertEqual(self.mouse.smoothing_status()['register_value'],0x27)

    def test_abs_host_save_reload_and_legacy_defaults(self):
        self.assertEqual(self.mouse.abs_motion(), dict(enabled=False))
        self.assertEqual(self.mouse.abs_motion('on'), dict(enabled=True))
        self.assertEqual(self.mouse.motion_path('direct'), 'direct')
        self.dev.cpu.stub(0x0E0877E0, effect=lambda a: a.uc.mem_write(
            a.reg('r0'), bytes(a.uc.mem_read(a.reg('r1'), a.reg('r2')))) or a.reg('r0'))
        saved = self.mouse.save_advanced()
        self.assertEqual(saved['settings']['abs_motion'], 1)
        self.dev.cpu.run(self.build.symbols['advanced_queue_init'], 0)
        self.assertEqual(self.mouse.abs_motion(), dict(enabled=True))
        self.assertEqual(self.mouse.motion_path(), 'direct')
        with self.assertRaises(cfg.Unsupported):
            self.mouse.stats_reset()
        self.assertEqual(self.mouse.abs_motion('off'), dict(enabled=False))
        self.assertEqual(self.mouse.saved_advanced()['settings']['abs_motion'], 1)
        with self.assertRaises(cfg.CfgError):
            self.mouse.abs_motion('fast')


if __name__=='__main__':unittest.main()
