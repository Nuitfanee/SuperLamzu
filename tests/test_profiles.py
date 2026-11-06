"""SUPER firmware capabilities, persistence and real-Thumb verification."""
import unittest

from superlamzu.patch import build
from superlamzu.profile_checks import verify_super
from superlamzu.profiles import TELEMETRY_FLAGS, policy
from superlamzu.verify import verify
from superlamzu import protocol as P


class ProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.super = build('SUPER')

    def test_super_preserves_features_and_removes_telemetry(self):
        self.assertEqual(self.super.extension['flags'],
                         65471 & ~P.F_OPTICAL_CLICK & ~TELEMETRY_FLAGS)
        self.assertEqual(verify_super(self.super)['result'], 'PASS')
        self.assertEqual(policy('FULL')['telemetry_performance_gate'], False)
        self.assertFalse(policy('SUPER')['telemetry'])

    def test_complete_super_thumb_matrix(self):
        self.assertEqual(verify(self.super, 'SUPER')['result'], 'PASS')

    def test_host_rejects_telemetry_and_reloads_shared_saved_settings(self):
        from tests.test_integration import FirmwareDevice
        from superlamzu import cfg, target as T
        saved = None
        for _ in range(2):
            dev = FirmwareDevice(build('SUPER'))
            self.addCleanup(dev.close)
            mouse = cfg.Mouse(cfg.Link(dev, delay=0), 0)
            if saved is None:
                dev.cpu.stub(0x0E0877E0, effect=lambda a: a.uc.mem_write(
                    a.reg('r0'), bytes(a.uc.mem_read(a.reg('r1'), a.reg('r2')))) or a.reg('r0'))
                mouse.motion_path('direct')
                mouse.abs_motion('on')
                mouse.set_lock(True, 80)
                saved = mouse.save_advanced()
                raw = bytes(dev.cpu.uc.mem_read(T.ADV_STORAGE, 16))
            else:
                dev.cpu.uc.mem_write(T.ADV_STORAGE, raw)
                dev.cpu.run(dev.builder.symbols['advanced_queue_init'], 0)
                self.assertEqual(mouse.saved_advanced(), saved)
                self.assertEqual(mouse.motion_path(), 'direct')
                self.assertTrue(mouse.abs_motion()['enabled'])
                self.assertTrue(mouse.lock_status()['enabled'])
            self.assertEqual(mouse.capabilities()['stats_bytes'], 0)
            for operation in (mouse.stats, mouse.stats_reset,
                              lambda: mouse.stats_switch(True),
                              mouse.channels, lambda: mouse.channels('on')):
                with self.assertRaises(cfg.Unsupported):
                    operation()
            dev.close()
