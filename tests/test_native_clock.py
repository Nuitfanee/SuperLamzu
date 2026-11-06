import unittest

from superlamzu import native_clock
from superlamzu.native_clock_checks import abi_check, failure_check, generation_check, interleave_check, native_power_check, ownership_check, phase_boundary_check, integration_check, hook_interleave_check, combined_layout_check
from superlamzu.patch import build


class NativeClockTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.b = build('SUPER')
        if not hasattr(cls.b, 'native_clock'):
            cls.b.native_clock = native_clock.install(cls.b)

    def test_native_manager_ownership(self):
        self.assertGreater(ownership_check(self.b), 20)

    def test_native_failures(self):
        self.assertGreater(failure_check(self.b), 10)

    def test_real_thumb_interleavings(self):
        self.assertGreater(interleave_check(self.b), 30)

    def test_masks_and_abi(self):
        self.assertEqual(abi_check(self.b), 18)

    def test_off_then_new_on(self):
        self.assertEqual(generation_check(self.b), 8)

    def test_native_power_and_source_writers(self):
        self.assertEqual(native_power_check(self.b), 24)

    def test_draining_never_releases_twice(self):
        self.assertEqual(phase_boundary_check(self.b), 4)

    def test_production_queue_and_timer_boundaries(self):
        self.assertGreater(integration_check(self.b), 30)

    def test_production_pm_interleavings(self):
        self.assertEqual(hook_interleave_check(self.b), 5)

    def test_combined_clock_and_layout_ownership(self):
        self.assertEqual(combined_layout_check(self.b), 26)


if __name__ == '__main__':
    unittest.main()
