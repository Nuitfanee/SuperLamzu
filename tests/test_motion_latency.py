"""Thorn's native lift scheduling must not starve timer motion retries."""
import unittest

from superlamzu.patch import build
from superlamzu.motion_checks import (
    callback_tail_check, ownership_boundary_sweep, registered_report_check,
    tail_switch_check,
)


class MotionLatencyTests(unittest.TestCase):
    def test_registered_report_reaches_native_sampler(self):
        for profile,count in (('SUPER',24),):
            with self.subTest(profile=profile):
                self.assertEqual(registered_report_check(build(profile)),count)

    def test_super_callback_releases_before_native_scheduling(self):
        self.assertEqual(callback_tail_check(build('SUPER')), 38)

    @unittest.skip('FULL diagnostic build is outside the SUPER-only delivery')
    def test_full_callback_releases_before_native_scheduling(self):
        self.assertEqual(callback_tail_check(build('FULL')), 38)

    def test_super_tail_switch_preserves_native_callback_order(self):
        self.assertEqual(tail_switch_check(build('SUPER')), 2)

    @unittest.skip('FULL diagnostic build is outside the SUPER-only delivery')
    def test_full_tail_switch_preserves_native_callback_order(self):
        self.assertEqual(tail_switch_check(build('FULL')), 2)

    def test_super_unmasked_ownership_boundaries(self):
        # Literal address sharing removes 24 executed instruction boundaries;
        # the sweep still preempts every remaining unmasked boundary.
        self.assertEqual(ownership_boundary_sweep(build('SUPER')), 986)

    @unittest.skip('FULL diagnostic build is outside the SUPER-only delivery')
    def test_full_unmasked_ownership_boundaries(self):
        self.assertEqual(ownership_boundary_sweep(build('FULL')), 1040)


if __name__ == '__main__':
    unittest.main()
