import unittest

from superlamzu import frame_timing as F


class TimingTests(unittest.TestCase):
    def test_full_encoding_range_and_nonpreset_solution(self):
        self.assertEqual(F.PRODUCTS[0], 1)
        self.assertEqual(F.PRODUCTS[-1], 255 * 255)
        r = F.choose(16000, 759840)
        self.assertEqual((r['unit'], r['slow'], r['fast']), (47, 1, 1))
        self.assertAlmostEqual(r['estimated_max_hz'], 759840 / 47)
        self.assertEqual(r['slower'], dict(unit=24, slow=2, fast=2))
        self.assertEqual(r['faster'], dict(unit=23, slow=2, fast=2))
        for hz in (12, 4000, 15500, 16000, 20000, 60000, 400000):
            r = F.choose(hz, 759840)
            self.assertEqual(abs(r['error_hz']), min(abs(759840 / p - hz) for p in F.PRODUCTS))

    def test_boundaries_validation_and_dynamic_recipe(self):
        for value in (None, {}, dict(unit=0, slow=1, fast=1), dict(unit=True, slow=1, fast=1),
                      dict(unit=256, slow=1, fast=1), dict(unit=47, slow=1, fast=2)):
            with self.assertRaises(ValueError): F.recipe(value)
        self.assertIsNone(F.preview(dict(unit=255, slow=255, fast=255), 800000)['slower'])
        self.assertIsNone(F.preview(dict(unit=1, slow=1, fast=1), 800000)['faster'])
        r = F.preview(dict(unit=25, slow=4, fast=2), 760000)
        self.assertEqual(r['estimated_min_hz'], 7600)
        self.assertEqual(r['estimated_max_hz'], 15200)
        self.assertIsNone(r['faster'])
        for hz in (0, True, float('inf'), float('nan'), 1, 800001):
            with self.assertRaises(ValueError): F.choose(hz, 800000)
