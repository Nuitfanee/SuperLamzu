import unittest

from superlamzu.patch import build
from superlamzu.optical_checks import verify, retired_mode_check
from superlamzu.optical import stock_evidence
from superlamzu import protocol as P, target as T


class OpticalTests(unittest.TestCase):
    def test_stock_sampling_and_debounce_match_original_firmware(self):
        for profile in ('SUPER',):
            with self.subTest(profile=profile):
                self.assertGreaterEqual(verify(build(profile)),20)

    def test_retired_capability_and_hook_sites_are_absent(self):
        b=build('SUPER')
        self.assertFalse(b.extension['flags'] & P.F_OPTICAL_CLICK)
        self.assertFalse(any(name.startswith(('optical_','settings_click_')) for name in b.symbols))
        self.assertTrue(stock_evidence(b)['native'])
        address=T.flash_source(T.CLICK_SAMPLE_SITE)
        b.changes[address]=b.image.get(address,1)[0]^1
        with self.assertRaisesRegex(ValueError,'stock optical path was patched'):
            stock_evidence(b)

    def test_old_saved_direct_bit_is_ignored_without_resetting_other_settings(self):
        self.assertEqual(retired_mode_check(build('SUPER')),10)


if __name__=='__main__':unittest.main()
