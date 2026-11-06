import unittest
from superlamzu.patch import build
from superlamzu.settings import encode_record, decode_record
from superlamzu.settings_checks import persistence_check, smoothing_check, tracking_protocol_check


class AdvancedSettingsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.b=build('SUPER')

    def test_record_roundtrip(self):
        values=dict(fps=255,lock=1,lead=499,custom=(60,1,1),smoothing=1,tracking=1,motion_path=1,abs_motion=1,optical_click=1)
        self.assertEqual(decode_record(encode_record(**values)),values)

    def test_v1_record_compatibility(self):
        self.assertEqual(decode_record(encode_record(version=1))['tracking'], 0)
        with self.assertRaises(ValueError):
            encode_record(version=1, tracking=1)

    def test_tracking_protocol_real_thumb(self):
        self.assertGreater(tracking_protocol_check(self.b), 25)

    def test_v2_record_compatibility(self):
        record = encode_record(version=2, tracking=1)
        self.assertEqual(decode_record(record)['motion_path'], 0)
        with self.assertRaises(ValueError):
            encode_record(version=2, motion_path=1)

    def test_v3_record_compatibility(self):
        record = encode_record(version=3, tracking=1, motion_path=1)
        self.assertEqual(decode_record(record)['abs_motion'], 0)
        with self.assertRaises(ValueError):
            encode_record(version=3, abs_motion=1)

    def test_v4_record_compatibility(self):
        self.assertEqual(decode_record(encode_record(version=4,abs_motion=1))['optical_click'],0)
        with self.assertRaises(ValueError):encode_record(version=4,optical_click=1)

    def test_motion_path_real_thumb(self):
        from superlamzu.motion_checks import verify
        self.assertGreater(verify(self.b), 15)

    def test_abs_motion_real_thumb(self):
        from superlamzu.mouse_abs_checks import verify
        self.assertGreater(verify(self.b), 65)

    def test_abs_total_fast_path_preserves_atomic_publication_and_native_abi(self):
        from superlamzu.mouse_abs_checks import total_fast_path_check
        for profile, builder in (('SUPER', self.b),):
            with self.subTest(profile=profile):
                self.assertEqual(total_fast_path_check(builder), 36)

    def test_abs_retry_and_zero_total_preserve_temporal_order(self):
        from superlamzu.mouse_abs_checks import retransmit_order_check
        for profile in ('SUPER',):
            with self.subTest(profile=profile):
                self.assertEqual(retransmit_order_check(build(profile)), 9)

    def test_persistence_real_thumb(self):
        self.assertGreater(persistence_check(self.b),40)

    def test_abs_retry_cannot_overtake_concurrent_producer(self):
        from superlamzu.mouse_abs_checks import retransmit_producer_interleave_check
        for profile in ('SUPER',):
            with self.subTest(profile=profile):
                self.assertGreater(retransmit_producer_interleave_check(build(profile)),20)

    def test_smoothing_real_thumb(self):
        self.assertGreater(smoothing_check(self.b),50)
