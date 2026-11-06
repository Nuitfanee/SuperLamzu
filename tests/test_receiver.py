import unittest
import contextlib
import io
import json
from unittest.mock import patch

from superlamzu import receiver
from superlamzu.fw import inspect_image


class ReceiverTargetTests(unittest.TestCase):
    def test_supplied_two_core_inventory(self):
        result = receiver.inventory()
        self.assertEqual((result['vid'], result['app_pid']), (0x37B0, 0x002E))
        self.assertEqual([c['core'] for c in result['cores']], ['cpuapp', 'cpurad'])
        self.assertEqual([c['gap_bytes'] for c in result['cores']], [24, 22])
        self.assertEqual(result['hooks']['motion_copy']['address'], 0x0E0C5254)
        self.assertEqual(result['hooks']['sof_isr']['address'], 0x0E0B80F6)
        self.assertEqual(result['hooks']['sof_callback']['address'], 0x0E0C5E78)
        for core in result['cores']:
            self.assertFalse(core['flash_available'])
            self.assertEqual(core['write_entry_point'],'flasher/SuperLAMZU THORN V2-0.1.0-windows-x64.exe')
            self.assertEqual(core['verified_bootloader'],receiver.BL_VERSION)
        self.assertTrue(result['hardware_operations']['update_from_verified_full'])
        self.assertFalse(result['hardware_operations']['erase'])

    def test_receiver_cannot_inherit_mouse_flash_verification(self):
        for core in receiver.CORES:
            result = inspect_image(core.source)
            self.assertFalse(result['target_vectors_match'])
            self.assertFalse(result['bootloader_protocol_verified'])
            self.assertIsNone(result['write_entry_point'])
            self.assertIsNone(result['verified_bootloader'])

    def test_wrong_core_rejected(self):
        from superlamzu.hexfile import Image
        with patch.object(receiver, 'Image', return_value=Image(receiver.CORES[1].source)):
            with self.assertRaisesRegex(ValueError, 'span/vectors'):
                receiver.CORES[0].inspect()

    def test_receiver_info_cli_is_offline(self):
        from superlamzu import fw, cfg
        with patch.object(cfg, 'open_device', side_effect=AssertionError('offline only')), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(fw.main(['receiver-info']), 0)
        self.assertEqual(len(json.loads(output.getvalue())['cores']), 2)

    def test_sof_target_thumb_equivalence(self):
        from superlamzu.receiver_checks import verify
        result = verify(receiver.build())
        self.assertEqual(result['result'], 'PASS')
        self.assertGreater(result['callback_cases'], 1000)
        self.assertGreater(result['queue_contract_cases'], 1000)
        self.assertGreater(result['abs_cases'], 600)
        self.assertEqual(result['startup_cases'], 4)
        self.assertEqual(result['abs_dispatch_cases'], 80)
        self.assertEqual(result['abs_acceptance_cases'], 36)
        self.assertEqual(result['queue_capacity'], 25)
        self.assertEqual(result['queue_padding_bytes'], 5)
        self.assertTrue(result['abs_link_table_untouched'])

    def test_cpuapp_remains_exact_original(self):
        b = receiver.build('cpuapp')
        self.assertEqual(b.output_image(), b.image.data)
        self.assertFalse(b.changes)

    def test_sof_reuses_only_native_callback_and_preserves_sparse_hex(self):
        import tempfile
        from pathlib import Path
        from superlamzu.hexfile import Image
        b = receiver.build()
        self.assertLessEqual(sum(a['bytes'] for a in b.allocations
                                 if a['name'].startswith('sof_')),208)
        self.assertEqual(receiver.runtime(receiver.SOF_CALLBACK),0x230018FC)
        with tempfile.TemporaryDirectory() as tmp:
            p=b.write(Path(tmp)/'receiver.hex');out=Image(p)
            self.assertEqual(set(out.mem),set(b.image.mem))
            self.assertEqual(out.entry,b.image.entry)
            self.assertEqual(out.data,b.output_image())
        for c in receiver.CORES:
            with self.assertRaises(ValueError):b.write(c.source)

    def test_abs_recycles_only_native_code_and_queue_padding(self):
        b = receiver.build()
        for allocation in b.allocations:
            if allocation['name'].startswith('sof_'):
                continue
            address = int(allocation['address'], 16)
            self.assertGreaterEqual(address, receiver.QUEUE_RAW)
            self.assertLessEqual(address + allocation['bytes'], receiver.QUEUE_BLOCK_END)
        tails = set()
        used = receiver.QUEUE_HEADER + receiver.QUEUE_RECORD * receiver.QUEUE_CAPACITY
        for i in range(receiver.QUEUE_COUNT):
            start = receiver.QUEUE_BASE + i * receiver.QUEUE_STRIDE
            tails.update(range(start + used, start + receiver.QUEUE_STRIDE))
        state = {receiver.ABS_VALID, receiver.ABS_X, receiver.ABS_X + 1,
                 receiver.ABS_Y, receiver.ABS_Y + 1}
        self.assertLessEqual(state, tails)
        self.assertEqual(receiver.ABS_X % 2, 0)
        self.assertEqual(receiver.ABS_Y % 2, 0)
        self.assertTrue(b.manifest()['scope']['abs'])

    def test_abs_queue_preimage_is_required(self):
        with patch.object(receiver, 'QUEUE_ORIGINAL', bytes(len(receiver.QUEUE_ORIGINAL))):
            with self.assertRaisesRegex(ValueError, 'queue adapter allocation preimage'):
                receiver.build()

    def test_abs_report_acceptance_preimage_is_required(self):
        with patch.object(receiver, 'RECEIVE_REPORT_PREIMAGE', bytes(4)):
            with self.assertRaisesRegex(ValueError, 'report acceptance preimage'):
                receiver.build()
