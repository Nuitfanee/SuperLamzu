"""Sparse HEX contracts shared by inspect, build and device candidate checks."""
from pathlib import Path
import tempfile
import unittest

from superlamzu.hexfile import Image


def record(address, kind, data=b''):
    body = bytes((len(data), address >> 8, address & 255, kind)) + data
    return ':' + (body + bytes((-sum(body) & 255,))).hex()


class HexfileTests(unittest.TestCase):
    def image(self, lines):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'image.hex'
            path.write_text('\n'.join(lines) + '\n', encoding='ascii')
            return Image(path)

    def test_control_records_require_exact_payload_and_zero_address(self):
        for kind, payload in ((1, b'\x00'), (2, b'\x00'), (4, b'\x00'), (5, b'\x00\x00')):
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, 'control record'):
                self.image([record(0, 0, b'\x01'), record(0, kind, payload), record(0, 1)])
        for kind, payload in ((1, b''), (2, bytes(2)), (4, bytes(2)), (5, bytes(4))):
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, 'control record'):
                self.image([record(0, 0, b'\x01'), record(1, kind, payload), record(0, 1)])

    def test_short_empty_trailing_and_cross_boundary_records_rejected(self):
        for lines, error in (([':'], 'short'), ([record(0, 1)], 'no data'),
                             ([record(0, 0, b'\x01'), record(0, 1), record(1, 0, b'\x02')], 'after EOF'),
                             ([record(0xffff, 0, b'\x01\x02'), record(0, 1)], 'boundary')):
            with self.subTest(lines=lines), self.assertRaisesRegex(ValueError, error):
                self.image(lines)

    def test_segment_address_and_sparse_bytes_preserved(self):
        image = self.image([record(0, 2, b'\x12\x34'), record(2, 0, b'\x01'),
                            record(4, 0, b'\x02'), record(0, 1)])
        self.assertEqual(image.mem, {0x12342: 1, 0x12344: 2})
        self.assertEqual(image.data, b'\x01\xff\x02')

    def test_sparse_inspection_does_not_materialize_four_gibibyte_gap(self):
        from superlamzu import fw
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'sparse.hex'
            path.write_text('\n'.join((record(0, 0, b'\x01'), record(0, 4, b'\xff\xff'),
                                       record(0xffff, 0, b'\x02'), record(0, 1)))+'\n', encoding='ascii')
            image = Image(path)
            self.assertNotIn('data', image.__dict__)
            result = fw.inspect_image(path)
            self.assertEqual((result['data_bytes'], result['span_bytes']), (2, 2**32))
            self.assertEqual(result['gap_bytes'], 2**32-2)

    def test_vector_identity_does_not_imply_verified_write_span(self):
        from superlamzu import fw, target as T
        vectors = T.SP.to_bytes(4, 'little') + T.RESET.to_bytes(4, 'little')
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'vectors-only.hex'
            path.write_text('\n'.join((record(0, 4, (T.BASE >> 16).to_bytes(2, 'big')),
                                      record(T.BASE & 65535, 0, vectors), record(0, 1))) + '\n')
            result = fw.inspect_image(path)
        self.assertTrue(result['target_vectors_match'])
        self.assertFalse(result['bootloader_protocol_verified'])
        self.assertIsNone(result['write_entry_point'])
