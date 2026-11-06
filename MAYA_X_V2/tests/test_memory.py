"""Existing queue-boundary scenarios executed with MAYA's six-byte header."""
import unittest

from MAYA_X_V2 import target as T
from MAYA_X_V2.memory import evidence
from MAYA_X_V2.sensor import LAYOUT
from superlamzu.emulation import Arm
from superlamzu.hexfile import Image


class MemoryTests(unittest.TestCase):
    def test_native_queue_ownership_and_mpu_preimages(self):
        data = evidence(Image(T.STOCK))
        self.assertEqual(data['stats'], 0x2000EE50)
        self.assertEqual(data['queue3'], 0x2000EF0D)
        self.assertEqual(data['pointer'], 0x2000EE4D)
        self.assertEqual(data['absolute_tail_aliases'], [])

    def test_all_native_queue_accessors_preserve_reclaimed_tail(self):
        # Same full/wrap/pop contract as superlamzu.checks.queue_boundary_check;
        # MAYA stores payload inline at +6 and has no descriptor data pointer.
        with Arm(Image(T.STOCK), layout=LAYOUT) as cpu:
            def memcpy(cpu):
                cpu.uc.mem_write(cpu.reg('r0'), bytes(cpu.uc.mem_read(cpu.reg('r1'), cpu.reg('r2'))))
                return cpu.reg('r0')
            cpu.stub(T.NATIVE_MEMCPY, effect=memcpy)
            source, destination, length = 0x20015000, 0x20015100, 0x20015200
            cpu.uc.mem_write(source, bytes(range(12)))
            cpu.uc.mem_write(T.SNAPSHOT_POINTER, b'\xA5'*192)
            for writer in (T.QUEUE_WRITE_VARIABLE, T.QUEUE_WRITE_RAW):
                for cycle in range(16):
                    cpu.run(T.QUEUE_INIT, 2)
                    self.assertEqual(cpu.run(T.QUEUE_POINTER, 2), T.RADIO_QUEUE2)
                    self.assertEqual(cpu.run(T.QUEUE_COUNT, 2), 0)
                    for i in range(8):
                        self.assertEqual(cpu.run(writer, 2, source, 11 if writer == T.QUEUE_WRITE_VARIABLE else 12), 1)
                        self.assertLess(cpu.byte(T.RADIO_QUEUE2+2), 8)
                    self.assertEqual(cpu.run(T.QUEUE_COUNT, 2), 8)
                    self.assertEqual(cpu.run(writer, 2, source, 11), 0)
                    for reader in (T.QUEUE_READ_VARIABLE, T.QUEUE_READ_RAW):
                        for i in range(4):
                            self.assertEqual(cpu.run(reader, 2, destination,
                                length if reader == T.QUEUE_READ_VARIABLE else 12), 1)
                            self.assertLess(cpu.byte(T.RADIO_QUEUE2+3), 8)
                    self.assertEqual(cpu.run(T.QUEUE_COUNT, 2), 0)
                    self.assertEqual(cpu.run(T.QUEUE_READ_RAW, 2, destination, 12), 0)
                    self.assertEqual(bytes(cpu.uc.mem_read(T.SNAPSHOT_POINTER, 192)), b'\xA5'*192)
            cpu.run(T.QUEUE_INIT, 2)
            for i in range(8):
                cpu.run(T.QUEUE_WRITE_RAW, 2, source, 12)
            for n in (1, 2, 5):
                self.assertEqual(cpu.run(T.QUEUE_ADVANCE, 2, n), 1)
            self.assertEqual(cpu.run(T.QUEUE_COUNT, 2), 0)
            self.assertEqual(bytes(cpu.uc.mem_read(T.SNAPSHOT_POINTER, 192)), b'\xA5'*192)


if __name__ == '__main__':
    unittest.main()
