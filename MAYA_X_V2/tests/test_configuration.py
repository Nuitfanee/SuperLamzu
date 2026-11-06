"""Execute the shared SLZ1 handler against the real MAYA profile/reload ABI."""
import itertools
import unittest

from MAYA_X_V2 import target as T
from MAYA_X_V2.configuration import build_native
from MAYA_X_V2.sensor import LAYOUT
from superlamzu import protocol as P
from superlamzu.emulation import Arm
from superlamzu.verify import patched_image, request


class ConfigurationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.builder = build_native()
        cls.changed = patched_image(cls.builder)

    def cpu(self, patched=True):
        image = self.changed if patched else self.builder.image
        cpu = Arm(image, layout=LAYOUT)
        cpu.uc.mem_write(T.SETTINGS, image.get(T.SETTINGS_DEFAULT, T.SETTINGS_BYTES))
        cpu.stub(T.SCHEDULE_SAVE)
        return cpu

    def test_capabilities_only_advertise_implemented_features(self):
        with self.cpu() as cpu:
            status, data = request(cpu, P.GET, (0, P.CAPS), target=T)
            self.assertEqual(status, 0xA0)
            self.assertEqual(P.decode_capabilities(data), dict(
                api=1, flags=P.F_DB | P.F_B, profiles=3, cpi_max=40000,
                stats_bytes=0, preset_count=0))
            for operation in range(P.FPS, P.CHANNELS+1):
                for command in (P.GET, P.SET):
                    self.assertEqual(request(cpu, command, (0, operation), target=T)[0], 0xA2)

    def test_native_six_byte_reload_and_four_field_profile_writes(self):
        cases = 0
        with self.cpu() as cpu:
            for active, profile in itertools.product(range(3), range(1, 4)):
                cpu.uc.mem_write(T.ACTIVE_PROFILE, bytes((active,)))
                cpu.run(T.RELOAD_DB)
                before = bytes(cpu.uc.mem_read(T.SETTINGS, T.SETTINGS_BYTES))
                live = bytes(cpu.uc.mem_read(T.LIVE_DB, 6))
                values = bytes((profile*3, profile*5, profile*7, profile*11))
                response = request(cpu, P.SET, (profile, P.DEBOUNCE, *values), target=T)
                self.assertEqual(response, (0xA0, bytes((profile,))+values))
                expected = bytearray(before)
                offset = (profile-1)*T.PROFILE_STRIDE+7
                expected[offset:offset+4] = values
                self.assertEqual(bytes(cpu.uc.mem_read(T.SETTINGS, T.SETTINGS_BYTES)), expected)
                self.assertEqual(bytes(cpu.uc.mem_read(T.LIVE_DB, 6)),
                                 values+live[4:] if active == profile-1 else live)
                self.assertEqual(request(cpu, P.GET, (profile, P.DEBOUNCE), target=T),
                                 (0xA0, bytes((profile,))+values))
                self.assertEqual(cpu.calls[-1][0:3], (T.SCHEDULE_SAVE, 8, 0))
                self.assertEqual(cpu.reg('sp'), T.SP)
                cases += 1
            self.assertEqual(cases, 9)

    def test_full_byte_range_and_callee_saved_registers(self):
        with self.cpu() as cpu:
            for value in range(256):
                for reg in range(4, 12):
                    cpu.setreg(f'r{reg}', 0x1100+reg)
                payload = (3, P.DEBOUNCE, value, value, value, value)
                self.assertEqual(request(cpu, P.SET, payload, target=T),
                                 (0xA0, bytes((3, value, value, value, value))))
                self.assertEqual([cpu.reg(f'r{reg}') for reg in range(4, 12)],
                                 [0x1100+reg for reg in range(4, 12)])
                self.assertEqual(cpu.reg('sp'), T.SP)

    def test_malformed_operations_have_no_settings_or_save_side_effects(self):
        with self.cpu() as cpu:
            cases = [(P.GET, (p, P.DEBOUNCE), 2) for p in (0, 4, 255)]
            cases += [(P.SET, (p, P.DEBOUNCE, 1, 2, 3, 4), 6) for p in (0, 4, 255)]
            cases += [(cmd, payload, n) for cmd, payload in (
                (P.GET, (1, P.DEBOUNCE)), (P.SET, (1, P.DEBOUNCE, 1, 2, 3, 4)),
                (P.GET, (0, P.CAPS))) for n in (0, 1, 3, 5, 7, 58)
                if n != len(payload)]
            cases += [(P.SET, (0, P.CAPS), 2), (P.GET, (1, P.CAPS), 2)]
            for cmd, payload, length in cases:
                with self.subTest(cmd=cmd, payload=payload, length=length):
                    before = bytes(cpu.uc.mem_read(T.SETTINGS, T.SETTINGS_BYTES))
                    calls = len(cpu.calls)
                    self.assertEqual(request(cpu, cmd, payload, length, target=T)[0], 0xA2)
                    self.assertEqual(bytes(cpu.uc.mem_read(T.SETTINGS, T.SETTINGS_BYTES)), before)
                    self.assertEqual(len(cpu.calls), calls)

    def test_original_group1_commands_preserve_native_packet_and_settings(self):
        # The native descriptor is deliberately absent here, exercising the
        # stock null-callback paths rather than substituting a Thorn descriptor.
        commands = (0x80, 0x82, 0x84, 0x88, 0x89, 0x8A, 0x8B, 0x8D,
                    0x8E, 0x8F, 0x93, 0x94, 0x95, 0x97,
                    4, 8, 9, 10, 11, 13, 14, 19, 20, 21)
        for command, profile in itertools.product(commands, range(1, 4)):
            results = []
            for patched in (False, True):
                with self.cpu(patched) as cpu:
                    cpu.uc.mem_write(0x2000C004, b'\4')
                    reply = request(cpu, command, (profile, 0, 0), target=T)
                    results.append((reply, bytes(cpu.uc.mem_read(T.PACKET, 64)),
                                    bytes(cpu.uc.mem_read(T.SETTINGS, T.SETTINGS_BYTES)),
                                    cpu.calls, cpu.reg('sp')))
            self.assertEqual(results[0], results[1], (command, profile))


if __name__ == '__main__':
    unittest.main()
