"""Host-only regression tests. No HID device is opened, including subprocess tests."""
import contextlib
import importlib
import io
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from superlamzu import cfg, fw, protocol as abi, target
from superlamzu import __main__ as entry


class FakeDevice:
    """LAMZU-native request/reply fake at the reused ko1_hid device boundary."""

    def __init__(self, flags=abi.F_DB | abi.F_B, report_id=True):
        self.flags, self.report_id = flags, report_id
        self.db = {i: list(abi.DB_FACTORY) for i in range(1, 4)}
        self.stages = {i: [(800, 800), (1600, 1600)] for i in range(1, 4)}
        self.active_stages = {i: 1 for i in range(1, 4)}
        self.active = 1
        self.regs = {}
        self.log = []
        self.saved = []
        self.loaded = []
        self.reply = bytes(64)
        self.closed = False
        self.override = None
        self.fps_requested = self.fps_applied = 0
        self.fps_pending = False
        self.custom_recipe = bytes(3)
        self.custom_readback = bytes(3)
        self.custom_valid = False
        self.preset_count = 4
        self.lock_enabled, self.lock_lead, self.lock_effective_lead = False, 0, 80
        self.stats_enabled = False
        self.runtime = bytearray(abi.STATS_BYTES)
        self.runtime[0] = 1
        for i in range(43):
            struct.pack_into("<I", self.runtime, 16 + 4 * i, 0x10203040 + i)
        self.caps = abi.capabilities(flags or 0, self.preset_count if (flags or 0) & abi.F_FPS else 0)

    def set_report(self, req):
        assert len(req) == 64
        assert req[2] == 0, "tests only support the explicit wired APP target"
        self.log.append(bytes(req))
        group, cmd, profile = req[4], req[5], req[6]
        reply = bytearray(64)
        reply[0], reply[3], reply[4], reply[5] = 0xA1, req[3], group, cmd
        reply[6] = profile
        if (group, cmd) in ((1, abi.GET), (1, abi.SET)):
            if self.flags is None:
                reply[0] = 0xA3
            elif (cmd, req[3], req[6], req[7]) == (abi.GET, 2, 0, abi.CAPS):
                reply[3] = len(self.caps)
                reply[6:6 + len(self.caps)] = self.caps
            elif req[7] == abi.DEBOUNCE and profile in self.db and self.flags & abi.F_DB:
                if cmd == abi.SET and req[3] == 6:
                    self.db[profile] = list(req[8:12])
                    self.saved.append(profile)
                    if profile == self.active:
                        self.loaded.append(profile)
                elif cmd != abi.GET or req[3] != 2:
                    reply[0] = 0xA2
                reply[3] = 5
                reply[6:11] = bytes((profile, *self.db[profile]))
            elif req[7] == abi.FPS and profile == 0 and self.flags & abi.F_FPS:
                if cmd == abi.SET and req[3] == 3:
                    if req[8] >= self.preset_count:
                        reply[0] = 0xA2
                    else:
                        self.fps_requested = req[8]
                        self.fps_pending = True
                elif cmd != abi.GET or req[3] != 2:
                    reply[0] = 0xA2
                reply[3] = 6
                reply[6:12] = bytes((0, 2, self.fps_requested, self.fps_applied,
                                     self.fps_pending, self.preset_count))
            elif req[7] == abi.FPS_CUSTOM and profile == 0 and self.flags & abi.F_FPS_CUSTOM:
                if cmd == abi.SET and req[3] == 5:
                    self.custom_recipe = req[8:11]
                    self.fps_requested = abi.CUSTOM_FPS_ID
                    self.fps_pending = True
                elif cmd != abi.GET or req[3] != 2:
                    reply[0] = 0xA2
                reply[3] = 12
                reply[6:18] = (bytes((0, abi.FPS_CUSTOM, self.fps_requested,
                                     self.fps_applied, self.fps_pending)) + self.custom_recipe
                               + self.custom_readback + bytes((self.custom_valid,)))
            elif req[7] == abi.LOCK and profile == 0 and self.flags & abi.F_LOCK:
                if cmd == abi.SET and req[3] == 5:
                    self.lock_enabled = bool(req[8])
                    self.lock_lead = int.from_bytes(req[9:11], "little")
                    self.lock_effective_lead = self.lock_lead or 80
                elif cmd != abi.GET or req[3] != 2:
                    reply[0] = 0xA2
                reply[3] = 7
                reply[6:13] = bytes((0, 3, self.lock_enabled)) + struct.pack(
                    "<HH", self.lock_lead, self.lock_effective_lead)
            elif req[7] == abi.STATS and profile == 0 and self.flags & abi.F_STATS:
                if cmd == abi.GET and req[3] == 3 and req[8] < 6:
                    page = req[8]
                    data = self.runtime[page * 32:(page + 1) * 32]
                    reply[3] = 3 + len(data)
                    reply[6:9 + len(data)] = bytes((0, 4, page)) + data
                elif cmd == abi.SET and req[3] == 3 and req[8] < 3:
                    if req[8] < 2:
                        self.stats_enabled = bool(req[8])
                    reply[3] = 3
                    reply[6:9] = bytes((0, 4, self.stats_enabled))
                else:
                    reply[0] = 0xA2
            else:
                reply[0] = 0xA3
        elif (group, cmd) == (0, 0x81):
            reply[6:10] = bytes((0, 0, 1, 16))
        elif (group, cmd) == (0, 0x85):
            reply[6] = self.active
        elif (group, cmd) == (0, 0x86):
            reply[6] = 3
        elif (group, cmd) == (0, 5):
            self.active = profile
        elif (group, cmd) == (1, 0x8F):
            reply[6] = 4
        elif (group, cmd) == (0, 0x83):
            reply[6:8] = bytes((0, 87))
        elif (group, cmd) == (0, 0x88):
            reply[7] = self.db[profile][0]
        elif (group, cmd) == (0, 8):
            self.db[profile][0] = req[7]
        elif (group, cmd) == (1, 0x81):
            stages = self.stages[profile]
            reply[7] = len(stages)
            for i, (x, y) in enumerate(stages):
                reply[8 + 4 * i:12 + 4 * i] = struct.pack(">HH", x, y)
        elif (group, cmd) == (1, 1):
            self.stages[profile] = [struct.unpack(">HH", req[8 + 4 * i:12 + 4 * i]) for i in range(req[7])]
        elif (group, cmd) == (1, 2):
            self.active_stages[profile] = req[7]
        elif (group, cmd) == (1, 0x82):
            reply[7] = self.active_stages[profile]
        elif (group, cmd) == (0, 0x9A):
            reply[7:9] = self.regs.get((profile, group, cmd), bytes((0, 0)))
        elif (group, cmd) == (0, 0x1A):
            self.regs[(profile, group, cmd | 0x80)] = req[7:9]
        elif (group, cmd) == (0, 7):
            self.regs[(profile, group, cmd | 0x80)] = req[7:9]
        elif (group, cmd) == (0, 0x87):
            reply[7:9] = self.regs.get((profile, group, cmd), bytes((0, 120)))
        elif cmd < 0x80:
            self.regs[(profile, group, cmd | 0x80)] = req[7]
        else:
            reply[7] = self.regs.get((profile, group, cmd), 1)
        if self.override:
            self.override(req, reply)
        self.reply = bytes(reply)

    def get_report(self):
        return (b"\0" if self.report_id else b"") + self.reply

    def close(self):
        self.closed = True


class HostTest(unittest.TestCase):
    def setUp(self):
        self.sleep = patch.object(cfg.native.time, "sleep")
        self.sleep.start()
        # Fail loudly on accidental actual HID enumeration/open in ANY unit test.
        self.find_guard = patch.object(cfg.hid, "find_nodes", side_effect=AssertionError("real enumeration forbidden"))
        self.open_guard = patch.object(cfg.hid, "open_node", side_effect=AssertionError("real HID open forbidden"))
        self.find_guard.start(); self.open_guard.start()

    def tearDown(self):
        self.open_guard.stop(); self.find_guard.stop(); self.sleep.stop()

    def mouse(self, flags=abi.F_DB | abi.F_B, profile=1, report_id=True):
        dev = FakeDevice(flags, report_id)
        return cfg.Mouse(cfg.Link(dev, delay=0), 0, profile), dev

    def run_cfg(self, argv, dev=None):
        dev = dev or FakeDevice()
        output = io.StringIO()
        with patch.object(cfg, "open_device", return_value=(dev, target.APP_PID)), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            rc = cfg.main(argv)
        return rc, output.getvalue(), dev

    def test_reference_globals_and_transport_unchanged(self):
        self.assertEqual((cfg.native.VID, cfg.native.PID_WIRED, cfg.native.PID_RECEIVER),
                         (0x373E, 0x006A, 0x006B))
        self.assertIs(cfg.hid, importlib.import_module("ko1_hid"))
        self.assertIs(cfg.native.Mouse._set, cfg.Mouse._set)

    def test_caps_exact_envelope_and_cache(self):
        mouse, dev = self.mouse()
        caps = mouse.capabilities()
        self.assertEqual(caps, abi.decode_capabilities(abi.capabilities(abi.F_DB | abi.F_B)))
        req = dev.log[0]
        self.assertEqual(req[2:8], bytes((0, 2, 1, 0x96, 0, 0)))
        caps["flags"] = 0
        self.assertNotEqual(mouse.capabilities()["flags"], 0)
        self.assertEqual(len(dev.log), 1)
        mouse.capabilities(refresh=True)
        self.assertEqual(len(dev.log), 2)

    def test_default_profile_uses_active_native_profile(self):
        dev = FakeDevice(); dev.active = 3
        mouse = cfg.Mouse(cfg.Link(dev, delay=0))
        self.assertEqual(mouse.debounce_values(), abi.DB_FACTORY)
        self.assertEqual(dev.log[-1][6:8], bytes((3, abi.DEBOUNCE)))
        self.assertEqual(sum((p[4], p[5]) == (0, 0x85) for p in dev.log), 1)

    def test_retired_click_cli_is_removed_but_native_controls_remain(self):
        parser = cfg.build_parser()
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            parser.parse_args(['click', 'optical-direct'])
        self.assertEqual(parser.parse_args(['path', 'direct']).path, 'direct')
        self.assertEqual(parser.parse_args(['debounce-set', '--post', '2']).post, '2')
        self.assertEqual(parser.parse_args(['get', 'speed-click']).name, 'speed-click')

    def test_legacy_optical_api_is_capability_gated_and_keeps_old_reply_contract(self):
        mouse, dev = self.mouse()
        with self.assertRaises(cfg.Unsupported):
            mouse.optical_click()
        self.assertFalse(any(r[7] == abi.OPTICAL_CLICK for r in dev.log))
        raw = bytes((0, abi.OPTICAL_CLICK, 1, 0, 1, 0)) + bytes(6)
        with patch.object(mouse, '_global_extension', return_value=raw):
            status = mouse.optical_click('optical-direct')
            self.assertEqual((status['requested'], status['effective'], status['pending']),
                             ('optical-direct', 'stock', True))
            for mode in ('safe', 'fast', 1, True):
                with self.assertRaises(cfg.CfgError):
                    mouse.optical_click(mode)
        with patch.object(mouse, '_global_extension', return_value=bytes((0, abi.OPTICAL_CLICK, 1, 0, 0, 0)) + bytes(6)):
            with self.assertRaises(cfg.ProtocolError):
                mouse.optical_click()

    def test_stock_a3_is_unsupported_not_timeout(self):
        mouse, dev = self.mouse(flags=None)
        with self.assertRaisesRegex(cfg.Unsupported, "0xA3.*stock LAMZU"):
            mouse.capabilities()
        self.assertEqual(len(dev.log), 1)
        rc, out, _ = self.run_cfg(["caps"], FakeDevice(flags=None))
        self.assertEqual(rc, 3)
        self.assertIn("unsupported", out)
        self.assertNotIn("no valid reply", out)

    def test_caps_magic_version_length_geometry_checked(self):
        for name, payload in (("magic", b"NOPE" + abi.capabilities(1)[4:]),
                              ("version", b"SLZ1\x02" + abi.capabilities(1)[5:]),
                              ("length", b"SLZ1"),
                              ("profiles", abi.capabilities(1)[:7] + b"\x02" + abi.capabilities(1)[8:]),
                              ("cpi", abi.capabilities(1)[:8] + b"\x00\x01" + abi.capabilities(1)[10:])):
            with self.subTest(name=name):
                mouse, dev = self.mouse()
                dev.caps = payload
                with self.assertRaises(cfg.ProtocolError):
                    mouse.capabilities()

    def test_extension_payload_length_and_profile_mismatch_fail(self):
        for length in (0, 4, 6, 58):
            with self.subTest(length=length):
                mouse, dev = self.mouse()
                dev.override = lambda req, reply: reply.__setitem__(3, length) if req[7] == abi.DEBOUNCE else None
                with self.assertRaises(cfg.ProtocolError):
                    mouse.debounce_values()

    def test_db_capability_required_before_setting(self):
        mouse, dev = self.mouse(flags=abi.F_B)
        with self.assertRaises(cfg.Unsupported):
            mouse.set_debounce((1, 2, 3, 4))
        self.assertEqual(len(dev.log), 1)
        self.assertEqual(dev.saved, [])

    def test_db_three_profiles_and_integer_byte_semantics(self):
        for profile in range(1, 4):
            for report_id in (False, True):
                with self.subTest(profile=profile, report_id=report_id):
                    mouse, dev = self.mouse(profile=profile, report_id=report_id)
                    self.assertEqual(mouse.debounce_values(), abi.DB_FACTORY)
                    want = (0, 101, 128, 255)
                    self.assertEqual(mouse.set_debounce(want), want)
                    self.assertEqual(tuple(dev.db[profile]), want)
                    sets = [req for req in dev.log if req[5] == abi.SET]
                    self.assertEqual(len(sets), 1)
                    self.assertEqual(sets[0][3:12], bytes((6, 1, 0x16, profile, 1, *want)))
                    for p in set(range(1, 4)) - {profile}:
                        self.assertEqual(tuple(dev.db[p]), abi.DB_FACTORY)
                    self.assertEqual(dev.saved, [profile])
                    self.assertEqual(dev.loaded, [profile] if profile == 1 else [])

    def test_db_invalid_inputs_send_nothing(self):
        for values in ((-1, 2, 3, 4), (0, 256, 3, 4), (0.1, 2, 3, 4),
                       (True, 2, 3, 4), ("stock", 2, 3, 4), ("default", 2, 3, 4), (1, 2, 3)):
            with self.subTest(values=values):
                mouse, dev = self.mouse()
                with self.assertRaises(cfg.CfgError):
                    mouse.set_debounce(values)
                self.assertEqual(dev.log, [])

    def test_bad_profile_rejected_before_transfer(self):
        for profile in (0, 4, -1, 1.5, True):
            with self.subTest(profile=profile), self.assertRaises(cfg.CfgError):
                self.mouse(profile=profile)

    def test_db_stale_profile_and_set_ack_rejected(self):
        for command in (abi.GET, abi.SET):
            with self.subTest(command=command):
                mouse, dev = self.mouse()
                dev.override = lambda req, reply: reply.__setitem__(6, 3) if req[5] == command and req[7] == 1 else None
                with self.assertRaises(cfg.ProtocolError):
                    mouse.debounce_values() if command == abi.GET else mouse.set_debounce((1, 2, 3, 4))

    def test_db_readback_mismatch_fails(self):
        mouse, dev = self.mouse()
        def override(req, reply):
            if req[5] == abi.GET and req[7] == abi.DEBOUNCE:
                reply[7:11] = bytes(abi.DB_FACTORY)
        dev.override = override
        with self.assertRaisesRegex(cfg.ProtocolError, "readback mismatch"):
            mouse.set_debounce((4, 3, 2, 1))

    def test_partial_db_write_keeps_other_fields(self):
        rc, out, dev = self.run_cfg(["--profile", "2", "debounce-set", "--post", "255"])
        self.assertEqual(rc, 0, out)
        self.assertEqual(dev.db[2], [0, 255, 20, 20])
        self.assertEqual(dev.db[1], [0, 2, 20, 20])
        self.assertTrue(dev.closed)

    def test_db_factory_is_values_not_special_codes(self):
        dev = FakeDevice(); dev.db[3] = [255] * 4
        rc, out, dev = self.run_cfg(["--profile", "3", "set", "debounce", "factory"], dev)
        self.assertEqual(rc, 0, out)
        self.assertEqual(dev.db[3], list(abi.DB_FACTORY))

    def test_native_panel_pre_preserves_other_fields_and_needs_no_slz(self):
        dev = FakeDevice(flags=None)
        rc, out, dev = self.run_cfg(["--profile", "2", "set", "panel-debounce", "37"], dev)
        self.assertEqual(rc, 0, out)
        self.assertEqual(dev.db[2], [37, 2, 20, 20])
        self.assertEqual([(p[4], p[5]) for p in dev.log], [(0, 8), (0, 0x88)])

    def test_all_five_lod_presets_and_no_research_codes(self):
        mouse, dev = self.mouse()
        for label, code in cfg.LOD_CODES.items():
            mouse.set_lod(label)
            self.assertEqual(dev.log[-1][3:8], bytes((2, 1, 8, 1, code)))
            self.assertEqual(mouse.lod(), float(label))
        for value in (2, 0x8F, 0, 255):
            before = len(dev.log)
            with self.assertRaises(cfg.CfgError):
                mouse.set_lod_raw(value)
            self.assertEqual(len(dev.log), before)

    def test_cli_lod_labels_are_target_specific(self):
        for label in cfg.LOD_CODES:
            rc, out, _ = self.run_cfg(["set", "lod", label])
            self.assertEqual(rc, 0, out)
        rc, out, dev = self.run_cfg(["set", "lod", "2"])
        self.assertEqual(rc, 1, out)
        self.assertEqual(dev.log, [])
        rc, out, dev = self.run_cfg(["set", "lod", "1.3000001"])
        self.assertEqual(rc, 1, out)
        self.assertEqual(dev.log, [])

    def test_cpi_one_step_full_range_no_native_50_step_check(self):
        rc, out, dev = self.run_cfg(["--profile", "3", "dpi", "1", "801x799", "40000"])
        self.assertEqual(rc, 0, out)
        self.assertEqual(dev.stages[3], [(1, 1), (801, 799), (40000, 40000)])
        self.assertNotIn("multiple of 50", out)
        for value in ("0", "40001", "0.1", "800x40001"):
            rc, out, dev = self.run_cfg(["dpi", value])
            self.assertEqual(rc, 1, out)
            self.assertFalse(any((r[4], r[5]) == (1, 1) for r in dev.log))

    def test_dpi_set_preserves_other_stages_and_can_activate(self):
        rc, out, dev = self.run_cfg(["dpi-set", "40000x1", "--stage", "2", "--activate"])
        self.assertEqual(rc, 0, out)
        self.assertEqual(dev.stages[1], [(800, 800), (40000, 1)])
        self.assertEqual(dev.active_stages[1], 2)

    def test_native_basic_set_and_get_reuse(self):
        commands = [("polling", ["8000"]), ("motion-sync", ["off"]),
                    ("angle-snap", ["on"]), ("ripple", ["off"]),
                    ("hyper", ["on"]), ("ce", ["on"]), ("dpi-xy", ["on"]),
                    ("angle-tune", ["-30"]), ("sleep", ["3"]),
                    ("speed-click", ["on", "off"])]
        for name, values in commands:
            with self.subTest(name=name):
                rc, out, dev = self.run_cfg(["set", name, *values])
                self.assertEqual(rc, 0, out)
                self.assertTrue(dev.closed)
                self.assertFalse(any(r[5] in (abi.GET, abi.SET) for r in dev.log))

    def test_native_gets_and_profile_switch(self):
        dev = FakeDevice(flags=None)
        for name in ("dpi", "dpi-now", "battery", "profile", "lod", "panel-debounce", "speed-click"):
            rc, out, _ = self.run_cfg(["get", name], dev)
            self.assertEqual(rc, 0, out)
        rc, out, _ = self.run_cfg(["profile", "3"], dev)
        self.assertEqual(rc, 0, out)
        self.assertEqual(dev.active, 3)

    def test_stock_info_is_success_with_clear_unsupported_extension(self):
        rc, out, dev = self.run_cfg(["info"], FakeDevice(flags=None))
        self.assertEqual(rc, 0, out)
        self.assertIn("37B0:0040", out)
        self.assertIn("40000 (step 1)", out)
        self.assertIn("0xA3", out)
        self.assertTrue(dev.closed)

    def test_drako_research_not_sent(self):
        mouse, dev = self.mouse()
        for operation in (lambda: mouse.poke(1, 2, 3), mouse.sensor_value,
                          lambda: mouse.fps_apply(0), lambda: mouse._db_req(0xC8),
                          lambda: mouse._stats_req(0)):
            with self.assertRaises(cfg.Unsupported):
                operation()
        self.assertEqual(dev.log, [])

    def test_terminal_error_during_pending_poll_is_immediate(self):
        class Pending(FakeDevice):
            def __init__(self, status):
                super().__init__(); self.reads = 0; self.status = status
            def get_report(self):
                self.reads += 1
                if self.reads == 1:
                    reply = bytearray(self.reply); reply[0] = 0xA0
                    return b"\0" + reply
                reply = bytearray(self.reply); reply[0] = self.status
                return b"\0" + reply
        for status, exc in ((0xA2, cfg.CfgRejected), (0xA3, cfg.Unsupported)):
            dev = Pending(status)
            mouse = cfg.Mouse(cfg.Link(dev, delay=0), 0, 1)
            with self.assertRaises(exc):
                mouse.capabilities()
            self.assertEqual(len(dev.log), 1)
            self.assertEqual(dev.reads, 2)

    def test_stale_command_reply_is_ignored_not_misclassified(self):
        class Stale(FakeDevice):
            def __init__(self):
                super().__init__(); self.reads = 0
            def get_report(self):
                self.reads += 1
                if self.reads == 1:
                    reply = bytearray(self.reply); reply[0] = 0xA3; reply[5] = 0x81
                    return b"\0" + reply
                return super().get_report()
        dev = Stale()
        mouse = cfg.Mouse(cfg.Link(dev, delay=0), 0, 1)
        self.assertEqual(mouse.capabilities()["api"], 1)
        self.assertEqual(len(dev.log), 2)

    def test_truncated_reply_is_protocol_error(self):
        dev = FakeDevice()
        dev.get_report = lambda: b"\xa1"
        with self.assertRaisesRegex(cfg.ProtocolError, "truncated"):
            cfg.Mouse(cfg.Link(dev, delay=0), 0, 1).capabilities()

    def test_configuration_reset_sends_native_not_bootloader(self):
        for argv in (["reset-settings", "--yes"], ["reset-profile", "2", "--yes"]):
            rc, out, dev = self.run_cfg(argv)
            self.assertEqual(rc, 0, out)
            self.assertTrue(dev.closed)
            self.assertFalse(any((r[4], r[5], r[6]) == (0, 0, 0xB0) for r in dev.log))

    def test_error_paths_close_open_device(self):
        rc, out, dev = self.run_cfg(["get", "nonexistent"])
        self.assertEqual(rc, 1, out)
        self.assertTrue(dev.closed)

    def test_receiver_and_reset_not_authorized_before_open(self):
        for argv in (["--via", "receiver", "info"], ["reset-settings"], ["reset-profile", "1"]):
            with patch.object(cfg, "open_device", side_effect=AssertionError("must not open")), \
                    contextlib.redirect_stderr(io.StringIO()):
                self.assertNotEqual(cfg.main(argv), 0)

    def test_device_selection_uses_lamzu_only_and_validates_node(self):
        node = cfg.hid.Node("lamzu-app", b"lamzu-app", target.VID, target.APP_PID,
                            usage_page=0xFF00)
        fake = FakeDevice()
        with patch.object(cfg.hid, "find_nodes", return_value=[node]) as find, \
                patch.object(cfg.hid, "open_node", return_value=fake) as opened:
            self.assertEqual(cfg.open_device("auto", "lamzu-app"), (fake, target.APP_PID))
            find.assert_called_with(0x37B0, 0x0040)
            opened.assert_called_once_with(node)
            with self.assertRaises(cfg.CfgError):
                cfg.open_device("wired", "drako-or-bootloader")
            self.assertEqual(opened.call_count, 1)

    def test_list_does_not_open_device(self):
        with patch.object(cfg, "find_nodes", return_value=[]), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cfg.main(["list"]), 0)

    def test_patch_dispatch_forwards_argv_unchanged(self):
        stub = types.ModuleType("superlamzu.patch")
        stub.main = Mock(return_value=17)
        argv = ["FULL", "-o", "a path with spaces.hex"]
        with patch.dict(sys.modules, {"superlamzu.patch": stub}):
            self.assertEqual(entry.main(["patch", *argv]), 17)
        stub.main.assert_called_once_with(argv)

    def test_help_import_and_patch_dispatch_are_hardware_free(self):
        program = """
import sys, types
guard = types.ModuleType('hid')
def forbidden(*a, **kw): raise AssertionError('actual HID access')
guard.enumerate = guard.device = forbidden
sys.modules['hid'] = guard
import superlamzu.cfg, superlamzu.fw
assert 'unicorn' not in sys.modules and 'capstone' not in sys.modules
from superlamzu.__main__ import main
assert main(['--help']) == 0
try: main(['cfg', '--help'])
except SystemExit as e: assert e.code == 0
try: main(['fw', '--help'])
except SystemExit as e: assert e.code == 0
"""
        result = subprocess.run([sys.executable, "-c", program], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_offline_inspection_preserves_sparse_meaning(self):
        report = fw.inspect_image(target.STOCK)
        self.assertEqual((report["span_bytes"], report["data_bytes"], report["gap_bytes"]),
                         (170500, 170477, 23))
        self.assertTrue(report["target_vectors_match"])
        self.assertFalse(report["flash_available"])
        self.assertTrue(report["bootloader_protocol_verified"])
        self.assertFalse(report["erase_supported"])
        self.assertEqual(report["write_entry_point"], "flasher/SuperLAMZU THORN V2-0.1.0-windows-x64.exe")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(fw.main(["dry-run", str(target.STOCK), "--json"]), 0)
        self.assertEqual(json.loads(out.getvalue())["gap_bytes"], 23)

    def test_offline_malformed_hex_and_gaps_are_not_written(self):
        def record(addr, kind, data):
            b = bytes((len(data), addr >> 8, addr & 255, kind)) + data
            return ":" + (b + bytes((-sum(b) & 255,))).hex()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sparse.hex"
            text = "\n".join((record(0, 4, b"\x0e\x06"), record(0x7000, 0, b"\x01\x02"),
                               record(0x7005, 0, b"\x03"), record(0, 1, b""))) + "\n"
            path.write_text(text)
            report = fw.inspect_image(path)
            self.assertEqual((report["data_bytes"], report["gap_bytes"]), (3, 3))
            self.assertEqual(path.read_text(), text)
            path.write_text(":this is not hex\n")
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(fw.main(["inspect", str(path)]), 1)

    def test_fw_dangerous_operations_unavailable_before_any_hid(self):
        for command in ("flash", "erase", "dump", "verify", "enter-bl", "exit-bl"):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
                fw.main([command])
            self.assertEqual(raised.exception.code, 2)

    def advanced_mouse(self, saved=False):
        flags = abi.F_DB | abi.F_B | abi.F_FPS | abi.F_LOCK | abi.F_STATS
        return self.mouse(flags | (abi.F_ADV_SAVED if saved else 0), profile=3)

    def test_advanced_requests_are_global_despite_selected_profile(self):
        m, dev = self.advanced_mouse()
        m.fps_status(); m.lock_status(); m.stats_page(0)
        self.assertTrue(all(req[6] == 0 for req in dev.log))
        self.assertFalse(any((req[4], req[5]) == (0, 0x85) for req in dev.log))

    def test_fps_status_set_wire_and_pending_not_completion(self):
        m, dev = self.advanced_mouse()
        status = m.fps_status()
        self.assertEqual(status, dict(requested=0, applied=0, pending=False, preset_count=4))
        self.assertEqual(dev.log[-1][3:8], bytes((2, 1, 0x96, 0, 2)))
        result = m.fps_set(2)
        self.assertEqual(dev.log[-1][3:9], bytes((3, 1, 0x16, 0, 2, 2)))
        self.assertEqual(result, dict(requested=2, applied=0, pending=True, preset_count=4))
        self.assertEqual(sum(req[5] == abi.SET for req in dev.log), 1)
        self.assertEqual(dev.saved, [])
        result = m.fps_set(0)
        self.assertEqual(result["requested"], 0)

    def test_fps_invalid_local_input_never_transfers(self):
        for value in (-1, 256, "1.5", 1.5, True):
            with self.subTest(value=value):
                m, dev = self.advanced_mouse()
                with self.assertRaises(cfg.CfgError):
                    m.fps_set(value)
                self.assertEqual(dev.log, [])

    def test_fps_count_includes_stock_and_bounds_before_set(self):
        m, dev = self.advanced_mouse()
        for ident in (4, 5, 255):
            with self.assertRaisesRegex(cfg.CfgError, "0..3"):
                m.fps_set(ident)
        self.assertEqual(len(dev.log), 1)
        self.assertFalse(any(req[5] == abi.SET for req in dev.log))
        self.assertEqual(m.fps_set(3)["requested"], 3)

    def test_fps_malformed_pending_count_prefix_length_and_set_ack(self):
        for offset, value in ((3, 5), (6, 2), (7, 3), (8, 4), (9, 4), (10, 2), (11, 9)):
            with self.subTest(offset=offset):
                m, dev = self.advanced_mouse()
                dev.override = lambda req, reply: reply.__setitem__(offset, value) if req[7] == 2 else None
                with self.assertRaises(cfg.ProtocolError):
                    m.fps_status()
        m, dev = self.advanced_mouse()
        dev.override = lambda req, reply: reply.__setitem__(8, 0) if req[7] == 2 and req[5] == abi.SET else None
        with self.assertRaises(cfg.ProtocolError):
            m.fps_set(2)

    def test_lock_status_set_uses_seven_byte_reply_and_le16(self):
        m, dev = self.advanced_mouse()
        self.assertEqual(m.lock_status(), dict(enabled=False, lead_us=0, effective_lead_us=80))
        self.assertEqual(dev.log[-1][3:8], bytes((2, 1, 0x96, 0, 3)))
        result = m.set_lock(True, 499)
        self.assertEqual(dev.log[-1][3:11], bytes((5, 1, 0x16, 0, 3, 1, 0xF3, 1)))
        self.assertEqual(result, dict(enabled=True, lead_us=499, effective_lead_us=499))
        result = m.set_lock(False, 0)
        self.assertEqual(result, dict(enabled=False, lead_us=0, effective_lead_us=80))
        self.assertEqual(dev.saved, [])

    def test_lock_partial_set_preserves_other_setting(self):
        m, dev = self.advanced_mouse()
        m.set_lock(True, 123)
        self.assertEqual(m.lock_switch(False)["lead_us"], 123)
        self.assertFalse(m.lock_lead(222)["enabled"])
        self.assertEqual(dev.lock_lead, 222)

    def test_lock_invalid_input_and_malformed_reply(self):
        for enabled, lead in ((True, -1), (True, 500), (True, 0.1), (2, 80), ("maybe", 80)):
            with self.subTest(enabled=enabled, lead=lead):
                m, dev = self.advanced_mouse()
                with self.assertRaises(cfg.CfgError):
                    m.set_lock(enabled, lead)
                self.assertEqual(dev.log, [])
        for offset, value in ((3, 8), (6, 1), (7, 2), (8, 2), (10, 2), (11, 81)):
            with self.subTest(offset=offset):
                m, dev = self.advanced_mouse()
                dev.override = lambda req, reply: reply.__setitem__(offset, value) if req[7] == 3 else None
                with self.assertRaises(cfg.ProtocolError):
                    m.lock_status()

    def test_stats_pages_and_exact_188_byte_assembly(self):
        m, dev = self.advanced_mouse()
        self.assertEqual(m.stats_raw(), bytes(dev.runtime))
        requests = [req for req in dev.log if req[7] == abi.STATS]
        self.assertEqual(len(requests), 6)
        self.assertEqual([req[3:9] for req in requests],
                         [bytes((3, 1, 0x96, 0, 4, page)) for page in range(6)])
        self.assertEqual(len(m.stats_page(5)), 28)
        self.assertEqual(m.stats()["record_bytes"], 188)

    def test_stats_field_map_matches_documented_version_one(self):
        from superlamzu.advanced import FIELDS, OFF
        m, dev = self.advanced_mouse()
        dev.runtime[:16] = bytes((1, 1, 1, 2, 0xF3, 1, 0x34, 0x12, 1, 1, 1, 8, 1, 0, 0, 0))
        decoded = m.stats()
        self.assertEqual(decoded["layout_version"], 1)
        self.assertTrue(decoded["counting_enabled"])
        self.assertTrue(decoded["lock_enabled"])
        self.assertEqual(decoded["fps_requested"], 2)
        self.assertEqual(decoded["lead_us"], 499)
        self.assertEqual(decoded["last_phase_capture_us"], 0x1234)
        self.assertEqual(decoded["fps_applied"], 1)
        self.assertTrue(decoded["fps_pending"])
        self.assertTrue(decoded["last_connected"])
        self.assertEqual(decoded["last_slot_state"], 8)
        self.assertTrue(decoded["lock_interval_owned"])
        self.assertEqual(decoded["header_reserved_hex"], "000000")
        self.assertFalse(decoded["snapshot_atomic"])
        self.assertEqual(tuple(decoded["counters"]), FIELDS)
        for i, name in enumerate(FIELDS):
            self.assertEqual(OFF[name], 16 + 4 * i)
            self.assertEqual(decoded["counters"][name], 0x10203040 + i)
        self.assertEqual(bytes.fromhex(decoded["raw_hex"]), bytes(dev.runtime))

    def test_stats_outcome_semantics_require_firmware_capability(self):
        for flag, expected in ((0, 'legacy-unverified'),
                               (abi.F_RADIO_OUTCOMES, abi.RADIO_OUTCOME_SEMANTICS)):
            with self.subTest(flag=flag):
                mouse, dev = self.mouse(abi.F_DB | abi.F_B | abi.F_STATS | flag)
                result = mouse.stats()
                self.assertEqual(result['radio_outcome_semantics'], expected)
                self.assertEqual(bytes.fromhex(result['raw_hex']), bytes(dev.runtime))
                self.assertFalse(any(req[5] == abi.SET for req in dev.log))

    def test_stats_decoder_rejects_unknown_versions_flags_and_truncation(self):
        m, dev = self.advanced_mouse()
        for offset, value in ((0, 2), (1, 2), (2, 2), (9, 2), (10, 2), (12, 2), (5, 2)):
            with self.subTest(offset=offset):
                record = bytearray(dev.runtime); record[offset] = value
                with self.assertRaises(cfg.ProtocolError):
                    cfg.decode_stats_record(record)
        with self.assertRaises(cfg.ProtocolError):
            cfg.decode_stats_record(dev.runtime[:-1])

    def test_stats_uint32_values_are_not_signed_or_fine_db_aliases(self):
        m, dev = self.advanced_mouse()
        for offset in range(16, 188, 4):
            struct.pack_into("<I", dev.runtime, offset, 0xFFFFFFFF)
        self.assertTrue(all(value == 4294967295 for value in m.stats()["counters"].values()))
        self.assertNotIn("pre", m.stats())

    def test_stats_unknown_version_raw_cli_is_available(self):
        _, dev = self.advanced_mouse(); dev.runtime[0] = 7
        rc, out, _ = self.run_cfg(["stats", "--json"], dev)
        self.assertEqual(rc, 1, out)
        self.assertIn("unsupported STATS layout version 7", out)
        rc, out, _ = self.run_cfg(["stats", "--raw", "--json"], dev)
        self.assertEqual(rc, 0, out)
        decoded = json.loads(out)
        self.assertEqual(bytes.fromhex(decoded["raw_hex"]), bytes(dev.runtime))
        self.assertNotIn("counters", decoded)

    def test_stats_text_is_readable_with_live_session_semantics(self):
        _, dev = self.advanced_mouse()
        rc, out, _ = self.run_cfg(["stats"], dev)
        self.assertEqual(rc, 0, out)
        self.assertIn("STATS layout 1", out)
        self.assertIn("multi-page live view", out)
        self.assertIn("current power session", out)
        self.assertIn("ticks: 270544960", out)
        self.assertIn("capture_fail:", out)

    def test_stats_control_actions_and_preserved_config(self):
        m, dev = self.advanced_mouse()
        m.set_lock(True, 499); m.fps_set(2)
        self.assertTrue(m.stats_switch(True))
        self.assertEqual(dev.log[-1][3:9], bytes((3, 1, 0x16, 0, 4, 1)))
        self.assertTrue(m.stats_reset())
        self.assertEqual(dev.log[-1][3:9], bytes((3, 1, 0x16, 0, 4, 2)))
        self.assertEqual((dev.lock_enabled, dev.lock_lead, dev.fps_requested), (True, 499, 2))
        self.assertFalse(m.stats_switch(False))
        self.assertFalse(m.stats_reset())
        self.assertEqual(dev.saved, [])

    def test_stats_page_and_action_rejections_before_transfer(self):
        for value in (-1, 6, True, 1.5):
            m, dev = self.advanced_mouse()
            with self.assertRaises(cfg.CfgError):
                m.stats_page(value)
            self.assertEqual(dev.log, [])
        for value in (-1, 3, True, 1.5):
            m, dev = self.advanced_mouse()
            with self.assertRaises(cfg.CfgError):
                m.stats_control(value)
            self.assertEqual(dev.log, [])

    def test_stats_wrong_page_prefix_length_and_capability_size_rejected(self):
        for offset, value in ((3, 34), (6, 1), (7, 3), (8, 1)):
            with self.subTest(offset=offset):
                m, dev = self.advanced_mouse()
                dev.override = lambda req, reply: reply.__setitem__(offset, value) if req[7] == 4 else None
                with self.assertRaises(cfg.ProtocolError):
                    m.stats_page(0)
        m, dev = self.advanced_mouse()
        caps = bytearray(dev.caps); caps[10] = 191; dev.caps = bytes(caps)
        with self.assertRaises(cfg.ProtocolError):
            m.stats_raw()

    def test_stats_invalid_set_ack_is_not_success(self):
        for state in (0, 2):
            m, dev = self.advanced_mouse()
            dev.override = lambda req, reply: reply.__setitem__(8, state) if req[7] == 4 else None
            with self.assertRaises(cfg.ProtocolError):
                m.stats_switch(True)

    def test_missing_advanced_capability_never_sends_operation(self):
        for action in (lambda m: m.fps_status(), lambda m: m.fps_set(0),
                       lambda m: m.lock_status(), lambda m: m.set_lock(True, 80),
                       lambda m: m.stats_raw(), lambda m: m.stats_control(1),
                       lambda m: m.sensor_snapshot(), lambda m: m.sensor_snapshot_status()):
            m, dev = self.mouse()
            with self.assertRaises(cfg.Unsupported):
                action(m)
            self.assertEqual(len(dev.log), 1)
            self.assertEqual(dev.log[0][6:8], b"\x00\x00")

    def test_sensor_snapshot_host_freshness_and_failures(self):
        def payload(state, token=0, completed=0, error=0):
            raw = bytearray(24)
            raw[:4] = bytes((1, state, error, 0))
            struct.pack_into("<HH", raw, 4, token, completed)
            raw[8:12] = bytes((4, 3, 0, 0))
            raw[12:20] = bytes((37, 1, 1, 0xA8, 0x90, 0x40, 0, 0x80))
            return bytes((0, 6))+raw
        m, _ = self.advanced_mouse()
        m.require = Mock()
        m._global_extension = Mock(side_effect=[payload(0), payload(1, 1), payload(2, 1, 1)])
        result = m.sensor_snapshot()
        self.assertTrue(result['valid'] and result['fresh'])
        self.assertEqual(result['registers']['06:6D'], 0xA8)
        self.assertEqual(m._global_extension.call_args_list[1].args, (6, (1, 0)))
        for reply, message in ((payload(3, 1, 1, 7), 'stage 7'),
                               (payload(2, 2, 2), 'replaced')):
            m._global_extension = Mock(side_effect=[payload(0), reply])
            with self.assertRaisesRegex(cfg.CfgError, message):
                m.sensor_snapshot()
        m._global_extension = Mock(return_value=payload(1, 1))
        with self.assertRaisesRegex(cfg.CfgError, 'already pending'):
            m.sensor_snapshot()
        self.assertEqual(m._global_extension.call_count, 1)
        m._global_extension = Mock(side_effect=[payload(2, 65535, 65535), payload(2, 1, 1)])
        self.assertEqual(m.sensor_snapshot()['request_token'], 1)
        m._global_extension = Mock(side_effect=[payload(0), payload(1, 1)])
        with patch.object(cfg.time, 'monotonic', side_effect=[0, 1]):
            with self.assertRaisesRegex(cfg.CfgError, 'timed out'):
                m.sensor_snapshot(timeout=.01)
        for bad in (b'\x00\x06'+bytes(24), b'\x00\x06\x01\x04'+bytes(22),
                    b'\x00\x06\x01\x00\x00\x02'+bytes(20), payload(2),
                    payload(2, 1, 1, 7), payload(2, 1, 2)):
            with self.assertRaises(cfg.ProtocolError):
                cfg.Mouse._decode_sensor_snapshot(bad)
        m._global_extension = Mock(side_effect=[payload(0), payload(2, 1, 1, 7)])
        with self.assertRaisesRegex(cfg.ProtocolError, 'ready sensor snapshot'):
            m.sensor_snapshot()

    def test_advanced_cli_get_set_and_session_wording(self):
        for argv in (["get", "fps"], ["fps-status"], ["fps-set", "2"], ["set", "fps", "stock"],
                     ["get", "lock"], ["get", "lock-lead"], ["lock-status"],
                     ["lock-set", "on", "499"], ["set", "lock", "on", "0"],
                     ["set", "lock-lead", "1"], ["lock-on", "--lead", "80"], ["lock-off"]):
            with self.subTest(argv=argv):
                _, dev = self.advanced_mouse()
                rc, out, _ = self.run_cfg(["--profile", "3", *argv], dev)
                self.assertEqual(rc, 0, out)
                self.assertIn("current power session", out)
                self.assertIn("reboot restores FPS stock / LOCK off", out)
                self.assertNotIn("saved on", out)
                self.assertTrue(dev.closed)

    def test_advanced_json_persistence_is_feature_driven(self):
        for saved in (False, True):
            for cmd in ("fps-status", "lock-status"):
                _, dev = self.advanced_mouse(saved)
                rc, out, _ = self.run_cfg([cmd, "--json"], dev)
                self.assertEqual(rc, 0, out)
                data = json.loads(out)
                self.assertEqual(data["advanced_saved"], saved)
                self.assertEqual("F_ADV_SAVED" in data["persistence"], saved)

    def test_show_displays_runtime_fps_lock_without_persistence_claim(self):
        _, dev = self.advanced_mouse()
        rc, out, _ = self.run_cfg(["show"], dev)
        self.assertEqual(rc, 0, out)
        self.assertIn("fps: requested=", out)
        self.assertIn("lock: off", out)
        self.assertIn("current power session", out)

    def test_numeric_fps_list_and_stock_cli(self):
        _, dev = self.advanced_mouse()
        rc, out, _ = self.run_cfg(["fps-list"], dev)
        self.assertEqual(rc, 0, out)
        self.assertIn("0: stock", out)
        self.assertIn("preset_count=4", out)
        self.assertFalse(any(req[5] == abi.SET for req in dev.log))

    def test_fps_list_uses_authoritative_names_only_with_matching_count(self):
        from superlamzu.advanced import PRESETS, SUPPORTED_PRESET_COUNTS
        for count in SUPPORTED_PRESET_COUNTS:
            with self.subTest(count=count):
                m, dev = self.advanced_mouse()
                dev.preset_count = count
                dev.caps = abi.capabilities(dev.flags, count)
                presets = m.fps_presets()
                self.assertEqual([p["name"] for p in presets["presets"]], [p[0] for p in PRESETS[:count]])
                self.assertEqual([p["id"] for p in presets["presets"]], list(range(count)))

    def test_db_and_numeric_advanced_do_not_import_firmware_generators(self):
        m, dev = self.advanced_mouse()
        original = __import__("builtins").__import__
        def restricted(name, *args, **kwargs):
            if name in ("advanced", "unicorn", "capstone", "keystone"):
                raise AssertionError("numeric host operations must not import " + name)
            return original(name, *args, **kwargs)
        with patch("builtins.__import__", side_effect=restricted):
            m.debounce_values(); m.fps_set(2); m.set_lock(True, 499); m.stats_raw()

    def test_stats_cli_single_read_pages_and_control(self):
        for argv in (["stats", "--json"], ["stats", "--page", "5", "--json"],
                     ["get", "stats"], ["stats-on"], ["stats-off"], ["stats-reset"],
                     ["set", "stats", "reset"], ["set", "stats", "on"]):
            with self.subTest(argv=argv):
                _, dev = self.advanced_mouse()
                rc, out, _ = self.run_cfg(argv, dev)
                self.assertEqual(rc, 0, out)
                self.assertTrue(dev.closed)
                if "--page" in argv:
                    data = json.loads(out)
                    self.assertEqual(data["page"], 5)
                    self.assertEqual(len(bytes.fromhex(data["raw_hex"])), 28)


if __name__ == "__main__":
    unittest.main()
