"""Shared runtime transport preserves request identity without device access."""
import unittest

from superlamzu import cfg, protocol as P
from superlamzu.runtime_link import RuntimeLink


class RuntimeLinkTests(unittest.TestCase):
    def test_wrong_preset_or_target_ack_is_rejected(self):
        request = cfg.native.pkt(2, 3, 1, P.SET, 0, P.FPS, 5)
        reply = bytearray(64)
        reply[0] = 0xA1
        reply[2:6] = bytes((2, 6, 1, P.SET))
        reply[6:12] = bytes((0, P.FPS, 1, 1, 0, 35))
        self.assertFalse(RuntimeLink._ok(reply, request, True))
        reply[8] = 5
        self.assertTrue(RuntimeLink._ok(reply, request, True))
        reply[2] = 0
        self.assertFalse(RuntimeLink._ok(reply, request, True))

    def test_wrong_stats_page_is_rejected(self):
        request = cfg.native.pkt(2, 3, 1, P.GET, 0, P.STATS, 3)
        reply = bytearray(64)
        reply[0] = 0xA1
        reply[2:6] = bytes((2, 35, 1, P.GET))
        reply[6:9] = bytes((0, P.STATS, 1))
        self.assertFalse(RuntimeLink._ok(reply, request, True))
        reply[8] = 3
        self.assertTrue(RuntimeLink._ok(reply, request, True))

    def test_sensor_snapshot_ack_matches_request_token(self):
        request = cfg.native.pkt(2, 4, 1, P.SET, 0, P.SENSOR_SNAPSHOT, 0x34, 0x12)
        reply = bytearray(64)
        reply[:8] = bytes((0xA1, 0, 2, 26, 1, P.SET, 0, P.SENSOR_SNAPSHOT))
        reply[12:14] = bytes((0x34, 0x12))
        self.assertTrue(RuntimeLink._ok(reply, request, True))
        reply[12] = 0x35
        self.assertFalse(RuntimeLink._ok(reply, request, True))
