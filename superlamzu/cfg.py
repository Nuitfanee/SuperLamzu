"""LAMZU adapter for the reference configurator and its shared HID transport.

Importing this module never enumerates or opens a HID interface.  Only the
explicit CLI/device entry points do so.  SLZ1 is not the Drako override ABI.
"""
from __future__ import annotations

import argparse
import importlib
import json
import math
import struct
import sys
import time

from . import protocol as abi, target


def _reference(name):
    # Keep the reference modules intact: no replacement VID/PID globals.
    path = str(target.REFERENCE)
    if path not in sys.path:
        sys.path.append(path)
    return importlib.import_module(name)


native = _reference("ko1_cfg")
hid = native.ko1_hid
CfgError, CfgRejected = native.CfgError, native.CfgRejected


class Unsupported(CfgError):
    """A real unsupported reply, distinct from a failed communication."""


class ProtocolError(CfgError):
    """A successful transfer contained a malformed or incompatible reply."""


LOD_CODES = {"0.7": 0x87, "1": 0x01, "1.3": 0x13, "1.5": 0x15, "1.7": 0x17}
LOD_LABELS = {code: label for label, code in LOD_CODES.items()}
FEATURES = {abi.DEBOUNCE: abi.F_DB, abi.FPS: abi.F_FPS,
            abi.LOCK: abi.F_LOCK, abi.STATS: abi.F_STATS, abi.FPS_CUSTOM: abi.F_FPS_CUSTOM,
            abi.SENSOR_SNAPSHOT: abi.F_SENSOR_SNAPSHOT, abi.SMOOTHING: abi.F_SMOOTHING,
            abi.SAVE_ADVANCED: abi.F_ADV_SAVED, abi.IDLE_TRACKING: abi.F_IDLE_TRACKING,
            abi.MOTION_PATH: abi.F_MOTION_PATH, abi.ABS_MOTION: abi.F_ABS,
            abi.OPTICAL_CLICK: abi.F_OPTICAL_CLICK, abi.CHANNELS: abi.F_CHANNELS}
FEATURE_NAMES = {abi.F_DB: "db", abi.F_B: "downshift-b", abi.F_FPS: "fps",
                 abi.F_STATS: "stats", abi.F_LOCK: "lock",
                 abi.F_ADV_SAVED: "advanced-saved", abi.F_A: "downshift-a",
                 abi.F_FPS_CUSTOM: "custom-frame-timing",
                 abi.F_SENSOR_SNAPSHOT: "sensor-register-snapshot",
                 abi.F_SMOOTHING: "down-smoothing", abi.F_IDLE_TRACKING: "idle-tracking",
                 abi.F_MOTION_PATH: "motion-path", abi.F_ABS: "absolute-motion",
                 abi.F_OPTICAL_CLICK: "optical-click", abi.F_CHANNELS: "channels",
                 abi.F_RADIO_OUTCOMES: "receiver-window-outcomes"}

# docs/protocol.md: SLZ1 field map, layout version 1. Separate from the old Drako RAM layout.
STATS_COUNTERS = (
    "ticks", "not_ready", "health_skip", "health_trip", "last_bad_status",
    "reads_started", "read_start_fail", "spi_ok", "spi_bad", "reinit",
    "samples", "samples_motion", "tx_queued", "tx_full",
    "slot_ends", "acked", "no_ack", "hops", "link_lost", "link_up",
    "tx_attempts", "idle_slots", "miss_run", "max_miss_run",
    "lock_adjust", "lock_skip", "lock_rescue",
    "phase_count", "phase_sum_us", "phase_max_us", "period_us",
    "phase_bin0", "phase_bin1", "phase_bin2", "phase_bin3",
    "phase_bin4", "phase_bin5", "phase_bin6", "phase_bin7",
    "fps_apply", "fps_fail", "capture_fail", "reserved",
)


def decode_stats_record(record):
    """Decode exactly the documented 188-byte v1 record, without device access."""
    record = bytes(record)
    if len(record) != abi.STATS_BYTES:
        raise ProtocolError(f"STATS record must contain {abi.STATS_BYTES} bytes")
    if record[0] != 1:
        raise ProtocolError(f"unsupported STATS layout version {record[0]}; use stats --raw")
    for offset, label in ((1, "counting"), (2, "LOCK"), (9, "FPS pending"),
                          (10, "connected"), (12, "LOCK interval ownership")):
        if record[offset] not in (0, 1):
            raise ProtocolError(f"STATS {label} flag must be 0 or 1")
    lead, last_capture = struct.unpack_from("<HH", record, 4)
    if lead > 499:
        raise ProtocolError("STATS LOCK configured lead exceeds 499 us")
    return dict(layout_version=record[0], counting_enabled=bool(record[1]),
                lock_enabled=bool(record[2]), fps_requested=record[3], lead_us=lead,
                last_phase_capture_us=last_capture, fps_applied=record[8],
                fps_pending=bool(record[9]), last_connected=bool(record[10]),
                last_slot_state=record[11], lock_interval_owned=bool(record[12]),
                header_reserved_hex=record[13:16].hex(),
                counters=dict(zip(STATS_COUNTERS, struct.unpack_from("<43I", record, 16))),
                record_bytes=len(record), raw_hex=record.hex(), snapshot_atomic=False)


def integer(value, low, high, name):
    """Whole-number input only; 255 is 255 ms, never a special override code."""
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise CfgError(f"{name} must be an integer in {low}..{high}")
    try:
        result = int(value, 10) if isinstance(value, str) else value
    except ValueError:
        raise CfgError(f"{name} must be an integer in {low}..{high}") from None
    if not low <= result <= high:
        raise CfgError(f"{name} must be in {low}..{high}")
    return result


def profile_number(value):
    return integer(value, 1, abi.PROFILE_COUNT, "profile")


class Link(native.Link):
    """Reuse native transactions, but recognize terminal A2/A3 during polling too."""

    def xfer(self, req, strict=True, rounds=5, poll=30):
        self._request = req
        try:
            return super().xfer(req, strict=strict, rounds=rounds, poll=poll)
        finally:
            self._request = None

    def _get(self):
        try:
            reply = super()._get()
        except IndexError:
            raise ProtocolError("truncated HID reply") from None
        if len(reply) < 6:
            raise ProtocolError("truncated HID reply")
        req = getattr(self, "_request", None)
        if req is not None and reply[4:6] == req[4:6]:
            if reply[0] == 0xA3:
                message = f"command unsupported (reply 0xA3, group {req[4]} cmd 0x{req[5]:02X})"
                if req[3:8] == bytes((2, abi.GROUP, abi.GET, 0, abi.CAPS)):
                    message += "; stock LAMZU firmware does not provide SLZ1 extensions"
                raise Unsupported(message)
            if reply[0] == 0xA2:
                raise CfgRejected(f"mouse rejected this value (reply 0xA2, group {req[4]} cmd 0x{req[5]:02X})")
        return reply


class Mouse(native.Mouse):
    """Native profile settings and versioned SLZ1 DB/global runtime operations."""

    def __init__(self, link, target_byte=0, profile=None):
        super().__init__(link, target_byte, None if profile is None else profile_number(profile))
        self._caps = None

    @property
    def profile(self):
        return profile_number(super().profile)

    def dpi_max(self):
        return abi.NATIVE_CPI_MAX

    def set_profile(self, idx):
        return super().set_profile(profile_number(idx))

    def reset_profile(self, idx):
        return super().reset_profile(profile_number(idx))

    def lod(self):
        code = self.lod_raw()
        if code not in LOD_LABELS:
            raise ProtocolError(f"unknown stock LOD code 0x{code:02X}; no height is inferred")
        return float(LOD_LABELS[code])

    def set_lod(self, mm):
        try:
            value = float(str(mm).lower().removesuffix("mm"))
        except (TypeError, ValueError):
            value = None
        code = {float(label): code for label, code in LOD_CODES.items()}.get(value)
        if code is None:
            raise CfgError("LOD must be one of 0.7, 1, 1.3, 1.5, 1.7 (stock preset labels)")
        return self.set_lod_raw(code)

    def set_lod_raw(self, code):
        code = integer(code, 0, 255, "LOD code")
        if code not in LOD_LABELS:
            raise CfgError("only stock LOD codes 0x87, 0x01, 0x13, 0x15, 0x17 are supported")
        # Bypass the reference's Drako-specific rejection/reflash advice.
        self._set(2, 1, 8, code)

    def set_panel_debounce(self, ms):
        self._set(2, 0, 0x08, integer(ms, 0, 255, "panel pre ms"))

    def set_stages(self, stages):
        stages = list(stages)
        if not 1 <= len(stages) <= native.MAX_STAGES:
            raise CfgError(f"give 1..{native.MAX_STAGES} CPI stages")
        for stage in stages:
            if len(stage) != 2:
                raise CfgError("each CPI stage needs X and Y")
            for v in stage:
                integer(v, 1, abi.NATIVE_CPI_MAX, "CPI")
        return super().set_stages(stages)

    def _extension(self, profile, op, args=(), *, write=False, reply_length):
        """SLZ1 envelope only; advanced operation payloads belong to their ABI owner."""
        data = (profile, op, *args)
        if len(data) > 58 or any(type(v) is not int or not 0 <= v <= 255 for v in data):
            raise CfgError("invalid SLZ1 payload")
        cmd = abi.SET if write else abi.GET
        reply = self.l.xfer(native.pkt(self.t, len(data), abi.GROUP, cmd, *data))
        lengths = (reply_length,) if isinstance(reply_length, int) else tuple(reply_length)
        if reply[3] not in lengths or len(reply) < 6 + reply[3]:
            raise ProtocolError(f"SLZ1 reply length {reply[3]}, expected {reply_length}")
        return bytes(reply[6:6 + reply[3]])

    def capabilities(self, refresh=False):
        if self._caps is None or refresh:
            payload = self._extension(0, abi.CAPS, reply_length=12)
            try:
                caps = abi.decode_capabilities(payload)
            except ValueError as exc:
                raise ProtocolError(str(exc)) from exc
            if caps["profiles"] != abi.PROFILE_COUNT or caps["cpi_max"] != abi.NATIVE_CPI_MAX:
                raise ProtocolError("SLZ1 target geometry does not match the LAMZU adapter")
            self._caps = caps
        return dict(self._caps)

    def require(self, op):
        if op not in FEATURES:
            raise CfgError(f"no host contract for operation {op}")
        caps = self.capabilities()
        if not caps["flags"] & FEATURES[op]:
            raise Unsupported(f"SLZ1 operation {op} is not enabled in this firmware build")
        return caps

    def debounce_values(self):
        self.require(abi.DEBOUNCE)
        profile = self.profile
        data = self._extension(profile, abi.DEBOUNCE, reply_length=5)
        if data[0] != profile:
            raise ProtocolError(f"SLZ1 DB reply profile {data[0]}, expected {profile}")
        return tuple(data[1:])

    def set_debounce(self, values):
        values = tuple(values)
        if len(values) != 4:
            raise CfgError("debounce requires PRE POST PLOCK RELOCK integer ms")
        values = tuple(integer(v, 0, 255, name + " ms") for name, v in zip(abi.DB_NAMES, values))
        self.require(abi.DEBOUNCE)
        profile = self.profile
        reply = self._extension(profile, abi.DEBOUNCE, values, write=True, reply_length=5)
        if reply != bytes((profile, *values)):
            raise ProtocolError("SLZ1 DB SET reply does not match the requested profile/values")
        verify(self.debounce_values, values, "debounce readback")
        return values

    def click_debounce(self, tries=1):
        return dict(zip(abi.DB_NAMES, self.debounce_values()))

    def debounce_set(self, name, value, fine=None):
        if fine is not None:
            raise CfgError("LAMZU uses native integer ms; no fine/override encoding")
        if name not in abi.DB_NAMES:
            raise CfgError("unknown debounce field")
        ms = integer(value, 0, 255, name + " ms")
        values = list(self.debounce_values())
        values[abi.DB_NAMES.index(name)] = ms
        return self.set_debounce(values)

    def advanced_persistence(self):
        if self.capabilities()["flags"] & abi.F_ADV_SAVED:
            return "F_ADV_SAVED: explicit device save available; changes remain in the current power session until save-advanced"
        return "current power session only; reboot restores FPS stock / LOCK off"

    def _global_extension(self, op, args=(), *, write=False, reply_length):
        self.require(op)
        data = self._extension(0, op, args, write=write, reply_length=reply_length)
        if data[:2] != bytes((0, op)):
            raise ProtocolError(f"SLZ1 operation {op} reply has an incorrect global profile/operation")
        return data

    def _decode_fps(self, data):
        requested, applied, pending, count = data[2:]
        if pending not in (0, 1):
            raise ProtocolError("SLZ1 FPS pending must be 0 or 1")
        if count != self.capabilities()["preset_count"]:
            raise ProtocolError("SLZ1 FPS preset count disagrees with capabilities")
        custom = bool(self.capabilities()["flags"] & abi.F_FPS_CUSTOM)
        if count == 0 or any(i >= count and not (custom and i == abi.CUSTOM_FPS_ID)
                             for i in (requested, applied)):
            raise ProtocolError("SLZ1 FPS requested/applied id is outside the advertised preset count")
        return dict(requested=requested, applied=applied, pending=bool(pending), preset_count=count)

    def fps_status(self):
        return self._decode_fps(self._global_extension(abi.FPS, reply_length=6))

    def smoothing_status(self):
        raw = self._global_extension(abi.SMOOTHING, reply_length=3)[2]
        index = (raw >> 3) & 7
        values = (None, 2, 0x10, 0x13, 0x27, 0x90)
        if raw & 0x80 or index >= len(values) or (raw & 4 and (raw & 66 or not index)):
            raise ProtocolError('invalid smoothing state')
        return dict(requested='reduced' if raw & 1 else 'stock', pending=bool(raw & 2),
                    verified=bool(raw & 4), failed=bool(raw & 64),
                    register_value=values[index] if raw & 4 else None)

    def tracking_status(self):
        value = self._global_extension(abi.IDLE_TRACKING, reply_length=3)[2]
        if value not in (0, 1):
            raise ProtocolError('invalid idle tracking state')
        return dict(enabled=bool(value))

    def tracking_set(self, enabled):
        value = int(_switch(enabled))
        reply = self._global_extension(abi.IDLE_TRACKING, (value,), write=True, reply_length=3)
        result = self.tracking_status()
        if reply[2] != value or result['enabled'] != bool(value):
            raise ProtocolError('idle tracking ACK/readback mismatch')
        return result

    def motion_path(self, path=None):
        """dev thread/direct selection; wireless direct, wired native thread."""
        if path is not None:
            if path not in ('thread', 'direct'):
                raise CfgError('path must be thread or direct')
            value = int(path == 'direct')
            reply = self._global_extension(abi.MOTION_PATH, (value,), write=True, reply_length=3)
            if reply[2] != value:
                raise ProtocolError('motion path ACK mismatch')
        value = self._global_extension(abi.MOTION_PATH, reply_length=3)[2]
        if value not in (0, 1):
            raise ProtocolError('invalid motion path')
        result = 'direct' if value else 'thread'
        if path is not None and result != path:
            raise ProtocolError('motion path readback mismatch')
        return result

    def saved_advanced(self):
        from .settings import decode_record
        raw = self._global_extension(abi.SAVE_ADVANCED, reply_length=19)
        if raw[2] not in (0, 1):
            raise ProtocolError('invalid saved settings validity')
        try:
            record = decode_record(raw[3:]) if raw[2] else None
        except ValueError as exc:
            raise ProtocolError(str(exc)) from exc
        return dict(valid=bool(raw[2]), settings=record)

    def abs_motion(self, enabled=None):
        """Dev totals format; enable only with the paired SUPER receiver."""
        if enabled is not None:
            value = int(_switch(enabled))
            reply = self._global_extension(abi.ABS_MOTION, (value,), write=True, reply_length=3)
            if reply[2] != value:
                raise ProtocolError('ABS ACK mismatch')
        value = self._global_extension(abi.ABS_MOTION, reply_length=3)[2]
        if value not in (0,1) or enabled is not None and value != int(_switch(enabled)):
            raise ProtocolError('ABS readback mismatch')
        return dict(enabled=bool(value))

    def channels(self, action=None):
        """Per-channel diagnostics; capability identifies corrected outcomes."""
        if action is not None:
            if action not in ('off','on','reset'):
                raise CfgError('channels action must be off, on or reset')
            ack=self._global_extension(abi.CHANNELS,(('off','on','reset').index(action),),
                                       write=True,reply_length=(28,36))
            try:
                abi.decode_channels(ack)
            except ValueError as exc:
                raise ProtocolError(str(exc)) from exc
            if action!='reset' and ack[2]!=int(action=='on'):
                raise ProtocolError('channels enable ACK mismatch')
        raw=self._global_extension(abi.CHANNELS,reply_length=(28,36))
        try:
            result=abi.decode_channels(raw)
        except ValueError as exc:
            raise ProtocolError(str(exc)) from exc
        if action in ('on','off') and raw[2]!=int(action=='on'):
            raise ProtocolError('channels enable readback mismatch')
        result['outcome_semantics'] = (abi.RADIO_OUTCOME_SEMANTICS
            if self.capabilities()['flags'] & abi.F_RADIO_OUTCOMES else 'legacy-unverified')
        return result

    def optical_click(self, mode=None):
        """Deprecated compatibility API for old F_OPTICAL_CLICK firmware only.

        Current firmware uses native debounce and does not advertise this bit.
        """
        modes=('stock','optical-direct')
        if mode is not None:
            if mode not in modes:raise CfgError('click mode must be stock or optical-direct')
            ack=self._global_extension(abi.OPTICAL_CLICK,(modes.index(mode),),write=True,reply_length=12)
            if ack[2]!=modes.index(mode):raise ProtocolError('click request ACK mismatch')
        raw=self._global_extension(abi.OPTICAL_CLICK,reply_length=12)
        if (any(v not in (0,1) for v in raw[2:6]) or raw[10] not in (0,1)
                or raw[11]>31 or raw[4] != (raw[2]^raw[3])):
            raise ProtocolError('invalid optical click status')
        if mode is not None and raw[2]!=modes.index(mode):raise ProtocolError('click request readback mismatch')
        return dict(requested=modes[raw[2]],effective=modes[raw[3]],pending=bool(raw[4]),
                    ready=bool(raw[5]),overflow=int.from_bytes(raw[6:10],'little'),
                    edge_loss=bool(raw[10]),queued=raw[11])

    def save_advanced(self):
        reply = self._global_extension(abi.SAVE_ADVANCED, (1,), write=True, reply_length=19)
        result = self.saved_advanced()
        if reply[2] != 1 or not result['valid']:
            raise ProtocolError('advanced settings save not verified')
        from .settings import decode_record
        try:
            if decode_record(reply[3:]) != result['settings']:
                raise ProtocolError('saved settings ACK/readback mismatch')
        except ValueError as exc:
            raise ProtocolError(str(exc)) from exc
        return result

    def smoothing_set(self, mode, timeout=3.0):
        if mode not in ('stock', 'reduced'):
            raise CfgError('smoothing must be stock or reduced')
        self._global_extension(abi.SMOOTHING, (int(mode == 'reduced'),), write=True, reply_length=3)
        saved = self.save_advanced()
        deadline = time.monotonic() + timeout
        while True:
            result = self.smoothing_status()
            if result['requested'] != mode or result['failed']:
                raise ProtocolError('smoothing worker application failed')
            if not result['pending']:
                return dict(result, saved=saved)
            if time.monotonic() >= deadline:
                raise CfgError('smoothing selection saved; sensor worker application is still pending')
            time.sleep(0.025)

    @staticmethod
    def _decode_sensor_snapshot(data):
        raw = data[2:]
        if len(raw) != abi.SENSOR_SNAPSHOT_BYTES or raw[0] != 1 or raw[1] not in range(4) or raw[3] not in (0, 1):
            raise ProtocolError("invalid sensor snapshot layout/status")
        requested, completed = struct.unpack_from("<HH", raw, 4)
        if raw[1] == 2 and (raw[2] or not requested or requested != completed):
            raise ProtocolError("ready sensor snapshot has an error or invalid completion token")
        registers = {f"{page:02X}:{reg:02X}": raw[12+i]
                     for i, (page, reg) in enumerate(abi.SENSOR_REGISTERS)}
        return dict(version=raw[0], state=("empty", "pending", "ready", "error")[raw[1]],
                    error_stage=raw[2], request_token=requested, completed_token=completed,
                    mode=raw[8], variant=raw[9], fps_requested=raw[10], fps_applied=raw[11],
                    fps_pending=bool(raw[3]), dpi=dict(zip(("x", "y"), struct.unpack_from("<HH", raw, 20))),
                    registers=registers, recipe=dict(unit=raw[12], slow=raw[13], fast=raw[14]),
                    valid=raw[1] == 2 and requested == completed, fresh=False,
                    source="sensor-worker-spi", raw_hex=raw.hex())

    def sensor_snapshot_status(self):
        """Last explicit snapshot; GET alone does not initiate a sensor read."""
        data = self._global_extension(abi.SENSOR_SNAPSHOT, reply_length=26)
        return self._decode_sensor_snapshot(data)

    def sensor_snapshot(self, timeout=3.0):
        """Queue a new read-only SPI snapshot without reapplying any mode."""
        if not math.isfinite(timeout) or timeout <= 0:
            raise CfgError("snapshot timeout must be finite and positive")
        self.require(abi.SENSOR_SNAPSHOT)
        before = self.sensor_snapshot_status()
        if before["state"] == "pending":
            raise CfgError("a sensor snapshot is already pending; read its status before retrying")
        # Avoid mistaking a cached completion for this request, including wrap.
        token = before["request_token"] % 65535 + 1
        args = tuple(struct.pack("<H", token))
        result = self._decode_sensor_snapshot(self._global_extension(
            abi.SENSOR_SNAPSHOT, args, write=True, reply_length=26))
        deadline = time.monotonic() + timeout
        while True:
            if result["request_token"] != token:
                raise ProtocolError("sensor snapshot was replaced by another request")
            if result["state"] == "error":
                raise CfgError(f"sensor snapshot failed at SPI/queue stage {result['error_stage']}")
            if result["valid"] and result["completed_token"] == token:
                return dict(result, fresh=True)
            if time.monotonic() >= deadline:
                raise CfgError("sensor snapshot timed out; no fresh register values confirmed")
            time.sleep(.025)
            result = self.sensor_snapshot_status()

    def fps_custom_status(self):
        data = self._global_extension(abi.FPS_CUSTOM, reply_length=12)
        requested, applied, pending = data[2:5]
        count = self.capabilities()["preset_count"]
        if pending not in (0, 1) or data[11] not in (0, 1) or any(
                i >= count and i != abi.CUSTOM_FPS_ID for i in (requested, applied)):
            raise ProtocolError("invalid custom FPS status flags/identifiers")
        from .frame_timing import FIELDS, recipe
        wanted, actual = (dict(zip(FIELDS, data[a:a + 3])) for a in (5, 8))
        try:
            if requested == abi.CUSTOM_FPS_ID:
                recipe(wanted)
            if data[11]:
                recipe(actual)
        except ValueError as exc:
            raise ProtocolError(f"invalid custom FPS recipe: {exc}") from exc
        return dict(requested=requested, applied=applied, pending=bool(pending),
                    recipe=wanted, readback=actual, readback_valid=bool(data[11]),
                    readback_matches=bool(data[11]) and wanted == actual)

    def fps_custom_set(self, value):
        from .frame_timing import recipe, FIELDS
        value = recipe(value)
        self._global_extension(abi.FPS_CUSTOM, tuple(value[k] for k in FIELDS),
                               write=True, reply_length=12)
        # Independent GET, including actual worker SPI readback when completed.
        result = self.fps_custom_status()
        if result["requested"] != abi.CUSTOM_FPS_ID or result["recipe"] != value:
            raise ProtocolError("custom FPS request did not independently read back")
        return result

    def fps_set(self, preset):
        preset = integer(preset, 0, 255, "FPS preset id")
        count = self.require(abi.FPS)["preset_count"]
        if not count:
            raise ProtocolError("SLZ1 FPS advertises no presets")
        if preset >= count:
            raise CfgError(f"FPS preset id must be 0..{count - 1} (0=stock)")
        data = self._global_extension(abi.FPS, (preset,), write=True, reply_length=6)
        result = self._decode_fps(data)
        if result["requested"] != preset:
            raise ProtocolError("SLZ1 FPS SET did not acknowledge the requested preset")
        # A pending request is successful queueing, not completed sensor SPI.
        return result

    def fps_presets(self):
        caps = self.require(abi.FPS)
        count = caps["preset_count"]
        if not count:
            raise ProtocolError("SLZ1 FPS advertises no presets")
        # Names are metadata only; no builder, emulator or hardware use on import.
        from .advanced import PRESETS, SUPPORTED_PRESET_COUNTS
        # The calibration table is append-only. The original 35-ID firmware
        # remains usable with this host; unknown tables still receive no names.
        names = ([item[0] for item in PRESETS[:count]]
                 if count in SUPPORTED_PRESET_COUNTS else None)
        return dict(preset_count=count, stock_id=0, presets=[
            dict(id=i, name=(names[i] if names is not None else "stock" if i == 0 else None))
            for i in range(count)])

    @staticmethod
    def _decode_lock(data):
        if data[2] not in (0, 1):
            raise ProtocolError("SLZ1 LOCK enabled must be 0 or 1")
        lead, effective = struct.unpack("<HH", data[3:])
        if lead > 499:
            raise ProtocolError("SLZ1 LOCK configured lead exceeds 499 us")
        if effective != (lead or 80):
            raise ProtocolError("SLZ1 LOCK effective lead disagrees with the configured/auto lead")
        return dict(enabled=bool(data[2]), lead_us=lead, effective_lead_us=effective)

    def lock_status(self):
        return self._decode_lock(self._global_extension(abi.LOCK, reply_length=7))

    def set_lock(self, enabled, lead_us):
        enabled = _switch(enabled)
        lead_us = integer(lead_us, 0, 499, "LOCK lead us")
        data = self._global_extension(abi.LOCK, (int(enabled), lead_us & 255, lead_us >> 8),
                                      write=True, reply_length=7)
        result = self._decode_lock(data)
        if (result["enabled"], result["lead_us"]) != (enabled, lead_us):
            raise ProtocolError("SLZ1 LOCK SET reply disagrees with requested enabled/lead")
        return result

    def lock_switch(self, enabled):
        enabled = _switch(enabled)
        return self.set_lock(enabled, self.lock_status()["lead_us"])

    def lock_lead(self, us):
        us = integer(us, 0, 499, "LOCK lead us")
        return self.set_lock(self.lock_status()["enabled"], us)

    def lock_persistence(self):
        self.require(abi.LOCK)
        return self.advanced_persistence()

    def stats_page(self, page):
        page = integer(page, 0, (abi.STATS_BYTES - 1) // 32, "STATS page")
        caps = self.require(abi.STATS)
        if caps["stats_bytes"] != abi.STATS_BYTES:
            raise ProtocolError("SLZ1 STATS record size does not match the host ABI")
        size = min(32, abi.STATS_BYTES - page * 32)
        data = self._global_extension(abi.STATS, (page,), reply_length=3 + size)
        if data[2] != page:
            raise ProtocolError(f"SLZ1 STATS reply page {data[2]}, expected {page}")
        return data[3:]

    def stats_raw(self):
        return b"".join(self.stats_page(page) for page in range((abi.STATS_BYTES + 31) // 32))

    def stats(self):
        result = decode_stats_record(self.stats_raw())
        result['radio_outcome_semantics'] = (abi.RADIO_OUTCOME_SEMANTICS
            if self.capabilities()['flags'] & abi.F_RADIO_OUTCOMES else 'legacy-unverified')
        return result

    def stats_control(self, action):
        action = integer(action, 0, 2, "STATS action (0 off, 1 on, 2 reset)")
        data = self._global_extension(abi.STATS, (action,), write=True, reply_length=3)
        if data[2] not in (0, 1) or (action < 2 and data[2] != action):
            raise ProtocolError("SLZ1 STATS SET returned an incorrect counting state")
        return bool(data[2])

    def stats_switch(self, enabled):
        return self.stats_control(int(_switch(enabled)))

    def stats_reset(self):
        return self.stats_control(2)

    # Prevent accidental use of inherited Drako research/override transactions.
    def _research(self, *args, **kwargs):
        raise Unsupported("LOD research and arbitrary register operations are not part of this port")

    def sensor_value(self):
        raise Unsupported("SQUAL is not part of this port")

    def _db_req(self, *args, **kwargs):
        raise Unsupported("Drako global-override packets are not the SLZ1 ABI")

    def _stats_req(self, *args, **kwargs):
        raise Unsupported("Drako STATS/LOCK packets are not the SLZ1 ABI")

    def fps_apply(self, idx):
        raise Unsupported("direct Drako register application is unavailable; use fps_set to queue the target sensor worker")

    def hyperfps_apply(self, on):
        raise Unsupported("direct Drako hyper-FPS application is unavailable; use fps_set")


def find_nodes(pid=target.APP_PID):
    return hid.find_nodes(target.VID, pid)


def open_device(via="wired", node=None):
    if via not in ("wired", "auto"):
        raise CfgError("receiver identity/relay is not mapped; use the wired LAMZU APP interface")
    nodes = find_nodes()
    if node is not None:
        # Never let --node silently redirect writes to a Drako/bootloader device.
        nodes = [n for n in nodes if n.path == node]
    if not nodes:
        raise CfgError(f"no matching LAMZU APP interface ({target.VID:04X}:{target.APP_PID:04X})")
    chosen = hid.pick_config_node(nodes)
    return hid.open_node(chosen), target.APP_PID


def verify(read, wanted, name):
    got = native.settle(read, wanted)
    if got != wanted:
        raise ProtocolError(f"{name} mismatch: requested {wanted!r}, received {got!r}")
    return got


def _switch(value):
    if isinstance(value, bool):
        return value
    if type(value) is int and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        return native.parse_bool(value)
    raise CfgError("switch must be on/off or 0/1")


def _preset(value):
    return 0 if str(value).lower() == "stock" else integer(value, 0, 255, "FPS preset id")


def _fps_text(m, status):
    label = lambda ident: "stock (0)" if ident == 0 else str(ident)
    state = "queued, sensor apply pending" if status["pending"] else "no apply pending"
    return (f"requested={label(status['requested'])}, applied={label(status['applied'])}, "
            f"{state}; {m.advanced_persistence()}")


def _lock_text(m, status):
    lead = f"{status['lead_us']} us" if status["lead_us"] else "auto (0)"
    return (f"{'on' if status['enabled'] else 'off'}, lead={lead}, "
            f"effective lead={status['effective_lead_us']} us; {m.advanced_persistence()}")


def _advanced_print(m, op, result, as_json=False):
    if as_json:
        result = dict(result, advanced_saved=bool(m.capabilities()["flags"] & abi.F_ADV_SAVED),
                      persistence=m.advanced_persistence())
        print(json.dumps(result, sort_keys=True))
    else:
        print(_fps_text(m, result) if op == abi.FPS else _lock_text(m, result))


def _stats_print(m, *, as_json=False, page=None, raw=False):
    if page is not None:
        result = dict(page=page, raw_hex=m.stats_page(page).hex())
    elif raw:
        record = m.stats_raw()
        result = dict(record_bytes=len(record), raw_hex=record.hex(), snapshot_atomic=False)
    else:
        result = m.stats()
    if as_json:
        print(json.dumps(result, sort_keys=True))
    elif page is not None or raw:
        print(result["raw_hex"])
    else:
        print(f"STATS layout {result['layout_version']}; counting "
              f"{'on' if result['counting_enabled'] else 'off'}; multi-page live view")
        print(f"FPS requested={result['fps_requested']} applied={result['fps_applied']} "
              f"pending={int(result['fps_pending'])}; LOCK "
              f"{'on' if result['lock_enabled'] else 'off'}, lead={result['lead_us']} us; "
              f"{m.advanced_persistence()}")
        print(f"last phase capture={result['last_phase_capture_us']} us; "
              f"last connected={int(result['last_connected'])}; "
              f"last slot state={result['last_slot_state']}")
        print(f"radio outcomes={result['radio_outcome_semantics']}; "
              "legacy-unverified counters do not establish response or loss rates")
        for name, value in result["counters"].items():
            print(f"  {name}: {value}")


def _db_text(values):
    return " ".join(f"{key}={ms}ms" for key, ms in zip(abi.DB_NAMES, values))


def _caps_text(caps):
    names = [name for bit, name in FEATURE_NAMES.items() if caps["flags"] & bit]
    return f"SLZ1 API {caps['api']}; features: {', '.join(names) or 'none'}; " \
           f"profiles={caps['profiles']}; CPI max={caps['cpi_max']}"


def _read_setting(m, name):
    name = native.SET_ALIASES.get(name, name)
    if name == "fps":
        return _fps_text(m, m.fps_status())
    if name in ("lock", "lock-lead"):
        return _lock_text(m, m.lock_status())
    if name == "stats":
        return json.dumps(m.stats(), sort_keys=True)
    if name == "debounce":
        return _db_text(m.debounce_values())
    if name.startswith("debounce-") and name[9:] in abi.DB_NAMES:
        return m.debounce_values()[abi.DB_NAMES.index(name[9:])]
    getters = {"polling": m.polling, "lod": m.lod,
               "lod-raw": lambda: f"0x{m.lod_raw():02X}", "angle-tune": m.angle_tune,
               "sleep": m.sleep_seconds, "panel-debounce": m.debounce,
               "dpi-active": m.active_stage, "dpi": lambda: " ".join(map(native.fmt_stage, m.stages())),
               "dpi-now": lambda: native.fmt_dpi_now(m), "profile": m.active_profile,
               "battery": lambda: m.battery()[1],
               "speed-click": lambda: " ".join("on" if b else "off" for b in m.speed_click())}
    getters.update({k: lambda k=k: "on" if m.flag(k) else "off" for k in native.BOOLS})
    if name not in getters:
        raise CfgError(f"unknown setting {name!r}; use cfg --help")
    return getters[name]()


def _set_setting(m, name, values):
    name = native.SET_ALIASES.get(name, name)
    if name == "fps":
        if len(values) != 1:
            raise CfgError("fps takes one numeric preset id or stock")
        _advanced_print(m, abi.FPS, m.fps_set(_preset(values[0])))
        return
    if name == "lock":
        if len(values) not in (1, 2):
            raise CfgError("lock takes on|off [lead_us]")
        enabled = _switch(values[0])
        result = m.lock_switch(enabled) if len(values) == 1 else m.set_lock(enabled, values[1])
        _advanced_print(m, abi.LOCK, result)
        return
    if name == "lock-lead":
        if len(values) != 1:
            raise CfgError("lock-lead takes one integer us value (0 auto, 1..499 explicit)")
        _advanced_print(m, abi.LOCK, m.lock_lead(values[0]))
        return
    if name == "stats":
        if len(values) != 1:
            raise CfgError("stats takes on|off|reset")
        enabled = m.stats_reset() if values[0] == "reset" else m.stats_switch(_switch(values[0]))
        print(f"counting {'on' if enabled else 'off'} (current power session)")
        return
    if name == "debounce":
        wanted = abi.DB_FACTORY if values == ["factory"] else values
        print(_db_text(m.set_debounce(wanted)))
        return
    if name.startswith("debounce-") and name[9:] in abi.DB_NAMES:
        if len(values) != 1:
            raise CfgError(f"{name} takes one integer ms value")
        print(_db_text(m.debounce_set(name[9:], values[0])))
        return
    if name in ("panel-debounce", "lod", "lod-raw"):
        if len(values) != 1:
            raise CfgError(f"{name} takes one value")
        value = values[0]
        if name == "panel-debounce":
            wanted = integer(value, 0, 255, "panel pre ms")
            m.set_panel_debounce(wanted)
            verify(m.debounce, wanted, name)
        elif name == "lod":
            m.set_lod(value)
            verify(m.lod, float(value.lower().removesuffix("mm")), name)
        else:
            try:
                wanted = int(value, 0)
            except ValueError:
                raise CfgError("LOD code must be an integer, e.g. 0x13") from None
            m.set_lod_raw(wanted)
            verify(m.lod_raw, wanted, name)
        print(f"{name}: {wanted if name != 'lod' else value} OK")
        return
    # This allowlist excludes Drako fps/lock/LOD research branches.
    if name not in {"polling", "angle-tune", "sleep", "speed-click", *native.BOOLS}:
        raise CfgError(f"unknown setting {name!r}; use cfg --help")
    native.do_set(m, name, values)


def _cpi_stage(token):
    try:
        pair = native.parse_stage(token)
    except ValueError:
        raise CfgError(f"invalid CPI stage {token!r}") from None
    return tuple(integer(v, 1, abi.NATIVE_CPI_MAX, "CPI") for v in pair)


def _set_dpi(m, tokens):
    wanted = [_cpi_stage(v) for v in tokens]
    active = m.active_stage()
    m.set_stages(wanted)
    verify(m.stages, wanted, "CPI stages")
    if active > len(wanted):
        m.set_active_stage(1)
        verify(m.active_stage, 1, "active stage")
    print("CPI stages:", " ".join(map(native.fmt_stage, wanted)), "OK")


def build_parser():
    ap = argparse.ArgumentParser(prog="python -m superlamzu cfg", description=__doc__)
    ap.add_argument("--via", choices=("wired", "auto", "receiver"), default="wired",
                    help="auto currently selects the verified wired APP identity only")
    ap.add_argument("--node", help="select a listed LAMZU APP path")
    ap.add_argument("--backend", choices=("auto", "hidraw", "hidapi"))
    ap.add_argument("--profile", type=lambda s: profile_number(s), metavar="1..3")
    ap.add_argument("--delay", type=float, default=0.02)
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for cmd in ("list", "info", "show", "debounce-status"):
        sub.add_parser(cmd)
    schema = sub.add_parser("schema", help="offline LAMZU setting metadata; no HID access")
    schema.add_argument("--json", action="store_true")
    options = sub.add_parser("options", help="offline setting types, limits and persistence")
    options.add_argument("name", nargs="?")
    dump = sub.add_parser("dump", help="typed preset of supported settings; read-only")
    dump.add_argument("--json", action="store_true")
    apply = sub.add_parser("apply", help="preflight a preset, skip unchanged values and independently read back writes")
    apply.add_argument("preset")
    apply.add_argument("--dry-run", action="store_true")
    apply.add_argument("--only", action="append", default=[])
    apply.add_argument("--skip", action="append", default=[])
    apply.add_argument("--save", action="store_true", help="explicitly save all current advanced settings after applying")
    preset = sub.add_parser("preset", help="local named presets; separate from device save-advanced")
    preset.add_argument("action", choices=("list", "save", "show", "load", "delete"))
    preset.add_argument("name", nargs="?")
    preset.add_argument("--dry-run", action="store_true")
    preset.add_argument("--only", action="append", default=[])
    preset.add_argument("--skip", action="append", default=[])
    preset.add_argument("--save", action="store_true")
    cap = sub.add_parser("caps", help="discover SLZ1 magic, API and feature bits")
    cap.add_argument("--json", action="store_true")
    get = sub.add_parser("get", help="native settings or SLZ1 debounce/fps/lock/lock-lead/stats")
    get.add_argument("name")
    put = sub.add_parser("set", help="native settings; debounce values; fps ID; lock on|off [us]; stats on|off|reset")
    put.add_argument("name"); put.add_argument("values", nargs="+")
    db = sub.add_parser("debounce-set", help="whole ms 0..255; omitted fields keep their profile values")
    for key in abi.DB_NAMES:
        db.add_argument("--" + key)
    sub.add_parser("debounce-factory", help="set this profile to 0/2/20/20 ms")
    for cmd in ("fps-status", "lock-status"):
        status = sub.add_parser(cmd, help="global runtime settings, not per profile")
        status.add_argument("--json", action="store_true")
    sub.add_parser("fps-list", help="query the firmware's preset count; 0 selects stock")
    fps = sub.add_parser("fps-set", help="numeric preset id or stock; sensor apply may be queued")
    fps.add_argument("preset")
    fps.add_argument("--json", action="store_true")
    custom = sub.add_parser("fps-custom", help="worker SPI injection: U slow fast, each 1..255; use save-advanced to persist on supported SUPER")
    custom.add_argument("values", type=int, nargs=3, metavar=("U", "SLOW", "FAST"))
    sub.add_parser("fps-custom-status", help="requested recipe and last verified sensor SPI readback")
    sub.add_parser("sensor-snapshot", help="fresh worker SPI reads of timing/control registers; no mode reapplication")
    sub.add_parser("sensor-snapshot-status", help="last snapshot status only; does not read the sensor again")
    sub.add_parser("smoothing-status", help="saved selection and worker register verification")
    smoothing = sub.add_parser("smoothing-set", help="apply stock/reduced in the sensor worker and save current advanced settings")
    smoothing.add_argument("mode", choices=("stock", "reduced"))
    sub.add_parser("tracking-status", help="idle tracking selection; active only with eligible wireless LOCK")
    tracking = sub.add_parser("tracking-set", help="set runtime idle tracking; use save-advanced to persist")
    tracking.add_argument("enabled", choices=("on", "off"))
    path = sub.add_parser("path", help="show/set thread or wireless direct; save-advanced persists")
    path.add_argument("path", nargs="?", choices=("thread", "direct"))
    absolute = sub.add_parser("abs", help="show/set cumulative wireless motion; enable only with paired SUPER receiver")
    absolute.add_argument("enabled", nargs="?", choices=("on", "off"))
    channels=sub.add_parser('channels',help='per-channel response/window-timeout counters; check outcome_semantics; default off, no save')
    channels.add_argument('action',nargs='?',choices=('on','off','reset'))
    sub.add_parser("save-advanced", help="save current FPS, custom timing, LOCK, tracking, path, ABS and smoothing to device")
    sub.add_parser("saved-advanced", help="read persisted advanced record without writes")
    lock = sub.add_parser("lock-set", help="global LOCK; lead 0=auto, 1..499 us explicit")
    lock.add_argument("enabled")
    lock.add_argument("lead", help="0=auto (80 us starting value), or 1..499 us")
    lock.add_argument("--json", action="store_true")
    for cmd in ("lock-on", "lock-off"):
        lock = sub.add_parser(cmd, help="keep existing lead unless --lead is given")
        lock.add_argument("--lead")
        lock.add_argument("--json", action="store_true")
    lead = sub.add_parser("lock-lead", help="set lead, retaining the current LOCK enabled state")
    lead.add_argument("us")
    lead.add_argument("--json", action="store_true")
    stats = sub.add_parser("stats", help="read the versioned 188-byte record (six independent page reads)")
    stats.add_argument("--json", action="store_true")
    stats.add_argument("--raw", action="store_true", help="keep raw record bytes; do not decode its layout")
    stats.add_argument("--page", type=int, choices=range(6), help="read one raw page, not a decoded record")
    stats.add_argument("--once", action="store_true", help="single read (default; no background monitoring)")
    for cmd in ("stats-on", "stats-off", "stats-reset"):
        sub.add_parser(cmd, help="runtime counting/reset; reset preserves counting and FPS/LOCK")
    dpi = sub.add_parser("dpi", help="1..5 CPI stages; range 1..40000 in 1-CPI steps")
    dpi.add_argument("stages", nargs="+")
    ds = sub.add_parser("dpi-set", help="replace one CPI stage without changing the others")
    ds.add_argument("value"); ds.add_argument("--stage", type=int); ds.add_argument("--activate", action="store_true")
    da = sub.add_parser("dpi-active"); da.add_argument("stage", type=int)
    profile = sub.add_parser("profile"); profile.add_argument("number", type=int, nargs="?")
    for cmd in ("reset-profile", "reset-settings"):
        reset = sub.add_parser(cmd, help="native factory reset; requires explicit --yes")
        if cmd == "reset-profile":
            reset.add_argument("number", type=int)
        reset.add_argument("--yes", action="store_true")
    return ap


def main(argv=None):
    try:
        a = build_parser().parse_args(argv)
        if not math.isfinite(a.delay) or a.delay < 0:
            raise CfgError("delay must be a finite nonnegative number")
        from . import config_registry as registry
        if a.cmd in ("schema", "options"):
            document = registry.schema()
            if a.cmd == "options" and a.name:
                document = next((r for r in document["settings"] if r["name"] == a.name), None)
                if document is None:
                    raise CfgError(f"unknown setting {a.name!r}")
            print(json.dumps(document, ensure_ascii=False, indent=2))
            return 0
        if a.cmd == "preset":
            if a.action == "list":
                directory = registry.preset_path("listing", must_exist=False).parent
                print(json.dumps(sorted(p.stem for p in directory.glob("*.json")), ensure_ascii=False))
                return 0
            if not a.name:
                raise CfgError(f"preset {a.action} needs a name or JSON path")
            if a.action == "show":
                print(json.dumps(registry.load_preset(a.name), ensure_ascii=False, indent=2))
                return 0
            if a.action == "delete":
                path = registry.preset_path(a.name)
                path.unlink()
                print(f"deleted {path}")
                return 0
            if a.action == "load":
                a.cmd, a.preset = "apply", a.name
        document = registry.load_preset(a.preset) if a.cmd == "apply" else None
        if a.via == "receiver":
            raise CfgError("receiver identity/relay is not mapped; connect by wire")
        if a.cmd.startswith("reset-") and not a.yes:
            raise CfgError("reset requires explicit --yes")
        if a.backend:
            hid.set_backend(a.backend)
        if a.cmd == "list":
            nodes = find_nodes()
            for node in nodes:
                print(node.describe())
            if not nodes:
                print(f"no LAMZU APP interfaces ({target.VID:04X}:{target.APP_PID:04X})")
            return 0
        dev, _ = open_device(a.via, a.node)
        try:
            m = Mouse(Link(dev, a.delay, a.verbose), 0, a.profile)
            if a.cmd == "dump":
                print(json.dumps(registry.make_preset(m), ensure_ascii=False, indent=2))
            elif a.cmd == "apply":
                result = registry.do_apply(m, document, dry_run=a.dry_run,
                                           only=a.only, skip=a.skip, save=a.save)
                print(json.dumps(result, ensure_ascii=False, indent=2))
                if not result["complete"]:
                    return 1
            elif a.cmd == "preset":
                path = registry.preset_path(a.name, must_exist=False)
                document = registry.make_preset(m, a.name)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
                print(f"saved profile {m.profile} to {path}")
            elif a.cmd == "caps":
                caps = m.capabilities()
                print(json.dumps(caps, sort_keys=True) if a.json else _caps_text(caps))
            elif a.cmd == "info":
                print(f"LAMZU wired APP {target.VID:04X}:{target.APP_PID:04X}")
                print("firmware:", m.fw())
                print(f"profile: {m.active_profile()} of {m.profile_count()}")
                print(f"sensor backend: {m.sensor_model()}; CPI max: {m.dpi_max()} (step 1)")
                try:
                    print(_caps_text(m.capabilities()))
                except Unsupported as exc:
                    print(f"extension: {exc}")
            elif a.cmd == "show":
                print(f"profile {m.profile}")
                for name in ("dpi", "dpi-active", "polling", "lod", "angle-tune", "sleep",
                             "panel-debounce", "speed-click", *native.BOOLS):
                    native.row(name, lambda name=name: _read_setting(m, name))
                try:
                    caps = m.capabilities()
                    print(_caps_text(caps))
                    if caps["flags"] & abi.F_DB:
                        print("debounce:", _db_text(m.debounce_values()))
                    if caps["flags"] & abi.F_FPS:
                        print("fps:", _fps_text(m, m.fps_status()))
                    if caps["flags"] & abi.F_LOCK:
                        print("lock:", _lock_text(m, m.lock_status()))
                except Unsupported as exc:
                    print(f"extension: {exc}")
            elif a.cmd == "get":
                print(_read_setting(m, a.name))
            elif a.cmd == "set":
                _set_setting(m, a.name, a.values)
            elif a.cmd == "debounce-status":
                print(f"profile {m.profile}:", _db_text(m.debounce_values()))
            elif a.cmd == "debounce-factory":
                print(_db_text(m.set_debounce(abi.DB_FACTORY)))
            elif a.cmd == "debounce-set":
                changed = {key: integer(getattr(a, key), 0, 255, key + " ms")
                           for key in abi.DB_NAMES if getattr(a, key) is not None}
                if not changed:
                    raise CfgError("give at least one of --pre --post --plock --relock")
                values = list(m.debounce_values())
                for key, value in changed.items():
                    values[abi.DB_NAMES.index(key)] = value
                print(_db_text(m.set_debounce(values)))
            elif a.cmd == "fps-status":
                _advanced_print(m, abi.FPS, m.fps_status(), a.json)
            elif a.cmd == "fps-set":
                _advanced_print(m, abi.FPS, m.fps_set(_preset(a.preset)), a.json)
            elif a.cmd == "fps-custom":
                print(json.dumps(m.fps_custom_set(dict(zip(("unit", "slow", "fast"), a.values)))))
            elif a.cmd == "fps-custom-status":
                print(json.dumps(m.fps_custom_status()))
            elif a.cmd == "sensor-snapshot":
                print(json.dumps(m.sensor_snapshot()))
            elif a.cmd == "sensor-snapshot-status":
                print(json.dumps(m.sensor_snapshot_status()))
            elif a.cmd == "smoothing-status":
                print(json.dumps(dict(runtime=m.smoothing_status(), saved=m.saved_advanced())))
            elif a.cmd == "smoothing-set":
                print(json.dumps(m.smoothing_set(a.mode)))
            elif a.cmd == "tracking-status":
                print(json.dumps(m.tracking_status()))
            elif a.cmd == "tracking-set":
                print(json.dumps(m.tracking_set(a.enabled)))
            elif a.cmd == "path":
                print(m.motion_path(a.path))
            elif a.cmd == "abs":
                print(json.dumps(m.abs_motion(a.enabled)))
            elif a.cmd == 'channels':
                print(json.dumps(m.channels(a.action)))
            elif a.cmd == "save-advanced":
                print(json.dumps(m.save_advanced()))
            elif a.cmd == "saved-advanced":
                print(json.dumps(m.saved_advanced()))
            elif a.cmd == "fps-list":
                info = m.fps_presets()
                print(f"preset_count={info['preset_count']} (includes 0=stock)")
                for preset in info["presets"]:
                    label = preset["name"] or "numeric id (local names do not match firmware count)"
                    print(f"{preset['id']}: {label}")
                print(m.advanced_persistence())
            elif a.cmd == "lock-status":
                _advanced_print(m, abi.LOCK, m.lock_status(), a.json)
            elif a.cmd == "lock-set":
                _advanced_print(m, abi.LOCK, m.set_lock(a.enabled, a.lead), a.json)
            elif a.cmd in ("lock-on", "lock-off"):
                enabled = a.cmd == "lock-on"
                result = m.lock_switch(enabled) if a.lead is None else m.set_lock(enabled, a.lead)
                _advanced_print(m, abi.LOCK, result, a.json)
            elif a.cmd == "lock-lead":
                _advanced_print(m, abi.LOCK, m.lock_lead(a.us), a.json)
            elif a.cmd == "stats":
                _stats_print(m, as_json=a.json, page=a.page, raw=a.raw)
            elif a.cmd in ("stats-on", "stats-off", "stats-reset"):
                enabled = m.stats_reset() if a.cmd == "stats-reset" else m.stats_switch(a.cmd == "stats-on")
                print(f"counting {'on' if enabled else 'off'} (current power session)")
            elif a.cmd == "dpi":
                _set_dpi(m, a.stages)
            elif a.cmd == "dpi-set":
                value = _cpi_stage(a.value)
                stages, active = m.stages(), m.active_stage()
                idx = active if a.stage is None else a.stage
                idx = integer(idx, 1, len(stages), "stage")
                stages[idx - 1] = value
                m.set_stages(stages)
                verify(m.stages, stages, "CPI stages")
                if a.activate:
                    m.set_active_stage(idx)
                    verify(m.active_stage, idx, "active stage")
                print(f"stage {idx}: {native.fmt_stage(value)} OK")
            elif a.cmd == "dpi-active":
                stage = integer(a.stage, 1, len(m.stages()), "stage")
                m.set_active_stage(stage)
                verify(m.active_stage, stage, "active stage")
                print(f"active stage: {stage} OK")
            elif a.cmd == "profile":
                if a.number is None:
                    print(m.active_profile())
                else:
                    m.set_profile(a.number)
                    verify(m.active_profile, a.number, "profile")
                    print(f"active profile: {a.number} OK")
            elif a.cmd == "reset-profile":
                m.reset_profile(a.number)
                print(f"profile {a.number} factory reset requested")
            elif a.cmd == "reset-settings":
                acknowledged = m.factory_reset()
                print("factory reset acknowledged" if acknowledged else
                      "factory reset sent; device disconnected before acknowledgement, re-read settings after reconnect")
        finally:
            dev.close()
        return 0
    except Unsupported as exc:
        print(f"unsupported: {exc}", file=sys.stderr)
        return 3
    except (CfgError, hid.HidOpenError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
