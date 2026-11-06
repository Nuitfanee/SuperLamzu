#!/usr/bin/env python3
"""
ko1_cfg.py - unofficial cross-platform (Linux / Windows / macOS) configurator for the CRDRAKO KO-ONE mouse.

Talks to the mouse the way the CRDRAKO PANEL web driver does, using packet formats
reverse-engineered from the panel's JavaScript (IsNewProtocol=1 model entry).
Works over the 8K receiver (373E:006B) or a wired connection (373E:006A).
NOT tested against real hardware by its author - start with the read-only commands.

Transport : 64-byte HID feature reports, report ID 0, via ko1_hid.py:
            /dev/hidraw* on Linux (no dependencies), hidapi on Windows/macOS.
Targets   : receiver: mouse = 2 (relayed over 2.4 GHz), receiver itself = 0
            wired   : mouse = 0   (the panel rewrites 2 -> 0 when wired)
Packet    : [2]=target [3]=length [4]=group [5]=cmd (get = cmd|0x80) [6]=profile [7..]=args
Reply     : [0]=0xA1 ok, [4]/[5] echo group/cmd, data from [6]/[7]

Read-only : list, info, show, get
Writes    : set, dpi, dpi-set, dpi-active, profile, lod-sweep   (each is read back and verified)
Research  : watch (SQUAL live view, stock too), poke / peek (LOD research build only)
Resets    : reset-settings (the panel's factory reset), reset-profile N - both ask for YES first
Never sent: bootloader/firmware-update commands (group 0 cmd 0x00 sub 0xB0 enters the bootloader).
"""
import argparse
import sys
import time

VID = 0x373E
PID_WIRED = 0x006A
PID_RECEIVER = 0x006B
CFG_DESC = b"\x95\x40\xb1\x02"          # 64-byte feature report in the HID descriptor
POLL_CODE = {125: 8, 250: 4, 500: 2, 1000: 1, 2000: 32, 4000: 64, 8000: 128}
CODE_POLL = {v: k for k, v in POLL_CODE.items()}
CODE_POLL[16] = 1000                    # the panel maps a legacy code 16 to 1000 Hz
MAX_STAGES = 5                          # DPIMaxStageNum in the model table
BOOLS = {                               # name: (set cmd, get cmd), all group 1, length 2
    "angle-snap": (4, 0x84),
    "motion-sync": (9, 0x89),
    "ripple": (10, 0x8A),
    "hyper": (11, 0x8B),
    "competition": (19, 0x93),
    "dpi-xy": (13, 0x8D),
}


class CfgError(RuntimeError):
    pass


class CfgRejected(CfgError):
    """The mouse answered 0xA2: it understood the command and refused the value."""


# ------------------------------------------------------------------ HID transport
# OS-specific code lives in ko1_hid.py (Linux hidraw, or hidapi on Windows/macOS).
import ko1_hid  # noqa: E402
from ko1_hid import HidOpenError, open_node, pick_config_node  # noqa: E402


def find_nodes(pid):
    return ko1_hid.find_nodes(VID, pid)


def open_device(via, node=None):
    """Return (device, pid)."""
    order = {"receiver": [PID_RECEIVER], "wired": [PID_WIRED],
             "auto": [PID_RECEIVER, PID_WIRED]}[via]
    found = [(pid, find_nodes(pid)) for pid in order]
    found = [(pid, n) for pid, n in found if n]
    if not found:
        raise CfgError("No KO-ONE found (373E:006B receiver or 373E:006A wired).")
    if via == "auto" and len(found) > 1:
        raise CfgError("Both the receiver and the wired mouse are present; "
                       "choose one with --via receiver|wired.")
    pid, nodes = found[0]
    return open_node(pick_config_node(nodes, node)), pid


# -------------------------------------------------------------------- protocol
def pkt(target, length, group, cmd, *payload):
    p = bytearray(64)
    p[2], p[3], p[4], p[5] = target, length, group, cmd
    p[6:6 + len(payload)] = bytes(payload)
    return bytes(p)


class Link:
    """Panel-compatible transaction handling (retrySetGet semantics)."""

    def __init__(self, dev, delay=0.02, verbose=False):
        self.dev, self.delay, self.verbose = dev, delay, verbose
        self.off = None                      # leading junk bytes in replies (0 or 1)

    def _get(self):
        raw = self.dev.get_report()
        if 0xA0 <= raw[0] <= 0xAF:
            self.off = 0
        elif 0xA0 <= raw[1] <= 0xAF:
            self.off = 1
        n = raw[self.off or 0:]
        if self.verbose:
            print("    <-", n[:16].hex(" "))
        return n

    @staticmethod
    def _ok(n, req, strict):
        if n[0] not in (0xA1, 0x02):
            return False
        return (not strict) or (n[4] == req[4] and n[5] == req[5])

    def xfer(self, req, strict=True, rounds=5, poll=30):
        """Send `req`, return the native reply.  strict=True also requires the reply to
        echo group/cmd (guards against stale replies, important over the radio link)."""
        last = None
        for _ in range(rounds):
            if self.verbose:
                print("    ->", req[:16].hex(" "))
            self.dev.set_report(req)
            time.sleep(self.delay)
            n = last = self._get()
            if self._ok(n, req, strict):
                return n
            if n[0] == 0xA2 and n[4] == req[4] and n[5] == req[5]:
                raise CfgRejected("the mouse rejected this value (reply 0xA2, group %d cmd 0x%02X)"
                                  % (req[4], req[5]))
            if n[0] < 0xA1:                   # pending: poll before resending
                for _ in range(poll):
                    time.sleep(self.delay)
                    n = last = self._get()
                    if self._ok(n, req, strict):
                        return n
            time.sleep(self.delay)
        raise CfgError("no valid reply (last: %s). Over the receiver this usually means the "
                       "mouse is asleep or out of range - move it and retry." % last[:12].hex(" "))


class Mouse:
    def __init__(self, link, target, profile=None):
        self.l, self.t = link, target
        self._profile = profile

    # ---- queries (read-only)
    def fw(self, target=None):
        n = self.l.xfer(pkt(self.t if target is None else target, 16, 0, 0x81))
        return ".".join(str(b) for b in n[6:10])

    def battery(self):
        n = self.l.xfer(pkt(self.t, 2, 0, 0x83))
        return n[6], n[7]                      # (charge flag, percent)

    def eid(self):
        return self.l.xfer(pkt(self.t, 1, 0, 0x82))[6]

    # ---- resets (group 0). Traced in v01.09.02.05 at 0x0E06FD9C / 0x0E06FE8C and run in emulation:
    #   cmd 0x00, [6]=0xC0, [7]=1: copy the factory settings image, schedule the save; the save then restarts
    #     the mouse ([7]=0 restarts at once; [6]=0xB0 enters the bootloader - never sent)
    #   cmd 0x0D, [6]=profile 1..3: that profile back to its factory record, saved; the rest untouched
    def factory_reset(self):
        """All settings back to factory (every profile, and the hyperdrako settings to their build defaults).
        The mouse saves and restarts, so the reply may never come."""
        try:
            self.l.xfer(pkt(self.t, 2, 0, 0x00, 0xC0, 0x01), rounds=2)
            return True
        except CfgRejected:
            raise
        except CfgError:
            return False                       # most likely already restarting

    def reset_profile(self, n):
        """One profile back to factory (DPI stages, polling, LOD, buttons, ...). Global settings stay."""
        self.l.xfer(pkt(self.t, 1, 0, 0x0D, n))

    def profile_count(self):
        return self.l.xfer(pkt(self.t, 1, 0, 0x86))[6]

    def active_profile(self):
        return self.l.xfer(pkt(self.t, 1, 0, 0x85))[6]

    @property
    def profile(self):
        if self._profile is None:
            self._profile = self.active_profile()
        return self._profile

    def sensor_model(self):
        return self.l.xfer(pkt(self.t, 1, 1, 0x8F))[6]

    def dpi_max(self):
        """The firmware rejects a max-DPI query (cmd 0x8C answers with an error and the panel
        never sends it).  The panel derives the limit from the sensor model instead:
        1 -> 26000, 2 -> 30000, otherwise the model table's 30000."""
        try:
            model = self.sensor_model()
        except CfgError:
            model = 0
        return {1: 26000, 2: 30000}.get(model, 30000)

    def _g(self, length, group, cmd):
        return self.l.xfer(pkt(self.t, length, group, cmd, self.profile))

    def polling(self):
        v = self._g(2, 1, 0x80)[7]
        return CODE_POLL.get(v)

    def lod_raw(self):
        return self._g(2, 1, 0x88)[7]

    def lod(self):
        v = self.lod_raw()
        return v if v < 128 else (v - 128) / 10

    def flag(self, name):
        return self._g(2, 1, BOOLS[name][1])[7] == 1

    def angle_tune(self):
        v = self._g(2, 1, 0x94)[7]
        return v - 256 if v > 30 else v

    def sleep_seconds(self):
        n = self._g(3, 0, 0x87)
        return (n[7] << 8) | n[8]

    def debounce(self):
        return self._g(2, 0, 0x88)[7]

    def active_stage(self):
        return self._g(2, 1, 0x82)[7]

    def stages(self):
        n = self.l.xfer(pkt(self.t, 10, 1, 0x81, self.profile, 6))
        cnt = n[7]
        out = []
        for i in range(cnt):
            o = 8 + 4 * i
            out.append(((n[o] << 8) | n[o + 1], (n[o + 2] << 8) | n[o + 3]))
        return out

    def current_dpi(self):
        """(active stage number, (x_dpi, y_dpi)) for the active profile."""
        st, act = self.stages(), self.active_stage()
        if not 1 <= act <= len(st):
            raise CfgError(f"active stage {act} is outside the {len(st)} stage(s) reported")
        return act, st[act - 1]

    # ---- writes (every caller re-reads and verifies)
    def _set(self, length, group, cmd, *payload):
        self.l.xfer(pkt(self.t, length, group, cmd, self.profile, *payload), strict=False)
        time.sleep(0.05)

    def set_polling(self, hz):
        self._set(2, 1, 0, POLL_CODE[hz])

    def set_lod(self, mm):
        code = int(mm) if mm >= 1 else (int(round(mm * 10)) | 128)
        self._set(2, 1, 8, code)

    def set_lod_raw(self, code):
        try:
            self._set(2, 1, 8, code & 0xFF)
        except CfgRejected:
            raise CfgRejected(f"the mouse rejected LOD code {code:#04x} (reply 0xA2). The firmware on "
                              "the mouse is not the current LOD/ABLOD build: stock v1.9 (and the first "
                              "LOD build) only accept 1, 2 and 0x87. Flash out/patched_ABLOD.hex "
                              "(or re-run `ko1 patch ABLOD ...`), then `ko1 fw verify` it.") from None

    # ---- sensor research (LOD-patched firmware v2; `sensor_value` alone also works on stock)
    def _research(self, length, *payload, what):
        try:
            self.l.xfer(pkt(self.t, length, 1, 8, self.profile, *payload), strict=False)
        except CfgRejected:
            raise CfgRejected(f"the mouse rejected the {what} packet (reply 0xA2): it is not running the "
                              "LOD research build (patched_ABLOD.hex / patched_LOD.hex from this version, "
                              "or a spec made with this version of `ko1 lod spec`).") from None

    def poke(self, page, reg, value):
        """Write one sensor register (page:reg <- value). Not stored; a power cycle undoes it."""
        self._research(4, page, reg, value, what="poke")

    def select_peek(self, reg):
        """Choose which page-0 sensor register GET 0x96 reports (0x07 = SQUAL, the stock one)."""
        self._research(3, reg, 0, what="peek-select")

    def sensor_value(self):
        """GET group 1 cmd 0x96: returns the value read on the PREVIOUS request and queues a new
        read (stock firmware: always SQUAL, reg 0x07)."""
        return self.l.xfer(pkt(self.t, 1, 1, 0x96, self.profile))[6]

    # ---- telemetry (ABLODSTATS firmware): GET 0x96 with length 2 reads 16-byte pages of counters
    def _stats_req(self, page, tries=3):
        want = 1 if page >= 0x80 else STATS_PAGE
        for _ in range(tries):                 # over the radio a stale/odd reply can slip through once
            n = self.l.xfer(pkt(self.t, 2, 1, 0x96, self.profile, page))
            if n[3] == want:
                return n
            time.sleep(0.05)
        if n[3] != want:
            raise CfgError("the mouse did not return telemetry: it is not running the ABLODSTATS build "
                           "(flash out/patched_ABLODSTATS.hex, made with `ko1 patch ABLODSTATS ...`).")
        return n

    def stats(self):
        """Counter snapshot as {name: value} (32-bit, wrapping)."""
        need = (len(STATS_FIELDS) * 4 + STATS_PAGE - 1) // STATS_PAGE      # 8 pages
        raw = b"".join(bytes(self._stats_req(p)[6:6 + STATS_PAGE]) for p in range(need))
        d = {k: int.from_bytes(raw[4 * i:4 * i + 4], "little") for i, k in enumerate(STATS_FIELDS)}
        if "enabled" in d:
            d["enabled"] &= 0xFF                # byte 124 only; 125..127 hold debounce settings in DB builds
        if "lock_rescue" in d:
            d["lock_rescue"] = (d["lock_rescue"] >> 16) & 0xFF   # byte 2 of the word; bytes 0-1 are lock state
        return d

    def stats_reset(self):
        """Zero the counters; the on/off switch is kept."""
        self._stats_req(0xFF)

    def lock_switch(self, on):
        """Sensor-read phase lock on/off (on after every power-up). Returns the new state."""
        return bool(self._stats_req(0xFC if on else 0xFB)[6])

    def lock_persistence(self):
        """How long lock settings last on this build: DB builds without stats save them."""
        try:
            self._db_req(0xC8, tries=1)
        except CfgError:
            return "back to on / 80 us after power-up"
        try:
            self._stats_req(0, tries=1)
        except CfgError:
            return "saved on the mouse"
        return "back to on / 80 us after power-up: the stats build keeps the lock live only"

    def lock_status(self):
        """(on, lead_us) from the ABLODLOCK / ABLODSTATS firmware."""
        n = self.l.xfer(pkt(self.t, 2, 1, 0x96, self.profile, 0xFA))
        if n[3] != 3:
            raise CfgError("the mouse did not answer the lock query: it is not running ABLODLOCK or ABLODSTATS")
        return bool(n[6]), n[7] | n[8] << 8

    def lock_lead(self, us):
        """Set the lock's lead: how many us before the radio frame build the read is timed (0..252, step 4)."""
        if not 0 <= us <= 252:
            raise CfgError("lead must be 0..252 us")
        return self._stats_req(0x80 + us // 4)[6] * 4

    # ---- click debounce (ABLODDB / ABLODLOCKDB / ABLODSTATSDB): GET 0x96 with request length 3
    def _db_req(self, action, value=0, tries=3):
        for _ in range(tries):
            n = self.l.xfer(pkt(self.t, 3, 1, 0x96, self.profile, action, value))
            if n[3] in (12, 13, 14, 28):
                raw, eff, stock = list(n[6:10]), list(n[10:14]), list(n[14:18])
                fine = n[3] >= 28                      # fine builds: values in effect in 100 us units at [20..27]
                us = [n[20 + 2 * i] | n[21 + 2 * i] << 8 for i in range(4)] if fine else None
                d = {k: {"raw": raw[i], "ms": eff[i], "stock_ms": stock[i],
                         "us": us[i] * 100 if fine else eff[i] * 1000} for i, k in enumerate(DB_NAMES)}
                d["fine"] = fine
                d["hyperfps"] = bool(n[18]) if n[3] >= 13 else None
                # frame-rate presets: None = this build has only hyper-fps on/off (ABLODSTATSDB, older builds);
                # otherwise "stock" or the preset index
                d["fps_presets"] = n[19] if n[3] >= 14 else None
                d["fps"] = (None if n[3] < 14 else "stock" if n[18] == 0 or n[18] > n[19] else n[18] - 1)
                return d
            time.sleep(0.05)
        raise CfgError("the mouse did not answer the debounce query: it is not running a debounce build "
                       "(flash out/patched_ABLODDB.hex, ABLODLOCKDB or ABLODSTATSDB).")

    def click_debounce(self, tries=3):
        """hyperdrako DB builds: {name: {raw, ms, stock_ms}} for pre, post, plock, relock (values in effect),
        plus "hyperfps". Not to be confused with debounce(), the panel's own setting."""
        return self._db_req(0xC8, tries=tries)

    def debounce_set(self, name, code, fine=None):
        """Set one value. code: 0 = build default, 255 = stock, else a db_code() byte. Codes for 0.1 ms steps
        need a fine build (ABLODDB / ABLODLOCKDB): refused on others, which would read them as whole ms."""
        if FINE_BASE <= code < 255:
            if fine is None:
                fine = self.click_debounce()["fine"]
            if not fine:
                raise CfgError("this build takes whole ms only (ABLODSTATSDB or an older DB build); "
                               "flash ABLODDB / ABLODLOCKDB for 0.1 ms steps")
        return self._db_req(0xC0 + DB_NAMES.index(name), code)

    def hyperfps_set(self, on):
        """Hyper-fps on/off (off after every power-up). Returns the new state."""
        st = self._db_req(0xC4, 1 if on else 0)["hyperfps"]
        if st is None:
            raise CfgError("this firmware has the debounce command but not hyper-fps: rebuild the DB build")
        return st

    def fps_set(self, idx):
        """Frame-rate preset (index) or None = stock, saved on the mouse. Returns the click_debounce() dict."""
        d = self.click_debounce()
        if d["hyperfps"] is None:
            raise CfgError("this firmware has the debounce command but no frame-rate control: rebuild the DB build")
        if d["fps_presets"] is None:
            if idx not in (None, 0):
                raise CfgError("this build (ABLODSTATSDB or an older DB build) only has hyper-fps on/off: "
                               "use 'stock' or '20k', or flash ABLODDB / ABLODLOCKDB for the other presets")
            return self._db_req(0xC4, 0 if idx is None else 1)
        if idx is not None and idx >= d["fps_presets"]:
            raise CfgError(f"preset {FPS_PRESETS[idx][0]} is not in this build (it has {d['fps_presets']} presets)")
        return self._db_req(0xC4, 0 if idx is None else idx + 1)

    def active_script(self):
        """Best guess at the sensor script running now: (name, note)."""
        if self.flag("competition"):
            return "D", ""
        poll = self.polling() or 0
        if poll > 1000:
            return ("C" if max(self.current_dpi()[1]) > 6999 else "B"), ""
        if self.flag("hyper"):
            return "B", " (at 1000 Hz and below this depends on the last mode change; a polling change picks Hyper off)"
        return "copy2", ""

    def fps_apply(self, idx):
        """Write the five frame-rate registers now for preset idx (None = the active script's own values).
        The firmware writes the same values itself at the next mode, DPI or polling change and at power-up."""
        script, note = self.active_script()
        vals = fps_values(idx) if idx is not None else dict(zip(FPS_FIELDS, FPS_STOCK[script]))
        for (page, reg) in ((7, 0x42), (6, 0x53), (6, 0x62), (6, 0x6D), (6, 0x6E)):
            self.poke(page, reg, vals[(page, reg)])
        return f"applied now to the active mode ({SCRIPT_TEXT[script]}){note}"

    def hyperfps_apply(self, on):
        """Write the three page-6 frame-rate registers now, if the active sensor script is one hyper-fps
        changes (B or copy2). Returns a note for the user."""
        if self.flag("competition"):
            return "CE is on: its own script already runs the sensor at 20k; nothing to apply now"
        dpi = max(self.current_dpi()[1])
        poll = self.polling() or 0
        if self.flag("hyper") and poll > 1000 and dpi > 6999:
            return ("Hyper above 6999 DPI uses script C, already 20k; hyper-fps applies when the DPI "
                    "goes back to 6999 or below")
        for reg, (stock, fast) in HF_VALUES.items():
            self.poke(6, reg, fast if on else stock)
        return "applied now (06:53/6D/6E written)"

    def stats_switch(self, on):
        """Counting on/off (off after every power-up). Returns the new state."""
        return bool(self._stats_req(0xFE if on else 0xFD)[6])

    def peek(self, reg, gap=0.03):
        self.select_peek(reg)
        self.sensor_value(); time.sleep(gap)
        self.sensor_value(); time.sleep(gap)     # first fresh read with the new selector
        return self.sensor_value()

    def set_flag(self, name, on):
        self._set(2, 1, BOOLS[name][0], 1 if on else 0)

    def set_angle_tune(self, v):
        self._set(2, 1, 20, v & 0xFF)

    def speed_click(self):
        """Speed Click flags (slot 1, slot 2) of the profile: group 0 cmd 0x9A, profile +0x12 / +0x13.
        Each switches one button slot (most likely left / right) to the firmware's alternate button timers."""
        n = self._g(1, 0, 0x9A)
        return bool(n[7]), bool(n[8])

    def set_speed_click(self, a, b):
        self._set(3, 0, 0x1A, 1 if a else 0, 1 if b else 0)

    def set_sleep(self, seconds):
        self._set(3, 0, 7, (seconds >> 8) & 0xFF, seconds & 0xFF)

    def set_active_stage(self, idx):
        self._set(2, 1, 2, idx)

    def set_stages(self, stages):
        p = bytearray(64)
        p[2], p[3], p[4], p[5], p[6], p[7] = self.t, 26, 1, 1, self.profile, len(stages)
        for i, (x, y) in enumerate(stages):
            o = 8 + 4 * i
            p[o], p[o + 1], p[o + 2], p[o + 3] = x >> 8, x & 255, y >> 8, y & 255
        self.l.xfer(bytes(p), strict=False)
        time.sleep(0.05)

    def set_profile(self, idx):
        self.l.xfer(pkt(self.t, 1, 0, 5, idx), strict=False)
        time.sleep(0.05)
        self._profile = idx


# -------------------------------------------------------------------- CLI logic
def parse_bool(s):
    s = s.lower()
    if s in ("1", "on", "true", "yes", "enable", "enabled"):
        return True
    if s in ("0", "off", "false", "no", "disable", "disabled"):
        return False
    raise CfgError(f"expected on/off, got {s!r}")


def parse_stage(tok):
    t = tok.lower().replace(",", "x")
    x, _, y = t.partition("x")
    return int(x), int(y or x)


def fmt_stage(s):
    return f"{s[0]}" if s[0] == s[1] else f"{s[0]}x{s[1]}"


def settle(read, want, tries=4, gap=0.15):
    """Read back, retrying briefly: the firmware applies settings asynchronously and a
    read straight after a write over the radio link can return a stale value."""
    v = read()
    for _ in range(tries - 1):
        if v == want:
            break
        time.sleep(gap)
        v = read()
    return v


def row(label, fn):
    """Print one line; a failing query shows n/a instead of aborting the whole listing."""
    try:
        v = fn()
    except CfgError as e:
        v = "n/a (" + str(e).split(" (last")[0] + ")"
    print(f"  {label:<13s} : {v}")


def fmt_dpi_now(m):
    act, s = m.current_dpi()
    return f"{fmt_stage(s)} DPI (stage {act})"


def fmt_stages(m):
    st, act = m.stages(), m.active_stage()
    return "  ".join(("[%s]" if i + 1 == act else "%s") % fmt_stage(s) for i, s in enumerate(st))


def fmt_sleep(m):
    sl = m.sleep_seconds()
    return "disabled" if sl in (0, 0xFFFF, 0xFF00) else f"{sl // 60} min ({sl} s)"


# --- LOD millimetre ESTIMATE (data-mined, see README_lod.md "Estimating millimetres") ----------
# Only two enabled points exist in any firmware we have: 0x85 = "1 mm", 0x8F = "2 mm" (KO-ONE
# v1.06/v1.07/v1.09). With bit 7 = enable and bits 0..6 = threshold t this gives
#     mm ~= 0.5 + 0.1 * t           (two-point linear fit)
# 0x00 (and, inferred, any value with bit 7 clear) = fine layer off = sensor default ~0.7 mm.
LOD_MM_MIN, LOD_MM_MAX = 0.5, 0.5 + 0.1 * 127


MODE_SCRIPT_REGS = {  # generated from emulation of patched_ABLOD.hex; pages != 0, regs that differ
    'copy2': {(0x05, 0x43): 0xE4, (0x05, 0x49): 0x10, (0x05, 0x51): 0x40, (0x05, 0x55): 0xFC, (0x05, 0x5B): 0xFC, (0x05, 0x5F): 0x90, (0x05, 0x61): 0x3B, (0x05, 0x6D): 0xB8, (0x05, 0x6E): 0xDF, (0x05, 0x7B): 0x10, (0x06, 0x53): 0x03, (0x06, 0x62): 0x01, (0x06, 0x6D): 0x8F, (0x06, 0x6E): 0x70, (0x06, 0x6F): 0x04, (0x06, 0x7A): 0x02, (0x07, 0x42): 0x28, (0x09, 0x40): 0x01, (0x09, 0x43): 0x13, (0x09, 0x44): 0x88, (0x09, 0x47): 0x00, (0x09, 0x4F): 0x0C, (0x09, 0x51): 0x04, (0x09, 0x55): 0x3F, (0x09, 0x56): 0x3F, (0x09, 0x59): 0x0F, (0x09, 0x5A): 0x0F, (0x09, 0x73): 0x0C, (0x0A, 0x4A): 0x11, (0x0C, 0x4A): 0x1C, (0x0C, 0x4B): 0x14, (0x0C, 0x4C): 0x4F, (0x0C, 0x4D): 0x02, (0x0C, 0x50): 0x00, (0x0C, 0x51): 0x01, (0x0C, 0x53): 0x16, (0x0C, 0x55): 0x10, (0x0C, 0x62): 0x18, (0x18, 0x48): 0x65, (0x18, 0x4C): 0x2C, (0x18, 0x4D): 0x38, (0x18, 0x4E): 0x32, (0x18, 0x50): 0x34, (0x18, 0x51): 0x54, (0x18, 0x52): 0x38, (0x18, 0x53): 0x5F, (0x18, 0x55): 0x7F, (0x18, 0x5B): 0x1E, (0x18, 0x5D): 0x06, (0x18, 0x5E): 0x02, (0x18, 0x61): 0x1C, (0x18, 0x62): 0x60, (0x18, 0x63): 0xFF, (0x18, 0x64): 0x00, (0x18, 0x6D): 0xF5, (0x18, 0x6E): 0x06, (0x18, 0x6F): 0x06, (0x18, 0x71): 0xF2, (0x18, 0x72): 0xF6, (0x18, 0x77): 0x32, (0x18, 0x79): 0xCC, (0x19, 0x47): 0x12, (0x19, 0x4B): 0x01, (0x19, 0x4C): 0x01},
    'B': {(0x05, 0x43): 0x64, (0x05, 0x49): 0x20, (0x05, 0x51): 0x40, (0x05, 0x55): 0xFB, (0x05, 0x5B): 0xFB, (0x05, 0x5F): 0x90, (0x05, 0x61): 0x31, (0x05, 0x6D): 0xB8, (0x05, 0x6E): 0xCF, (0x05, 0x7B): 0x50, (0x06, 0x53): 0x03, (0x06, 0x62): 0x02, (0x06, 0x6D): 0x8F, (0x06, 0x6E): 0x70, (0x06, 0x6F): 0x07, (0x06, 0x7A): 0x03, (0x07, 0x42): 0x14, (0x09, 0x40): 0x01, (0x09, 0x43): 0x23, (0x09, 0x44): 0x88, (0x09, 0x47): 0x00, (0x09, 0x4F): 0x0C, (0x09, 0x51): 0x04, (0x09, 0x55): 0x3F, (0x09, 0x56): 0x3F, (0x09, 0x59): 0x0F, (0x09, 0x5A): 0x0F, (0x09, 0x73): 0x0C, (0x0A, 0x4A): 0x14, (0x0C, 0x4A): 0x20, (0x0C, 0x4B): 0x1F, (0x0C, 0x4C): 0x5C, (0x0C, 0x4D): 0x90, (0x0C, 0x50): 0x14, (0x0C, 0x51): 0x15, (0x0C, 0x53): 0x1E, (0x0C, 0x55): 0x02, (0x0C, 0x62): 0x02, (0x18, 0x48): 0x55, (0x18, 0x4C): 0x20, (0x18, 0x4D): 0x30, (0x18, 0x4E): 0x28, (0x18, 0x50): 0x18, (0x18, 0x51): 0x40, (0x18, 0x52): 0x20, (0x18, 0x53): 0x38, (0x18, 0x55): 0x68, (0x18, 0x5B): 0x24, (0x18, 0x5D): 0x02, (0x18, 0x5E): 0x01, (0x18, 0x61): 0x0A, (0x18, 0x62): 0x1A, (0x18, 0x63): 0x48, (0x18, 0x64): 0x40, (0x18, 0x6D): 0x85, (0x18, 0x6E): 0x0C, (0x18, 0x6F): 0x0A, (0x18, 0x71): 0x88, (0x18, 0x72): 0x88, (0x18, 0x77): 0x22, (0x18, 0x79): 0xCB, (0x19, 0x47): 0x24, (0x19, 0x4B): 0x02, (0x19, 0x4C): 0x02},
    'C': {(0x05, 0x43): 0x64, (0x05, 0x49): 0x20, (0x05, 0x51): 0x10, (0x05, 0x55): 0xFB, (0x05, 0x5B): 0xFB, (0x05, 0x5F): 0x80, (0x05, 0x61): 0x31, (0x05, 0x6D): 0xA7, (0x05, 0x6E): 0xCD, (0x05, 0x7B): 0x50, (0x06, 0x53): 0x02, (0x06, 0x62): 0x02, (0x06, 0x6D): 0x98, (0x06, 0x6E): 0x80, (0x06, 0x6F): 0x07, (0x06, 0x7A): 0x03, (0x07, 0x42): 0x14, (0x09, 0x40): 0x03, (0x09, 0x43): 0x23, (0x09, 0x44): 0x98, (0x09, 0x47): 0x18, (0x09, 0x4F): 0x00, (0x09, 0x51): 0x11, (0x09, 0x55): 0x54, (0x09, 0x56): 0x54, (0x09, 0x59): 0x20, (0x09, 0x5A): 0x20, (0x09, 0x73): 0x0E, (0x0A, 0x4A): 0x14, (0x0C, 0x4A): 0x20, (0x0C, 0x4B): 0x1F, (0x0C, 0x4C): 0x5C, (0x0C, 0x4D): 0x90, (0x0C, 0x50): 0x14, (0x0C, 0x51): 0x15, (0x0C, 0x53): 0x1E, (0x0C, 0x55): 0x02, (0x0C, 0x62): 0x02, (0x18, 0x48): 0x55, (0x18, 0x4C): 0x20, (0x18, 0x4D): 0x30, (0x18, 0x4E): 0x28, (0x18, 0x50): 0x18, (0x18, 0x51): 0x40, (0x18, 0x52): 0x20, (0x18, 0x53): 0x38, (0x18, 0x55): 0x68, (0x18, 0x5B): 0x24, (0x18, 0x5D): 0x02, (0x18, 0x5E): 0x01, (0x18, 0x61): 0x0A, (0x18, 0x62): 0x1A, (0x18, 0x63): 0x48, (0x18, 0x64): 0x40, (0x18, 0x6D): 0x85, (0x18, 0x6E): 0x0C, (0x18, 0x6F): 0x0A, (0x18, 0x71): 0x88, (0x18, 0x72): 0x88, (0x18, 0x77): 0x22, (0x18, 0x79): 0xCB, (0x19, 0x47): 0x24, (0x19, 0x4B): 0x02, (0x19, 0x4C): 0x02},
    'D': {(0x05, 0x43): 0x64, (0x05, 0x49): 0x20, (0x05, 0x51): 0x10, (0x05, 0x55): 0xFB, (0x05, 0x5B): 0xFB, (0x05, 0x5F): 0x80, (0x05, 0x61): 0x31, (0x05, 0x6D): 0xA7, (0x05, 0x6E): 0xCD, (0x05, 0x7B): 0x50, (0x06, 0x53): 0x02, (0x06, 0x62): 0x02, (0x06, 0x6D): 0x98, (0x06, 0x6E): 0x80, (0x06, 0x6F): 0x07, (0x06, 0x7A): 0x03, (0x07, 0x42): 0x14, (0x09, 0x40): 0x03, (0x09, 0x43): 0x23, (0x09, 0x44): 0x98, (0x09, 0x47): 0x18, (0x09, 0x4F): 0x00, (0x09, 0x51): 0x11, (0x09, 0x55): 0x54, (0x09, 0x56): 0x54, (0x09, 0x59): 0x20, (0x09, 0x5A): 0x20, (0x09, 0x73): 0x0E, (0x0A, 0x4A): 0x14, (0x0C, 0x4A): 0x20, (0x0C, 0x4B): 0x1F, (0x0C, 0x4C): 0x5C, (0x0C, 0x4D): 0x90, (0x0C, 0x50): 0x14, (0x0C, 0x51): 0x15, (0x0C, 0x53): 0x1E, (0x0C, 0x55): 0x02, (0x0C, 0x62): 0x02, (0x18, 0x48): 0x55, (0x18, 0x4C): 0x20, (0x18, 0x4D): 0x30, (0x18, 0x4E): 0x28, (0x18, 0x50): 0x18, (0x18, 0x51): 0x40, (0x18, 0x52): 0x20, (0x18, 0x53): 0x38, (0x18, 0x55): 0x68, (0x18, 0x5B): 0x24, (0x18, 0x5D): 0x02, (0x18, 0x5E): 0x01, (0x18, 0x61): 0x0A, (0x18, 0x62): 0x1A, (0x18, 0x63): 0x48, (0x18, 0x64): 0x40, (0x18, 0x6D): 0x85, (0x18, 0x6E): 0x0C, (0x18, 0x6F): 0x0A, (0x18, 0x71): 0x88, (0x18, 0x72): 0x88, (0x18, 0x77): 0x22, (0x18, 0x79): 0xCB, (0x19, 0x47): 0x24, (0x19, 0x4B): 0x02, (0x19, 0x4C): 0x02},
}


def script_pokes(name, pages=None):
    """(page, reg, value) list that moves the sensor's mode-dependent registers to the values the
    named perf script leaves (copy2 = 1 kHz/Hyper off, B/C = 2 kHz+, D = CE)."""
    if name not in MODE_SCRIPT_REGS:
        raise CfgError("script must be one of: " + ", ".join(MODE_SCRIPT_REGS))
    out = [(p, r, v) for (p, r), v in MODE_SCRIPT_REGS[name].items() if pages is None or p in pages]
    if not out:
        raise CfgError("no registers on those pages")
    return out


STATS_PAGE = 16
DB_NAMES = ("pre", "post", "plock", "relock")
HF_VALUES = {0x53: (0x03, 0x02), 0x6D: (0x8F, 0x98), 0x6E: (0x70, 0x80)}   # page 6: (Hyper stock, 20k)
# Sensor frame-rate presets (ABLODDB / ABLODLOCKDB). Mirrors out/debounce_patch.FPS_PRESETS (a test checks it):
# name, 07:42 unit (x 1.25 us), longest frame, shortest frame (in units). The index is saved on the mouse.
FPS_FIELDS = ((6, 0x53), (6, 0x62), (6, 0x6D), (6, 0x6E), (7, 0x42))
FPS_PRESETS = (
    ("20k", 20, 2, 2), ("19k", 21, 2, 2), ("18k", 22, 2, 2), ("17k", 24, 2, 2), ("16k", 25, 2, 2),
    ("15k", 27, 2, 2), ("14k", 29, 2, 2), ("13k", 31, 2, 2), ("12k", 33, 2, 2), ("11k", 36, 2, 2),
    ("10k", 20, 4, 4), ("9k", 22, 4, 4), ("8k", 20, 5, 5), ("7k", 38, 3, 3), ("6k", 33, 4, 4),
    ("5k", 20, 8, 8), ("4k", 20, 10, 10),
    ("13-20k", 20, 3, 2), ("10-20k", 20, 4, 2), ("8-20k", 20, 5, 2), ("6.7-20k", 20, 6, 2), ("5-20k", 20, 8, 2),
    ("8-16k", 25, 4, 2), ("8-13k", 20, 5, 3), ("8-12k", 33, 3, 2),
    ("9.2k", 29, 3, 3), ("6.9k", 29, 4, 4), ("5.5k", 29, 5, 5), ("4.6k", 29, 6, 6),
    ("9.2-13.8k", 29, 3, 2), ("6.9-13.8k", 29, 4, 2), ("5.5-13.8k", 29, 5, 2),
    ("4-8k", 20, 10, 5), ("13.3k", 20, 3, 3))
FPS_STOCK = {"B": (0x03, 0x02, 0x8F, 0x70, 0x14), "C": (0x02, 0x02, 0x98, 0x80, 0x14),
             "D": (0x02, 0x02, 0x98, 0x80, 0x14), "copy2": (0x03, 0x01, 0x8F, 0x70, 0x28)}
SCRIPT_TEXT = {"B": "Hyper", "C": "Hyper above 6999 DPI", "D": "CE", "copy2": "Hyper off"}


def fps_values(i):
    """{(page, reg): value} for preset index i (same rule as the firmware table)."""
    _, k, slow, fast = FPS_PRESETS[i]
    pair = (0x98, 0x80) if slow * k == 40 else (0x8F, 0x70)
    return dict(zip(FPS_FIELDS, (slow, fast, pair[0], pair[1], k)))


def fps_range(unit, slow, fast):
    """Text for a frame-time setting: 'fixed 16.0k fps' or '13.3k-20.0k fps (variable)'."""
    lo, hi = 1e3 / (slow * unit * 1.25), 1e3 / (fast * unit * 1.25)
    if slow == fast:
        return f"fixed {hi:.1f}k fps (frame {fast * unit * 1.25:g} us)"
    return f"{lo:.1f}k-{hi:.1f}k fps, variable (frames {fast * unit * 1.25:g}-{slow * unit * 1.25:g} us)"


def fps_text(i):
    _, k, slow, fast = FPS_PRESETS[i]
    return fps_range(k, slow, fast)


def fps_index(name):
    names = [p[0] for p in FPS_PRESETS]
    v = str(name).strip().lower().replace("fps", "")
    v = {"13.8k": "14k", "13.3-20k": "13-20k"}.get(v, v)   # real rates of the 14k / 13-20k presets
    if v in names:
        return names.index(v)
    raise CfgError(f"unknown frame-rate preset {name!r}: use 'stock' or one of {', '.join(names)} (fps-list)")
DB_TEXT = {"pre": "press debounce (before the click)", "post": "release debounce (after the click)",
           "plock": "lockout after a press", "relock": "lockout after a release"}


FINE_BASE, FINE_PER_MS, FINE_MS = 102, 9, 17   # mirrors out/debounce_patch (fine debounce codes)
FINE_MIN_US = 1000    # sub-ms button timers made the mouse hitch / drop its link; the firmware also floors at 1 ms


def db_code(v):
    """Setting byte for 'stock', 'default' or a time: ms ('2', '2.3', '2.3ms') or us ('2300us').
    Whole ms 0..100 are codes 1..101; 0.1 ms steps below 17 ms are codes 102..254 (fine builds only)."""
    v = str(v).strip().lower()
    if v == "stock":
        return 255
    if v in ("default", "def"):
        return 0
    try:
        if v.endswith("us") or v.endswith("µs"):
            us = float(v[:-2])
        else:
            us = float(v[:-2] if v.endswith("ms") else v) * 1000
    except ValueError:
        raise CfgError(f"debounce value {v!r}: use ms (0..100, e.g. 2 or 2.3), us (e.g. 2300us), "
                       "'stock' or 'default'") from None
    t = int(round(us / 100.0))                 # 0.1 ms steps
    if not 0 <= t <= 1000:
        raise CfgError("debounce values are 0..100 ms")
    if 0 < us and t < 10:
        t = 10                                 # the 1 ms floor
    if t % 10 == 0 or t >= FINE_MS * 10:
        return int(round(t / 10.0)) + 1
    return FINE_BASE + (t // 10) * FINE_PER_MS + (t % 10 - 1)


def code_us(b):
    """Saved byte -> us (None for default / stock)."""
    if b in (0, 255):
        return None
    if b < FINE_BASE:
        return (b - 1) * 1000
    q, r = divmod(b - FINE_BASE, FINE_PER_MS)
    return max(q * 1000 + (r + 1) * 100, FINE_MIN_US)


def db_floor_note(values):
    """A line for non-zero values below 1 ms (raised to 1 ms), else None."""
    low = []
    for v in values:
        t = str(v).strip().lower()
        try:
            us = float(t[:-2]) if t.endswith(("us", "µs")) else float(t[:-2] if t.endswith("ms") else t) * 1000
        except ValueError:
            continue
        if 0 < us < 950:
            low.append(t)
    return (f"note: {', '.join(low)} raised to 1 ms, the shortest non-zero debounce (shorter timers made the mouse "
            "hitch or drop its link); use 0 for no debounce") if low else None


def fmt_ms(us):
    """'2 ms', '2.3 ms'."""
    return f"{us / 1000:g} ms"


def db_lines(d):
    out = [f"{'':7s} {'now':>6s}  {'source':8s} {'stock':>6s}  meaning"]
    for k in DB_NAMES:
        x = d[k]
        src = "stock" if x["raw"] == 255 else "default" if x["raw"] == 0 else "set"
        out.append(f"{k:7s} {fmt_ms(x['us']):>6s}  {src:8s} {str(x['stock_ms']) + ' ms':>6s}  {DB_TEXT[k]}")
    return out
LOCK_LEAD_DEFAULT = 80               # mirrors out/stats_patch.LEAD_DEFAULT
STATS_FIELDS = ["ticks", "not_ready", "health_skip", "health_trip", "last_bad_status",
                "reads_started", "read_start_fail", "spi_ok", "spi_bad", "reinit",
                "samples", "samples_motion", "tx_queued", "tx_full",
                "script_B", "script_C", "script_D", "script_copy2",
                "slot_ends", "acked", "no_ack", "hops", "link_lost", "link_up",
                "tx_attempts", "idle_slots", "link_quality", "max_miss_run",
                "miss_run", "last_conn", "last_post", "enabled",
                # sensor-read -> radio-frame wait (report-timer phase when a frame is built), 128 us bins
                "ph_count", "ph_sum_us", "ph_max_us", "ph_period_us",
                "ph_bin0", "ph_bin1", "ph_bin2", "ph_bin3", "ph_bin4", "ph_bin5", "ph_bin6", "ph_bin7",
                # phase lock: byte 0 on/off, bytes 2-3 lead (us); then retimes done / skipped
                "lock_cfg", "lock_adj", "lock_skip",
                # byte 2: read timer found past its compare and restarted (8-bit); bytes 0-1 internal, byte 3 not ours
                "lock_rescue"]
                # mirrors out/stats_patch.FIELDS + its phase block
STATS_VALUES = {"last_bad_status", "link_quality", "max_miss_run", "miss_run", "last_conn", "last_post", "enabled",
                "ph_max_us", "ph_period_us", "lock_cfg"}
STATS_INTERNAL = {"miss_run", "last_conn", "last_post"}


def stats_delta(a, b):
    """b - a per counter (32-bit wrap); last_bad_status is a value, not a counter."""
    return {k: (b[k] if k in STATS_VALUES else (b[k] - a[k]) & (0xFF if k == "lock_rescue" else 0xFFFFFFFF))
            for k in b}


def stats_line(d, dt):
    """One line; every count is per second (the interval also contains the time the read itself takes)."""
    dt = dt or 1.0
    r = lambda k: f"{d[k] / dt:5.0f}"
    pct = lambda x, n: f"{100.0 * x / n:5.2f}%" if n else "  -  "
    sent = d["acked"] + d["no_ack"]                      # real transmissions: each ends acked or not
    return (f"[{dt:4.2f}s] ticks {r('ticks')}/s reads {r('reads_started')} | skipped {d['health_skip']} "
            f"({pct(d['health_skip'], d['ticks'])}) trips {d['health_trip']} reinit {d['reinit']} "
            f"not-ready {d['not_ready']} read-fail {d['read_start_fail']} spi-bad {d['spi_bad']} | "
            f"samples {r('samples')}/s moving {pct(d['samples_motion'], d['samples'])} | "
            f"queued {r('tx_queued')}/s full {d['tx_full']} | "
            f"scripts B{d['script_B']} C{d['script_C']} D{d['script_D']} 2:{d['script_copy2']} | "
            f"slots {r('slot_ends')}/s sent {sent / dt:5.0f}/s no-ack {d['no_ack']} ({pct(d['no_ack'], sent)}) "
            f"idle {r('idle_slots')}/s hops {r('hops')}/s worst run {d['max_miss_run']} | "
            f"link lost {d['link_lost']} up {d['link_up']} q {d['link_quality']} | "
            f"read->frame avg {(d['ph_sum_us'] / d['ph_count']) if d['ph_count'] else 0:4.0f} us "
            f"max {d['ph_max_us']} us"
            + (f" | lock on lead {(d['lock_cfg'] >> 16) or LOCK_LEAD_DEFAULT} us retimed {d['lock_adj']} skipped {d['lock_skip']}"
               + (f" RESCUED {d['lock_rescue']}" if d.get("lock_rescue") else "")
               if not d.get("lock_cfg", 0) & 0xFF else " | lock off")
            + (f" | last bad status {d['last_bad_status']:#06x}" if d["health_skip"] else ""))


def do_stats(m, seconds, interval, log=None, once=False, out=print, clock=time.monotonic, sleep=time.sleep):
    prev = m.stats(); t_prev = clock()
    if once:
        for k, v in prev.items():
            if k in STATS_INTERNAL:
                continue
            if k == "lock_cfg":
                out(f"{'lock':16s} {'off' if v & 0xFF else 'on'}, lead {(v >> 16) or LOCK_LEAD_DEFAULT} us")
                continue
            out(f"{k:16s} {v:#x}" if k == "last_bad_status" else
                f"{k:16s} {'on' if v else 'off'}" if k == "enabled" else f"{k:16s} {v}")
        return prev
    if not prev.get("enabled", 1):
        out("note: counting is OFF on the mouse (the default after power-up). Run `stats-on` first.")
    f = None
    if log:
        import csv
        f = open(log, "w", newline="")
        w = csv.writer(f)
        w.writerow(["time", "dt"] + STATS_FIELDS)
    first = dict(prev); t0 = t_prev
    out("live counters (Ctrl+C stops); deltas per interval:")
    try:
        end = t0 + seconds if seconds else None
        while end is None or clock() < end:
            sleep(interval)
            cur = m.stats(); t = clock()
            d = stats_delta(prev, cur)
            out("  " + stats_line(d, t - t_prev))
            if f:
                w.writerow([time.strftime("%H:%M:%S"), f"{t - t_prev:.3f}"] + [d[k] for k in STATS_FIELDS]); f.flush()
            prev, t_prev = cur, t
    except KeyboardInterrupt:
        pass
    finally:
        if f:
            f.close()
    tot = stats_delta(first, prev)
    out("total: " + stats_line(tot, max(t_prev - t0, 1e-9)))
    return tot


def lod_code_to_mm(code):
    """Estimated mm for a saved LOD code (assumes the stock 1/2 mm presets)."""
    if code == 1:
        return 1.0
    if code == 2:
        return 2.0
    if code == 0x87 or not code & 0x80:
        return 0.7
    return round(0.5 + 0.1 * (code & 0x7F), 1)


def lod_mm_to_code(mm):
    """Raw LOD code for a target mm (estimate). 0.7 -> the 0.7 mm preset (sensor default)."""
    if abs(mm - 0.7) < 1e-9:
        return 0x87
    if not LOD_MM_MIN - 1e-9 <= mm <= LOD_MM_MAX + 1e-9:
        raise CfgError(f"lod-mm must be 0.5 .. {LOD_MM_MAX:.1f} (estimate range of the LOD register)")
    t = int(round((mm - 0.5) * 10))
    code = 0x80 | t
    if code == 0x87:
        raise CfgError("1.2 mm maps to 0x87, which is the panel's 0.7 mm preset code and can't be saved as a raw "
                       "value. Use 1.1 or 1.3, or `lod-poke 0x87` (not saved).")
    return code


def fmt_lod(v):
    if v in (1, 2):
        return f"{v} mm preset"
    if v == 0x87:
        return "0.7 mm preset"
    est = "sensor default, fine layer off" if not v & 0x80 else "estimate"
    return (f"raw {v:#04x} (~{lod_code_to_mm(v):.1f} mm, {est}; LOD research build only, stock firmware "
            "treats it as 1 mm or ignores it)")


def show(m):
    # The first query is allowed to raise: if it gets no reply at all the link is down
    # (mouse asleep / out of range) and there is no point retrying every row.
    print(f"profile {m.profile} of {m.profile_count()}")
    row("current dpi", lambda: fmt_dpi_now(m))
    row("polling", lambda: f"{m.polling()} Hz")
    row("dpi stages", lambda: fmt_stages(m) + "   ([ ] = active)")
    row("lod", lambda: fmt_lod(m.lod_raw()))
    for name in BOOLS:
        row(name, lambda name=name: "on" if m.flag(name) else "off")
    row("angle-tune", m.angle_tune)
    row("sleep", lambda: fmt_sleep(m))
    row("speed click", lambda: (lambda t: ("on" if t[0] else "off") if t[0] == t[1] else
                                f"slot 1 {'on' if t[0] else 'off'}, slot 2 {'on' if t[1] else 'off'}")(m.speed_click()))
    row("debounce", lambda: f"{m.debounce()} ms (panel setting)")
    show_hyperdrako(m)


def show_hyperdrako(m):
    """The hyperdrako rows, only for the features the flashed build has (one quick query each)."""
    try:
        d = m.click_debounce(tries=1)
    except CfgError:
        d = None
    try:
        lock = m.lock_status()
    except CfgError:
        lock = None
    if d is None and lock is None:
        return
    print("hyperdrako")
    if d is not None:
        tag = lambda k: {255: " (stock)", 0: " (default)"}.get(d[k]["raw"], "")
        print(f"  {'click timing':<13s} : " + ", ".join(f"{k} {fmt_ms(d[k]['us'])}{tag(k)}" for k in DB_NAMES))
        if d.get("fps") is not None:
            f = d["fps"]
            print(f"  {'frame rate':<13s} : " + ("stock (each mode's own)" if f == "stock"
                                               else f"{FPS_PRESETS[f][0]}: {fps_text(f)}"))
        elif d.get("hyperfps") is not None:
            print(f"  {'hyper-fps':<13s} : {'on' if d['hyperfps'] else 'off'}")
    if lock is not None:
        print(f"  {'phase lock':<13s} : {'on' if lock[0] else 'off'}, lead {lock[1]} us")


HD_SET = ("fps", "lock", "lock-lead", "debounce", "debounce-pre", "debounce-post", "debounce-plock",
          "debounce-relock", "stats")


def fps_short(d):
    f = d["fps"]
    if f is None:                                      # on/off-only build
        return "20k" if d["hyperfps"] else "stock"
    return "stock" if f == "stock" else FPS_PRESETS[f][0]


def do_set_hd(m, name, values, apply=True):
    """The hyperdrako settings, inline with the panel ones: set fps|lock|lock-lead|debounce...|stats."""
    one = lambda: values[0] if len(values) == 1 else (_ for _ in ()).throw(
        CfgError(f"set {name} takes one value"))
    if name == "fps":
        want = one().strip().lower()
        idx = None if want == "stock" else fps_index(want)
        old = fps_short(m.click_debounce())
        d = m.fps_set(idx)
        new = fps_short(d)
        print(f"fps: {old} -> {new}  OK  ({'stock: each mode its own' if new == 'stock' else fps_text(fps_index(new))}; "
              "saved on the mouse)")
        if apply:
            print(m.hyperfps_apply(d["hyperfps"]) if d["fps"] is None else
                  m.fps_apply(None if d["fps"] == "stock" else d["fps"]))
    elif name == "lock":
        on = parse_bool(one())
        old = m.lock_status()[0]
        new = m.lock_switch(on)
        print(f"lock: {'on' if old else 'off'} -> {'on' if new else 'off'}  "
              f"{'OK' if new == on else 'MISMATCH'}  ({m.lock_persistence()})")
    elif name == "lock-lead":
        try:
            us = int(one())
        except ValueError:
            raise CfgError("lock-lead is a number of microseconds, 0..252 in steps of 4") from None
        old = m.lock_status()[1]
        new = m.lock_lead(us)
        print(f"lock-lead: {old} us -> {new} us  {'OK' if new == us - us % 4 else 'MISMATCH'}  "
              f"({m.lock_persistence()})")
    elif name == "debounce" or name.startswith("debounce-"):
        note = db_floor_note(values)
        if note:
            print(note)
    if name == "debounce":
        if len(values) == 1 and values[0].lower() in ("stock", "default"):
            todo = [(k, db_code(values[0])) for k in DB_NAMES]
        elif len(values) == 4:
            todo = [(k, db_code(v)) for k, v in zip(DB_NAMES, values)]
        else:
            raise CfgError("set debounce PRE POST PLOCK RELOCK (ms 0..100, 'stock' or 'default' each), "
                           "or set debounce stock|default")
        d = None
        for k, c in todo:
            d = m.debounce_set(k, c)
        for line in db_lines(d):
            print(line)
        print("(saved on the mouse: kept after power-off; factory reset in the panel clears it)")
    elif name.startswith("debounce-"):
        k = name[len("debounce-"):]
        d = m.debounce_set(k, db_code(one()))
        for line in db_lines(d):
            print(line)
    elif name == "stats":
        on = parse_bool(one())
        print(f"stats: counting {'on' if m.stats_switch(on) else 'off'} (resets to off at power-up)")


def hd_get(m, name):
    """Values for `get` of the hyperdrako settings (None if the name is not one)."""
    if name == "fps":
        d = m.click_debounce()
        f = fps_short(d)
        return f if f == "stock" else f"{f}: {fps_text(fps_index(f))}"
    if name == "lock":
        on, lead = m.lock_status()
        return f"{'on' if on else 'off'}, lead {lead} us"
    if name == "lock-lead":
        return f"{m.lock_status()[1]} us"
    if name == "debounce":
        return "\n".join(db_lines(m.click_debounce()))
    if name.startswith("debounce-") and name[len("debounce-"):] in DB_NAMES:
        x = m.click_debounce()[name[len("debounce-"):]]
        src = "stock" if x["raw"] == 255 else "default" if x["raw"] == 0 else "set"
        return f"{fmt_ms(x['us'])} ({src}; stock {x['stock_ms']} ms)"
    return None


SET_ALIASES = {"ce": "competition"}       # short names accepted by set/get


def do_set(m, name, value):
    name = SET_ALIASES.get(name, name)
    if isinstance(value, (list, tuple)):
        if name in HD_SET:
            return do_set_hd(m, name, list(value))
        if name == "speed-click":
            value = [" ".join(value)]
        if len(value) != 1:
            raise CfgError(f"set {name} takes one value")
        value = value[0]
    if name == "polling":
        hz = int(value)
        if hz not in POLL_CODE:
            raise CfgError(f"polling must be one of {sorted(POLL_CODE)}")
        want = hz; old = m.polling(); m.set_polling(hz); new = settle(m.polling, want)
    elif name == "lod":
        v = float(value.lower().replace("mm", "").strip())
        if v not in (0.7, 1.0, 2.0):
            raise CfgError("lod must be 0.7, 1 or 2 (mm). These are the only three values the "
                           "v1.9 firmware implements; any other code is treated as 1 mm or ignored.")
        want = v if v < 1 else int(v); old = m.lod(); m.set_lod(v); new = settle(m.lod, want)
    elif name == "lod-raw":
        v = parse_lod_raw(value)
        want = v; old = m.lod_raw(); m.set_lod_raw(v); new = settle(m.lod_raw, want)
        print(f"lod-raw: saved; sensor 0x18:0x7A <- {lod_raw_effect(v)}  (values below 0x80 need the "
              "v3 LOD research build)")
        want, old, new = f"{want:#04x}", f"{old:#04x}", f"{new:#04x}"
    elif name == "lod-mm":
        try:
            mm = float(value.lower().replace("mm", "").strip())
        except ValueError:
            raise CfgError(f"lod-mm expects a number of millimetres such as 1.5, got {value!r}") from None
        v = lod_mm_to_code(mm)
        want = v; old = m.lod_raw(); m.set_lod_raw(v); new = settle(m.lod_raw, want)
        print(f"lod-mm {mm:g}: saved raw {v:#04x} (estimate ~{lod_code_to_mm(v):.1f} mm from the two-point fit "
              "mm = 0.5 + 0.1*t; not measured)")
        if mm > 3.0:
            print("note: above ~3 mm the estimate is meaningless; the sensor's optics cut off first.")
        want, old, new = f"{want:#04x}", f"{old:#04x}", f"{new:#04x}"
    elif name in BOOLS:
        on = parse_bool(value)
        want = on; old = m.flag(name); m.set_flag(name, on); new = settle(lambda: m.flag(name), want)
    elif name == "speed-click":
        parts = str(value).replace(",", " ").split()
        if len(parts) == 1:
            want = (parse_bool(parts[0]),) * 2
        elif len(parts) == 2:
            want = (parse_bool(parts[0]), parse_bool(parts[1]))
        else:
            raise CfgError("speed-click takes on|off (both buttons) or two values, e.g. 'on off'")
        old = m.speed_click(); m.set_speed_click(*want); new = settle(m.speed_click, want)
        f2 = lambda t: " ".join("on" if x else "off" for x in t) if t[0] != t[1] else ("on" if t[0] else "off")
        status = "OK" if new == want else f"MISMATCH (asked {f2(want)})"
        print(f"speed-click: {f2(old)} -> {f2(new)}  {status}")
        if new != want:
            sys.exit(2)
        return
    elif name == "angle-tune":
        v = int(value)
        if not -30 <= v <= 30:
            raise CfgError("angle-tune must be -30..30")
        want = v; old = m.angle_tune(); m.set_angle_tune(v); new = settle(m.angle_tune, want)
    elif name == "sleep":
        minutes = int(value)
        if not 1 <= minutes <= 30:
            raise CfgError("sleep is 1..30 minutes (the panel's range)")
        want = minutes * 60; old = m.sleep_seconds(); m.set_sleep(want); new = settle(m.sleep_seconds, want)
    else:
        raise CfgError(f"unknown setting {name!r}; choose from polling lod lod-raw lod-mm angle-tune sleep "
                       + " ".join(BOOLS) + " | hyperdrako: " + " ".join(HD_SET))
    fmt = lambda v: ("on" if v else "off") if isinstance(v, bool) else v
    status = "OK" if new == want else f"MISMATCH (asked {fmt(want)})"
    print(f"{name}: {fmt(old)} -> {fmt(new)}  {status}")
    if new != want:
        sys.exit(2)


def parse_lod_raw(value):
    """Raw LOD code saved in the profile. With the LOD research build (v3) every value 0..255 is
    written to sensor reg 0x18:0x7A as-is, except the panel presets 1 (1 mm), 2 (2 mm) and
    0x87 (0.7 mm). Older builds only honour 0x80..0xFF."""
    try:
        v = int(value, 0)
    except ValueError:
        raise CfgError(f"lod-raw expects a byte such as 0x9F, got {value!r}") from None
    if not 0 <= v <= 0xFF:
        raise CfgError("lod-raw must be 0..255 (0x00..0xFF)")
    return v


def lod_raw_effect(v):
    return {1: "1 mm preset (0x85 unless rebuilt with --lod1)",
            2: "2 mm preset (0x8F unless rebuilt with --lod2)",
            0x87: "0x00 (0.7 mm preset)"}.get(v, f"{v:#04x}")


def do_lod_sweep(m, start, stop, step, ask=input):
    """Walk raw LOD values so the user can find the lift-off height they want.
    Restores the original setting unless the user keeps one."""
    orig = m.lod_raw()
    vals = [v for v in range(start, stop + (1 if step > 0 else -1), step) if v != 0x87]
    print(f"current LOD code {orig:#04x}. For each value: lift the mouse slowly with a shim stack / "
          "card under the front and rear feet while moving it, and note where tracking stops.")
    print("keys: Enter = next value, k = keep this value, b = back, q = quit and restore")
    i = 0
    while 0 <= i < len(vals):
        v = vals[i]
        m.set_lod_raw(v)
        got = settle(m.lod_raw, v)
        if got != v:
            raise CfgError(f"mouse reports {got:#04x} after writing {v:#04x}")
        ans = ask(f"  [{i + 1}/{len(vals)}] LOD code {v:#04x} (threshold {v & 0x7F:3d}) > ").strip().lower()
        if ans == "k":
            print(f"kept {v:#04x} on profile {m.profile}. Bake it into the panel's 2 mm button with: "
                  f"ko1 lod spec --base AB --lod2 {v:#04x}")
            return v
        if ans == "q":
            break
        i = i - 1 if ans == "b" and i > 0 else i + 1
    m.set_lod_raw(orig)
    print(f"restored {orig:#04x}")
    return orig


def parse_byte(s, what):
    try:
        v = int(s, 0)
    except ValueError:
        raise CfgError(f"{what} must be a number like 0x4E, got {s!r}") from None
    if not 0 <= v <= 0xFF:
        raise CfgError(f"{what} must be 0..0xFF")
    return v


class _Keys:
    """Non-blocking single-key reader (Windows console or POSIX tty); silently off otherwise."""

    def __init__(self):
        self.mode, self.old = None, None
        try:
            import msvcrt                     # noqa: F401
            self.mode = "win"
        except ImportError:
            try:
                import termios, tty           # noqa: E401
                if sys.stdin.isatty():
                    self.old = termios.tcgetattr(sys.stdin)
                    tty.setcbreak(sys.stdin.fileno())
                    self.mode = "posix"
            except Exception:                 # noqa: BLE001
                self.mode = None

    def get(self):
        if self.mode == "win":
            import msvcrt
            if msvcrt.kbhit():
                return msvcrt.getwch()
        elif self.mode == "posix":
            import select
            if select.select([sys.stdin], [], [], 0)[0]:
                return sys.stdin.read(1)
        return None

    def close(self):
        if self.mode == "posix" and self.old is not None:
            import termios
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, self.old)


def do_watch(m, regs, interval, count=None, out=print, keys=None):
    """Live view of page-0 sensor registers (default SQUAL). Lift the mouse slowly and watch
    where the value collapses versus where the cursor stops.  Press a key (e.g. 1..9) to tag
    the following lines with the step you are doing."""
    names = {0x02: "Motion", 0x15: "Observ", 0x07: "SQUAL", 0x08: "RawSum", 0x09: "RawMax", 0x0A: "RawMin", 0x0B: "ShutLo", 0x0C: "ShutHi"}
    single = regs == [0x07]
    keys = keys if keys is not None else _Keys()
    tag = "-"
    if not single:
        m.select_peek(regs[0])
    out("watching " + ", ".join(f"{names.get(r, 'reg')} 0x{r:02X}" for r in regs)
        + "  (press 1-9 to tag the step you are doing, Ctrl-C to stop)")
    n = 0
    t0 = time.time()
    try:
        while count is None or n < count:
            k = keys.get()
            if k and k.strip():
                tag = k.strip()
                out(f"---- step {tag} ----")
            vals = []
            for r in regs:
                if not single:
                    m.select_peek(r)
                    m.sensor_value(); time.sleep(interval / 2)
                m.sensor_value(); time.sleep(interval / 2)
                vals.append(m.sensor_value())
            d = dict(zip(regs, vals))
            line = f"{time.time() - t0:6.1f}s [{tag}] " + "  ".join(
                f"{names.get(r, hex(r))}={v:3d}" for r, v in zip(regs, vals))
            if 0x02 in d:     # PixArt Motion reg: bit7 = motion seen, bit3 = lift flag (firmware decodes it)
                line += "  " + ("MOT " if d[0x02] & 0x80 else "--- ") + ("LIFT" if d[0x02] & 0x08 else "----")
            if 0x02 in d and not d[0x02] & 0x20:
                line += "  MOTION-BIT5-CLEAR(reinit trigger)"
            if 0x15 in d:     # firmware health check wants (obs & 0xF7) == 0xB7, else it re-inits the sensor
                line += "  obs-OK" if (d[0x15] & 0xF7) == 0xB7 else f"  OBS-BAD 0x{d[0x15]:02X} (reinit trigger)"
            if 0x0B in d and 0x0C in d:
                line += f"  Shutter={(d[0x0C] << 8) | d[0x0B]:5d}"
            out(line + "  |" + "#" * (vals[0] * 40 // 255))
            n += 1
    except KeyboardInterrupt:
        pass
    finally:
        keys.close()
        if not single:
            try:
                m.select_peek(0x07)
            except CfgError:
                pass


def _cursor_source():
    """Return a function giving the OS cursor position, or None if unsupported (Windows only)."""
    try:
        import ctypes
        from ctypes import wintypes
        user32 = ctypes.windll.user32
    except (ImportError, AttributeError):
        return None
    pt = wintypes.POINT()

    def pos():
        user32.GetCursorPos(ctypes.byref(pt))
        return pt.x, pt.y
    return pos


def setdown_events(samples, moves):
    """samples: [(t, lift_bool)] sensor polls; moves: sorted [t] cursor-change times.
    Returns [(t_land, delay_s or None, landed_for_s)] for every lifted->landed transition."""
    import bisect
    out = []
    prev = None
    for k, (t, lift) in enumerate(samples):
        if prev is True and lift is False:
            # next lift after this landing bounds the search window
            nxt = next((tt for tt, l in samples[k + 1:] if l), float("inf"))
            j = bisect.bisect_right(moves, t)
            end = nxt if nxt != float("inf") else samples[-1][0]
            out.append((t, moves[j] - t if j < len(moves) and moves[j] < nxt else None, end - t))
        prev = lift
    return out


def do_setdown(m, seconds, out=print, cursor=None, clock=time.perf_counter):
    """Measure 'set-down delay': time from the sensor clearing its LIFT flag to the first
    cursor movement.  Keep sliding the mouse sideways while you lift and land it."""
    import threading
    cursor = cursor or _cursor_source()
    if cursor is None:
        raise CfgError("setdown needs Windows (it watches the cursor with GetCursorPos)")
    m.select_peek(0x02)
    m.sensor_value(); m.sensor_value()
    moves, stop = [], threading.Event()

    def watch_cursor():
        last = cursor()
        while not stop.is_set():
            p = cursor()
            if p != last:
                moves.append(clock()); last = p
            time.sleep(0.0005)
    th = threading.Thread(target=watch_cursor, daemon=True)
    th.start()
    samples = []
    t_end = clock() + seconds
    out(f"recording {seconds:.0f} s: keep sliding the mouse sideways while you lift and land it")
    try:
        while clock() < t_end:
            v = m.sensor_value()
            samples.append((clock(), bool(v & 0x08)))
    except KeyboardInterrupt:
        pass
    finally:
        stop.set(); th.join(1)
        try:
            m.select_peek(0x07)
        except CfgError:
            pass
    if len(samples) > 1:
        rate = (len(samples) - 1) / (samples[-1][0] - samples[0][0])
        out(f"sensor polled at {rate:.0f} Hz (timing resolution ~{1000 / rate:.1f} ms)")
    ev = setdown_events(samples, sorted(moves))
    delays = sorted(d for _, d, _ in ev if d is not None)
    res = 1.0 / rate if len(samples) > 1 else 0
    missed = [(i, on) for i, (_, d, on) in enumerate(ev, 1) if d is None and on >= 0.1]
    for i, (t, d, on) in enumerate(ev, 1):
        what = (f"first movement after {d * 1000:6.1f} ms" if d is not None
                else ("NO MOVEMENT while landed" if on >= 0.1 else "no movement (very short touch)"))
        out(f"  landing {i:2d}: on pad {on * 1000:6.0f} ms, {what}")
    if delays:
        slow = [d for d in delays if d > 2 * res]
        out(f"landings {len(ev)}, with movement {len(delays)}: median {delays[len(delays) // 2] * 1000:.1f} ms,"
            f" max {delays[-1] * 1000:.1f} ms; slower than 2x resolution: {len(slow)}")
    out(f"landed >= 100 ms with NO movement at all: {len(missed)}"
        + (" (landings " + ", ".join(str(i) for i, _ in missed) + ")" if missed else ""))
    out(f"note: 'landed' is seen up to {res * 1000:.0f} ms late (sensor poll rate), so delays under that "
        "are within measurement error")
    return delays


def gap_stats(times, t0, t1, min_gap=0.03):
    """times: sorted cursor-change timestamps within [t0, t1]. Returns dict of gap statistics:
    every pause in cursor movement of at least min_gap seconds."""
    pts = [t0] + [t for t in times if t0 <= t <= t1] + [t1]
    gaps = sorted(b - a for a, b in zip(pts, pts[1:]) if b - a >= min_gap)
    total = t1 - t0
    return {"gaps": gaps, "count": len(gaps), "lost": sum(gaps), "total": total,
            "median": gaps[len(gaps) // 2] if gaps else 0.0}


def do_gaps(seconds, out=print, cursor=None, clock=time.perf_counter):
    """Mouse-independent test (works for ANY mouse): watch the cursor while you keep sliding and
    rapidly lifting/landing, and report how often and how long the cursor stalls."""
    cursor = cursor or _cursor_source()
    if cursor is None:
        raise CfgError("gaps needs Windows (it watches the cursor with GetCursorPos)")
    out(f"recording {seconds:.0f} s: slide left-right in the middle of the screen and keep doing quick "
        "lift-and-lands (stay away from the screen edges)")
    times, last = [], cursor()
    t0 = clock()
    t1 = t0 + seconds
    try:
        while True:
            t = clock()
            if t >= t1:
                break
            p = cursor()
            if p != last:
                times.append(t); last = p
            time.sleep(0.0005)
    except KeyboardInterrupt:
        t1 = clock()
    st = gap_stats(times, t0, t1)
    g = st["gaps"]
    out(f"cursor stalls >= 30 ms: {st['count']}, median {st['median'] * 1000:.0f} ms, "
        f"longest {g[-1] * 1000 if g else 0:.0f} ms")
    out(f"time with the cursor stalled: {st['lost'] * 1000:.0f} ms of {st['total'] * 1000:.0f} ms "
        f"({100 * st['lost'] / st['total']:.1f}%)")
    return st


def check_dpi(stages, mx):
    for x, y in stages:
        for v in (x, y):
            if v % 50 or not 50 <= v <= mx:
                raise CfgError(f"{v}: DPI must be a multiple of 50 between 50 and {mx}")


def do_dpi_set(m, value, stage, activate):
    """Change ONE stage (default: the active one) and leave the others untouched."""
    new_stage = parse_stage(value)
    check_dpi([new_stage], m.dpi_max())
    st, act = m.stages(), m.active_stage()
    idx = stage or act
    if not 1 <= idx <= len(st):
        raise CfgError(f"stage must be 1..{len(st)} (this profile has {len(st)} stage(s))")
    want = list(st)
    want[idx - 1] = new_stage
    m.set_stages(want)
    got = settle(m.stages, want)
    print(f"stage {idx}: {fmt_stage(st[idx - 1])} -> {fmt_stage(got[idx - 1])}  "
          + ("OK" if got == want else "MISMATCH"))
    if got != want:
        sys.exit(2)
    if activate and idx != act:
        m.set_active_stage(idx)
        a = settle(m.active_stage, idx)
        print(f"active stage -> {a}", "OK" if a == idx else "MISMATCH")
        if a != idx:
            sys.exit(2)
    elif idx != act:
        print(f"note: stage {idx} is not the active stage ({act}); add --activate or use the DPI button")


def do_dpi(m, tokens):
    stages = [parse_stage(t) for t in tokens]
    mx = m.dpi_max()
    if not 1 <= len(stages) <= MAX_STAGES:
        raise CfgError(f"give 1..{MAX_STAGES} stages")
    check_dpi(stages, mx)
    old, act = m.stages(), m.active_stage()
    m.set_stages(stages)
    new = settle(m.stages, stages)
    print("dpi stages:", " ".join(fmt_stage(s) for s in old), "->", " ".join(fmt_stage(s) for s in new))
    if new != stages:
        print("MISMATCH, asked:", " ".join(fmt_stage(s) for s in stages))
        sys.exit(2)
    if act > len(stages):
        m.set_active_stage(1)
        print("active stage was beyond the new list; set to 1")


def build_parser():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--via", choices=["auto", "receiver", "wired"], default="auto")
    ap.add_argument("--node", help="force a device path (/dev/hidrawN on Linux; see `list`)")
    ap.add_argument("--backend", choices=["auto", "hidraw", "hidapi"], default=None,
                    help="HID backend (default: hidraw on Linux, hidapi elsewhere)")
    ap.add_argument("--target", type=int, help="override the target byte (mouse: receiver 2, wired 0)")
    ap.add_argument("--profile", type=int, help="profile number (default: the active profile)")
    ap.add_argument("--delay", type=float, default=0.02, help="seconds between send and read")
    ap.add_argument("-v", "--verbose", action="store_true", help="print raw packets")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    sub.add_parser("info")
    sub.add_parser("show")
    g = sub.add_parser("get", help="read one setting (panel ones, plus fps, lock, lock-lead, debounce, "
                                   "debounce-pre/-post/-plock/-relock, panel-debounce)")
    g.add_argument("name")
    s = sub.add_parser("set", help="change one setting: panel ones (polling, lod-mm, competition, ...) and "
                                   "hyperdrako ones: (ce = competition) fps PRESET|stock, lock on|off, lock-lead US, "
                                   "debounce PRE POST PLOCK RELOCK | stock | default, debounce-post MS, stats on|off")
    s.add_argument("name"); s.add_argument("value", nargs="+")
    d = sub.add_parser("dpi", help="set the DPI stage list, e.g. dpi 800 1600 3200 6400x3200")
    d.add_argument("stages", nargs="+")
    ds = sub.add_parser("dpi-set", help="change ONE stage, e.g. dpi-set 30000 [--stage N] [--activate]")
    ds.add_argument("value"); ds.add_argument("--stage", type=int); ds.add_argument("--activate", action="store_true")
    a = sub.add_parser("dpi-active"); a.add_argument("stage", type=int)
    p = sub.add_parser("profile"); p.add_argument("number", type=int, nargs="?")
    rs = sub.add_parser("reset-settings", help="factory reset, like the web panel: every profile and setting, "
                                               "including hyperdrako's (back to build defaults); the mouse restarts")
    rs.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    rp = sub.add_parser("reset-profile", help="one profile back to factory (DPI, polling, LOD, buttons, ...)")
    rp.add_argument("number", type=int); rp.add_argument("--yes", action="store_true", help="do not ask")
    pk = sub.add_parser("poke", help="write one sensor register: poke PAGE REG VALUE (research build; "
                                      "not saved, unplug/replug to undo)")
    pk.add_argument("page"); pk.add_argument("reg"); pk.add_argument("value")
    ps = sub.add_parser("poke-script", help="poke the mode-dependent registers of one perf script "
                                             "(copy2, B, C, D) into the running sensor; not saved")
    ps.add_argument("script"); ps.add_argument("--pages", help="comma list of pages, e.g. 0C,18")
    ps.add_argument("--dry-run", action="store_true")
    st = sub.add_parser("stats", help="live firmware telemetry: sensor reads, health-check skips, re-inits, "
                                      "radio queue, sensor scripts (ABLODSTATS build)")
    st.add_argument("--interval", type=float, default=1.0)
    st.add_argument("--seconds", type=float, default=0, help="0 = until Ctrl+C")
    st.add_argument("--log", help="write one CSV row of deltas per interval")
    st.add_argument("--once", action="store_true", help="print the raw counters once and exit")
    sub.add_parser("stats-reset", help="zero all telemetry counters (ABLODSTATS build; keeps on/off)")
    lk2 = sub.add_parser("lock-on", help="time sensor reads just before each radio frame (ABLODLOCK/ABLODSTATS; "
                                          "on after power-up)")
    lk2.add_argument("--lead", type=int, help="microseconds between read and frame build (default 80)")
    sub.add_parser("lock-status", help="show phase lock on/off and lead (ABLODLOCK/ABLODSTATS)")
    sub.add_parser("lock-off", help="sensor reads back on their own timer (stock timing)")
    ll = sub.add_parser("lock-lead", help="set the lock lead in microseconds (0..252, step 4)")
    ll.add_argument("us", type=int)
    sub.add_parser("debounce-status", help="click debounce values in effect (debounce builds: ABLODDB, "
                                           "ABLODLOCKDB, ABLODSTATSDB)")
    dbs = sub.add_parser("debounce-set", help="set click debounce (saved on the mouse): --pre/--post/--plock/--relock "
                                              "MS (0..100) | stock | default")
    for k in DB_NAMES:
        dbs.add_argument("--" + k, help=DB_TEXT[k] + ": ms (0..100), 'stock' or 'default'")
    sub.add_parser("debounce-stock", help="all four debounce values back to the firmware's own (stock behaviour)")
    sub.add_parser("debounce-default", help="all four debounce values back to the build defaults "
                                            "(eager press, post = the panel's debounce)")
    sub.add_parser("fps-list", help="the sensor frame-rate presets (ABLODDB / ABLODLOCKDB)")
    sub.add_parser("fps-status", help="the frame-rate setting saved on the mouse")
    fs = sub.add_parser("fps-set", help="sensor frame rate, saved on the mouse: 'stock' or a preset from fps-list "
                                        "(e.g. 16k, 10k, 10-20k); also writes the registers now")
    fs.add_argument("preset")
    fs.add_argument("--no-apply", action="store_true", help="only save; takes effect at the next mode, DPI or "
                                                            "polling change, or power-up")
    sub.add_parser("hyperfps-status", help="same as fps-status (hyper-fps on = the 20k preset)")
    for x in ("on", "off"):
        hp = sub.add_parser("hyperfps-" + x, help=f"hyper-fps {x}: fps-set {'20k' if x == 'on' else 'stock'} "
                                                    "(saved on the mouse; also writes the registers now)")
        hp.add_argument("--no-apply", action="store_true", help="only set the switch; takes effect at the next "
                                                                "mode change, sensor re-init or replug")
    sub.add_parser("stats-on", help="start counting (ABLODSTATS build; counting is off after power-up)")
    sub.add_parser("stats-off", help="stop counting; hooks then only pass through (ABLODSTATS build)")
    lp = sub.add_parser("lod-poke", help="write ANY value 0..255 straight to the LOD register 0x18:0x7A "
                                         "(research build; not saved)")
    lp.add_argument("value")
    pe = sub.add_parser("peek", help="read one page-0 sensor register: peek REG (research build)")
    pe.add_argument("reg")
    wa = sub.add_parser("watch", help="live view of SQUAL (works on stock) or other page-0 registers")
    wa.add_argument("regs", nargs="*", default=["0x07"])
    wa.add_argument("--interval", type=float, default=0.1)
    wa.add_argument("--count", type=int)
    sd = sub.add_parser("setdown", help="measure the delay between landing and first cursor movement "
                                         "(Windows; research build)")
    sd.add_argument("--seconds", type=float, default=20)
    lk = sub.add_parser("link", help="live report-timing monitor: missed / late / bunched reports while "
                                      "moving (Windows; reads the polling rate unless --rate is given)")
    lk.add_argument("--seconds", type=float, default=30)
    lk.add_argument("--rate", type=int, help="expected report rate in Hz (skips reading it from the mouse)")
    lk.add_argument("--all", action="store_true", help="count every mouse, not only VID 373E")
    gp = sub.add_parser("gaps", help="cursor stall statistics for ANY mouse during lift-and-land "
                                      "(Windows; compare mice with the same gesture)")
    gp.add_argument("--seconds", type=float, default=10)
    sw = sub.add_parser("lod-sweep", help="step through raw LOD codes (LOD-patched firmware), "
                                          "e.g. lod-sweep 0x8F 0xBF --step 4")
    sw.add_argument("start", nargs="?", default="0x85"); sw.add_argument("stop", nargs="?", default="0xBF")
    sw.add_argument("--step", default="2")
    return ap


def main(argv=None):
    a = build_parser().parse_args(argv)
    try:
        if a.backend:
            ko1_hid.set_backend(a.backend)
        if a.cmd == "list":
            print(f"backend: {ko1_hid.backend().name}")
            for pid in (PID_RECEIVER, PID_WIRED):
                for n in find_nodes(pid):
                    print(n.describe())
            return
        if a.cmd == "gaps":
            do_gaps(a.seconds)
            return
        if a.cmd == "link" and a.rate:
            import ko1_link
            try:
                ko1_link.do_link(a.seconds, a.rate, all_mice=a.all)
            except RuntimeError as e:
                raise CfgError(str(e))
            return
        dev, pid = open_device(a.via, a.node)
        wired = pid == PID_WIRED
        target = a.target if a.target is not None else (0 if wired else 2)
        m = Mouse(Link(dev, a.delay, a.verbose), target, a.profile)
        if a.cmd == "link":
            import ko1_link
            rate = m.polling()
            dev.close() if hasattr(dev, "close") else None
            try:
                ko1_link.do_link(a.seconds, rate, all_mice=a.all)
            except RuntimeError as e:
                raise CfgError(str(e))
            return
        if a.cmd == "info":
            print(f"connection : {'wired' if wired else '8K receiver'} ({VID:04X}:{pid:04X}), target {target}")
            if not wired:
                row("receiver fw", lambda: m.fw(0))
            row("mouse fw", m.fw)
            row("battery", lambda: "%d%%%s" % (m.battery()[1], " (charging)" if m.battery()[0] else ""))
            row("profile", lambda: f"{m.active_profile()} of {m.profile_count()}")
            row("sensor model", m.sensor_model)
            row("dpi max", m.dpi_max)
            row("eid", m.eid)
        elif a.cmd == "show":
            show(m)
        elif a.cmd == "get":
            n = SET_ALIASES.get(a.name, a.name)
            hv = hd_get(m, n) if n == "fps" or n.startswith(("lock", "debounce")) else None
            if hv is not None:
                print(hv)
                return 0
            vals = {"polling": m.polling, "lod": m.lod, "angle-tune": m.angle_tune,
                    "sleep": m.sleep_seconds, "panel-debounce": m.debounce, "dpi-active": m.active_stage,
                    "dpi": lambda: " ".join(fmt_stage(s) for s in m.stages()),
                    "dpi-now": lambda: fmt_dpi_now(m),
                    "lod-raw": lambda: f"{m.lod_raw():#04x}",
                    "lod-mm": lambda: (lambda v: f"~{lod_code_to_mm(v):.1f} mm (raw {v:#04x}; estimate)")(m.lod_raw()),
                    "profile": m.active_profile, "battery": lambda: m.battery()[1],
                    "speed-click": lambda: " ".join("on" if x else "off" for x in m.speed_click())}
            vals.update({k: (lambda k=k: "on" if m.flag(k) else "off") for k in BOOLS})
            if n not in vals:
                raise CfgError("unknown name; choose from " + " ".join(sorted(vals)))
            print(vals[n]())
        elif a.cmd == "set":
            do_set(m, a.name, a.value)
        elif a.cmd == "dpi":
            do_dpi(m, a.stages)
        elif a.cmd == "dpi-set":
            do_dpi_set(m, a.value, a.stage, a.activate)
        elif a.cmd == "dpi-active":
            n = len(m.stages())
            if not 1 <= a.stage <= n:
                raise CfgError(f"stage must be 1..{n}")
            m.set_active_stage(a.stage)
            got = settle(m.active_stage, a.stage)
            print(f"active dpi stage -> {got}", "OK" if got == a.stage else "MISMATCH")
        elif a.cmd == "poke":
            pg, rg, v = parse_byte(a.page, "page"), parse_byte(a.reg, "reg"), parse_byte(a.value, "value")
            if (pg, rg) == (0, 0):
                raise CfgError("page 0 reg 0 cannot be poked (it is the read-only product ID)")
            m.poke(pg, rg, v)
            print(f"poked 0x{pg:02X}:0x{rg:02X} <- 0x{v:02X}  (not saved; unplug/replug or a sensor "
                  "re-init restores the firmware's value)")
        elif a.cmd == "poke-script":
            pages = None if not a.pages else {int(x, 16) for x in a.pages.split(",")}
            todo = script_pokes(a.script, pages)
            for pg, rg, v in todo:
                if not a.dry_run:
                    m.poke(pg, rg, v)
                print(f"0x{pg:02X}:0x{rg:02X} <- 0x{v:02X}")
            print(f"{len(todo)} registers {'listed' if a.dry_run else 'poked'} from script {a.script} "
                  "(not saved; changing polling/CE/Hyper/DPI or a replug re-runs the firmware's script)")
        elif a.cmd == "stats":
            do_stats(m, a.seconds, a.interval, a.log, a.once)
        elif a.cmd == "stats-reset":
            m.stats_reset()
            print("telemetry counters reset")
        elif a.cmd == "lock-on":
            if a.lead is not None:
                print(f"lead {m.lock_lead(a.lead)} us")
            print(f"phase lock {'on' if m.lock_switch(True) else 'off'}")
        elif a.cmd == "lock-off":
            print(f"phase lock {'on' if m.lock_switch(False) else 'off'} ({m.lock_persistence()})")
        elif a.cmd == "lock-status":
            on, lead = m.lock_status()
            print(f"phase lock {'on' if on else 'off'}, lead {lead} us")
        elif a.cmd == "lock-lead":
            print(f"lead {m.lock_lead(a.us)} us ({m.lock_persistence()})")
        elif a.cmd == "debounce-status":
            for line in db_lines(m.click_debounce()):
                print(line)
        elif a.cmd in ("debounce-set", "debounce-stock", "debounce-default"):
            if a.cmd == "debounce-set":
                todo = [(k, db_code(getattr(a, k))) for k in DB_NAMES if getattr(a, k) is not None]
                if not todo:
                    raise CfgError("give at least one of --pre --post --plock --relock")
            else:
                todo = [(k, 255 if a.cmd == "debounce-stock" else 0) for k in DB_NAMES]
            d = None
            for k, c in todo:
                d = m.debounce_set(k, c)
            for line in db_lines(d):
                print(line)
            print("(saved on the mouse: kept after power-off; factory reset in the panel clears it)")
        elif a.cmd == "fps-list":
            for i, (name, k, slow, fast) in enumerate(FPS_PRESETS):
                print(f"  {name:8s} {fps_range(k, slow, fast)}")
            print("  stock    each mode's own: Hyper 13.3k-20k, CE and Hyper above 6999 DPI fixed 20k, "
                  "Hyper off 6.7k-20k")
            print("Rates are computed from the registers (unit 07:42 x 1.25 us); the sensor's oscillator drifts "
                  "with temperature, so they are approximate.")
        elif a.cmd in ("fps-status", "hyperfps-status"):
            d = m.click_debounce()
            if d["hyperfps"] is None:
                print("frame rate: not in this build")
            elif d["fps"] is None:
                print("hyper-fps: " + ("on (20k)" if d["hyperfps"] else "off (stock)") +
                      "  (this build has only hyper-fps on/off)")
            else:
                f = d["fps"]
                print("frame rate: " + ("stock (each mode's own)" if f == "stock"
                                        else f"{FPS_PRESETS[f][0]}: {fps_text(f)}"))
        elif a.cmd in ("fps-set", "hyperfps-on", "hyperfps-off"):
            want = a.preset if a.cmd == "fps-set" else "20k" if a.cmd == "hyperfps-on" else "stock"
            idx = None if want.strip().lower() == "stock" else fps_index(want)
            d = m.fps_set(idx)
            if d["fps"] is None:                       # on/off-only build
                print(f"hyper-fps {'on (20k)' if d['hyperfps'] else 'off (stock)'} (saved on the mouse)")
                if not a.no_apply:
                    print(m.hyperfps_apply(d["hyperfps"]))
            else:
                f = d["fps"]
                print("frame rate: " + ("stock (each mode's own)" if f == "stock"
                                        else f"{FPS_PRESETS[f][0]}: {fps_text(f)}") +
                      " (saved on the mouse: kept after power-off)")
                if not a.no_apply:
                    print(m.fps_apply(None if f == "stock" else f))
        elif a.cmd in ("stats-on", "stats-off"):
            st = m.stats_switch(a.cmd == "stats-on")
            print(f"telemetry counting {'on' if st else 'off'} (resets to off at power-up)")
        elif a.cmd == "lod-poke":
            v = parse_byte(a.value, "value")
            m.poke(0x18, 0x7A, v)
            print(f"LOD register 0x18:0x7A <- 0x{v:02X} ({v})  (not saved: a replug, a sensor re-init or "
                  "changing LOD in the panel/`set lod` puts the saved LOD back)")
        elif a.cmd == "peek":
            r = parse_byte(a.reg, "reg")
            if r > 0x7F:
                raise CfgError("peek reads page-0 registers 0x00..0x7F")
            v = m.peek(r)
            m.select_peek(0x07)
            print(f"0x00:0x{r:02X} = 0x{v:02X} ({v})")
        elif a.cmd == "watch":
            regs = [parse_byte(r, "reg") for r in a.regs]
            if any(r > 0x7F for r in regs):
                raise CfgError("watch reads page-0 registers 0x00..0x7F")
            do_watch(m, regs, a.interval, a.count)
        elif a.cmd == "setdown":
            do_setdown(m, a.seconds)
        elif a.cmd == "lod-sweep":
            st, sp_, step = parse_lod_raw(a.start), parse_lod_raw(a.stop), int(a.step, 0)
            if step == 0:
                raise CfgError("--step must not be 0")
            do_lod_sweep(m, st, sp_, step if st <= sp_ else -abs(step))
        elif a.cmd == "reset-settings":
            if not a.yes and input("Factory reset: every profile and setting (including debounce, frame rate and "
                                   "lock) goes back to default, and the mouse restarts. Type YES: ") != "YES":
                print("cancelled")
                sys.exit(1)
            ok = m.factory_reset()
            print("factory reset sent: the mouse saves and restarts" + ("" if ok else
                  " (no reply - expected if it restarted already; run `show` in a few seconds to check)"))
        elif a.cmd == "reset-profile":
            cnt = m.profile_count()
            if not 1 <= a.number <= cnt:
                raise CfgError(f"profile must be 1..{cnt}")
            if not a.yes and input(f"Reset profile {a.number} to factory (DPI, polling, LOD, buttons ...)? "
                                   "Type YES: ") != "YES":
                print("cancelled")
                sys.exit(1)
            m.reset_profile(a.number)
            print(f"profile {a.number} reset to factory and saved")
        elif a.cmd == "profile":
            if a.number is None:
                print(m.active_profile())
            else:
                cnt = m.profile_count()
                if not 1 <= a.number <= cnt:
                    raise CfgError(f"profile must be 1..{cnt}")
                m.set_profile(a.number)
                got = settle(m.active_profile, a.number)
                print(f"active profile -> {got}", "OK" if got == a.number else "MISMATCH")
    except (CfgError, HidOpenError) as e:
        sys.exit(f"error: {e}")


if __name__ == "__main__":
    main()
