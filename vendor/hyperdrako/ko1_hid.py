#!/usr/bin/env python3
"""
ko1_hid.py - shared HID transport for ko1_flash.py and ko1_cfg.py.

Both tools only ever do two things with the mouse: send one 64-byte HID feature
report (report ID 0) and read one back.  This module isolates that, so the rest
of the code is OS-independent.

Backends
  hidraw  Linux only.  /dev/hidraw* + ioctls.  Pure Python, no dependencies.
          Used automatically on Linux.
  hidapi  Windows, macOS (and Linux if you ask for it).  Needs the `hidapi`
          package:  pip install hidapi   (the prebuilt exes already contain it).

Pick one with --backend {auto,hidraw,hidapi} or the KO1_HID_BACKEND env var.

Finding the config interface
  The mouse exposes several HID interfaces and only one takes the 64-byte feature
  reports.  hidraw can read the report descriptor and look for `95 40 B1 02`.
  hidapi cannot (Windows has no descriptor API), so there the interface is chosen
  by: only one candidate -> that one; else vendor-defined usage page (>= 0xFF00);
  else whichever candidate answers a (read-only) feature-report read.
  If that is still ambiguous, run `list` and pass the path with --node.
"""
import os
import sys
import time

CFG_DESC = b"\x95\x40\xb1\x02"        # 64-byte feature report in the HID descriptor
VENDOR_PAGE_MIN = 0xFF00
REPORT_LEN = 64


class HidOpenError(RuntimeError):
    """Could not find / open / choose a device. Message is meant for the user."""


class HidIOError(OSError):
    """A feature-report transfer failed (device reset, unplugged, wrong interface)."""


class Node:
    """One HID interface/collection of the mouse."""

    def __init__(self, path, raw, vid, pid, iface="?", descriptor=None,
                 usage_page=None, usage=None):
        self.path = path              # printable
        self.raw = raw                # what the backend opens (str for hidraw, bytes for hidapi)
        self.vid, self.pid = vid, pid
        self.iface = iface
        self.descriptor = descriptor  # bytes or None (hidapi can't read it)
        self.usage_page, self.usage = usage_page, usage

    @property
    def is_config(self):
        """True if this looks like the config interface (exact on hidraw, a guess on hidapi)."""
        if self.descriptor is not None:
            return CFG_DESC in self.descriptor
        return self.usage_page is not None and self.usage_page >= VENDOR_PAGE_MIN

    @property
    def exact(self):
        return self.descriptor is not None

    def describe(self):
        s = f"{self.path}  {self.vid:04X}:{self.pid:04X}  interface {self.iface}"
        if self.usage_page is not None:
            s += f"  usage {self.usage_page:#06x}/{(self.usage or 0):#06x}"
        if self.is_config:
            s += "  <- config interface" + ("" if self.exact else " (likely)")
        return s


# ---------------------------------------------------------------- Linux hidraw
class _HidrawDevice:
    def __init__(self, path):
        import fcntl
        self._fcntl = fcntl
        self.path = path
        try:
            self.fd = os.open(path, os.O_RDWR)
        except PermissionError:
            raise HidOpenError(f"{path}: permission denied. Run `ko1_flash.py udev-rule` for a "
                               "udev rule (then replug the mouse), or use sudo.")
        except OSError as e:
            raise HidOpenError(f"{path}: {e.strerror or e}")

    @staticmethod
    def _ioc(d, t, nr, sz):
        return (d << 30) | (sz << 16) | (ord(t) << 8) | nr

    def set_report(self, data):
        assert len(data) == REPORT_LEN
        # HIDIOCSFEATURE(65)
        self._fcntl.ioctl(self.fd, self._ioc(3, "H", 0x06, 65), bytes([0]) + bytes(data))

    def get_report(self):
        buf = bytearray(65)
        # HIDIOCGFEATURE(65)
        self._fcntl.ioctl(self.fd, self._ioc(3, "H", 0x07, 65), buf)
        return bytes(buf)

    def close(self):
        try:
            os.close(self.fd)
        except OSError:
            pass


def _read(path, mode="r"):
    try:
        with open(path, mode) as f:
            return f.read()
    except OSError:
        return None


class _HidrawBackend:
    name = "hidraw"

    @staticmethod
    def available():
        if not sys.platform.startswith("linux"):
            return False
        try:
            __import__("fcntl")
        except ImportError:
            return False
        return os.path.isdir("/sys/class/hidraw")

    @staticmethod
    def enumerate(vid, pid):
        import glob
        out = []
        tag = f"HID_ID=0003:{vid:08X}:{pid:08X}"
        for p in sorted(glob.glob("/sys/class/hidraw/hidraw*")):
            uev = _read(p + "/device/uevent")
            if not uev or tag not in uev.upper():
                continue
            rd = _read(p + "/device/report_descriptor", "rb") or b""
            iface = _read(os.path.realpath(p + "/device") + "/../bInterfaceNumber")
            dev = "/dev/" + os.path.basename(p)
            out.append(Node(dev, dev, vid, pid, iface.strip() if iface else "?", descriptor=rd))
        return out

    @staticmethod
    def open(node):
        return _HidrawDevice(node.raw)

    @staticmethod
    def node_from_path(path, vid=0, pid=0):
        return Node(path, path, vid, pid)


# ---------------------------------------------------------------------- hidapi
class _HidapiDevice:
    def __init__(self, hid, raw_path, shown):
        self.path = shown
        self._d = hid.device()
        try:
            self._d.open_path(raw_path)
        except (OSError, ValueError) as e:
            raise HidOpenError(_open_hint(shown, e))

    def _err(self):
        try:
            return self._d.error() or "transfer failed"
        except Exception:
            return "transfer failed"

    def set_report(self, data):
        assert len(data) == REPORT_LEN
        try:
            r = self._d.send_feature_report(bytes([0]) + bytes(data))
        except (OSError, ValueError) as e:
            raise HidIOError(str(e))
        if isinstance(r, int) and r < 0:       # some hidapi builds return -1 instead of raising
            raise HidIOError(self._err())

    def get_report(self):
        try:
            r = self._d.get_feature_report(0, 65)
        except (OSError, ValueError) as e:
            raise HidIOError(str(e))
        if r is None or (isinstance(r, int) and r < 0) or len(r) == 0:
            raise HidIOError(self._err())
        # Report ID 0 is returned as byte 0 (the tools auto-detect that offset).
        return bytes(r).ljust(65, b"\0")

    def close(self):
        try:
            self._d.close()
        except Exception:
            pass


def _open_hint(path, err):
    msg = f"{path}: could not open ({err})."
    if sys.platform.startswith("win"):
        msg += (" Close the CRDRAKO web panel/driver and any other mouse software, then retry. "
                "Windows only lets vendor-defined HID interfaces be opened this way; if this is "
                "the mouse/keyboard interface, pick another with --node (see `list`).")
    elif sys.platform == "darwin":
        msg += (" On macOS, allow your terminal under System Settings > Privacy & Security > "
                "Input Monitoring, then retry.")
    else:
        msg += " Check permissions (udev rule or sudo)."
    return msg


class _HidapiBackend:
    name = "hidapi"
    _mod = None

    @classmethod
    def _hid(cls):
        if cls._mod is None:
            try:
                import hid
            except ImportError:
                return None
            if not hasattr(hid, "enumerate") or not hasattr(hid, "device"):
                return None
            cls._mod = hid
        return cls._mod

    @classmethod
    def available(cls):
        return cls._hid() is not None

    @classmethod
    def enumerate(cls, vid, pid):
        out = []
        for d in cls._hid().enumerate(vid, pid):
            raw = d["path"]
            shown = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)
            out.append(Node(shown, raw, vid, pid, str(d.get("interface_number", -1)),
                            descriptor=None, usage_page=d.get("usage_page"), usage=d.get("usage")))
        out.sort(key=lambda n: (n.iface, n.path))
        return out

    @classmethod
    def open(cls, node):
        return _HidapiDevice(cls._hid(), node.raw, node.path)

    @classmethod
    def node_from_path(cls, path, vid=0, pid=0):
        return Node(path, path.encode() if isinstance(path, str) else path, vid, pid)


# ------------------------------------------------------------------- selection
_BACKENDS = {"hidraw": _HidrawBackend, "hidapi": _HidapiBackend}
_choice = os.environ.get("KO1_HID_BACKEND", "auto")
_active = None


def set_backend(name):
    global _choice, _active
    _choice, _active = (name or "auto"), None


def backend():
    global _active
    if _active is not None:
        return _active
    if _choice in _BACKENDS:
        b = _BACKENDS[_choice]
        if not b.available():
            hint = {"hidraw": "hidraw needs Linux with /sys/class/hidraw.",
                    "hidapi": "hidapi is not installed: pip install hidapi"}[_choice]
            raise HidOpenError(f"backend '{_choice}' is not available. {hint}")
        _active = b
    elif _choice == "auto":
        for b in (_HidrawBackend, _HidapiBackend):
            if b.available():
                _active = b
                break
        else:
            raise HidOpenError("no HID backend available. Install hidapi: pip install hidapi "
                               "(or use the prebuilt ko1 executable).")
    else:
        raise HidOpenError(f"unknown backend '{_choice}' (use auto, hidraw or hidapi)")
    return _active


def find_nodes(vid, pid):
    """All HID interfaces of vid:pid -> [Node]."""
    return backend().enumerate(vid, pid)


def open_node(node_or_path):
    """Open a Node (or a path string given by --node) -> device with set_report/get_report/close."""
    b = backend()
    node = node_or_path if isinstance(node_or_path, Node) else b.node_from_path(node_or_path)
    return b.open(node)


def _probe(node):
    """Read-only: does this interface answer a 64-byte feature-report read?"""
    try:
        dev = backend().open(node)
    except HidOpenError:
        return False
    try:
        dev.get_report()
        return True
    except (OSError, ValueError):
        return False
    finally:
        dev.close()


def pick_config_node(nodes, override=None):
    """Choose the interface that takes the 64-byte feature reports -> Node (or the --node path)."""
    if override:
        return backend().node_from_path(override)
    if not nodes:
        raise HidOpenError("no matching HID interface found")
    if len(nodes) == 1:
        return nodes[0]
    exact = [n for n in nodes if n.exact]
    if exact:
        cfg = [n for n in exact if CFG_DESC in n.descriptor]
        if len(cfg) == 1:
            return cfg[0]
        cands = cfg or nodes
    else:
        vendor = [n for n in nodes if n.is_config]
        cands = vendor or nodes
        if len(cands) == 1:
            return cands[0]
        ok = [n for n in cands if _probe(n)]
        if len(ok) == 1:
            return ok[0]
        cands = ok or cands
    raise HidOpenError("could not pick a unique config interface; use --node. Candidates:\n  "
                       + "\n  ".join(n.describe() for n in cands))


def wait_for_node(vid, pid, timeout, what):
    t0 = time.time()
    while time.time() - t0 < timeout:
        nodes = find_nodes(vid, pid)
        if nodes:
            time.sleep(0.3)
            return find_nodes(vid, pid)
        time.sleep(0.25)
    raise HidOpenError(f"timed out waiting for {what} ({vid:04X}:{pid:04X}).")


def udev_rule_text():
    if sys.platform.startswith("linux"):
        return ('# /etc/udev/rules.d/99-crdrako.rules, then: '
                'sudo udevadm control --reload && sudo udevadm trigger  (and replug the mouse)\n'
                'KERNEL=="hidraw*", ATTRS{idVendor}=="373e", MODE="0660", TAG+="uaccess"')
    return ("udev rules are Linux-only; nothing to install on this OS.\n"
            "Windows: no setup, but close the CRDRAKO web panel first.\n"
            "macOS: allow your terminal under Privacy & Security > Input Monitoring if opening fails.")
