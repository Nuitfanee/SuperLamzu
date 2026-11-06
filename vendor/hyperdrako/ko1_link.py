"""ko1_link.py -- watch the mouse's report stream from the host and count timing faults.

Why this works (see README_e2e_polling.md): the mouse reads the sensor once per report tick and sends
one radio packet per reading; the dongle forwards every packet as one USB report as soon as the host
polls (its endpoint uses bInterval 1, so the host polls every 125 us on high-speed USB). So while the
mouse moves steadily, reports should arrive exactly one report period apart. A radio packet that needed
a retry arrives one or more radio slots late and the next one arrives early (a "bunch"); a packet that
missed its tick entirely leaves a gap of two periods or more.

What the host can and cannot see: arrival times are taken when Windows delivers WM_INPUT, so they carry
some scheduling jitter (the tool prints it). A report that never arrives cannot be told apart from a
sensor tick with no motion, so the statistics only use intervals inside steady motion: keep the mouse
moving (circles) while it runs.

Windows only for the capture; link_stats() is pure and tested offline.
"""
import ctypes
import sys
import time

KO1_VID = "373E"


def link_stats(events, period, motion_gap=0.02, stall_max=0.3):
    """events: list of (t_seconds, dx, dy), in arrival order, one per report.
    period: expected report period in seconds (1/polling rate).
    Only intervals between two reports that both carry motion and are < motion_gap apart count
    (longer pauses are treated as the mouse standing still).
    Returns dict with counts and percentiles."""
    iv, runs, cur, stalls = [], [], [], []
    for (t0, x0, y0), (t1, x1, y1) in zip(events, events[1:]):
        d = t1 - t0
        if (x0 or y0) and (x1 or y1) and motion_gap <= d < stall_max:
            stalls.append(d)               # motion before and after, but a long hole: sensor re-init?
        if (x0 or y0) and (x1 or y1) and 0 <= d < motion_gap:
            cur.append(d)
        elif cur:
            runs.append(cur); cur = []
    if cur:
        runs.append(cur)
    for r in runs:
        iv.extend(r)
    n = len(iv)
    res = {"intervals": n, "period_us": period * 1e6, "stalls": len(stalls),
           "stall_max_ms": max(stalls) * 1e3 if stalls else 0.0}
    if not n:
        res.update(on_time=0, late=0, early=0, missed=0, miss_rate=0.0, late_rate=0.0, early_rate=0.0,
                   p50_us=0.0, p99_us=0.0, max_us=0.0, rate_hz=0.0)
        return res
    late = sum(1 for d in iv if d / period >= 1.5)
    early = sum(1 for d in iv if d / period < 0.5)
    on_time = n - late - early
    # a late packet followed by an early one still fills its tick; only ticks with no report count
    missed = sum(max(0, int(round(sum(r) / period)) - len(r)) for r in runs)
    s = sorted(iv)
    expected = sum(iv) / period            # report ticks covered by the moving intervals
    res.update(on_time=on_time, late=late, early=early, missed=missed,
               miss_rate=missed / expected if expected else 0.0,
               late_rate=late / n, early_rate=early / n,
               p50_us=s[n // 2] * 1e6, p99_us=s[min(n - 1, int(n * 0.99))] * 1e6, max_us=s[-1] * 1e6,
               rate_hz=n / sum(iv))
    return res


def format_stats(st, label=""):
    if not st["intervals"]:
        return f"{label}no moving reports (keep the mouse moving)"
    return (f"{label}{st['rate_hz']:7.0f} Hz moving | missed {st['missed']:4d} ({st['miss_rate']*100:5.2f}%)"
            f" | late {st['late_rate']*100:5.2f}% | bunched {st['early_rate']*100:5.2f}%"
            f" | interval p50 {st['p50_us']:5.0f} us p99 {st['p99_us']:5.0f} us max {st['max_us']:6.0f} us"
            + (f" | STALLS {st['stalls']} (max {st['stall_max_ms']:.0f} ms)" if st.get("stalls") else ""))


# ------------------------------------------------------------------ Windows raw input capture
class RawCapture:
    """Collects (t, dx, dy) for every raw mouse report from devices whose name contains VID_373E."""

    def __init__(self, vid=KO1_VID, all_mice=False):
        if sys.platform != "win32":
            raise RuntimeError("link capture needs Windows (raw input)")
        from ctypes import wintypes as W
        self.W = W
        self.u32 = ctypes.WinDLL("user32", use_last_error=True)
        self.k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.vid = vid.upper()
        self.all = all_mice
        self.events = []
        self.names = {}
        self._setup()

    def _setup(self):
        W, u32, k32 = self.W, self.u32, self.k32
        WNDPROC = ctypes.WINFUNCTYPE(ctypes.c_ssize_t, W.HWND, W.UINT, W.WPARAM, W.LPARAM)

        class WNDCLASS(ctypes.Structure):
            _fields_ = [("style", W.UINT), ("lpfnWndProc", WNDPROC), ("cbClsExtra", ctypes.c_int),
                        ("cbWndExtra", ctypes.c_int), ("hInstance", W.HINSTANCE), ("hIcon", W.HICON),
                        ("hCursor", W.HANDLE), ("hbrBackground", W.HBRUSH), ("lpszMenuName", W.LPCWSTR),
                        ("lpszClassName", W.LPCWSTR)]

        class RAWINPUTDEVICE(ctypes.Structure):
            _fields_ = [("usUsagePage", W.USHORT), ("usUsage", W.USHORT), ("dwFlags", W.DWORD),
                        ("hwndTarget", W.HWND)]

        class RAWINPUTHEADER(ctypes.Structure):
            _fields_ = [("dwType", W.DWORD), ("dwSize", W.DWORD), ("hDevice", W.HANDLE), ("wParam", W.WPARAM)]

        class RAWMOUSE(ctypes.Structure):
            _fields_ = [("usFlags", W.USHORT), ("usButtonFlags", W.USHORT), ("usButtonData", W.USHORT),
                        ("ulRawButtons", W.ULONG), ("lLastX", W.LONG), ("lLastY", W.LONG),
                        ("ulExtraInformation", W.ULONG)]

        class RAWINPUT(ctypes.Structure):
            _fields_ = [("header", RAWINPUTHEADER), ("mouse", RAWMOUSE)]

        self.RAWINPUT, self.RAWINPUTHEADER = RAWINPUT, RAWINPUTHEADER
        freq = ctypes.c_int64()
        k32.QueryPerformanceFrequency(ctypes.byref(freq))
        self.freq = float(freq.value)
        u32.DefWindowProcW.restype = ctypes.c_ssize_t
        u32.DefWindowProcW.argtypes = [W.HWND, W.UINT, W.WPARAM, W.LPARAM]
        u32.GetRawInputData.argtypes = [W.HANDLE, W.UINT, ctypes.c_void_p, ctypes.POINTER(W.UINT), W.UINT]
        u32.GetRawInputDeviceInfoW.argtypes = [W.HANDLE, W.UINT, ctypes.c_void_p, ctypes.POINTER(W.UINT)]
        buf = ctypes.create_string_buffer(64)
        qpc = ctypes.c_int64()

        def proc(hwnd, msg, wp, lp):
            if msg == 0x00FF:                                  # WM_INPUT
                k32.QueryPerformanceCounter(ctypes.byref(qpc))
                size = W.UINT(64)
                if u32.GetRawInputData(lp, 0x10000003, buf, ctypes.byref(size),
                                       ctypes.sizeof(RAWINPUTHEADER)) > 0:
                    ri = RAWINPUT.from_buffer_copy(buf.raw[:ctypes.sizeof(RAWINPUT)])
                    if ri.header.dwType == 0 and self._wanted(ri.header.hDevice):
                        self.events.append((qpc.value / self.freq, ri.mouse.lLastX, ri.mouse.lLastY))
                return 0
            return u32.DefWindowProcW(hwnd, msg, wp, lp)

        self._proc = WNDPROC(proc)
        wc = WNDCLASS(lpfnWndProc=self._proc, lpszClassName="ko1_link")
        u32.RegisterClassW(ctypes.byref(wc))
        u32.CreateWindowExW.restype = W.HWND
        # A visible window: Windows 11 limits raw input delivered to background windows (about 125 Hz),
        # so the capture only sees the real report rate while this window is in the foreground.
        WS_VISIBLE_OVERLAPPED = 0x10CF0000          # WS_OVERLAPPEDWINDOW | WS_VISIBLE
        self.hwnd = u32.CreateWindowExW(0x00000008, "ko1_link", "ko1 link - keep this window focused",  # TOPMOST
                                        WS_VISIBLE_OVERLAPPED, 200, 200, 520, 140, None, None, None, None)
        u32.SetForegroundWindow(self.hwnd)
        rid = RAWINPUTDEVICE(1, 2, 0x00000100, self.hwnd)          # mouse, RIDEV_INPUTSINK
        if not u32.RegisterRawInputDevices(ctypes.byref(rid), 1, ctypes.sizeof(rid)):
            raise RuntimeError("RegisterRawInputDevices failed")
        k32.SetPriorityClass(k32.GetCurrentProcess(), 0x00000080)      # HIGH_PRIORITY_CLASS
        k32.SetThreadPriority(k32.GetCurrentThread(), 2)                # THREAD_PRIORITY_HIGHEST
        ctypes.WinDLL("winmm").timeBeginPeriod(1)

    def _wanted(self, h):
        if self.all:
            return True
        key = int(h or 0)
        if key not in self.names:
            n = self.W.UINT(0)
            self.u32.GetRawInputDeviceInfoW(h, 0x20000007, None, ctypes.byref(n))   # RIDI_DEVICENAME
            b = ctypes.create_unicode_buffer(n.value + 1)
            self.u32.GetRawInputDeviceInfoW(h, 0x20000007, b, ctypes.byref(n))
            self.names[key] = b.value.upper()
        return ("VID_" + self.vid) in self.names[key]

    def focused(self):
        return self.u32.GetForegroundWindow() == self.hwnd

    def wait_focus(self, seconds, out):
        """Pump messages until the window is in the foreground (or time runs out)."""
        end = time.perf_counter() + seconds
        told = False
        while not self.focused() and time.perf_counter() < end:
            if not told:
                out("click the 'ko1 link' window once so it has focus (Windows throttles background raw input)")
                told = True
            self.pump(0.1)
        return self.focused()

    def pump(self, seconds):
        """Process messages for `seconds`."""
        W, u32 = self.W, self.u32
        msg = W.MSG()
        end = time.perf_counter() + seconds
        while time.perf_counter() < end:
            while u32.PeekMessageW(ctypes.byref(msg), None, 0, 0, 1):
                u32.TranslateMessage(ctypes.byref(msg))
                u32.DispatchMessageW(ctypes.byref(msg))
            u32.MsgWaitForMultipleObjects(0, None, False, 5, 0x04FF)


def do_link(seconds, rate_hz, out=print, capture=None, every=1.0, all_mice=False):
    """Live link monitor. Prints one line per `every` seconds, then a total."""
    cap = capture or RawCapture(all_mice=all_mice)
    period = 1.0 / rate_hz
    if hasattr(cap, "wait_focus") and not cap.wait_focus(15, out):
        out("warning: the window never got focus; results will show Windows' background limit, not the mouse")
    if hasattr(cap, "events"):
        del cap.events[:]                       # drop anything captured before the window had focus
    out(f"watching reports for {seconds:g} s at {rate_hz} Hz: keep the mouse moving in circles "
        "(Ctrl+C stops)")
    t_end = time.perf_counter() + seconds
    start = 0
    try:
        while time.perf_counter() < t_end:
            cap.pump(min(every, max(0.0, t_end - time.perf_counter())))
            chunk = cap.events[max(0, start - 1):]
            start = len(cap.events)
            line = format_stats(link_stats(chunk, period), label="  ")
            if hasattr(cap, "focused") and not cap.focused():
                line += "  [window NOT focused: throttled]"
            out(line)
    except KeyboardInterrupt:
        pass
    st = link_stats(cap.events, period)
    out(format_stats(st, label="total: "))
    if st["intervals"] and period <= 0.002 and st["p50_us"] > 6000:
        out("note: reports arrived about every 8 ms. That is Windows limiting raw input to a background "
            "window, not the mouse. Keep the 'ko1 link' window focused while moving.")
    return st
