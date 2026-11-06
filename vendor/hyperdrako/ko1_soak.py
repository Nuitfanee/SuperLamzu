#!/usr/bin/env python3
"""
ko1_soak.py - hardware soak logger (AGENT_TASK_stability.md, stage 1).

The user sees glitches and short outages while the battery is between about 100% and 90%,
and stock is not a clean baseline (it may glitch too, just less often). The only way to tell
"B is worse than A" from "B just got unlucky this run" is to log long unattended runs and
compare EVENT RATES, with a confidence interval -- not single runs.

  ko1 soak run SECONDS --label NAME [--build NAME] [--interval 5] [--via auto|receiver|wired]
        poll the mouse every --interval seconds for SECONDS (0 = until Ctrl+C); write
        work/logs/<date>_<build>_<label>.csv (one row per tick) and the matching .json
        (the event list below). Reads only: battery, profile, telemetry counters and phase-lock
        status if the build has them (ABLODSTATS / ABLODLOCK). Never opens the bootloader.

  ko1 soak summary STEM...
        events per hour by kind, per battery-% band, and a gap-duration histogram, for one or
        more logs (STEM is the path without .csv/.json).

  ko1 soak compare --a STEM... --b STEM...
        pools each group's logs and reports, per event kind: count, hours, rate/hour with a
        95% Poisson confidence interval, and an exact two-sided p-value for "A and B have the
        same rate" (a conditional binomial / E-test on the pooled counts -- no scipy needed).

Detected, each becomes one event in the .json (`kind`, `start`/`time`, `end`, `duration_s`):
  reboot          counters (ABLODSTATS) or a live-only setting (phase-lock on/off, lead) went
                  back to the power-up default without `ko1 soak` asking for it (H: a 32-bit
                  counter wrapping could in principle look the same; see detect_reboot()).
  link_drop       a poll got no reply at all. The mouse being asleep or out of range is normal;
                  only the RATE across builds says whether this is a bug (AGENT_TASKS_NEXT.md).
  receiver_reset  the receiver's HID node disappeared from the bus and came back: the
                  host-visible sign of a receiver crash or reset (wired runs: a cable unplug).
"""
import argparse
import bisect
import csv
import json
import math
import os
import sys
import time

import ko1_cfg
import ko1_hid

STATS_FIELDS = ko1_cfg.STATS_FIELDS
# counters that only ever go up between two successful polls (ABLODSTATS, "Counters are 32-bit,
# start at 0 at power-up" -- README_stats.md). A reboot is a LARGE drop back near zero; a wrap
# needs the counter to pass ~4.3e9, which at a few kHz is days of continuous ticks and would not
# hit every one of these counters at once, so "cur much smaller than prev" is reboot, not wrap.
REBOOT_MONOTONIC = ["ticks", "slot_ends", "samples", "reads_started", "tx_attempts"]
BATTERY_BAND_WIDTH = 5
LOCK_LEAD_DEFAULT = ko1_cfg.LOCK_LEAD_DEFAULT


# --------------------------------------------------------------------------------- one poll
def poll_once(m, has_stats=True, has_lock=True, clock=time.monotonic):
    """One read of everything soak cares about. Raises ko1_cfg.CfgError if the mouse (or the
    radio link to it) does not answer at all -- the caller counts that as a possible link drop."""
    charging, pct = m.battery()
    row = {"t": clock(), "battery_pct": pct, "charging": int(bool(charging)),
           "profile": m.active_profile(), "stats": None, "lock_on": None, "lock_lead": None}
    if has_stats:
        row["stats"] = m.stats()
    if has_lock:
        on, lead = m.lock_status()
        row["lock_on"], row["lock_lead"] = int(on), lead
    return row


def probe_capabilities(m):
    """Which optional queries this build answers, so the loop does not retry a losing query
    every single tick. Returns (has_stats, has_lock)."""
    has_stats = True
    try:
        m.stats()
    except ko1_cfg.CfgError:
        has_stats = False
    has_lock = True
    try:
        m.lock_status()
    except ko1_cfg.CfgError:
        has_lock = False
    return has_stats, has_lock


# ------------------------------------------------------------------------- event detection
def detect_reboot(prev, cur):
    """prev/cur: two consecutive successful poll_once() rows. Returns a reason string, or None."""
    if prev is None or cur is None:
        return None
    ps, cs = prev.get("stats"), cur.get("stats")
    if ps and cs:
        for k in REBOOT_MONOTONIC:
            if ps[k] > 1000 and cs[k] < ps[k] // 2:
                return f"counter '{k}' went from {ps[k]} to {cs[k]} (ABLODSTATS)"
        if ps.get("enabled") == 1 and cs.get("enabled") == 0:
            return "telemetry counting reset to off (power-up default)"
    if prev.get("lock_on") == 0 and cur.get("lock_on") == 1 and cur.get("lock_lead") == LOCK_LEAD_DEFAULT:
        return f"phase lock reset to on / {LOCK_LEAD_DEFAULT} us lead (power-up default)"
    return None


class NodeTracker:
    """Turns a sequence of find_nodes() presence checks into receiver_reset events."""

    def __init__(self, present_now, t0):
        self.present = present_now
        self.absent_since = None if present_now else t0

    def tick(self, present, t):
        event = None
        if present and not self.present:
            event = {"kind": "receiver_reset", "start": self.absent_since, "end": t,
                      "duration_s": t - self.absent_since}
            self.absent_since = None
        elif not present and self.present:
            self.absent_since = t
        self.present = present
        return event

    def close(self, t):
        if self.absent_since is not None:
            return {"kind": "receiver_reset", "start": self.absent_since, "end": t,
                     "duration_s": t - self.absent_since, "open": True}
        return None


class LinkTracker:
    """Turns a sequence of poll successes/failures into link_drop events."""

    def __init__(self):
        self.down_since = None

    def tick(self, ok, t):
        event = None
        if ok and self.down_since is not None:
            event = {"kind": "link_drop", "start": self.down_since, "end": t,
                      "duration_s": t - self.down_since}
            self.down_since = None
        elif not ok and self.down_since is None:
            self.down_since = t
        return event

    def close(self, t):
        if self.down_since is not None:
            return {"kind": "link_drop", "start": self.down_since, "end": t,
                     "duration_s": t - self.down_since, "open": True}
        return None


CSV_FIELDS = ["time", "t", "link_ok", "battery_pct", "charging", "profile",
              "stats_enabled", "lock_on", "lock_lead_us"] + STATS_FIELDS


def row_to_csv(t, t0, row):
    if row is None:
        return [time.strftime("%H:%M:%S"), f"{t - t0:.1f}", 0] + [""] * (len(CSV_FIELDS) - 3)
    s = row.get("stats") or {}
    return ([time.strftime("%H:%M:%S"), f"{t - t0:.1f}", 1, row["battery_pct"], row["charging"], row["profile"],
             s.get("enabled", ""), row["lock_on"] if row["lock_on"] is not None else "",
             row["lock_lead"] if row["lock_lead"] is not None else ""]
            + [s.get(k, "") for k in STATS_FIELDS])


# ------------------------------------------------------------------------------- the loop
def run_soak(m, pid, stem, seconds, interval, find_nodes=None, clock=time.monotonic,
             sleep=time.sleep, out=print):
    """Poll `m` every `interval` seconds for `seconds` (0 = until Ctrl+C or KeyboardInterrupt).
    Writes `<stem>.csv` (one row/tick) and `<stem>.json` (the event list). Returns the events."""
    find_nodes = find_nodes or (lambda: ko1_hid.find_nodes(ko1_cfg.VID, pid))
    os.makedirs(os.path.dirname(stem) or ".", exist_ok=True)
    has_stats, has_lock = probe_capabilities(m)
    out(f"soak: stats telemetry {'available' if has_stats else 'not in this build'}, "
        f"phase lock {'available' if has_lock else 'not in this build'}")
    t0 = clock()
    node_tracker = NodeTracker(bool(find_nodes()), t0)
    link_tracker = LinkTracker()
    events, prev_row = [], None
    end = t0 + seconds if seconds else None
    with open(stem + ".csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(CSV_FIELDS)
        try:
            while True:
                t = clock()
                if end is not None and t >= end:
                    break
                present = bool(find_nodes())
                ev = node_tracker.tick(present, t)
                if ev:
                    events.append(ev)
                    out(f"[{t - t0:7.1f}s] receiver re-enumerated after {ev['duration_s']:.1f}s off the bus")
                row = None
                if present:
                    try:
                        row = poll_once(m, has_stats, has_lock, clock=lambda: t)
                    except ko1_cfg.CfgError:
                        row = None
                ev = link_tracker.tick(row is not None, t)
                if ev:
                    events.append(ev)
                    out(f"[{t - t0:7.1f}s] link back after {ev['duration_s']:.1f}s with no reply")
                if row is not None:
                    reason = detect_reboot(prev_row, row)
                    if reason:
                        events.append({"kind": "reboot", "time": t, "reason": reason})
                        out(f"[{t - t0:7.1f}s] REBOOT suspected: {reason}")
                    prev_row = row
                w.writerow(row_to_csv(t, t0, row))
                f.flush()
                sleep(interval)
        except KeyboardInterrupt:
            pass
    t = clock()
    for ev in (link_tracker.close(t), node_tracker.close(t)):
        if ev:
            events.append(ev)
    with open(stem + ".json", "w") as f:
        json.dump({"events": events}, f, indent=2)
    out(f"soak done: {len(events)} event(s), log at {stem}.csv / {stem}.json")
    return events


def default_stem(build, label, when=None):
    date = (when or time.strftime("%Y-%m-%d"))
    return os.path.join("work", "logs", f"{date}_{build}_{label}")


# --------------------------------------------------------------------------- summary / compare
def load_log(stem):
    rows = []
    with open(stem + ".csv", newline="") as f:
        rows = list(csv.DictReader(f))
    events = []
    if os.path.exists(stem + ".json"):
        events = json.load(open(stem + ".json")).get("events", [])
    return rows, events


def log_hours(rows):
    ts = [float(r["t"]) for r in rows if r.get("t") not in (None, "")]
    return (max(ts) - min(ts)) / 3600.0 if len(ts) > 1 else 0.0


def battery_band(pct, width=BATTERY_BAND_WIDTH):
    if pct is None:
        return "unknown"
    lo = (int(pct) // width) * width
    return f"{lo}-{lo + width - 1}%"


def battery_at(rows):
    """-> function t(seconds since start) -> nearest known battery_pct, or None."""
    pts = sorted((float(r["t"]), int(r["battery_pct"])) for r in rows
                 if r.get("battery_pct") not in (None, "") and r.get("t") not in (None, ""))
    ts = [t for t, _ in pts]

    def nearest(t):
        if not ts:
            return None
        i = bisect.bisect_left(ts, t)
        cand = [j for j in (i - 1, i) if 0 <= j < len(ts)]
        j = min(cand, key=lambda j: abs(ts[j] - t))
        return pts[j][1]
    return nearest


def event_time(ev):
    return ev.get("time", ev.get("start"))


def event_rates(events, hours):
    by_kind = {}
    for ev in events:
        by_kind.setdefault(ev["kind"], []).append(ev)
    return {k: {"count": len(v), "per_hour": len(v) / hours if hours else float("nan")}
            for k, v in by_kind.items()}


def gap_histogram(events, kind, edges=(0.1, 0.5, 1, 5, 30, 120)):
    durs = sorted(ev["duration_s"] for ev in events if ev["kind"] == kind and "duration_s" in ev)
    bins = {f"<{edges[0]:g}s": 0}
    for lo, hi in zip(edges, edges[1:]):
        bins[f"{lo:g}-{hi:g}s"] = 0
    bins[f">={edges[-1]:g}s"] = 0
    labels = list(bins)
    for d in durs:
        i = bisect.bisect_right(edges, d)
        bins[labels[i]] += 1
    return {"count": len(durs), "median_s": durs[len(durs) // 2] if durs else 0.0,
            "max_s": durs[-1] if durs else 0.0, "bins": bins}


def summarize(stem, out=print):
    rows, events = load_log(stem)
    hours = log_hours(rows)
    out(f"{stem}: {hours:.2f} h logged, {len(rows)} ticks, {len(events)} event(s)")
    rates = event_rates(events, hours)
    for kind in sorted(rates):
        r = rates[kind]
        out(f"  {kind:15s} {r['count']:4d}  ({r['per_hour']:.2f} / h)")
        if kind in ("link_drop", "receiver_reset"):
            h = gap_histogram(events, kind)
            out(f"    durations: median {h['median_s']:.1f}s max {h['max_s']:.1f}s  " +
                " ".join(f"{k}={v}" for k, v in h["bins"].items() if v))
    near = battery_at(rows)
    bands = {}
    for ev in events:
        t = event_time(ev)
        if t is None:
            continue
        pct = near(t)
        bands.setdefault(ev["kind"], {}).setdefault(battery_band(pct), 0)
        bands[ev["kind"]][battery_band(pct)] += 1
    for kind in sorted(bands):
        out(f"  {kind} by battery band: " +
            ", ".join(f"{b} x{n}" for b, n in sorted(bands[kind].items(), reverse=True)))
    return {"hours": hours, "rates": rates, "bands": bands}


# ------------------------------------------------------------------- Poisson rate statistics
Z_FOR_CONF = {0.80: 1.281552, 0.90: 1.644854, 0.95: 1.959964, 0.98: 2.326348, 0.99: 2.575829}


def poisson_ci(k, conf=0.95):
    """Byar's approximation to the exact Poisson confidence interval for a count k
    (Byar, 1980; the usual approximation when a chi-squared quantile function isn't at hand)."""
    z = Z_FOR_CONF.get(conf, Z_FOR_CONF[0.95])
    lo = 0.0 if k == 0 else k * (1 - 1 / (9 * k) - z / (3 * math.sqrt(k))) ** 3
    hi = (k + 1) * (1 - 1 / (9 * (k + 1)) + z / (3 * math.sqrt(k + 1))) ** 3
    return max(0.0, lo), hi


def binom_pmf(k, n, p):
    if p <= 0.0:
        return 1.0 if k == 0 else 0.0
    if p >= 1.0:
        return 1.0 if k == n else 0.0
    return math.comb(n, k) * (p ** k) * ((1 - p) ** (n - k))


def rate_compare_pvalue(count_a, hours_a, count_b, hours_b):
    """Exact two-sided test for 'A and B are the same Poisson rate': conditional on the pooled
    count n = count_a + count_b, count_a ~ Binomial(n, hours_a/(hours_a+hours_b)) under the null
    (the standard rate-ratio / E-test construction; no scipy / inverse-chi-squared needed)."""
    n = count_a + count_b
    if n == 0 or hours_a <= 0 or hours_b <= 0:
        return 1.0
    p = hours_a / (hours_a + hours_b)
    pk = binom_pmf(count_a, n, p)
    return min(1.0, sum(binom_pmf(k, n, p) for k in range(n + 1) if binom_pmf(k, n, p) <= pk * (1 + 1e-9)))


def compare(stems_a, stems_b, out=print, conf=0.95, label_a="A", label_b="B"):
    def pool(stems):
        rows_all, events_all, hours = [], [], 0.0
        for s in stems:
            rows, events = load_log(s)
            rows_all += rows
            events_all += events
            hours += log_hours(rows)
        return events_all, hours
    ev_a, hours_a = pool(stems_a)
    ev_b, hours_b = pool(stems_b)
    out(f"{label_a}: {hours_a:.2f} h over {len(stems_a)} log(s)   "
        f"{label_b}: {hours_b:.2f} h over {len(stems_b)} log(s)")
    kinds = sorted({ev["kind"] for ev in ev_a + ev_b})
    result = {}
    for kind in kinds:
        na = sum(1 for e in ev_a if e["kind"] == kind)
        nb = sum(1 for e in ev_b if e["kind"] == kind)
        ra, rb = (na / hours_a if hours_a else float("nan")), (nb / hours_b if hours_b else float("nan"))
        lo_a, hi_a = poisson_ci(na, conf)
        lo_b, hi_b = poisson_ci(nb, conf)
        p = rate_compare_pvalue(na, hours_a, nb, hours_b)
        result[kind] = {"a": {"count": na, "per_hour": ra}, "b": {"count": nb, "per_hour": rb}, "p": p}
        out(f"  {kind:15s} {label_a} {na:4d} ({ra:.2f}/h, {conf*100:.0f}% CI {lo_a/hours_a if hours_a else 0:.2f}-"
            f"{hi_a/hours_a if hours_a else 0:.2f}/h)   {label_b} {nb:4d} ({rb:.2f}/h, {conf*100:.0f}% CI "
            f"{lo_b/hours_b if hours_b else 0:.2f}-{hi_b/hours_b if hours_b else 0:.2f}/h)   p={p:.3f}"
            + ("  SIGNIFICANT" if p < (1 - conf) else ""))
    return result


# ------------------------------------------------------------------------------------- CLI
def build_parser():
    ap = argparse.ArgumentParser(prog="ko1 soak", description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--via", choices=["auto", "receiver", "wired"], default="auto")
    ap.add_argument("--node", help="force a device path (see `ko1 cfg list`)")
    ap.add_argument("--backend", choices=["auto", "hidraw", "hidapi"], default=None)
    ap.add_argument("--target", type=int, help="override the target byte")
    ap.add_argument("--profile", type=int, help="profile number (default: active profile)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="poll the mouse and log battery/counters/events")
    r.add_argument("seconds", type=float, help="0 = run until Ctrl+C")
    r.add_argument("--label", required=True, help="scenario label, e.g. discharge1")
    r.add_argument("--build", help="build name for the log filename (default: the mouse's fw version)")
    r.add_argument("--interval", type=float, default=5.0)
    r.add_argument("-o", "--out", help="log path stem (default: work/logs/<date>_<build>_<label>)")
    s = sub.add_parser("summary", help="events/hour, battery bands and gap histograms for one or more logs")
    s.add_argument("stems", nargs="+", help="log path stem(s), without .csv/.json")
    c = sub.add_parser("compare", help="pool two groups of logs and test whether their event rates differ")
    c.add_argument("--a", nargs="+", required=True, metavar="STEM")
    c.add_argument("--b", nargs="+", required=True, metavar="STEM")
    c.add_argument("--label-a", default="A")
    c.add_argument("--label-b", default="B")
    c.add_argument("--confidence", type=float, default=0.95)
    return ap


def main(argv=None):
    a = build_parser().parse_args(argv)
    if a.cmd == "summary":
        for stem in a.stems:
            summarize(stem)
        return 0
    if a.cmd == "compare":
        compare(a.a, a.b, label_a=a.label_a, label_b=a.label_b, conf=a.confidence)
        return 0
    if a.backend:
        ko1_hid.set_backend(a.backend)
    try:
        dev, pid = ko1_cfg.open_device(a.via, a.node)
        wired = pid == ko1_cfg.PID_WIRED
        target = a.target if a.target is not None else (0 if wired else 2)
        m = ko1_cfg.Mouse(ko1_cfg.Link(dev, 0.02, False), target, a.profile)
        build = a.build or ("stock-or-unknown-" + m.fw())
        stem = a.out or default_stem(build, a.label)
        run_soak(m, pid, stem, a.seconds, a.interval)
    except (ko1_cfg.CfgError, ko1_hid.HidOpenError) as e:
        sys.exit(f"error: {e}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
