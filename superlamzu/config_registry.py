"""LAMZU adapter of dev's registry / typed dump / preflight apply workflow.

The immutable dev registry is the organizational reference, not a wire ABI:
LAMZU keeps integer-ms debounce, exact CPI, native LOD and explicit saving.
No HID, builder or emulator is loaded to inspect the schema.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re

from . import protocol as P, target as T

SCHEMA_VERSION = PRESET_FORMAT = 1


def registry():
    def entry(name, label, kind, *, requires=0, saved="native", **kw):
        return dict(name=name, label=label, type=kind, requires=requires,
                    saved=saved, scope="global" if requires and name != "debounce" else "profile",
                    **kw)
    # Apply polling last: the native transport can re-enumerate on a rate change.
    return [
        entry("dpi", "CPI 档位", "stages", min=1, max=5, cpi_max=P.NATIVE_CPI_MAX),
        entry("dpi-active", "当前 CPI 档", "int", min=1, max=5),
        entry("lod", "LOD 原厂档位", "enum", values=["0.7", "1", "1.3", "1.5", "1.7"], unit="mm"),
        *[entry(n, label, "bool") for n, label in (
            ("angle-snap", "直线修正"), ("motion-sync", "原生运动同步"),
            ("ripple", "原生纹波控制"), ("hyper", "Hyper"),
            ("competition", "竞技模式"), ("dpi-xy", "独立 XY CPI"))],
        entry("angle-tune", "角度调整", "int", min=-30, max=30, unit="deg"),
        entry("sleep", "休眠时间", "int", min=1, max=30, unit="min"),
        entry("speed-click", "Speed Click", "pair", fields=["left", "right"]),
        entry("debounce", "原生四参数去抖", "multi", requires=P.F_DB,
              fields=list(P.DB_NAMES), min=0, max=255, unit="ms"),
        entry("fps", "传感器帧率", "fps", requires=P.F_FPS, saved="explicit-advanced",
              min=0, max=254, custom_requires=P.F_FPS_CUSTOM,
              help="0=stock；数字为固件预设 ID；自定义为 {unit, slow, fast}。请求读回不代表 SPI 已完成。"),
        entry("lock", "无线调相", "bool", requires=P.F_LOCK, saved="explicit-advanced"),
        entry("lock-lead", "调相提前量", "int", requires=P.F_LOCK, saved="explicit-advanced",
              min=0, max=499, unit="us"),
        entry("tracking", "静止跟踪", "bool", requires=P.F_IDLE_TRACKING, saved="explicit-advanced"),
        entry("path", "运动路径", "enum", requires=P.F_MOTION_PATH, saved="explicit-advanced",
              values=["thread", "direct"]),
        entry("abs", "累计无线位移", "bool", requires=P.F_ABS, saved="explicit-advanced",
              help="开启前确认配套接收器已更新 SUPER。"),
        entry("smoothing", "落地平滑", "enum", requires=P.F_SMOOTHING | P.F_ADV_SAVED,
              saved="all-advanced-on-change", values=["stock", "reduced"],
              help="应用此项会保存当前全部高级选择；不改原生 ripple。"),
        entry("polling", "回报率", "enum", values=[125, 250, 500, 1000, 2000, 4000, 8000],
              unit="Hz", help="最后应用；设备可能重新枚举，需要重新扫描。"),
    ]


def schema():
    return dict(schema_version=SCHEMA_VERSION, target="Thorn V2 / 00.00.01.16",
                settings=registry())


def _cfg():
    from . import cfg
    return cfg


def validate_typed(name, value):
    C = _cfg()
    r = next((r for r in registry() if r["name"] == name), None)
    if r is None:
        raise C.CfgError(f"unknown preset setting {name!r}")
    t = r["type"]
    if t == "bool":
        valid = type(value) is bool
    elif t == "int":
        valid = type(value) is int and r["min"] <= value <= r["max"]
    elif t == "enum":
        valid = type(value) is type(r["values"][0]) and value in r["values"]
    elif t == "pair":
        valid = isinstance(value, list) and len(value) == 2 and all(type(x) is bool for x in value)
    elif t == "multi":
        valid = isinstance(value, dict) and set(value) == set(P.DB_NAMES) and all(
            type(x) is int and 0 <= x <= 255 for x in value.values())
    elif t == "stages":
        valid = isinstance(value, list) and 1 <= len(value) <= 5 and all(
            isinstance(x, list) and len(x) == 2 and all(type(n) is int and 1 <= n <= P.NATIVE_CPI_MAX for n in x)
            for x in value)
    elif t == "fps":
        if isinstance(value, dict):
            from .frame_timing import recipe
            try:
                return recipe(value)
            except ValueError as exc:
                raise C.CfgError(f"fps: {exc}") from exc
        valid = type(value) is int and 0 <= value < P.CUSTOM_FPS_ID
    else:
        valid = False
    if not valid:
        raise C.CfgError(f"{name}: invalid {t} value {value!r}; use cfg options {name}")
    return value


def capabilities(m):
    C = _cfg()
    try:
        return m.capabilities()
    except C.Unsupported:
        return dict(flags=0, preset_count=0)


def read_typed(m, name):
    if name == "dpi": return [list(x) for x in m.stages()]
    if name == "dpi-active": return m.active_stage()
    if name == "lod": return format(m.lod(), "g")
    if name == "sleep":
        seconds = m.sleep_seconds()
        if seconds % 60 or not 60 <= seconds <= 1800:
            raise _cfg().ProtocolError(f"native sleep value {seconds}s cannot be represented in preset minutes")
        return seconds // 60
    if name == "speed-click": return [bool(x) for x in m.speed_click()]
    if name == "debounce": return dict(zip(P.DB_NAMES, m.debounce_values()))
    if name == "fps":
        status = m.fps_status()
        return m.fps_custom_status()["recipe"] if status["requested"] == P.CUSTOM_FPS_ID else status["requested"]
    if name == "lock": return m.lock_status()["enabled"]
    if name == "lock-lead": return m.lock_status()["lead_us"]
    if name == "tracking": return m.tracking_status()["enabled"]
    if name == "path": return m.motion_path()
    if name == "abs": return m.abs_motion()["enabled"]
    if name == "smoothing": return m.smoothing_status()["requested"]
    if name == "polling": return m.polling()
    if name == "angle-tune": return m.angle_tune()
    return bool(m.flag(name))


def dump_settings(m, caps=None):
    caps = capabilities(m) if caps is None else caps
    # Unlike the donor's best-effort dump, communication errors are not hidden.
    return {r["name"]: read_typed(m, r["name"]) for r in registry()
            if caps["flags"] & r["requires"] == r["requires"]}


def make_preset(m, name=None):
    result = dict(superlamzu_preset=PRESET_FORMAT, schema_version=SCHEMA_VERSION,
                  target="Thorn V2 / 00.00.01.16", settings=dump_settings(m))
    if name is not None:
        result["name"] = name
    return result


def validate_preset(preset):
    if (not isinstance(preset, dict) or type(preset.get("superlamzu_preset")) is not int
            or preset["superlamzu_preset"] != PRESET_FORMAT
            or type(preset.get("schema_version")) is not int or preset["schema_version"] != SCHEMA_VERSION
            or preset.get("target") != "Thorn V2 / 00.00.01.16"
            or not isinstance(preset.get("settings"), dict)):
        raise _cfg().CfgError("expected a SuperLamzu Thorn V2 preset (format/schema 1)")
    return preset


def apply_typed(m, name, value):
    C = _cfg()
    if name == "dpi":
        m.set_stages([tuple(x) for x in value])
    elif name == "dpi-active": m.set_active_stage(value)
    elif name == "lod": m.set_lod(value)
    elif name == "sleep": m.set_sleep(value * 60)
    elif name == "speed-click": m.set_speed_click(*value)
    elif name == "debounce": m.set_debounce([value[k] for k in P.DB_NAMES])
    elif name == "fps":
        if isinstance(value, dict): m.fps_custom_set(value)
        else: m.fps_set(value)
    elif name == "lock": m.lock_switch(value)
    elif name == "lock-lead": m.lock_lead(value)
    elif name == "tracking": m.tracking_set(value)
    elif name == "path": m.motion_path(value)
    elif name == "abs": m.abs_motion(value)
    elif name == "smoothing": m.smoothing_set(value)
    elif name == "polling": m.set_polling(value)
    elif name == "angle-tune": m.set_angle_tune(value)
    else: m.set_flag(name, value)
    C.verify(lambda: read_typed(m, name), value, name)


def do_apply(m, preset, *, dry_run=False, only=(), skip=(), save=False):
    """Validate the complete selected input before writes; stop on first failure.

    Reuse dev semantics: capability skips, unchanged skips, ordered typed writes,
    and dry-run. Target differences: no hidden failed reads or implicit defaults.
    """
    C = _cfg()
    validate_preset(preset)
    rows = {r["name"]: r for r in registry()}
    for n in (*only, *skip):
        if n not in rows:
            raise C.CfgError(f"unknown selection {n!r}")
    todo, result = {}, []
    for name, value in preset["settings"].items():
        if name not in rows:
            result.append(dict(name=name, status="unknown-skipped"))
        elif (not only or name in only) and name not in skip:
            todo[name] = validate_typed(name, value)
    caps = capabilities(m)
    if save and not caps["flags"] & P.F_ADV_SAVED:
        raise C.Unsupported("explicit advanced save is not supported by this firmware")
    supported = {}
    for n, v in todo.items():
        required = rows[n]["requires"] | (P.F_FPS_CUSTOM if n == "fps" and isinstance(v, dict) else 0)
        if caps["flags"] & required != required:
            result.append(dict(name=n, status="unsupported-skipped"))
        else:
            supported[n] = v
    if isinstance(supported.get("fps"), int) and supported["fps"] >= caps["preset_count"]:
        raise C.CfgError("fps preset ID is not available in this firmware")
    now = {n: read_typed(m, n) for n in supported}
    if "dpi" in supported or "dpi-active" in supported:
        stages = supported.get("dpi") or read_typed(m, "dpi")
        active = supported.get("dpi-active", read_typed(m, "dpi-active"))
        if active > len(stages):
            raise C.CfgError("dpi-active exceeds the resulting stage count; include a valid dpi-active")
    order = list(rows)
    # Shrinking the stage list must not temporarily retain an out-of-range
    # active index; expanding does the inverse (list first, index second).
    if "dpi" in supported and "dpi-active" in supported and supported["dpi-active"] <= len(read_typed(m, "dpi")):
        order.remove("dpi-active")
        order.insert(0, "dpi-active")
    saved = False
    for name in order:
        if name not in supported:
            continue
        if name == "polling" and save and not dry_run:
            m.save_advanced()
            saved = True
        value = supported[name]
        status = "unchanged" if now[name] == value else "would-change" if dry_run else "changed"
        item = dict(name=name, status=status, before=now[name], requested=value)
        result.append(item)
        if status == "changed":
            try:
                apply_typed(m, name, value)
            except (C.CfgError, OSError) as exc:
                item.update(status="failed", error=str(exc))
                return dict(dry_run=False, results=result, complete=False, saved=saved)
    if save and not dry_run and not saved:
        m.save_advanced()
    return dict(dry_run=dry_run, results=result, complete=True, saved=bool(save and not dry_run))


def preset_path(name, *, must_exist=True):
    path = Path(name)
    if path.suffix.lower() != ".json" and len(path.parts) == 1:
        if not re.fullmatch(r"[A-Za-z0-9_-][A-Za-z0-9._-]*", name):
            raise _cfg().CfgError("preset name must contain letters, digits, dot, underscore or hyphen")
        path = Path(os.environ.get("SUPERLAMZU_PRESETS", T.ROOT / ".panel" / "presets")) / (name + ".json")
    if must_exist and not path.is_file():
        raise _cfg().CfgError(f"preset does not exist: {path}")
    return path


def load_preset(name):
    try:
        return validate_preset(json.loads(preset_path(name).read_text(encoding="utf-8")))
    except (OSError, ValueError) as exc:
        raise _cfg().CfgError(f"cannot read preset: {exc}") from exc
