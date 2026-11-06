"""Representable PAW3955 timing recipes; no device access or invented fractions."""
from __future__ import annotations

import bisect
import math

FIELDS = ("unit", "slow", "fast")
PRODUCTS = sorted({u * m for u in range(1, 256) for m in range(1, 256)})


def recipe(value):
    if not isinstance(value, dict) or set(value) != set(FIELDS):
        raise ValueError("自定义时序须包含 U、慢速倍率和快速倍率。")
    if any(type(value[k]) is not int or not 1 <= value[k] <= 255 for k in FIELDS):
        raise ValueError("三个寄存器参数均须为 1–255 的整数。")
    if value["slow"] < value["fast"]:
        raise ValueError("慢速倍率不能小于快速倍率；固定帧率请设为相同值。")
    return {key: value[key] for key in FIELDS}


def for_product(product):
    pairs = [(u, product // u) for u in range(1, 256)
             if product % u == 0 and 1 <= product // u <= 255]
    if not pairs:
        raise ValueError("该周期积无法用两个 8 位寄存器表示。")
    u, m = min(pairs, key=lambda p: (abs(p[1] - 2), -p[0]))
    return dict(unit=u, slow=m, fast=m)


def describe(value, coefficient):
    r = recipe(value)
    u, slow, fast = (r[k] for k in FIELDS)
    return dict(**r, fixed=slow == fast, nominal_min_hz=800000 / (u * slow),
                nominal_max_hz=800000 / (u * fast),
                estimated_min_hz=coefficient / (u * slow),
                estimated_max_hz=coefficient / (u * fast),
                nominal_period_us=u * fast * 1.25,
                registers={"07:42": u, "06:53": slow, "06:62": fast})


def preview(value, coefficient):
    info = describe(value, coefficient)
    if info["fixed"]:
        product = info["unit"] * info["fast"]
        i = bisect.bisect_left(PRODUCTS, product)
        info["faster"] = for_product(PRODUCTS[i - 1]) if i > 0 else None
        info["slower"] = for_product(PRODUCTS[i + 1]) if i + 1 < len(PRODUCTS) else None
    else:
        info.update(faster=None, slower=None)
    return info


def choose(target_hz, coefficient):
    low, high = coefficient / PRODUCTS[-1], coefficient / PRODUCTS[0]
    if type(target_hz) not in (int, float) or not math.isfinite(target_hz) or not low <= target_hz <= high:
        raise ValueError(f"目标须在可表示范围 {low:.3f}–{high:.3f} FPS 内。")
    product = min(PRODUCTS, key=lambda p: abs(coefficient / p - target_hz))
    return dict(target_hz=float(target_hz), error_hz=coefficient / product - target_hz,
                **preview(for_product(product), coefficient))
