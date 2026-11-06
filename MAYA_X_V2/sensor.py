"""MAYA sensor adaptation using the existing Builder and real Thumb runner.

This constructs the sensor foundation in memory. Verified paired FULL export
is owned by MAYA_X_V2.build; this module never offers hardware operations.
"""
from superlamzu.common import Builder
from superlamzu.emulation import MemoryLayout, sensor_run
from superlamzu.patch import compress_recipes

from . import target as T

LAYOUT = MemoryLayout(
    ram_regions=((0x20000000, 0x80000),), stack=T.SP, stop=0x2007F000,
    copies=T.COPIES, site_exclusions=((T.WR, T.RD + 8),))


def run(image, entry, wr=T.WR, rd=T.RD, rd_value=0xA5, args=(), mapped=False):
    return sensor_run(image, entry, (wr, T.NATIVE_WR), (rd, T.NATIVE_RD),
                      rd_value, args=args, mapped=True, layout=LAYOUT)


def stock():
    T.inventory()
    return Builder(T.STOCK, target=T)


def build_foundation():
    builder = stock()
    builder.recipes = compress_recipes(builder, target=T, runner=run)
    for site, value in T.DOWNSHIFT_SITES.items():
        address = T.flash_source(site) - 4
        if builder.image.get(address, 4) != bytes([value, 0x21, 0x44, 0x20]):
            raise ValueError(f'MAYA downshift original instruction changed at {address:#x}')
        builder.edit(address, bytes([value | 0x40]), 'downshift B outside compressed recipes')
    return builder
