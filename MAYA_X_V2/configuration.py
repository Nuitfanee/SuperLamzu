"""MAYA native-profile integration using the shared SLZ1 Thumb dispatcher.

The intermediate native fixture advertises only sensor/debounce capabilities;
FULL passes its complete installed owners. This module exports no image.
"""
from superlamzu.patch import install_extension

from . import target as T
from .sensor import build_foundation


def install(builder, advanced=None):
    if advanced is None:
        reject = builder.code('advanced_pending', ['movs r0,#0', 'bx lr'])
        advanced = dict(get=reject, set=reject, flags=0, preset_count=0)
    builder.extension = install_extension(builder, advanced, target=T)
    return builder.extension


def build_native():
    builder = build_foundation()
    install(builder)
    return builder
