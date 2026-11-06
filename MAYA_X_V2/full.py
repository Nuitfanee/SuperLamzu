"""Paired FULL diagnostics and SUPER daily-use builds with shared settings."""
from superlamzu.profiles import TELEMETRY_FLAGS,telemetry,policy
from . import target as T

PROFILE='FULL'
FLAGS=0xDFBF
MOUSE_FILENAME='LAMZU_MAYA_X_V2_MOUSE_FULL_0.0.3.0.hex'
RECEIVER_FILENAME='LAMZU_MAYA_X_V2_RECEIVER_FULL_0.0.3.0.hex'


def flags(profile='FULL'):
    return FLAGS if telemetry(profile) else FLAGS & ~TELEMETRY_FLAGS


def filenames(profile='FULL'):
    telemetry(profile)
    return (MOUSE_FILENAME.replace('_FULL_',f'_{profile}_'),
            RECEIVER_FILENAME.replace('_FULL_',f'_{profile}_'))


def build_pair(profile='FULL'):
    from .advanced import build_motion_stage
    from .receiver import build_absolute_stage
    mouse,receiver=build_motion_stage(profile),build_absolute_stage()
    receiver.profile=profile
    if mouse.extension['flags'] != flags(profile):
        raise ValueError(f'incomplete MAYA {profile} capabilities')
    return mouse,receiver


def scope(profile='FULL'):
    return dict(profile=profile,variant=policy(profile),version=T.VERSION,mouse_flags=flags(profile),
        hardware='not run; offline build only',
        preserved=['nine stock recipes','native LOD','six-byte burst','high-CPI differences',
                   'native debounce and optical IR/wake','receiver three LEDs',
                   'native 8kHz CC0=120us exception','stock MPU permissions'],
        target_differences=dict(profile_stride=233,native_settings_bytes=708,
            clock='native HFXO request/wait/release',
            lock='1MHz CC1 period / CC0 read; legacy for ineligible lead, storage or layout',
            wireless_motion='native synchronous direct / independent priority6 done thread',
            wired_motion='native synchronous; ordered old-thread transition drain',
            receiver_sof='USBHS PUBLISH_SOF -> DPPI -> TIMER20 CLEAR',
            channel_reply_bytes=36,channel_hops=5,unknown_bucket=5,
            radio_outcome_semantics='receiver-window-v1' if telemetry(profile) else None,
            mouse_heap_bytes=408,
            optional_done_runtime=dict(payload_request_bytes=1224,owned_bytes=1216,
                stack_bytes=1024,priority=6,lifetime='lazy once until restart'),
            receiver_abs_bytes=5),
        defaults=dict(click='stock',motion='direct',abs=False,stats=False,channels=False),
        persistence='explicit 16B SLZ2 v5; v1..v5 migration; native RRAM owner')
