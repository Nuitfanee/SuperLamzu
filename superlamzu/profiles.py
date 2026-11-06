"""Firmware variants share functional settings; only FULL includes telemetry."""
from . import protocol as P

PROFILES = ('FULL', 'SUPER')
TELEMETRY_FLAGS = P.F_STATS | P.F_CHANNELS | P.F_RADIO_OUTCOMES


def telemetry(profile):
    if profile not in PROFILES:
        raise ValueError(f'unsupported firmware profile: {profile!r}; choose FULL or SUPER')
    return profile == 'FULL'


def policy(profile):
    enabled = telemetry(profile)
    return dict(profile=profile, telemetry=enabled,
                purpose='diagnostic' if enabled else 'daily use',
                telemetry_performance_gate=False,
                snapshot='explicit on-demand configuration readback; retained in both variants')
