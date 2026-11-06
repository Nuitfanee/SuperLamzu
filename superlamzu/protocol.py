"""SLZ1 extension ABI, independent of HyperDrako's global-override protocol.

64-byte report: [3] payload length, [4] group 1, [5] SET 0x16 / GET 0x96.
Payload starts at [6]: profile (1..3 for DB, 0 for global operations), operation,
then arguments. Unknown operations are rejected without side effects.
"""
import struct

MAGIC = b"SLZ1"
API_VERSION = 1
GROUP = 1
SET = 0x16
GET = 0x96
CAPS, DEBOUNCE, FPS, LOCK, STATS = range(5)
FPS_CUSTOM = 5
SENSOR_SNAPSHOT = 6
SMOOTHING, SAVE_ADVANCED = 7, 8
IDLE_TRACKING = 9
MOTION_PATH = 10
ABS_MOTION = 11
OPTICAL_CLICK = 12
CHANNELS = 13
F_DB, F_B, F_FPS, F_STATS, F_LOCK, F_ADV_SAVED, F_A = (1 << i for i in range(7))
F_FPS_CUSTOM = 1 << 7
F_SENSOR_SNAPSHOT = 1 << 8
F_SMOOTHING = 1 << 9
F_IDLE_TRACKING = 1 << 10
F_MOTION_PATH = 1 << 11
F_ABS = 1 << 12
F_OPTICAL_CLICK = 1 << 13  # Legacy capability; current firmware never advertises it.
F_CHANNELS = 1 << 14
# Corrected receive-window outcomes; absent on older, misclassified FULLs.
F_RADIO_OUTCOMES = 1 << 15
RADIO_OUTCOME_SEMANTICS = 'receiver-window-v1'
# Explicit save keeps existing FPS/LOCK SET operations session-only unless saved.
ADV_MAGIC = b'SLZ2'
ADV_RECORD_VERSION = 5
ADV_RECORD_BYTES = 16


def decode_channels(raw):
    """Legacy four-hop diagnostics or explicit MAYA five-hop v1 snapshot."""
    import struct
    raw = bytes(raw)
    if len(raw) not in (28, 36) or raw[:2] != bytes((0, CHANNELS)) or raw[2] not in (0, 1):
        raise ValueError('invalid channel diagnostic envelope')
    if len(raw) == 28:
        if raw[3] != 0:
            raise ValueError('invalid legacy channel diagnostic status')
        count, start = 4, 4
    else:
        if raw[3:6] != bytes((1, 5, 0)) or raw[35] != 0:
            raise ValueError('invalid five-hop diagnostic version/count/reserved byte')
        count, start = 5, 6
    end = start + (count + 1) * 2
    hops = end + (count + 1) * 2
    return dict(enabled=bool(raw[2]), sent=list(struct.unpack(f'<{count+1}H', raw[start:end])),
                missed=list(struct.unpack(f'<{count+1}H', raw[end:hops])),
                hops=list(raw[hops:hops+count]), unknown_bucket=count,
                counter_bits=16, snapshot_atomic=True)

SENSOR_REGISTERS = ((7, 0x42), (6, 0x53), (6, 0x62), (6, 0x6D),
                    (6, 0x6E), (7, 0x40), (7, 0x43), (0, 0x40))
SENSOR_SNAPSHOT_BYTES = 24
CUSTOM_FPS_ID = 255
PROFILE_COUNT = 3
NATIVE_CPI_MAX = 40000
DB_NAMES = ("pre", "post", "plock", "relock")
DB_FACTORY = (0, 2, 20, 20)
STATS_BYTES = 188


def capabilities(flags, preset_count=0):
    """Reply: magic[4], API, flags LE16, profiles, max CPI LE16, stats bytes, presets."""
    return MAGIC + struct.pack("<BHBHBB", API_VERSION, flags, PROFILE_COUNT,
                               NATIVE_CPI_MAX, STATS_BYTES if flags & F_STATS else 0,
                               preset_count)


def decode_capabilities(data):
    if len(data) != 12 or data[:4] != MAGIC:
        raise ValueError("not an SLZ1 capability reply")
    version, flags, profiles, cpi, stats_bytes, presets = struct.unpack("<BHBHBB", data[4:])
    if version != API_VERSION:
        raise ValueError(f"unsupported SLZ1 API version {version}")
    return dict(api=version, flags=flags, profiles=profiles, cpi_max=cpi,
                stats_bytes=stats_bytes, preset_count=presets)
