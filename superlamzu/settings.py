"""Versioned FULL settings and worker-only 0C:4D adjustment.

The snapshot ABI remains 24 bytes; its native-heap block also holds ABS totals. One byte at
the end of queue2 holds requested/pending/verified/readback state. No new
per-motion SPI or heap allocation is introduced.
"""
import struct

from . import protocol as P, target as T
from .advanced import addr, call, tail

REQUEST, PENDING, VALID, ERROR = 1, 2, 4, 64
VALUES = (0, 2, 0x10, 0x13, 0x27, 0x90)


def encode_record(fps=0, lock=0, lead=0, custom=(0, 0, 0), smoothing=0, tracking=0, version=P.ADV_RECORD_VERSION, motion_path=0, abs_motion=0, optical_click=0):
    from .advanced import PRESETS
    if fps not in (*range(len(PRESETS)), P.CUSTOM_FPS_ID) or lock not in (0, 1):
        raise ValueError('invalid saved FPS/LOCK')
    if not 0 <= lead <= 499 or smoothing not in (0, 1) or tracking not in (0,1):
        raise ValueError('invalid saved lead/smoothing')
    if (version not in (1,2,3,4,5) or version==1 and tracking or motion_path not in (0,1)
            or version<3 and motion_path or abs_motion not in (0,1) or version<4 and abs_motion
            or optical_click not in (0,1) or version<5 and optical_click):
        raise ValueError('invalid saved version/tracking/path')
    custom = bytes(custom)
    if len(custom) != 3 or (fps == 255 and (not all(custom) or custom[1] < custom[2])):
        raise ValueError('invalid saved custom recipe')
    data = P.ADV_MAGIC + bytes((version, smoothing, fps, lock)) + custom + bytes((tracking | motion_path<<1 | abs_motion<<2 | optical_click<<3,)) + struct.pack('<H', lead)
    return data + struct.pack('<H', (sum(data) + 0x5A5A) & 65535)


def decode_record(data):
    data = bytes(data)
    if len(data) != 16 or data[:4] != P.ADV_MAGIC or data[4] not in (1,2,3,4,5) or data[11] > (0,0,1,3,7,15)[data[4]]:
        raise ValueError('invalid settings magic/version/reserved byte')
    fields = dict(fps=data[6], lock=data[7], lead=int.from_bytes(data[12:14], 'little'),
                  custom=tuple(data[8:11]), smoothing=data[5], tracking=data[11]&1,
                  motion_path=(data[11]>>1)&1, abs_motion=(data[11]>>2)&1, optical_click=(data[11]>>3)&1)
    if encode_record(**fields,version=data[4]) != data:
        raise ValueError('invalid settings checksum')
    return fields


def memory_evidence(image):
    if T.SMOOTHING_STATE + 1 != T.RADIO_QUEUE2 + 298:
        raise ValueError('smoothing state must end exactly before queue3')
    for address, original in ((T.STORAGE_WRITE, T.STORAGE_WRITE_PREIMAGE),
                              (T.STORAGE_DRIVER, T.STORAGE_DRIVER_BYTES),
                              (T.STORAGE_LOAD_HOOK, bytes.fromhex('04f083ff'))):
        if image.get(address, len(original)) != original:
            raise ValueError(f'advanced storage preimage changed at {address:#x}')
    return dict(runtime=T.SMOOTHING_STATE, runtime_bytes=1,
                storage=T.ADV_STORAGE, storage_bytes=16, driver=T.STORAGE_WRITE,
                native_profile_range=[0x1A7000, 0x1A72C0],
                next_native_owner=0x1A8000,
                lifecycle='explicit save; native reset/profile writes remain confined to 704 bytes',
                evidence='target-adaptation storage callers, lifecycle, driver and reset boundaries')


def _validate_lines(preset_count):
    # r0 points to the persisted record; returns 1/0 and preserves r4..r11.
    return (['push {r4,lr}', 'mov r4,r0', 'ldr r1,[r4]'] + addr('r2', int.from_bytes(P.ADV_MAGIC, 'little'))
        + ['cmp r1,r2', 'bne bad', 'ldrb r1,[r4,#4]', 'cmp r1,#1', 'blo bad', 'cmp r1,#5', 'bhi bad',
           'ldrb r2,[r4,#11]', 'subs r1,#1', 'movs r3,#1', 'lsls r3,r1', 'subs r3,#1', 'cmp r2,r3', 'bhi bad',
           'ldrb r1,[r4,#5]', 'cmp r1,#1', 'bhi bad', 'ldrb r1,[r4,#7]', 'cmp r1,#1', 'bhi bad',
           'ldrh r1,[r4,#12]', 'movw r2,#499',
           'cmp r1,r2', 'bhi bad', 'ldrb r1,[r4,#6]', 'cmp r1,#255', 'beq custom',
           f'cmp r1,#{preset_count}', 'bhs bad', 'b checksum', 'custom:',
           'ldrb r1,[r4,#8]', 'cmp r1,#0', 'beq bad', 'ldrb r1,[r4,#10]', 'cmp r1,#0', 'beq bad',
           'ldrb r2,[r4,#9]', 'cmp r2,r1', 'blo bad', 'checksum:', 'movs r1,#0', 'movs r2,#0',
           'sum:', 'ldrb r3,[r4,r1]', 'adds r2,r3', 'adds r1,#1', 'cmp r1,#14', 'bne sum',
           'movw r3,#0x5a5a', 'adds r2,r3', 'uxth r2,r2', 'ldrh r3,[r4,#14]', 'cmp r2,r3',
           'bne bad', 'movs r0,#1', 'pop {r4,pc}', 'bad:', 'movs r0,#0', 'pop {r4,pc}'])


def _save_lines(*, target=T):
    T = target
    from functools import partial
    call = partial(globals()["call"], target=target)
    # Snapshot live settings atomically; no changes to native profile data.
    lines = ['push {r4,r5,lr}', 'sub sp,#20'] + addr('r4', T.ADV_RAM)
    lines += addr('r0', int.from_bytes(P.ADV_MAGIC, 'little')) + ['str r0,[sp]', f'movs r0,#{P.ADV_RECORD_VERSION}', 'strb r0,[sp,#4]']
    lines += ['.hword 0xf3ef,0x8510', 'cpsid i'] + addr('r0', T.SMOOTHING_STATE)
    lines += ['ldrb r0,[r0]', 'lsrs r1,r0,#7', 'and r0,r0,#1', 'strb r0,[sp,#5]']
    lines += addr('r0', T.MOTION_STATE) + ['ldrb r0,[r0]', 'ubfx r2,r0,#6,#1',
             'ubfx r0,r0,#4,#1', 'orr r1,r1,r0,lsl #1',
             'orr r1,r1,r2,lsl #2', 'strb r1,[sp,#11]']
    for source, dest in ((3,6),(2,7),(13,8),(14,9),(15,10)):
        lines += [f'ldrb r0,[r4,#{source}]', f'strb r0,[sp,#{dest}]']
    lines += ['ldrh r0,[r4,#4]', 'strh r0,[sp,#12]',
              '.hword 0xf385,0x8810', 'mov r1,sp', 'movs r2,#0', 'movs r3,#14',
              'sum:', 'ldrb r0,[r1],#1', 'adds r2,r0', 'subs r3,#1', 'bne sum',
              'movw r0,#0x5a5a', 'adds r2,r0', 'strh r2,[sp,#14]']
    lines += addr('r0', T.ADV_STORAGE_OFFSET) + ['mov r1,sp', 'movs r2,#16'] + call(T.STORAGE_WRITE)
    lines += ['cmp r0,#0', 'bne bad'] + addr('r1', T.ADV_STORAGE)
    lines += ['mov r2,sp', 'movs r3,#16', 'verify:', 'ldrb r0,[r1],#1', 'ldrb r4,[r2],#1',
              'cmp r0,r4', 'bne bad', 'subs r3,#1', 'bne verify', 'movs r0,#1', 'b out',
              'bad:', 'movs r0,#0', 'out:', 'add sp,#20', 'pop {r4,r5,pc}']
    return lines


def _apply_lines(*, target=T):
    from functools import partial
    call = partial(globals()["call"], target=target)
    # r0/r1 = actual dispatcher mode/variant, not globals updated after dispatch.
    lines = ['push {r4,r5,r6,r7,lr}', 'sub sp,#4', 'mov r5,r0', 'mov r6,r1'] + addr('r4', target.SMOOTHING_STATE)
    lines += ['ldrb r7,[r4]', 'and r7,r7,#127', 'cmp r7,#0', 'beq out', 'and r7,r7,#1', 'movs r0,#0', 'str r0,[sp]',
              'cmp r5,#4', 'beq eligible', 'cmp r5,#6', 'beq eligible', 'cmp r5,#7', 'beq eligible',
              # No SPI in stock/unaffected modes; explicitly invalidate stale readback.
              'movs r0,#0', 'b publish', 'eligible:', 'cmp r6,#1', 'blo failed', 'cmp r6,#3', 'bhi failed',
              'cmp r6,#1', 'beq small',
              'cmp r7,#1', 'beq small', 'cmp r5,#4', 'beq wired', 'cmp r5,#6', 'beq two',
              'movs r6,#39', 'movs r5,#4', 'b selected', 'two:', 'movs r6,#19', 'movs r5,#3',
              'b selected', 'wired:', 'movs r6,#144', 'movs r5,#5', 'b selected',
              'small:', 'movs r6,#2', 'movs r5,#1', 'selected:',
              'movs r0,#127', 'movs r1,#12'] + call(target.WR)
    lines += ['cmp r0,#0', 'beq failed', 'cmp r7,#0', 'beq read', 'movs r0,#77', 'movs r1,#2'] + call(target.WR)
    lines += ['cmp r0,#0', 'beq failed', 'read:', 'movs r0,#77', 'mov r1,sp'] + call(target.RD)
    lines += ['cmp r0,#0', 'beq failed', 'ldrb r0,[sp]', 'cmp r0,r6', 'bne failed',
              'movs r0,#127', 'movs r1,#0'] + call(target.WR)
    lines += ['cmp r0,#0', 'beq failed', 'lsls r0,r5,#3', 'orr r0,r0,#4', 'b publish', 'failed:',
              'movs r0,#127', 'movs r1,#0'] + call(target.WR)
    lines += ['movs r0,#66', 'publish:', '.hword 0xf3ef,0x8c10', 'cpsid i',
              'ldrb r1,[r4]', 'and r2,r1,#1', 'cmp r2,r7', 'bne changed', 'and r1,r1,#128',
              'orrs r0,r7', 'orrs r0,r1', 'strb r0,[r4]',
              'changed:', '.hword 0xf38c,0x8810', 'out:', 'add sp,#4', 'pop {r4,r5,r6,r7,pc}']
    return lines


def install(b, getter, setter, preset_count, storage):
    evidence = memory_evidence(b.image)
    validate = b.code('settings_validate', _validate_lines(preset_count))
    save = b.code('settings_save', _save_lines())
    restore = b.code('settings_restore', ['push {r4,lr}', 'add r4,r4,#9']
        + addr('r0', T.ADV_STORAGE_OFFSET) + ['mov r1,r4', 'movs r2,#16'] + call(T.STORAGE_WRITE)
        + ['cmp r0,#0', 'bne bad'] + addr('r1', T.ADV_STORAGE)
        + ['movs r2,#16', 'compare:', 'ldrb r0,[r1],#1', 'ldrb r3,[r4],#1', 'cmp r0,r3',
           'bne bad', 'subs r2,#1', 'bne compare', 'movs r0,#1', 'pop {r4,pc}',
           'bad:', 'movs r0,#0', 'pop {r4,pc}'])
    # Queue init happens after native load. Load the extension at queue startup,
    # after the 188-byte STATS clear, so it cannot be accidentally zeroed again.
    # Both callers run in thread context. Failure leaves ABS off; it never
    # publishes an enabled flag pointing at unallocated memory.
    abs_set = b.code('settings_abs_set', ['push {r4,lr}', 'mov r4,r0', 'cbz r0,publish']
        + call(storage) + ['cbz r0,out', 'publish:']
        + addr('r1', T.MOTION_STATE) + ['.hword 0xf3ef,0x8c10', 'cpsid i',
           'ldrb r2,[r1]', 'ubfx r0,r2,#6,#1', 'cmp r0,r4', 'beq success',
           'tst r2,#32', 'bne busy']
        # A full downstream queue can leave XY outside queue2. Switching to
        # ABS then would replace those deltas with unrelated saved totals.
        + [f'sub.w r3,r1,#{T.MOTION_STATE-T.RADIO_QUEUE2}',
           f'subw r0,r3,#{T.RADIO_QUEUE2-T.MOTION_ACC_Y}',
           'ldr r0,[r0]', 'cbnz r0,busy',
           'ldrb r0,[r3]', 'cbnz r0,busy',
           'ldrb r0,[r3,#2]', 'ldrb r3,[r3,#3]', 'cmp r0,r3', 'bne busy',
           # Validated 0/1 differs from the live mode on this path.
           'eor r2,r2,#64', 'strb r2,[r1]',
           'success:', 'movs r0,#1', 'b unmask', 'busy:', 'movs r0,#0',
           'unmask:', '.hword 0xf38c,0x8810', 'out:', 'pop {r4,pc}'])
    load = b.code('settings_load', ['push {r4,r5,r6,lr}'] + addr('r4', T.ADV_STORAGE)
        + ['mov r0,r4'] + call(validate) + ['cmp r0,#0', 'beq out'] + addr('r5', T.ADV_RAM)
        + ['ldrb r0,[r4,#6]', 'strb r0,[r5,#3]', 'ldrb r0,[r4,#7]', 'strb r0,[r5,#2]',
           'ldrh r0,[r4,#12]', 'strh r0,[r5,#4]', 'ldrb r0,[r4,#8]', 'strb r0,[r5,#13]',
           'ldrb r0,[r4,#9]', 'strb r0,[r5,#14]', 'ldrb r0,[r4,#10]', 'strb r0,[r5,#15]']
        + ['movs r0,#1', 'strb r0,[r5,#9]'] + addr('r5', T.SMOOTHING_STATE)
        + ['ldrb r0,[r4,#5]', 'ldrb r1,[r4,#11]', 'orr r0,r0,r1,lsl #7', 'orr r0,r0,#2', 'strb r0,[r5]']
        + addr('r5', T.MOTION_STATE) + ['ldrb r0,[r5]', 'bic r0,r0,#16', 'and r1,r1,#2',
           'orr r0,r0,r1,lsl #3', 'strb r0,[r5]',
           'ldrb r0,[r4,#11]', 'ubfx r0,r0,#2,#1'] + call(abs_set)
        # v5 bit 3 belonged to the retired optical-direct mode. Validate old
        # records, but never apply that bit or discard their other settings.
        + addr('r0', T.SENSOR_READY)
        + ['ldrb r0,[r0]', 'cmp r0,#0', 'beq out'] + addr('r0', T.SENSOR_MODE)
        + ['ldrb r0,[r0]'] + call(T.SET_SENSOR_MODE) + ['out:', 'pop {r4,r5,r6,pc}'])
    get = b.code('settings_get', ['subs r0,r5,#7', 'cmp r0,#4', 'bls ours'] + tail(getter)
        + ['ours:', 'push {r7,lr}', 'cmp r6,#0', 'bne bad', 'ldrb r0,[r4,#3]', 'cmp r0,#2', 'bne bad',
           'cmp r5,#8', 'beq saved', 'cmp r5,#10', 'blo smoothing']
        + addr('r1', T.MOTION_STATE) + ['ldrb r0,[r1]', 'cmp r5,#11', 'ite eq',
           'ubfxeq r0,r0,#6,#1', 'ubfxne r0,r0,#4,#1', 'b value', 'smoothing:'] + addr('r1', T.SMOOTHING_STATE)
        + ['ldrb r0,[r1]', 'cmp r5,#9', 'ite eq', 'lsreq r0,r0,#7', 'andne r0,r0,#127',
           'value:', 'strb r0,[r4,#8]', 'movs r0,#3', 'b success', 'saved:']
        + addr('r0', T.ADV_STORAGE) + call(validate) + ['strb r0,[r4,#8]', 'add r2,r4,#9']
        + addr('r1', T.ADV_STORAGE) + ['movs r3,#16', 'copy:', 'ldrb r0,[r1],#1', 'strb r0,[r2],#1',
           'subs r3,#1', 'bne copy', 'movs r0,#19', 'success:', 'strb r0,[r4,#3]', 'movs r0,#1',
           'pop {r7,pc}', 'bad:', 'movs r0,#0', 'pop {r7,pc}'])
    set = b.code('settings_set', ['subs r0,r5,#7', 'cmp r0,#4', 'bls ours'] + tail(setter)
        + ['ours:', 'push {r7,lr}', 'cmp r6,#0', 'bne bad', 'ldrb r0,[r4,#3]',
           'cmp r5,#8', 'bne normal', 'cmp r0,#19', 'bne normal', 'ldrb r0,[r4,#8]',
           'cmp r0,#2', 'bne bad'] + call(restore) + ['cmp r0,#0', 'beq bad', 'b reply',
           'normal:', 'cmp r0,#3', 'bne bad',
           'ldrb r0,[r4,#8]', 'cmp r5,#8', 'beq save', 'cmp r0,#1', 'bhi bad',
           'cmp r5,#11', 'bne path'] + call(abs_set) + ['cmp r0,#0', 'beq bad', 'b reply', 'path:',
           'cmp r5,#10', 'bne smoothing'] + addr('r1', T.MOTION_STATE)
        + ['.hword 0xf3ef,0x8c10', 'cpsid i', 'ldrb r2,[r1]', 'bic r2,r2,#16',
           'orr r0,r2,r0,lsl #4', 'strb r0,[r1]', '.hword 0xf38c,0x8810', 'b reply', 'smoothing:']
        + addr('r1', T.SMOOTHING_STATE) + ['.hword 0xf3ef,0x8c10', 'cpsid i', 'ldrb r2,[r1]',
           'cmp r5,#9', 'beq track', 'and r2,r2,#128', 'orrs r0,r2', 'orr r0,r0,#2', 'strb r0,[r1]',
           '.hword 0xf38c,0x8810', 'b mode', 'track:', 'and r2,r2,#127', 'orr r0,r2,r0,lsl #7',
           'strb r0,[r1]', '.hword 0xf38c,0x8810', 'b reply', 'mode:'] + addr('r0', T.SENSOR_MODE)
        + ['ldrb r0,[r0]'] + call(T.SET_SENSOR_MODE) + ['b reply', 'save:', 'cmp r0,#1', 'bne bad']
        + call(save) + ['cmp r0,#0', 'beq bad', 'reply:', 'movs r0,#2', 'strb r0,[r4,#3]']
        + call(get) + ['pop {r7,pc}', 'bad:', 'movs r0,#0', 'pop {r7,pc}'])
    apply = b.code('settings_smoothing_apply', _apply_lines())
    return dict(get=get, set=set, load=load, apply=apply, save=save,
                abs_set=abs_set,memory=evidence)
