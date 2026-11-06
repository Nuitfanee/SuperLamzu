"""Target-native FPS, timing counters and radio phase lock (session-only).

Only install() mutates a Builder. Importing this module never accesses a device.
"""
import struct

from . import protocol as P, target as T

ADV_RAM, ADV_BYTES = T.ADV_RAM, T.ADV_BYTES
REPORT_TIMER, RADIO_EVENT = T.REPORT_TIMER, T.RADIO_EVENT
RSTATE, Q2 = T.RADIO_STATE, T.RADIO_QUEUE2
DIVIDER, TPMS, HOP = T.REPORT_DIVIDER, T.TICKS_PER_MS, T.HOP_INDEX
MODE, VARIANT = T.SENSOR_MODE, T.SENSOR_VARIANT
WR, RD = T.WR, T.RD
IRQ, DISPATCH = T.RADIO_IRQ, T.RECIPE_DISPATCH
SNAP_PTR = T.SNAPSHOT_POINTER  # Three-byte pointer in the reclaimed queue2 tail.
SNAP_ALLOC = T.NATIVE_ALLOC  # Native k_malloc wrapper, also used by the protocol worker.
SENSOR_QUEUE, SENSOR_READY, SNAP_MESSAGE = T.SENSOR_QUEUE, T.SENSOR_READY, 11

# First 16 bytes are live configuration/recovery state; reset never clears them.
VERSION, ENABLED, LOCK_ON, FPS, LEAD, LAST = 0, 1, 2, 3, 4, 6
APPLIED, PENDING, LAST_CONN, LAST_POST = 8, 9, 10, 11
LOCK_OWNS = 12
CUSTOM_REQUEST = 13  # U, slow, fast; retained by a counter reset
CUSTOM_READBACK = 184  # Previously reserved word: U, slow, fast, verified flag
COUNTER_START = 16
FIELDS = (
    'ticks', 'not_ready', 'health_skip', 'health_trip', 'last_bad_status',
    'reads_started', 'read_start_fail', 'spi_ok', 'spi_bad', 'reinit',
    'samples', 'samples_motion', 'tx_queued', 'tx_full',
    'slot_ends', 'acked', 'no_ack', 'hops', 'link_lost', 'link_up',
    'tx_attempts', 'idle_slots', 'miss_run', 'max_miss_run',
    'lock_adjust', 'lock_skip', 'lock_rescue',
    'phase_count', 'phase_sum_us', 'phase_max_us', 'period_us',
    'phase_bin0', 'phase_bin1', 'phase_bin2', 'phase_bin3',
    'phase_bin4', 'phase_bin5', 'phase_bin6', 'phase_bin7',
    'fps_apply', 'fps_fail', 'capture_fail', 'reserved',
)
OFF = {name: COUNTER_START + i * 4 for i, name in enumerate(FIELDS)}
assert COUNTER_START + len(FIELDS) * 4 == ADV_BYTES

# Source mechanism's periods. Keep the target mode/variant's 06:6D/6E pair.
# Index zero is stock, so preset identifiers are unambiguous on the wire.
PRESETS = (
    ('stock', 0, 0, 0),
    ('20k', 20, 2, 2), ('19k', 21, 2, 2), ('18k', 22, 2, 2),
    ('17k', 24, 2, 2), ('16k', 25, 2, 2), ('15k', 27, 2, 2),
    ('14k', 29, 2, 2), ('13k', 31, 2, 2), ('12k', 33, 2, 2),
    ('11k', 36, 2, 2), ('10k', 20, 4, 4), ('9k', 22, 4, 4),
    ('8k', 20, 5, 5), ('7k', 38, 3, 3), ('6k', 33, 4, 4),
    ('5k', 20, 8, 8), ('4k', 20, 10, 10),
    ('13-20k', 20, 3, 2), ('10-20k', 20, 4, 2),
    ('8-20k', 20, 5, 2), ('6.7-20k', 20, 6, 2), ('5-20k', 20, 8, 2),
    ('8-16k', 25, 4, 2), ('8-13k', 20, 5, 3), ('8-12k', 33, 3, 2),
    ('9.2k', 29, 3, 3), ('6.9k', 29, 4, 4), ('5.5k', 29, 5, 5),
    ('4.6k', 29, 6, 6), ('9.2-13.8k', 29, 3, 2),
    ('6.9-13.8k', 29, 4, 2), ('5.5-13.8k', 29, 5, 2),
    ('4-8k', 20, 10, 5), ('13.3k', 20, 3, 3),
    # Append only: the original 0..34 IDs retain their exact register recipes.
    # Scope observations give ~15.83k for U=24; U=23 brackets the 16k target
    # at ~16.52k. These names are calibration candidates, not measured FPS.
    ('16k-cal', 24, 2, 2), ('16k-cal-fast', 23, 2, 2),
    # ID37 is the dev single-multiplier recipe; ID34 stays 20/3/3.
    ('13.3k-b', 60, 1, 1),
)
LEGACY_PRESET_COUNT = 35
SUPPORTED_PRESET_COUNTS = (LEGACY_PRESET_COUNT, 37, len(PRESETS))
CALIBRATION_IDS = (35, 36)


def addr(reg, value):
    return [f'movw {reg},#{value & 65535}', f'movt {reg},#{value >> 16}']


def call(value, *, target=T):
    # Generated helpers run in the small native Flash recipe span. Native and
    # generated Flash callees fit BL; copied RAM code still needs BLX.
    if target.BASE <= value < target.BASE + target.SPAN:
        return [f'bl #{value & ~1:#x}']
    return addr('r12', value | 1) + ['blx r12']


def tail(value, *, target=T):
    if target.BASE <= value < target.BASE + target.SPAN:
        return [f'b.w #{value & ~1:#x}']
    return addr('r12', value | 1) + ['bx r12']


def inc(name, base='r4', tmp='r0'):
    off = OFF[name]
    return [f'ldr {tmp},[{base},#{off}]', f'adds {tmp},#1',
            f'str {tmp},[{base},#{off}]']


def capture(prefix, fail, *, target=T):
    REPORT_TIMER = target.REPORT_TIMER
    return (addr('r1', REPORT_TIMER + 0x54C) + ['mvn r0,#0', 'str r0,[r1]']
            + addr('r3', REPORT_TIMER + 0x4C)
            + ['movs r0,#1', 'str r0,[r3]', 'movs r3,#8', f'{prefix}_wait:',
               'ldr r0,[r1]', 'adds r0,#1', f'bne {prefix}_ok',
               'subs r3,#1', f'bne {prefix}_wait', f'b {fail}',
               f'{prefix}_ok:', 'subs r0,#1'])


def memory_evidence(image):
    """Fail closed if queue descriptors/pointer inventory differ from this image.

    All seven exact references to the queue-array base are accounted for; no
    interior absolute pointers address reclaimed payload slots. CPU tests cover
    all target queue accessors and capacity wraparound, not only init/push/pop.
    """
    refs = tuple(a for a in range(image.base, image.end - 3)
                 if image.get(a, 4) == struct.pack('<I', 0x2300D83B))
    expected = (0x0E073F50, 0x0E073FD0, 0x0E08C59C, 0x0E08C5FC,
                0x0E08C650, 0x0E08C6BC, 0x0E08C6F0)
    if refs != expected:
        raise ValueError('queue-array reference inventory changed')
    interiors = []
    for a in range(image.base, image.end - 3):
        value = int.from_bytes(image.get(a, 4), 'little')
        if Q2 + 10 <= value < Q2 + 298:
            interiors.append((a, value))
    if interiors:
        raise ValueError(f'queue2 payload pointer aliases: {interiors}')
    if image.get(0x0E073F2C, 22) != bytes.fromhex(
            '16bf1821082211714ff00c0104fb00f008bf83f85822'):
        raise ValueError('queue2 capacity-8 initialization changed')
    # Include every direct call and the one literal veneer to the variable
    # writer. This inventory is target-specific, not a general free-RAM guess.
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
    cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS)
    targets = {0x0E073F0C, 0x0E073F54, 0x230039B8, 0x23003A2C,
               0x23003A8C, 0x23003AE0, 0x23003B4C, 0x230057D8}
    calls = []
    for a in range(image.base, image.end - 3, 2):
        if int.from_bytes(image.get(a, 2), 'little') & 0xF800 != 0xF000:
            continue
        runtime = (T.RAM_RUN + a - T.RAM_SRC
                   if T.RAM_SRC <= a < T.RAM_SRC + T.RAM_LEN else a)
        ins = next(cs.disasm(image.get(a, 4), runtime), None)
        if ins and ins.mnemonic in ('bl', 'b.w'):
            target = int(ins.op_str.lstrip('#'), 0)
            if target in targets:
                calls.append((runtime, target))
    expected_calls = [(0x0E07F876, 0x0E073F0C), (0x23002D3A, 0x230057D8),
        (0x23002D7C, 0x230039B8), (0x23002D8E, 0x23003A2C),
        (0x23002DA4, 0x230039B8), (0x23002DE4, 0x23003B4C),
        (0x2300310C, 0x23003AE0), (0x23003148, 0x23003A8C),
        (0x2300316A, 0x23003A8C), (0x23003184, 0x23003A8C),
        (0x23003356, 0x23003B4C), (0x2300348C, 0x23003B4C),
        (0x23003498, 0x23003B4C)]
    if calls != expected_calls or image.u32(T.flash_source(0x230057DC)) != 0x0E073F55:
        raise ValueError('queue accessor call/veneer inventory changed')
    return dict(base=ADV_RAM, bytes=ADV_BYTES, queue2=Q2, queue3=Q2+298,
                raw_payload_end=Q2+10+8*12, pointer_references=list(refs),
                capacity=8, record_bytes=12, absolute_payload_aliases=interiors,
                direct_calls=calls, variable_writer_veneer=0x230057D8,
                functions=[0x0E073F0C, 0x0E073F54, 0x230039B8,
                           0x23003A2C, 0x23003A8C, 0x23003AE0, 0x23003B4C])


def snapshot_memory_evidence(image):
    """Reuse three already-proven data bytes and the target's normal allocator.

    RAM code padding is deliberately excluded: the stock MPU makes it RO.
    The three bytes store the low 24 bits of a 0x23xxxxxx RAM pointer; zero is
    unallocated. No extra queue slots or settings storage are taken.
    """
    if SNAP_PTR != Q2+10+8*12 or SNAP_PTR+3 != ADV_RAM:
        raise ValueError('snapshot pointer overlaps live queue/runtime bytes')
    expected = bytes.fromhex('02460021014b024806f03dbfd5fa070e747b0023')
    if image.get(SNAP_ALLOC, len(expected)) != expected:
        raise ValueError('native allocation wrapper changed')
    if image.get(T.NATIVE_FREE, len(T.NATIVE_FREE_PREIMAGE)) != T.NATIVE_FREE_PREIMAGE:
        raise ValueError('native heap release wrapper changed')
    # Keep the original MPU descriptor intact; never relax its permissions.
    descriptor = struct.unpack('<III', image.get(0x0E088AB0, 12))
    if descriptor != (0x23000C60, 0x4BE0, 0x10006):
        raise ValueError('native RAM-code protection descriptor changed')
    return dict(pointer=SNAP_PTR, pointer_bytes=3, bytes=P.SENSOR_SNAPSHOT_BYTES,
                storage_bytes=T.SNAPSHOT_STORAGE_BYTES, abs_total_offset=T.ABS_TOTAL_OFFSET,
                pointer_address_bits=20, pointer_byte2_flags=dict(direct=0x10, report_owner=0x20, abs=0x40),
                owner='native heap; lazily allocated once per power session',
                allocator=SNAP_ALLOC, allocation_failure='request rejected; no sensor access',
                readonly_code_region=dict(base=descriptor[0], bytes=descriptor[1], attributes=descriptor[2]))


def snapshot_pointer(reg, tmp1, tmp2, *, target=T):
    SNAP_PTR = target.SNAPSHOT_POINTER
    from functools import partial
    call = partial(globals()["call"], target=target)
    snapshot_pointer = partial(globals()["snapshot_pointer"], target=target)
    # The preceding byte belongs to the last reserved queue2 record. Read an
    # aligned word, then discard that byte and all pointer tags. This does
    # not depend on CCR.UNALIGN_TRP or read the adjacent version byte.
    if SNAP_PTR & 3 != 1 or SNAP_PTR-1 < target.RADIO_QUEUE2 or SNAP_PTR+3 != target.ADV_RAM:
        raise ValueError('snapshot pointer aligned read exceeds its owned layout')
    return (addr(reg, SNAP_PTR-1)
        + [f'ldr {reg},[{reg}]', f'ubfx {reg},{reg},#8,#20',
           f'cmp {reg},#0', 'it ne', f'orrne {reg},{reg},#{getattr(target,"RAM_POINTER_BASE",0x23000000):#x}'])


def _snapshot_worker_lines(*, target=T):
    MODE, VARIANT = target.SENSOR_MODE, target.SENSOR_VARIANT
    ADV_RAM, WR, RD = target.ADV_RAM, target.WR, target.RD
    from functools import partial
    call = partial(globals()["call"], target=target)
    snapshot_pointer = partial(globals()["snapshot_pointer"], target=target)
    # The native worker already owns its sensor semaphore and has waited for
    # the in-flight burst to finish. Only page selections are written here.
    lines = ['push {r4,r5,r6,r7,lr}', 'sub sp,#28'] + snapshot_pointer('r4', 'r0', 'r1')
    # Fix widths before Keystone resolves absolute BL operands: relaxing these
    # two long forward branches later would shift the resolved calls by 4B.
    lines += ['beq.w out', 'ldrb r0,[r4,#1]', 'cmp r0,#1', 'bne.w out',
              'movs r0,#0']
    for off in range(0, 24, 4):
        lines += [f'str r0,[sp,#{off}]']
    lines += ['movs r0,#1', 'strb r0,[sp]', 'ldrh r5,[r4,#4]',
              'strh r5,[sp,#4]', 'strh r5,[sp,#6]']
    for fields, width in ((((MODE, 8), (VARIANT, 9)), 'b'),
                          (((target.SENSOR_CPI_X, 20),
                            (target.SENSOR_CPI_Y, 22)), 'h')):
        base = min(a for a, _ in fields)
        lines += addr('r1', base)
        for address, offset in fields:
            lines += [f'ldr{width} r0,[r1,#{address-base}]', f'str{width} r0,[sp,#{offset}]']
    lines += addr('r1', ADV_RAM)
    for source, offset in ((3,10),(8,11),(9,3)):
        lines += [f'ldrb r0,[r1,#{source}]', f'strb r0,[sp,#{offset}]']
    page = None
    commands = []
    for i, (p, reg) in enumerate(P.SENSOR_REGISTERS):
        if p != page:
            commands += [127, p]
            page = p
        commands += [reg, 12+i]
    commands += [127, 0]
    lines += [f'movs r5,#{len(commands)//2}', 'movs r6,#0', 'adr r7,commands',
              'transaction:', 'adds r6,#1', 'ldrb r0,[r7],#1', 'ldrb r1,[r7],#1',
              'cmp r0,#127', 'bne read'] + call(WR)
    lines += ['b checked', 'read:', 'add r1,sp,r1'] + call(RD)
    lines += ['checked:', 'cmp r0,#0', 'beq failed', 'subs r5,#1', 'bne transaction',
              'movs r0,#2', 'strb r0,[sp,#1]', 'b publish',
              'failed:', 'strb r6,[sp,#2]', 'movs r0,#127', 'movs r1,#0'] + call(WR)
    lines += ['movs r0,#3', 'strb r0,[sp,#1]',
              # No partial or previous register values masquerade as valid data.
              'movs r0,#0', 'str r0,[sp,#12]', 'str r0,[sp,#16]',
              'publish:', '.hword 0xf3ef,0x8c10', 'cpsid i']
    lines += ['mov r7,sp', 'ldmia r7!,{r0,r1,r2,r3,r5,r6}', 'stmia r4!,{r0,r1,r2,r3,r5,r6}',
              '.hword 0xf38c,0x8810', 'out:', 'add sp,#28', 'pop {r4,r5,r6,r7,pc}',
              '.balign 4', 'commands:', '.byte '+','.join(str(v) for v in commands)]
    return lines


def _snapshot_storage_lines(*, target=T):
    SNAP_PTR, SNAP_ALLOC = target.SNAPSHOT_POINTER, target.NATIVE_ALLOC
    from functools import partial
    call = partial(globals()["call"], target=target)
    snapshot_pointer = partial(globals()["snapshot_pointer"], target=target)
    # Called only by configuration/boot threads, never by motion/radio IRQs.
    return (['push {r4,r5,r6,lr}'] + snapshot_pointer('r4', 'r0', 'r1')
        + ['bne out', f'movw r0,#{target.SNAPSHOT_STORAGE_BYTES}'] + call(SNAP_ALLOC)
        + ['movs r1,#0', 'mov r4,r0', 'cmp r0,#0', 'beq out']
        + ['mov r2,r4', f'movs r3,#{target.SNAPSHOT_STORAGE_BYTES//4}', 'zero:',
           'str r1,[r2],#4', 'subs r3,#1', 'bne zero']
        + ['movs r1,#1', 'strb r1,[r4]', 'mov r6,r4',
           '.hword 0xf3ef,0x8510', 'cpsid i']
        + snapshot_pointer('r4', 'r0', 'r1')
        + ['beq publish', '.hword 0xf385,0x8810', 'mov r0,r6']
        + call(target.NATIVE_FREE)
        + ['b out', 'publish:', 'mov r4,r6'] + addr('r0', SNAP_PTR)
        + ['strb r4,[r0]', 'lsrs r1,r4,#8', 'strb r1,[r0,#1]',
           'lsrs r1,r4,#16', 'and r1,r1,#15', 'ldrb r2,[r0,#2]', 'and r2,r2,#240',
           'orrs r1,r2', 'strb r1,[r0,#2]', '.hword 0xf385,0x8810',
           'out:', 'mov r0,r4', 'pop {r4,r5,r6,pc}'])


def _snapshot_request_lines(getter, storage, *, target=T):
    SENSOR_READY, SENSOR_QUEUE = target.SENSOR_READY, target.SENSOR_QUEUE
    from functools import partial
    call = partial(globals()["call"], target=target)
    snapshot_pointer = partial(globals()["snapshot_pointer"], target=target)
    return (['push {r7,lr}', 'sub sp,#16', 'ldrb r0,[r4,#3]',
             'cmp r6,#0', 'bne invalid', 'cmp r0,#4', 'bne invalid',
             'ldrh r1,[r4,#8]', 'cmp r1,#0', 'beq invalid']
        + addr('r0', SENSOR_READY)
        + ['ldrb r0,[r0]', 'cmp r0,#0', 'beq invalid']
        + call(storage)
        + ['cmp r0,#0', 'beq invalid', 'mov r7,r0', 'ldrh r1,[r4,#8]',
           'ldrb r0,[r7,#1]', 'cmp r0,#1', 'bne queue',
           'ldrh r0,[r7,#4]', 'cmp r0,r1', 'beq reply', 'b invalid',
           'queue:', 'strh r1,[r7,#4]', 'movs r0,#0', 'strb r0,[r7,#2]',
           'movs r0,#1', 'strb r0,[r7,#1]',
           f'movs r0,#{getattr(target,"SNAP_MESSAGE",SNAP_MESSAGE)}', 'str r0,[sp]',
           'movs r0,#0', 'str r0,[sp,#4]', 'str r0,[sp,#8]']
        + addr('r0', SENSOR_QUEUE)
        + ['mov r1,sp', 'movs r2,#0', 'movs r3,#0'] + call(getattr(target,"SENSOR_POST",0x0E086F68))
        + ['cmp r0,#0', 'beq reply',
           'ldrh r0,[r7,#4]', 'strh r0,[r7,#6]',
           'movs r0,#255', 'strb r0,[r7,#2]',
           'movs r0,#3', 'strb r0,[r7,#1]',
           'reply:', 'movs r0,#2', 'strb r0,[r4,#3]'] + call(getter)
        + ['b out', 'invalid:', 'movs r0,#0', 'out:',
           'add sp,#16', 'pop {r7,pc}'])


def _get_lines(*, target=T, telemetry=True):
    ADV_RAM = target.ADV_RAM
    from functools import partial
    call = partial(globals()["call"], target=target)
    snapshot_pointer = partial(globals()["snapshot_pointer"], target=target)
    # r4/r5/r6 are incoming packet/op/profile; r7 is our RAM base.
    lines = (['push {r7,lr}', '.hword 0xf3ef,0x8c10', 'cpsid i',
             'cmp r6,#0', 'bne invalid'] + addr('r7', ADV_RAM)
        + ['ldrb r0,[r4,#3]', 'cmp r5,#4', 'beq stats',
           'cmp r0,#2', 'bne invalid', 'cmp r5,#6', 'beq snapshot',
           'cmp r5,#5', 'beq custom',
           'cmp r5,#2', 'beq fps',
           'cmp r5,#3', 'bne invalid',
           'lock:', 'ldrb r0,[r7,#2]', 'strb r0,[r4,#8]',
           'ldrh r0,[r7,#4]', 'strh r0,[r4,#9]', 'cmp r0,#0',
           'it eq', 'moveq r0,#80', 'strh r0,[r4,#11]', 'movs r0,#7', 'b success',
           'fps:', 'ldrb r0,[r7,#3]', 'strb r0,[r4,#8]',
           'ldrb r0,[r7,#8]', 'strb r0,[r4,#9]',
           'ldrb r0,[r7,#9]', 'strb r0,[r4,#10]',
           f'movs r0,#{len(PRESETS)}', 'strb r0,[r4,#11]', 'movs r0,#6', 'b success',
           'custom:', 'ldrb r0,[r7,#3]', 'strb r0,[r4,#8]',
           'ldrb r0,[r7,#8]', 'strb r0,[r4,#9]',
           'ldrb r0,[r7,#9]', 'strb r0,[r4,#10]',
           'ldrb r0,[r7,#13]', 'strb r0,[r4,#11]',
           'ldrb r0,[r7,#14]', 'strb r0,[r4,#12]',
           'ldrb r0,[r7,#15]', 'strb r0,[r4,#13]',
           'ldr r0,[r7,#184]', 'str r0,[r4,#14]',
           'movs r0,#12', 'b success',
           'snapshot:'] + snapshot_pointer('r1', 'r2', 'r3')
        + ['cmp r1,#0', 'bne snapready', 'movs r0,#0']
        + [f'str r0,[r4,#{8+off}]' for off in range(0,24,4)]
        + ['movs r0,#1', 'strb r0,[r4,#8]', 'movs r0,#26', 'b success',
            'snapready:']
        # Both the native heap payload and packet+8 are word aligned. Keep
        # all six words under the same PRIMASK interval as token/status.
        + [line for off in range(0,24,4)
           for line in (f'ldr r0,[r1,#{off}]', f'str r0,[r4,#{8+off}]')]
        + ['movs r0,#26', 'b success',
           'stats:', 'cmp r0,#3', 'bne invalid', 'ldrb r0,[r4,#8]',
           'cmp r0,#5', 'bhi invalid', 'lsls r0,r0,#5', 'add r1,r7,r0',
           'movs r2,#32', 'cmp r0,#160', 'it eq', 'moveq r2,#28',
           'add r3,r4,#9', 'mov r0,r2',
           'copy:', 'ldrb lr,[r1],#1', 'strb lr,[r3],#1', 'subs r2,#1', 'bne copy',
           'adds r0,#3',
           'success:', 'strb r0,[r4,#3]', 'movs r0,#1',
           '.hword 0xf38c,0x8810', 'pop {r7,pc}',
           'invalid:', 'movs r0,#0', '.hword 0xf38c,0x8810', 'pop {r7,pc}'])
    if not telemetry:
        lines[lines.index('beq stats')] = 'beq invalid'
        del lines[lines.index('stats:'):lines.index('success:')]
    return lines


def _set_lines(getter, release, *, target=T, telemetry=True, apply=None):
    ADV_RAM, MODE = target.ADV_RAM, target.SENSOR_MODE
    from functools import partial
    call = partial(globals()["call"], target=target)
    snapshot_pointer = partial(globals()["snapshot_pointer"], target=target)
    lines = (['push {r7,lr}', 'cmp r6,#0', 'bne invalid'] + addr('r7', ADV_RAM)
        + ['ldrb r0,[r4,#3]', 'cmp r5,#5', 'beq custom',
           'cmp r5,#2', 'beq fps', 'cmp r5,#3', 'beq lock',
           'cmp r5,#4', 'bne invalid', 'cmp r0,#3', 'bne invalid',
           'ldrb r0,[r4,#8]', 'cmp r0,#2', 'bhi invalid',
           'cmp r0,#2', 'beq reset', 'strb r0,[r7,#1]', 'b statreply',
           'reset:', '.hword 0xf3ef,0x8c10', 'cpsid i', 'add r1,r7,#16',
           'movs r2,#42', 'movs r0,#0', 'zero:', 'str r0,[r1],#4',
           'subs r2,#1', 'bne zero', '.hword 0xf38c,0x8810',
           'statreply:', 'ldrb r0,[r7,#1]', 'strb r0,[r4,#8]',
           'movs r0,#3', 'strb r0,[r4,#3]', 'b ok',
           'lock:', 'cmp r0,#5', 'bne invalid', 'ldrb r0,[r4,#8]',
           'cmp r0,#1', 'bhi invalid', 'ldrh r1,[r4,#9]',
           'movw r2,#499', 'cmp r1,r2', 'bhi invalid',
           '.hword 0xf3ef,0x8c10', 'cpsid i', 'strb r0,[r7,#2]',
           'strh r1,[r7,#4]', 'movs r0,#0', 'strh r0,[r7,#6]',
           '.hword 0xf38c,0x8810', 'ldrb r0,[r7,#2]', 'cmp r0,#0',
           'bne lockreply'] + call(release)
        + ['lockreply:', 'movs r0,#2', 'strb r0,[r4,#3]',
           'b reply',
           'custom:', 'cmp r0,#5', 'bne invalid',
           'ldrb r0,[r4,#8]', 'cmp r0,#0', 'beq invalid',
           'ldrb r1,[r4,#9]', 'cmp r1,#0', 'beq invalid',
           'ldrb r2,[r4,#10]', 'cmp r2,#0', 'beq invalid',
           'cmp r1,r2', 'blo invalid',
           '.hword 0xf3ef,0x8c10', 'cpsid i',
           'strb r0,[r7,#13]', 'strb r1,[r7,#14]', 'strb r2,[r7,#15]',
           'movs r0,#255', 'b queue',
           'fps:', 'cmp r0,#3', 'bne invalid', 'ldrb r0,[r4,#8]',
           f'cmp r0,#{len(PRESETS)}', 'bhs invalid',
           '.hword 0xf3ef,0x8c10', 'cpsid i',
           'queue:', 'strb r0,[r7,#3]',
           'movs r0,#1', 'strb r0,[r7,#9]', '.hword 0xf38c,0x8810'] + addr('r0', MODE)
        + ['ldrb r0,[r0]'] + call(getattr(target,"SET_SENSOR_MODE",0x0E07E568))
        + ['movs r0,#2', 'strb r0,[r4,#3]', 'reply:'] + call(getter)
        + ['pop {r7,pc}', 'ok:', 'movs r0,#1', 'pop {r7,pc}',
           'invalid:', 'movs r0,#0', 'pop {r7,pc}'])
    if not telemetry:
        start = lines.index('cmp r5,#4')
        lines[start:lines.index('lock:')] = ['b invalid']
    if apply is not None:
        start = lines.index('strh r1,[r7,#4]') + 1
        end = lines.index('lockreply:')
        lines[start:end] = ['.hword 0xf38c,0x8810'] + call(apply)
    return lines


def without_diagnostic_counters(lines):
    """Remove generated counter increments, preserving control-state stores."""
    sequences = [inc(name) for name in OFF]
    sequences += [inc(name, 'r4', 'r3') for name in OFF]
    result = list(lines)
    for sequence in sequences:
        i = 0
        while i <= len(result) - len(sequence):
            if result[i:i+len(sequence)] == sequence:
                del result[i:i+len(sequence)]
            else:
                i += 1
    return result


def _fps_lines(table, custom, *, target=T):
    ADV_RAM, WR, RD = target.ADV_RAM, target.WR, target.RD
    from functools import partial
    call = partial(globals()["call"], target=target)
    tail = partial(globals()["tail"], target=target)
    def readback(reg, offset):
        return ([f'movs r0,#{reg}', 'mov r1,sp'] + call(RD)
            + ['cmp r0,#0', 'beq.w fail', 'ldrb r0,[sp]',
               f'ldrb r1,[r6,#{offset}]', 'cmp r0,r1', 'bne.w fail'])
    # Called only after original RAM recipe dispatcher, inside the sensor worker.
    return (['push {r4,r5,r6,r7,lr}', 'sub sp,#4'] + addr('r4', ADV_RAM)
        + ['ldrb r5,[r4,#3]', 'cmp r5,#255', 'bne preset',
           'add sp,#4', 'pop {r4,r5,r6,r7,lr}'] + tail(custom)
        + ['preset:', 'cmp r5,#0', 'beq.w stock',
           'movs r0,#1', 'strb r0,[r4,#9]',
           f'cmp r5,#{len(PRESETS)}', 'bhs.w fail', 'mov r7,r5', 'subs r5,#1',
           'add r5,r5,r5,lsl #1'] + addr('r6', table)
        + ['add r6,r5', 'movs r0,#0x7f', 'movs r1,#6'] + call(WR)
        + ['cmp r0,#0', 'beq.w fail', 'movs r0,#0x53', 'ldrb r1,[r6,#1]'] + call(WR)
        + ['cmp r0,#0', 'beq.w fail'] + readback(0x53, 1)
        + ['movs r0,#0x62', 'ldrb r1,[r6,#2]'] + call(WR)
        + ['cmp r0,#0', 'beq.w fail'] + readback(0x62, 2)
        + ['movs r0,#0x7f', 'movs r1,#7'] + call(WR)
        + ['cmp r0,#0', 'beq fail', 'movs r0,#0x42', 'ldrb r1,[r6]'] + call(WR)
        + ['cmp r0,#0', 'beq fail'] + readback(0x42, 0)
        + ['movs r0,#0x7f', 'movs r1,#0'] + call(WR)
        + ['cmp r0,#0', 'beq fail', 'mov r5,r7', 'stock:',
           '.hword 0xf3ef,0x8c10', 'cpsid i',
           'strb r5,[r4,#8]', 'ldrb r0,[r4,#3]', 'cmp r0,r5', 'bne out',
           'movs r0,#0', 'strb r0,[r4,#9]']
        + inc('fps_apply') + ['out:', '.hword 0xf38c,0x8810',
           'add sp,#4', 'pop {r4,r5,r6,r7,pc}', 'fail:'] + inc('fps_fail')
        + ['movs r0,#0x7f', 'movs r1,#0'] + call(WR)
        + ['add sp,#4', 'pop {r4,r5,r6,r7,pc}'])

def _custom_fps_lines(*, target=T):
    ADV_RAM, WR, RD = target.ADV_RAM, target.WR, target.RD
    from functools import partial
    call = partial(globals()["call"], target=target)
    """A worker-only three-register transaction, with real SPI verification.

    No sensor access occurs in the HID handler. Snapshot all three bytes while
    interrupts are masked; a concurrent SET can never splice two recipes.
    r5/r6/r7 keep the snapshot across the native SPI calls.
    """
    lines = (['push {r4,r5,r6,r7,lr}', 'sub sp,#12'] + addr('r4', ADV_RAM)
        + ['.hword 0xf3ef,0x8c10', 'cpsid i',
           'ldrb r5,[r4,#13]', 'ldrb r6,[r4,#14]', 'ldrb r7,[r4,#15]',
           'movs r0,#1', 'strb r0,[r4,#9]',
           'movs r0,#0', 'strb r0,[r4,#187]',
           '.hword 0xf38c,0x8810',
           'cmp r5,#0', 'beq fail', 'cmp r7,#0', 'beq fail',
           'cmp r6,r7', 'blo fail',
           'movs r0,#0', 'str r0,[sp]',
           'strb r5,[sp,#4]', 'strb r6,[sp,#5]', 'strb r7,[sp,#6]',
           'movs r5,#10', 'adr r6,commands',
           'transaction:', 'ldrb r0,[r6],#1', 'ldrb r1,[r6],#1',
           'cmp r0,#128', 'bhs read', 'cmp r0,#127', 'beq write',
           'ldrb r1,[sp,r1]', 'write:'] + call(WR)
        + ['b checked', 'read:', 'subs r0,#128', 'add r1,sp,r1'] + call(RD)
        + ['checked:', 'cmp r0,#0', 'beq fail', 'subs r5,#1', 'bne transaction',
           'ldrb r5,[sp,#4]', 'ldrb r6,[sp,#5]', 'ldrb r7,[sp,#6]'])
    # The table re-selects both pages and verifies actual SPI readback.
    lines += ['ldrb r0,[sp]', 'cmp r0,r5', 'bne fail',
              'ldrb r0,[sp,#1]', 'cmp r0,r6', 'bne fail',
              'ldrb r0,[sp,#2]', 'cmp r0,r7', 'bne fail',
              'movs r0,#127', 'movs r1,#0'] + call(WR)
    lines += ['cmp r0,#0', 'beq fail',
              '.hword 0xf3ef,0x8c10', 'cpsid i',
              'movs r0,#1', 'strb r0,[sp,#3]',
              'ldr r0,[sp]', 'str r0,[r4,#184]',
              'movs r0,#255', 'strb r0,[r4,#8]',
              'ldrb r1,[r4,#3]', 'cmp r1,#255', 'bne changed',
              'ldrb r1,[r4,#13]', 'cmp r1,r5', 'bne changed',
              'ldrb r1,[r4,#14]', 'cmp r1,r6', 'bne changed',
              'ldrb r1,[r4,#15]', 'cmp r1,r7', 'bne changed',
              'movs r0,#0', 'strb r0,[r4,#9]',
              'changed:', '.hword 0xf38c,0x8810'] + inc('fps_apply')
    lines += ['add sp,#12', 'pop {r4,r5,r6,r7,pc}', 'fail:'] + inc('fps_fail')
    lines += ['movs r0,#127', 'movs r1,#0'] + call(WR)
    lines += ['add sp,#12', 'pop {r4,r5,r6,r7,pc}', '.balign 4', 'commands:',
              '.byte 127,6,83,5,98,6,127,7,66,4,127,6,211,1,226,2,127,7,194,0']
    return lines


def _idle_lines(*, target=T):
    # Adapt dev _idle_block to target LOCK ownership. r0=c, r1=&CC3, r7=R.
    return (['push {r4,r5,r6,r7,lr}', 'sub sp,#4'] + addr('r3', target.SMOOTHING_STATE)
        + ['ldrb r3,[r3]', 'tst r3,#128', 'beq out', 'and r3,r6,#255', 'cmp r3,#8', 'bne out',
           'ldrb r3,[r5,#0x186]', 'cmp r3,#8', 'bne out', 'ldr r2,[r1,#-12]',
           'subs r2,r2,r0', 'cmp r2,#16', 'blo out', 'ldrh r3,[r4,#4]', 'cmp r3,#0',
           'it eq', 'moveq r3,#80', 'lsrs r5,r7,#1', 'cmp r3,r5', 'bhs out',
           'add r6,r2,r3', 'mod:', 'cmp r6,r5', 'blo phased', 'subs r6,r6,r5', 'b mod',
           'phased:', 'lsrs r3,r5,#1', 'cmp r6,r3', 'bhi longer', 'cmp r6,#4', 'blo out',
           'add r3,r6,#16', 'cmp r2,r3', 'blo longer', 'subs r3,r2,r6', 'b set',
           'longer:', 'subs r3,r5,r6', 'cmp r3,#4', 'blo out', 'adds r3,r2',
           'set:', 'adds r3,r0', 'str r3,[r1,#-12]', 'movs r3,#1', 'strb r3,[r4,#12]',
           'out:', 'add sp,#4', 'pop {r4,r5,r6,r7,pc}'])


def _lock_lines(idle, *, target=T):
    from functools import partial
    call = partial(globals()["call"], target=target)
    capture = partial(globals()["capture"], target=target)
    DIVIDER, TPMS, REPORT_TIMER = target.REPORT_DIVIDER, target.TICKS_PER_MS, target.REPORT_TIMER
    # r4=ADV, r5=RSTATE, r6=pre ISR state/pending/connected/queue flags.
    return (['push {r4,r5,r6,r7,lr}', 'sub sp,#4', 'ldrb r0,[r4,#2]',
             'cmp r0,#0', 'beq out', 'tst r6,#0x100', 'beq out',
             'tst r6,#0x200', 'beq out', 'ldrb r0,[r5,#1]', 'cmp r0,#0',
             'beq out', 'ldrb r0,[r5,#2]', 'cmp r0,#0', 'beq out']
        + addr('r1', DIVIDER) + ['ldrb r1,[r1]', 'cmp r1,#1', 'bne out']
        + addr('r1', TPMS) + ['ldrb r1,[r1]', 'cmp r1,#1', 'beq rate',
             'cmp r1,#2', 'beq rate', 'cmp r1,#4', 'bne out', 'rate:',
             'movw r2,#1000', 'lsrs r1,r1,#1', 'lsr r7,r2,r1'] + capture('lc','failed')
        + ['ldr r3,[r1,#-12]', 'cmp r0,r3', 'bhi rescue',
           'ldrh r3,[r4,#6]', 'strh r0,[r4,#6]', 'cmp r0,r3', 'bhs candidate',
           'cmp.w r0,r7,lsr #1', 'bhs candidate', 'str r7,[r1,#-12]',
           'movs r3,#0', 'strb r3,[r4,#12]',
           'candidate:', 'tst r6,#0x400', 'beq idle', 'and r3,r6,#255',
           'cmp r3,#8', 'bne out', 'ldrb r3,[r5,#0x186]', 'cmp r3,#4', 'bne out',
           'ldrh r3,[r4,#4]', 'cmp r3,#0', 'it eq', 'moveq r3,#80',
           'cmp.w r3,r7,lsr #1', 'bhs skipped', 'subs r3,r7,r3',
           'add r0,r3', 'str r0,[r1,#-12]', 'movs r3,#1',
           'strb r3,[r4,#12]'] + inc('lock_adjust')
        + ['b out', 'rescue:', 'str r7,[r1,#-12]'] + addr('r3',REPORT_TIMER+12)
        + ['movs r0,#1', 'str r0,[r3]', 'movs r0,#0', 'strh r0,[r4,#6]',
           'strb r0,[r4,#12]']
        + inc('lock_rescue') + ['b out', 'failed:'] + inc('capture_fail')
        + ['skipped:'] + inc('lock_skip')
        + ['b out', 'idle:'] + call(idle)
        + ['out:', 'add sp,#4', 'pop {r4,r5,r6,r7,pc}'])


def _release_lines(*, target=T):
    ADV_RAM, DIVIDER, TPMS = target.ADV_RAM, target.REPORT_DIVIDER, target.TICKS_PER_MS
    REPORT_TIMER = target.REPORT_TIMER
    # Restore only an interval this runtime retimed. An explicit timer CLEAR
    # makes the disable transition independent of capture availability/phase.
    # Native rate/divider changes already own the timer; do not overwrite them.
    return (['push {r4,lr}', '.hword 0xf3ef,0x8c10', 'cpsid i']
        + addr('r4', ADV_RAM) + ['ldrb r0,[r4,#12]', 'cmp r0,#0', 'beq out']
        + addr('r1', DIVIDER) + ['ldrb r1,[r1]', 'cmp r1,#1', 'bne clear']
        + addr('r1', TPMS) + ['ldrb r1,[r1]', 'cmp r1,#1', 'beq rate',
           'cmp r1,#2', 'beq rate', 'cmp r1,#4', 'bne clear', 'rate:',
           'movw r2,#1000', 'lsrs r1,r1,#1', 'lsr r2,r2,r1']
        + addr('r1', REPORT_TIMER + 0x540) + ['str r2,[r1]']
        + addr('r1', REPORT_TIMER + 12) + ['movs r0,#1', 'str r0,[r1]',
           'clear:', 'movs r0,#0', 'strb r0,[r4,#12]', 'strh r0,[r4,#6]',
           'out:', '.hword 0xf38c,0x8810', 'pop {r4,pc}'])


def _radio_count_lines(*, target=T):
    from functools import partial
    capture = partial(globals()["capture"], target=target)
    HOP = target.HOP_INDEX
    return (['push {r4,r5,r6,lr}', 'ldrb r0,[r4,#1]', 'cmp r0,#0', 'beq out',
             'tst r6,#0x100', 'beq links', 'ldrb r0,[r5,#2]', 'cmp r0,#0',
             'beq links'] + inc('slot_ends')
        + ['ldrb r2,[r5,#0x186]', 'ldrb r1,[r4,#11]', 'strb r2,[r4,#11]',
           'and r0,r6,#255', 'cmp r0,#8', 'bne links',
           'cmp r2,#4', 'beq phase'] + inc('idle_slots')
        + ['b links','phase:']
        + capture('pc','capturebad')
        + [f'ldr r3,[r4,#{OFF["phase_sum_us"]}]', 'add r3,r0',
           f'str r3,[r4,#{OFF["phase_sum_us"]}]',
           f'ldr r3,[r4,#{OFF["phase_max_us"]}]', 'cmp r0,r3', 'it hi',
           f'strhi r0,[r4,#{OFF["phase_max_us"]}]',
           'subw r3,r1,#0x34c', 'ldr r3,[r3]', 'cmp r3,#2', 'ite eq',
           'ldreq r3,[r1,#-8]', 'ldrne r3,[r1,#-12]',
           f'str r3,[r4,#{OFF["period_us"]}]'] + inc('phase_count','r4','r3')
        + ['lsrs r0,r0,#7', 'cmp r0,#7', 'it hi', 'movhi r0,#7',
           f'add r1,r4,#{OFF["phase_bin0"]}', 'add r1,r0,lsl #2',
           'ldr r3,[r1]', 'adds r3,#1', 'str r3,[r1]', 'b links', 'capturebad:']
        + inc('capture_fail') + ['links:', 'tst r6,#0x100', 'beq conn'] + addr('r1', HOP)
        + ['ldrb r1,[r1]', 'ubfx r2,r6,#16,#8', 'cmp r1,r2', 'beq conn']
        + inc('hops') + ['conn:', 'ldrb r0,[r5,#1]', 'ldrb r1,[r4,#10]',
           'strb r0,[r4,#10]', 'cmp r0,r1', 'beq out', 'cmp r0,#0', 'beq lost']
        + inc('link_up') + ['b out', 'lost:'] + inc('link_lost')
        + ['out:', 'pop {r4,r5,r6,pc}'])


def install(b, *, telemetry=True):
    evidence = memory_evidence(b.image)
    snap_evidence = snapshot_memory_evidence(b.image)
    table = b.alloc('advanced_fps_table', bytes(v for _,k,s,f in PRESETS[1:] for v in (k,s,f)))
    diagnostic = (lambda lines: lines) if telemetry else without_diagnostic_counters
    custom = b.code('advanced_custom_fps_apply', diagnostic(_custom_fps_lines()))
    fps = b.code('advanced_fps_apply', diagnostic(_fps_lines(table, custom)))
    getter = b.code('advanced_get', _get_lines(telemetry=telemetry))
    storage = b.code('advanced_snapshot_storage', _snapshot_storage_lines())
    from .native_clock import install as install_clock, install_hooks as install_clock_hooks
    b.native_clock = install_clock(b)
    b.optical = dict(mode='stock', native=True, exposed=False)
    snapshot_request = b.code('advanced_snapshot_request', _snapshot_request_lines(getter, storage))
    release = b.code('advanced_lock_release', _release_lines())
    if not telemetry:
        from .native_timing import install as install_timing
        b.native_plock = install_timing(b, storage, b.native_clock, release)
        install_clock_hooks(b, b.native_clock, after_start=b.native_plock['start'],
                            after_stop=b.native_plock['stop'],
                            before_hfxo_off=b.native_plock['clock_off'])
    else:
        install_clock_hooks(b, b.native_clock)
    setter = b.code('advanced_set', _set_lines(getter, release, telemetry=telemetry,
        apply=b.native_plock['configure'] if not telemetry else None))
    set_router = b.code('advanced_set_router',
        ['cmp r5,#6', 'bne original'] + tail(snapshot_request) + ['original:'] + tail(setter))
    from .settings import install as install_settings
    settings = install_settings(b, getter, set_router, len(PRESETS), storage)
    from .channels import install as install_channels
    channels = install_channels(b,settings,storage) if telemetry else settings
    from .mouse_abs import install as install_abs, send_lines
    absolute = install_abs(b)
    dispatch = b.code('advanced_recipe_dispatch',
        ['push {r4,r5,r6,lr}', 'mov r4,r0', 'mov r5,r1'] + call(DISPATCH)
        + ['mov r6,r0', 'mov r0,r4', 'mov r1,r5'] + call(settings['apply'])
        + ['cmp r4,#2', 'beq apply', 'cmp r4,#3', 'beq apply',
           'cmp r4,#4', 'beq apply', 'cmp r4,#6', 'beq apply', 'cmp r4,#7',
           'bne done', 'apply:'] + call(fps)
        + ['done:', 'mov r0,r6', 'pop {r4,r5,r6,pc}'])
    snapshot_worker = b.code('advanced_snapshot_worker', _snapshot_worker_lines())
    snapshot_dispatch = b.code('advanced_snapshot_dispatch',
        ['ldr r3,[sp,#4]', 'cmp r3,#11', 'bne native'] + call(snapshot_worker)
        + ['b.w #0x0e07ec16', 'native:', 'subs r3,#1', 'b.w #0x0e07eb02'])
    if b.image.get(0x0E07EAFE, 4) != bytes.fromhex('019b013b'):
        raise ValueError('sensor worker message dispatch changed')
    b.branch(0x0E07EAFE, snapshot_dispatch, 'read-only snapshot in native sensor worker')
    idle = b.code('advanced_idle_tracking', diagnostic(_idle_lines()))
    lock = b.code('advanced_phase_lock', diagnostic(_lock_lines(idle)))
    radiocount = b.code('advanced_radio_count', _radio_count_lines()) if telemetry else None
    if telemetry:
        radio = b.code('advanced_radio_irq',
        ([] if telemetry else addr('r0',ADV_RAM) + ['ldrb r1,[r0,#2]', 'cbz r1,passthru_fast'])
        + ['push {r4,r5,r6,r7,lr}', 'sub sp,#4']
        + (addr('r4',ADV_RAM) if telemetry else ['mov r4,r0'])
        + (['ldrb r0,[r4,#1]', 'ldrb r1,[r4,#2]', 'orrs r0,r1', 'beq passthru'] if telemetry
           else []) + addr('r5',RSTATE)
        + ['ldrb r6,[r5,#0x186]'] + addr('r1',Q2)
        + ['ldrb r1,[r1,#1]', 'cmp r1,#0', 'it eq', 'orreq r6,r6,#0x400']
        + addr('r1',RADIO_EVENT) + ['ldr r1,[r1]', 'cmp r1,#0', 'it ne',
           'orrne r6,r6,#0x100', 'ldrb r1,[r5,#1]', 'cmp r1,#0', 'it ne',
           'orrne r6,r6,#0x200'] + (addr('r1',HOP)
        + ['ldrb r1,[r1]', 'orr r6,r6,r1,lsl #16'] if telemetry else [])
        + ['movs r0,#0'] + call(IRQ)
        + ['mov r7,r0'] + call(lock) + (call(radiocount) if telemetry else [])
        + ['mov r0,r7', 'add sp,#4', 'pop {r4,r5,r6,r7,pc}']
        + (['passthru:', 'add sp,#4', 'pop {r4,r5,r6,r7,lr}'] if telemetry else [])
        + ['passthru_fast:', 'movs r0,#0'] + tail(IRQ))
    else:
        from .native_plock import install_radio
        radio = install_radio(b, b.native_plock, lock, telemetry=False)
        b.symbols['advanced_radio_irq'] = radio
        b.native_plock['radio'] = radio
    # Initialize once at queue-system startup, before radio interrupts are enabled.
    init = b.code('advanced_queue_init', ['push {r4,lr}', 'mov r4,r0']
        + call(0x0E073F0C) + ['cmp r4,#0', 'bne out'] + addr('r1',ADV_RAM)
        + ['movs r2,#47', 'movs r3,#0', 'zero:', 'str r3,[r1],#4',
           'subs r2,#1', 'bne zero'] + addr('r1',ADV_RAM)
        + ['movs r3,#1', 'strb r3,[r1]']
        + snapshot_pointer('r4', 'r0', 'r1')
        + ['beq reset_tags', 'mov r0,r4', 'movs r1,#7', 'movs r3,#0',
           'reset_snapshot:', 'str r3,[r0],#4', 'subs r1,#1', 'bne reset_snapshot',
           'movs r1,#1', 'strb r1,[r4]', 'addw r0,r4,#308', 'movs r1,#9',
           'reset_control:', 'str r3,[r0],#4', 'subs r1,#1', 'bne reset_control',
           'reset_tags:'] + addr('r1', SNAP_PTR + 2)
        + ['ldrb r3,[r1]', 'and r3,r3,#15', 'strb r3,[r1]', 'movs r3,#0']
        + addr('r1', T.SMOOTHING_STATE)
        # Saved ABS is loaded during queue0 initialization, before the native
        # loop reaches queue2. Establish its empty header before busy checks.
        + ['strb r3,[r1]', 'movs r0,#2'] + call(0x0E073F0C)
        + call(settings['load']) + addr('r0', T.NATIVE_CLOCK_READY)
        + ['ldrb r0,[r0]', 'cbz r0,out'] + call(storage)
        + call(b.native_clock['bootstrap'])
        + (call(b.native_plock['configure']) if not telemetry else [])
        + ['out:', 'pop {r4,pc}'])
    tick = b.code('advanced_tick', ['push {r0,r1,r4,lr}'] + addr('r4',ADV_RAM)
        + ['ldrb r0,[r4,#1]', 'cmp r0,#0', 'beq go'] + inc('ticks')
        + addr('r1',0x2300E07E) + ['ldrb r0,[r1]', 'cmp r0,#0', 'beq notready']
        + addr('r1',0x2300CA64) + ['ldr r0,[r1]', 'cmp r0,#0', 'bne notready']
        + addr('r1',0x2300CA6C) + ['ldr r0,[r1]', 'cmp r0,#0', 'bne notready']
        + addr('r1',0x2300E073) + ['ldrb r0,[r1]', 'and r0,r0,#0xf7',
           'cmp r0,#0xb7', 'bne unhealthy'] + addr('r1',0x2300E074)
        + ['ldrb r0,[r1]', 'cmp r0,#1', 'bne go', 'unhealthy:'] + inc('health_skip')
        + addr('r1',0x2300E073) + ['ldrh r0,[r1]', f'str r0,[r4,#{OFF["last_bad_status"]}]']
        + inc('health_trip') + ['b go', 'notready:'] + inc('not_ready')
        + ['go:', 'pop {r0,r1,r4,lr}'] + tail(0x0E07E6DC)) if telemetry else None
    burst = b.code('advanced_burst', ['push {r4,lr}'] + call(0x0E06CFE8)
        + addr('r4',ADV_RAM) + ['ldrb r1,[r4,#1]', 'cmp r1,#0', 'beq out',
           'cmp r0,#0', 'beq fail'] + inc('reads_started','r4','r1')
        + ['b out', 'fail:'] + inc('read_start_fail','r4','r1') + ['out:', 'pop {r4,pc}']) if telemetry else None
    done = b.code('advanced_spi_done', ['push {r0,r1,r4,lr}'] + addr('r4',ADV_RAM)
        + ['ldrb r2,[r4,#1]', 'cmp r2,#0', 'beq go', 'cmp r0,#0', 'beq bad',
           'cmp r1,#0', 'beq bad'] + inc('spi_ok','r4','r2')
        + ['b go', 'bad:'] + inc('spi_bad','r4','r2')
        + ['go:', 'pop {r0,r1,r4,lr}'] + tail(0x0E07E600)) if telemetry else None
    from .motion import install as install_motion, owned_call
    path = install_motion(b)
    motion = b.code('advanced_motion', ['push {r0,r1,r4,lr}'] + addr('r4',ADV_RAM)
        + ['ldrb r1,[r4,#1]', 'cbz r1,go'] + inc('samples','r4','r1')
        + ['ldrb r1,[r0]', 'cbz r1,go'] + inc('samples_motion','r4','r1')
        + ['go:', 'pop {r0,r1,r4,lr}'] + owned_call(T.MOTION_NATIVE)) if telemetry else b.code(
            'advanced_motion', owned_call(T.MOTION_NATIVE))
    reinit = b.code('advanced_reinit', ['push {r0,r1,r4,lr}'] + addr('r4',ADV_RAM)
        + ['ldrb r1,[r4,#1]', 'cmp r1,#0', 'beq go'] + inc('reinit','r4','r1')
        + ['go:', 'pop {r0,r1,r4,lr}'] + tail(0x0E07E798)) if telemetry else None
    send = b.code('advanced_send', ['push {r4,r5,r6,lr}', 'mov r5,r0']
        + send_lines(absolute['pointer'])
        + call(0x23002D54) + (addr('r4',ADV_RAM)
        + ['ldrb r1,[r4,#1]', 'cmp r1,#0', 'beq out', 'cmp r5,#9', 'bne out',
           'cmp r0,#1', 'beq queued', 'cmp r0,#6', 'bne out']
        + inc('tx_full','r4','r1') + ['b out', 'queued:']
        + inc('tx_queued','r4','r1') if telemetry else []) + ['out:', 'pop {r4,r5,r6,pc}'])
    def pointer(site, expected, new, reason):
        if b.image.get(site,4) != struct.pack('<I',expected):
            raise ValueError(f'{reason} pointer preimage changed')
        b.edit(site,struct.pack('<I',new|1),reason)
    pointer(0x0E07EDC0,DISPATCH|1,dispatch,'advanced worker recipe dispatch')
    pointer(0x0E073EDC,IRQ|1,radio,'advanced IRQ wrapper')
    if telemetry:
        pointer(0x0E0897AC,0x0E07E6DD,tick,'advanced tick')
        pointer(0x0E0897B0,0x0E07E601,done,'advanced SPI done')
    pointer(0x0E089205,0x0E071DC1,motion,'advanced motion callback')
    pointer(0x0E0879DC,0x23002D55,send,'advanced motion queue result')
    if telemetry:
        b.bl(0x0E07E716,burst,'advanced burst result counter')
        b.bl(0x0E07EA32,reinit,'advanced reinitialization counter')
    b.bl(0x0E07F876,init,'initialize advanced state once at queue startup')
    flags=P.F_FPS|P.F_LOCK|P.F_FPS_CUSTOM|P.F_SENSOR_SNAPSHOT|P.F_SMOOTHING|P.F_ADV_SAVED|P.F_IDLE_TRACKING|P.F_MOTION_PATH|P.F_ABS
    if telemetry:
        flags |= P.F_STATS|P.F_CHANNELS|P.F_RADIO_OUTCOMES
    return dict(get=channels['get'],set=channels['set'],flags=flags,telemetry=telemetry,
                preset_count=len(PRESETS),ram=evidence,
                snapshot_ram=snap_evidence,
                init=dict(address=init,hook=0x0E07F876,defaults=dict(fps=0,lock=0,stats=0)),
                hooks=dict(dispatch=dispatch,radio=radio,tick=tick,done=done,motion=motion,
                           burst=burst,lock=lock,idle=idle,release=release,radio_count=radiocount,
                           fps=fps,custom_fps=custom,send=send,
                           snapshot=snapshot_worker,snapshot_dispatch=snapshot_dispatch),
                persistence=True,settings=settings,channels=channels,motion_path=path,absolute=absolute,
                native_clock=b.native_clock,native_plock=getattr(b,'native_plock',None),
                layout_version=1,stats_fields=OFF)


def verify(b):
    """Run the repository's real-Thumb checks against this exact Builder.

    Keep the static wire maps importable without Unicorn or an assembler;
    build verification loads the shared checks only when explicitly requested.
    """
    from .checks import run_checks
    return run_checks(b)
