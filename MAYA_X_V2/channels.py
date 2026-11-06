"""Five native hops plus an unknown bucket, counted only at actual decisions.

The legacy Thorn payload has four hops. MAYA uses a distinct 36-byte v1
payload; the fifth real hop must never be silently labelled unknown.
"""
from superlamzu import advanced as A, protocol as P

from . import target as T


def install(builder, getter, setter, storage):
    def call(value):
        return A.call(value, target=T)

    def tail(value):
        return A.tail(value, target=T)

    pointer = builder.code('maya_channels_pointer', A.snapshot_pointer('r0', 'r1', 'r2', target=T)
        + ['cmp r0,#0', 'it ne', f'addwne r0,r0,#{T.CHAN_OFFSET}', 'bx lr'])
    count = builder.code('channels_count', [
        'push {r4,r5,r6,lr}', 'mov r6,r2', *call(pointer),
        'cmp r0,#0', 'beq out', 'mov r4,r0', 'ldrb r0,[r4]',
        'cmp r0,#0', 'beq out', *A.addr('r0', T.CHAN_FREQUENCY),
        'ldr r0,[r0]', *A.addr('r3', T.CHAN_HOPS), 'movs r1,#0',
        'copy:', 'ldrb r5,[r3,r1]', 'add r2,r4,#28', 'strb r5,[r2,r1]',
        'adds r1,#1', 'cmp r1,#5', 'bne copy', 'movs r1,#0',
        'find:', 'ldrb r5,[r3,r1]', 'cmp r5,r0', 'beq found',
        'adds r1,#1', 'cmp r1,#5', 'bne find',
        'found:', 'add r4,r4,r1,lsl #1', 'ldrh r0,[r4,#4]',
        'adds r0,#1', 'strh r0,[r4,#4]', 'cmp r6,#0', 'beq out',
        'ldrh r0,[r4,#16]', 'adds r0,#1', 'strh r0,[r4,#16]',
        'out:', 'pop {r4,r5,r6,pc}'])
    get = builder.code('channels_get', [
        'cmp r5,#13', 'beq ours', *tail(getter), 'ours:', 'push {r7,lr}',
        'cmp r6,#0', 'bne bad', 'ldrb r0,[r4,#3]', 'cmp r0,#2', 'bne bad',
        'add r2,r4,#8', 'movs r0,#0', 'movs r1,#34',
        'zero:', 'strb r0,[r2],#1', 'subs r1,#1', 'bne zero',
        'movs r0,#1', 'strb r0,[r4,#9]', 'movs r0,#5', 'strb r0,[r4,#10]',
        '.hword 0xf3ef,0x8710', 'cpsid i', *call(pointer),
        'cmp r0,#0', 'beq reply', 'ldrb r1,[r0]', 'strb r1,[r4,#8]',
        'adds r0,#4', 'add r2,r4,#12', 'movs r3,#29',
        'copy:', 'ldrb r1,[r0],#1', 'strb r1,[r2],#1', 'subs r3,#1', 'bne copy',
        'reply:', '.hword 0xf387,0x8810', 'movs r0,#36', 'strb r0,[r4,#3]',
        'movs r0,#1', 'pop {r7,pc}', 'bad:', 'movs r0,#0', 'pop {r7,pc}'])
    set_ = builder.code('channels_set', [
        'cmp r5,#13', 'beq ours', *tail(setter), 'ours:', 'push {r7,lr}',
        'cmp r6,#0', 'bne bad', 'ldrb r0,[r4,#3]', 'cmp r0,#3', 'bne bad',
        'ldrb r0,[r4,#8]', 'cmp r0,#2', 'bhi bad', *call(storage),
        'cmp r0,#0', 'beq bad', f'addw r0,r0,#{T.CHAN_OFFSET}',
        'ldrb r1,[r4,#8]', 'cmp r1,#2', 'beq reset', 'strb r1,[r0]', 'b reply',
        'reset:', '.hword 0xf3ef,0x8710', 'cpsid i', 'adds r0,#4',
        'movs r1,#0', 'movs r2,#8',
        'clear:', 'str r1,[r0],#4', 'subs r2,#1', 'bne clear',
        '.hword 0xf387,0x8810', 'reply:', 'movs r0,#2', 'strb r0,[r4,#3]',
        *call(get), 'pop {r7,pc}', 'bad:', 'movs r0,#0', 'pop {r7,pc}'])
    return dict(get=get, set=set_, count=count, flags=P.F_CHANNELS,
                outcome_semantics=P.RADIO_OUTCOME_SEMANTICS,
                default=False, heap_offset=T.CHAN_OFFSET, heap_bytes=T.CHAN_BYTES,
                wire_bytes=36, wire_version=1, hops=5, unknown_bucket=5,
                counter='u16 wrapping; first matching native hop')
