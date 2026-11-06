"""Cumulative XY on MAYA type2 frames; retain native signed saturation.

Queued samples carry totals at enqueue time. The native assembler retains
both ordered samples; button-only frames use current totals. Retransmits may
catch up to current totals only after all older queued samples have drained.
The paired receiver must understand type0A before enabling this setting.
"""
import struct

from superlamzu import advanced as A
from superlamzu.common import assemble

from . import target as T

ENABLED = 0x40


def install(builder):
    for site, original in T.ABS_PREIMAGES.items():
        if builder.image.get(T.flash_source(site), len(original)) != original:
            raise ValueError(f'MAYA ABS preimage changed at {site:#x}')

    def call(value):
        return A.call(value, target=T)

    def tail(value):
        return A.tail(value, target=T)

    pointer = builder.code('abs_pointer', [
        *A.addr('r3', T.SNAPSHOT_POINTER-1), 'ldr r3,[r3]',
        'tst r3,#0x40000000', 'beq off',
        'ubfx r3,r3,#8,#20', 'cmp r3,#0', 'it ne',
        f'orrne r3,r3,#{T.RAM_POINTER_BASE:#x}', 'bx lr',
        'off:', 'movs r3,#0', 'bx lr'])
    # Decode the enable bit and heap address from the same aligned word.
    assert T.SNAPSHOT_POINTER & 3 == 1
    total = builder.code('abs_total', [
        *A.addr('r2', T.SNAPSHOT_POINTER-1), 'ldr r2,[r2]',
        f'tst r2,#{ENABLED << 24}', 'beq replay',
        'push {r0,r1,r4,lr}',
        'ubfx r3,r2,#8,#20', 'cbz r3,restore',
        f'orr r3,r3,#{T.RAM_POINTER_BASE:#x}',
        # Native stack locals +14/+16, plus this helper's 16-byte frame.
        'ldr r1,[r3,#24]','ldrh.w r4,[sp,#30]','adds r2,r1,r4',
        'ldrh.w r4,[sp,#32]','add r1,r1,r4,lsl #16','bfi r1,r2,#0,#16','str r1,[r3,#24]',
        'restore:', 'pop {r0,r1,r4,lr}', 'replay:', *A.addr('r2', T.MOTION_ACC_X),
        'ldrsh.w r1,[sp,#14]', 'ldrsh.w r3,[r2]', 'add r3,r1', 'bx lr'])
    veneer = assemble(A.addr('r12', total | 1)+['blx r12', 'nop'], T.ABS_ACC_SITE)
    builder.edit(T.ABS_ACC_SITE, veneer, 'MAYA totals after transform; original saturation branches retained')

    native = builder.code('maya_frame_native', [
        'push {r0-r8,lr}', 'mov r6,r1', 'mov r4,r0', 'cmp r0,#0',
        'beq null', *tail(T.ABS_FRAME_CONTINUE), 'null:', *tail(0x200044F6)])
    # Use the count actually consumed by the native frame, not an earlier
    # wrapper observation. Its r5 survives the native return only on stack;
    # save count, pre-check total and format in the wrapper's owned locals.
    # The frame uses that same observation, without decoding the pointer twice.
    count = builder.code('abs_frame_count',[
        *A.addr('r3',T.SNAPSHOT_POINTER-1),'ldr r3,[r3]',
        'tst r3,#0x40000000','beq relative','ubfx r3,r3,#8,#20',
        'cmp r3,#0','beq relative',f'orr r3,r3,#{T.RAM_POINTER_BASE:#x}',
        'push {r4,r5,r12,lr}','mov r5,r3','ldr r4,[r3,#24]',
        'movs r0,#2',*call(T.QUEUE_COUNT),
        'str r0,[sp,#56]','str r4,[sp,#60]','str r5,[sp,#64]','pop {r4,r5,r12,pc}',
        # The native frame has 40 bytes on its stack. Only the format marker
        # is needed for relative motion; tail-call without touching r12/LR.
        'relative:','movs r3,#0','str r3,[sp,#48]',
        'movs r0,#2',f'ldr.w pc,={T.QUEUE_COUNT|1:#x}', '.ltorg'])
    builder.edit(T.ABS_FRAME_COUNT_POINTER,struct.pack('<I',count|1),
                 'capture native frame count and earlier total without masking')
    frame = builder.code('abs_frame', [
        'push {r4,lr}', 'sub sp,#16', 'mov r4,r0', *call(native),
        'cmp r0,#1', 'bne out', 'ldrb r1,[r4,#2]', 'cmp r1,#2', 'bne out',
        'ldr r2,[sp,#8]', 'cmp r2,#0', 'beq out', 'movs r1,#10', 'strb r1,[r4,#2]',
        'ldr r1,[sp]','cmp r1,#0', 'bne out', 'ldr r1,[sp,#4]',
        'strh r1,[r4,#4]','lsrs r1,r1,#16','strh r1,[r4,#6]',
        'out:', 'add sp,#16', 'pop {r4,pc}'])
    # One entry covers both native radio assembler calls without far BL.
    builder.edit(T.ABS_FRAME_NATIVE, assemble(A.addr('r12', frame | 1)+['bx r12'],
                                             T.ABS_FRAME_NATIVE),
                 'MAYA type2 dual-sample ABS frame wrapper')
    copy = builder.code('abs_copy', [
        'push {r12}',
        *A.addr('r12', T.MOTION_STATE), 'ldrb.w r12,[r12]',
        f'tst r12,#{ENABLED}', 'pop {r12}', 'beq copy_native',
        'push {r0,r1,r2,r4,r5,r6,r7,lr}', 'mov r4,r1', 'mov r5,r0',
        # Only state4/6 retransmits refresh. Fresh state8 dual-sample copies
        # retain both enqueue-time totals, including their temporal order.
        *A.addr('r0', T.ABS_DMA_BUFFER), 'cmp r5,r0', 'bne native',
        *A.addr('r0', T.ABS_TX_BUFFER), 'cmp r4,r0', 'bne native',
        *A.addr('r0', T.RADIO_STATE+0x186), 'ldrb r0,[r0]',
        'cmp r0,#4', 'beq candidate', 'cmp r0,#6', 'bne native',
        'candidate:', 'ldrb r0,[r4,#2]', 'cmp r0,#10', 'bne native',
        'ldrb r0,[r4]', 'cmp r0,#7', 'beq refresh', 'cmp r0,#11', 'bne native',
        # Do not send live totals ahead of older queued samples. Otherwise
        # the next normal frame moves the receiver backwards through backlog.
        'refresh:', *A.snapshot_pointer('r3','r1','r2',target=T),
        'cmp r3,#0', 'beq native',
        *A.addr('r0',T.MOTION_STATE),
        'ldrb r1,[r0]','tst r1,#32','bne native','ldr r6,[r3,#24]',
        *A.addr('r0',T.RADIO_QUEUE2),
        'ldrb r1,[r0]','cmp r1,#0','bne native',
        'ldrb r1,[r0,#2]','ldrb r0,[r0,#3]','cmp r0,r1','bne native',
        'uxth r0,r6','lsrs r1,r6,#16','strh r0,[r4,#4]','strh r1,[r4,#6]',
        # Keep the second sample cumulative, not zero or stale on retransmit.
        'ldrb r2,[r4]', 'cmp r2,#11', 'bne native',
        'strh r0,[r4,#8]', 'strh r1,[r4,#10]',
        'native:', 'pop {r0,r1,r2,r4,r5,r6,r7,lr}',
        'copy_native:', *tail(T.NATIVE_MEMCPY)])
    builder.edit(T.ABS_COPY_POINTER, struct.pack('<I', copy | 1),
                 'MAYA radio copy adapter; actual memcpy entry preserved')
    return dict(pointer=pointer, total=total, frame=frame, copy=copy,
                enable_mask=ENABLED, type_relative=2, type_absolute=10,
                native_saturation=True, native_dual_sample=True)


def send_lines(pointer):
    return ['cmp r5,#9', 'bne abs_send_done',
            *A.call(pointer, target=T), 'cmp r3,#0', 'beq abs_send_done',
            'ldrh r2,[r3,#24]', 'strh r2,[r1,#4]',
            'ldrh r2,[r3,#26]', 'strh r2,[r1,#6]', 'abs_send_done:']


def router(builder,getter,setter,storage):
    def call(value):return A.call(value,target=T)
    def tail(value):return A.tail(value,target=T)
    set_enabled=builder.code('settings_abs_enable',[
        'push {r4,lr}','mov r4,r0','cmp r0,#0','beq publish',*call(storage),
        'cmp r0,#0','beq out','publish:',*A.addr('r1',T.MOTION_STATE),
        '.hword 0xf3ef,0x8c10','cpsid i','ldrb r2,[r1]',
        # Queue2 records have no per-record format tag. Do not reinterpret
        # older relative deltas as totals (or totals as relative motion).
        # OWNER excludes an already-running sample/report producer; the
        # masked queue-header check excludes a producer starting afterwards.
        'ubfx r0,r2,#6,#1','cmp r0,r4','beq success',
        'tst r2,#32','bne busy',
        # Queue2 can be empty while an earlier failed send still owns XY.
        *A.addr('r3',T.MOTION_ACC_Y),'ldr r0,[r3]','cbnz r0,busy',
        *A.addr('r3',T.RADIO_QUEUE2),
        'ldrb r0,[r3]','cmp r0,#0','bne busy',
        'ldrb r0,[r3,#2]','ldrb r3,[r3,#3]','cmp r0,r3','bne busy',
        'bic r2,r2,#64','orr r2,r2,r4,lsl #6','strb r2,[r1]',
        'success:','movs r0,#1','b unmask','busy:','movs r0,#0',
        'unmask:','.hword 0xf38c,0x8810','out:','pop {r4,pc}'])
    get=builder.code('settings_abs_get',[
        'cmp r5,#11','beq ours',*tail(getter),'ours:','cmp r6,#0','bne bad',
        'ldrb r0,[r4,#3]','cmp r0,#2','bne bad',*A.addr('r1',T.MOTION_STATE),
        'ldrb r0,[r1]','ubfx r0,r0,#6,#1','strb r0,[r4,#8]',
        'movs r0,#3','strb r0,[r4,#3]','movs r0,#1','bx lr','bad:','movs r0,#0','bx lr'])
    set_=builder.code('settings_abs_set',[
        'cmp r5,#11','beq ours',*tail(setter),'ours:','push {r7,lr}',
        'cmp r6,#0','bne bad','ldrb r0,[r4,#3]','cmp r0,#3','bne bad',
        'ldrb r0,[r4,#8]','cmp r0,#1','bhi bad',*call(set_enabled),
        'cmp r0,#0','beq bad','movs r0,#2','strb r0,[r4,#3]',*call(get),
        'pop {r7,pc}','bad:','movs r0,#0','pop {r7,pc}'])
    return dict(get=get,set=set_,enable=set_enabled)
