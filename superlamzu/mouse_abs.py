"""Dev cumulative motion, button-only frames and retransmits, adapted to Thorn."""
from . import target as T
from .advanced import addr, call
from .common import assemble

ENABLED = 0x40


def send_lines(pointer):
    # advanced_send already preserves r6 and the report ID. Only message 9
    # owns a motion payload; buttons and wheel retain their original messages.
    return (['cmp r5,#9', 'bne abs_send_done', 'mov r6,r1', f'bl #{pointer:#x}',
             'cbz r3,abs_send_restore',
             'ldrh r2,[r3,#24]', 'strh r2,[r6,#4]', 'ldrh r2,[r3,#26]', 'strh r2,[r6,#6]',
             'abs_send_restore:', 'mov r1,r6', 'abs_send_done:'])


def install(b):
    for site, original in ((T.ABS_ACC_SITE, T.ABS_ACC_PREIMAGE),
                           (T.ABS_HEADER_SITE, T.ABS_HEADER_PREIMAGE),
                           (T.ABS_FRAME_POP_SITE, T.ABS_FRAME_POP_PREIMAGE),
                           (T.ABS_RETX_SITE, T.ABS_RETX_PREIMAGE)):
        if b.image.get(T.flash_source(site), len(original)) != original:
            raise ValueError(f'ABS hook preimage changed at {site:#x}')
    # Reuse the existing conservative direct-branch/literal inventory for
    # the displaced accumulator too. The interval starts two bytes earlier
    # because the common scanner deliberately excludes its entry itself.
    from types import SimpleNamespace
    from .patch import check_external_recipe_entries
    check_external_recipe_entries(b.image,target=SimpleNamespace(
        FLASH_RECIPES=(T.ABS_ACC_SITE+2,),RECIPE_SIZES=(len(T.ABS_ACC_PREIMAGE)-2,),
        RECIPE_NONPOINTERS={}))
    # Shared decode: r0 preserved, r1/r2 scratch, r3 storage or zero. Enabling
    # ABS is published only after thread-context storage allocation succeeds.
    assert T.SNAPSHOT_POINTER & 3 == 1
    pointer = b.code('abs_pointer', addr('r3', T.SNAPSHOT_POINTER-1)
        + ['ldr r3,[r3]', f'tst r3,#{ENABLED << 24}', 'beq off',
           'ubfx r3,r3,#8,#20',
           'orr r3,r3,#0x23000000', 'bx lr', 'off:', 'movs r3,#0', 'bx lr'])
    # Read enable and pointer together; relative mode skips the helper's
    # stack frame. OWNER spans this total publication and the native sums.
    total = b.code('abs_total', addr('r2', T.SNAPSHOT_POINTER-1)
        + ['ldr r2,[r2]', f'tst r2,#{ENABLED << 24}', 'beq native',
           'push {r0,r4,r5,lr}', 'ubfx r3,r2,#8,#20',
           'orr r3,r3,#0x23000000',
           'ldrh.w r4,[sp,#18]', 'ldrh.w r5,[sp,#20]',
           'ldr r1,[r3,#24]','adds r2,r1,r4',
           'add r1,r1,r5,lsl #16','bfi r1,r2,#0,#16','str r1,[r3,#24]',
           'pop {r0,r4,r5,lr}', 'native:'] + addr('r2', T.MOTION_ACC_Y)
        + ['ldrh.w r1,[sp,#2]', 'ldrh r3,[r2,#2]', 'adds r3,r1', 'strh r3,[r2,#2]',
           'ldrh.w r1,[sp,#4]', 'ldrh r3,[r2]', 'adds r3,r1', 'strh r3,[r2]',
           f'b.w #{T.ABS_ACC_SITE+24:#x}'])
    # Capture actual pop validity in SP+0 (SP+3 is buttons/wheel). SP+8 is
    # another unused native local: snapshot before pop so a later producer
    # cannot make button-only totals overtake its newly queued sample.
    pop = b.code('abs_frame_pop',['push {r1,r2,r4,lr}','movs r4,#0',f'bl #{pointer:#x}',
        'cbz r3,pop','ldr r4,[r3,#24]','pop:','ldm sp,{r1,r2}']+call(T.ABS_QUEUE_POP)
        + ['strb.w r0,[sp,#16]','str r4,[sp,#24]','pop {r1,r2,r4,pc}'])
    header = b.code('abs_header',
        ['strb r0,[r3]', 'ldrh r6,[sp,#4]', 'push {r0,r1,r2,r3,r7,lr}', f'bl #{pointer:#x}',
         'cbz r3,relative', 'orr r0,r0,#8', 'ldrb r1,[sp,#24]',
         'cbnz r1,relative', 'ldr r6,[sp,#32]', 'lsrs r5,r6,#16',
         'relative:', 'strb r0,[r4,#2]', 'strh r6,[r4,#4]', 'strh r5,[r4,#6]',
         'pop {r0,r1,r2,r3,r7,lr}', 'subs r3,#1', 'strb r2,[r3]']
        + addr('r12', T.ABS_HEADER_SITE+16 | 1) + ['bx r12'])
    # Snapshot before checking emptiness: a later producer can only enqueue
    # totals at or after this snapshot. OWNER rejects a suspended transaction;
    # totals publish as one aligned word, so reads cannot mix X/Y generations.
    retransmit = b.code('abs_retransmit', ['push {r5,r6,r7,lr}', f'bl #{pointer:#x}',
        'adds r1,r4,#6', 'ldrb r2,[r1]', 'cbz r3,copy',
        'cmp r2,#7', 'bne copy', 'ldrb r0,[r1,#2]', 'and r0,r0,#15',
        'cmp r0,#10', 'bne copy']
        + addr('r5', T.RADIO_QUEUE2)
        + [f'ldrb r0,[r5,#{T.MOTION_STATE-T.RADIO_QUEUE2}]',
           'lsls r0,r0,#26', 'bmi copy', 'ldr r6,[r3,#24]',
           'ldrb r0,[r5]', 'cbnz r0,copy', 'ldrb r0,[r5,#2]',
           'ldrb r5,[r5,#3]', 'cmp r0,r5', 'bne copy',
        'strh r6,[r1,#4]', 'lsrs r6,r6,#16', 'strh r6,[r1,#6]',
        'copy:', 'adds r2,#1', 'add.w r0,r1,#0x80'] + call(T.RADIO_MEMCPY)
        + ['movs r3,#1', 'pop {r5,r6,r7,pc}'])
    b.edit(T.ABS_ACC_SITE, assemble(f'b.w #{total:#x}', T.ABS_ACC_SITE),
           'ABS totals after native coordinate transform')
    # The guarded 24-byte straight-line accumulator is now a tail branch.
    # Its displaced 20 bytes are the only extra executable region reclaimed;
    # no padding, writable state, MPU change or new Flash span is involved.
    b.add_pool(T.ABS_ACC_SITE+4,T.ABS_ACC_SITE+24)
    # Two aligned absolute veneers share the displaced header allocation.
    # The first continues the frame; the second returns to its native pop BL.
    import struct
    veneers = (assemble(['ldr.w pc,[pc,#0]'], T.ABS_HEADER_SITE)
        + struct.pack('<I', header | 1)
        + assemble(['ldr.w pc,[pc,#0]'], T.ABS_HEADER_SITE+8)
        + struct.pack('<I', pop | 1))
    b.edit(T.ABS_HEADER_SITE, veneers, 'ABS frame/header and queue-pop ownership veneers')
    b.bl(T.ABS_FRAME_POP_SITE, T.ABS_HEADER_SITE+8, 'preserve actual motion-pop validity')
    for site, helper in ((T.ABS_RETX_SITE, retransmit),):
        # RAM is outside Flash's BL range, even when the helper itself is near.
        code = assemble(addr('r12', helper | 1) + ['blx r12'] + ['nop']*3, site)
        if len(code) != 16:
            raise ValueError('ABS RAM hook size changed')
        b.edit(site, code, 'ABS native frame/retransmit adapter')
    return dict(pointer=pointer, total=total, header=header, pop=pop, retransmit=retransmit,
                enable_mask=ENABLED, default='relative', total_bytes=4,
                snapshot_abi_bytes=24, storage_bytes=T.SNAPSHOT_STORAGE_BYTES)
