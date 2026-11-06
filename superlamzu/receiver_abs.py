"""dev RXABS differencing in the target's existing executable allocation.

Consolidating the three native send adapters leaves their callable entries
and queue contracts intact. Their reclaimed code holds the ABS helper.
State is five bytes in the verified tails of queues 0/1, never link data.
"""
from . import receiver as R
from .common import assemble


def _queue_core():
    # r3 < 0: raw record; otherwise prepend the low byte of r3.
    return [
        'push {r4,r5,r6,lr}', 'cbz r1,fail', 'cbz r2,fail',
        f'movw r4,#{R.QUEUE_STRIDE}', 'muls r0,r4',
        f'ldr r4,={R.QUEUE_BASE:#x}', 'add r4,r0',
        'ldrb r0,[r4]', 'cbnz r0,fail', 'ldrb r0,[r4,#2]',
        f'movs r5,#{R.QUEUE_RECORD}', 'muls r0,r5',
        f'adds r5,r4,#{R.QUEUE_HEADER}', 'add r0,r5',
        'cmp r3,#0', 'blt copy', 'strb r3,[r0]', 'adds r0,#1',
        'copy:', f'bl #{R.runtime(R.QUEUE_MEMCPY):#x}',
        'ldrb r0,[r4,#2]', 'adds r0,#1', 'uxtb r0,r0',
        'ldrb r1,[r4,#4]', 'cmp r1,r0', 'it ls', 'movls r0,#0',
        'ldrb r1,[r4,#3]', 'strb r0,[r4,#2]', 'cmp r1,r0',
        'itt eq', 'moveq r1,#1', 'strbeq r1,[r4]',
        'movs r0,#0', 'strb r0,[r4,#1]', 'movs r0,#1',
        'pop {r4,r5,r6,pc}', 'fail:', 'movs r0,#0',
        'pop {r4,r5,r6,pc}', '.ltorg']


def install(b):
    if b.image.get(R.QUEUE_RAW, len(R.QUEUE_ORIGINAL)) != R.QUEUE_ORIGINAL:
        raise ValueError('receiver queue adapter allocation preimage changed')
    site, original = R.RADIO_HOOKS['motion_copy']
    if b.image.get(site, len(original)) != original:
        raise ValueError('receiver ABS motion preimage changed')
    if b.image.get(R.RECEIVE_REPORT_SITE, 4) != R.RECEIVE_REPORT_PREIMAGE:
        raise ValueError('receiver report acceptance preimage changed')
    for address, original in (
            (R.REPORT_FIFO_SITE, R.REPORT_FIFO_PREIMAGE),
            (R.REPORT_CONSUMER_SITE, R.REPORT_CONSUMER_PREIMAGE)):
        if b.image.get(address, len(original)) != original:
            raise ValueError('receiver FIFO delivery preimage changed')
    # Preserve null/zero guards and the native BASEPRI_MAX critical section.
    prefix = [
        'cbz r1,fail', 'cbz r2,fail', 'push {r4,lr}',
        '.hword 0xf3ef,0x8411', 'movs r3,#0x60', '.hword 0xf383,0x8812',
        'isb', 'mov r3,r2', 'bl #CORE',
        '.hword 0xf384,0x8811', 'isb', 'pop {r4,pc}',
        'fail:', 'movs r0,#0', 'bx lr']
    # Fixed-width BL makes this sizing pass independent of the target.
    prefix_size = len(assemble([s.replace('CORE', hex(R.runtime(R.QUEUE_PREFIX)))
                                for s in prefix], R.runtime(R.QUEUE_PREFIX)))
    core = (R.QUEUE_PREFIX + prefix_size + 3) & ~3
    prefix = assemble([s.replace('CORE', hex(R.runtime(core))) for s in prefix],
                      R.runtime(R.QUEUE_PREFIX))
    raw = assemble(['mov.w r3,#-1', f'b.w #{R.runtime(core):#x}'],
                   R.runtime(R.QUEUE_RAW))
    obj = assemble([
        'cbz r1,fail', 'ldrb ip,[r1]', 'mov r1,r2', 'mov r2,r3',
        'mov r3,ip', f'b.w #{R.runtime(core):#x}',
        'fail:', 'movs r0,#0', 'bx lr'], R.runtime(R.QUEUE_OBJECT))
    queue_core = assemble(_queue_core(), R.runtime(core))
    if core + len(queue_core) > R.QUEUE_OBJECT:
        raise ValueError('shared receiver queue core exceeds native allocation')
    for name, address, data in (
            ('queue_raw', R.QUEUE_RAW, raw), ('queue_prefix', R.QUEUE_PREFIX, prefix),
            ('queue_object', R.QUEUE_OBJECT, obj), ('queue_core', core, queue_core)):
        b.edit(address, data, name + '; preserve native ring contract')
        b.symbols[name] = R.runtime(address)
        b.allocations.append(dict(name=name, address=hex(address),
                                  runtime=hex(R.runtime(address)), bytes=len(data)))

    cursor, limit = core + len(queue_core), R.QUEUE_OBJECT
    blocks = {}

    def emit(name, lines):
        nonlocal cursor
        address = cursor
        data = assemble(lines, R.runtime(address))
        if address + len(data) > limit:
            raise ValueError('receiver ABS tail exceeds native allocation')
        b.edit(address, data, name)
        b.symbols[name] = R.runtime(address)
        b.allocations.append(dict(name=name, address=hex(address),
                                  runtime=hex(R.runtime(address)), bytes=len(data)))
        blocks[name] = R.runtime(address)
        cursor += len(data)
        return blocks[name]

    publish = emit('abs_fifo_publish', [
        f'strb.w r8,[r1,#{R.REPORT_ABS_TAG}]',
        f'b.w #{R.runtime(R.FIFO_PUT):#x}'])
    cursor, limit = (R.QUEUE_RAW + len(raw) + 1) & ~1, R.QUEUE_PREFIX
    producer = emit('abs_fifo_report', [
        'push {r8,lr}', 'ldrb.w r8,[sp,#0x19]', 'and r8,r8,#8',
        'cmp r4,#1', 'it eq', 'lsleq.w r8,r8,#1',
        f'bl #{R.runtime(R.RECEIVE_REPORT):#x}', 'pop {r8,pc}'])
    difference = emit('receiver_abs', [
        'ldrh r0,[r4,#2]', 'ldrh r1,[r4,#4]', 'ldrb r2,[r5,#1]',
        'cbz r2,zero', 'ldrh r2,[r5,#2]',
        f'ldrh.w r3,[r5,#{R.ABS_Y-R.ABS_STATE}]',
        'subs r0,r0,r2', 'subs r1,r1,r3',
        'sxth r2,r0', f'cmp.w r2,#{R.ABS_JUMP_LIMIT}', 'bge zero',
        f'cmn.w r2,#{R.ABS_JUMP_LIMIT}', 'ble zero',
        'sxth r2,r1', f'cmp.w r2,#{R.ABS_JUMP_LIMIT}', 'bge zero',
        f'cmn.w r2,#{R.ABS_JUMP_LIMIT}', 'bgt store',
        'zero:', 'movs r0,#0', 'movs r1,#0',
        'store:', 'strh r0,[r4,#2]', 'strh r1,[r4,#4]', 'bx lr'])
    cursor, limit = (R.QUEUE_OBJECT + len(obj) + 1) & ~1, R.QUEUE_BLOCK_END
    consumer = emit('abs_usb_report', [
        'cmp r0,#2', 'bne native', 'push {r4,r5,r6,r7,lr}', 'sub sp,#4',
        'mov r4,r1', f'ldr r5,={R.ABS_STATE:#x}', 'ldrb r7,[r4,#8]',
        'cmp r7,#8', 'bne report', 'ldr r6,[r4,#2]',
        f'bl #{difference:#x}', 'report:', 'movs r0,#2', 'mov r1,r4',
        'movs r2,#8', f'bl #{R.runtime(R.USB_REPORT):#x}', 'cbz r0,out',
        'cmp r7,#16', 'beq out', 'lsrs r7,#3', 'strb r7,[r5,#1]',
        'cbz r7,out', 'strh r6,[r5,#2]', 'lsrs r6,#16',
        f'strh.w r6,[r5,#{R.ABS_Y-R.ABS_STATE}]',
        'out:', 'add sp,#4', 'pop {r4,r5,r6,r7,pc}',
        'native:', f'b.w #{R.runtime(R.USB_REPORT):#x}', '.ltorg'])
    b.edit(R.RECEIVE_REPORT_SITE,
           assemble(f'bl #{producer:#x}', R.runtime(R.RECEIVE_REPORT_SITE)),
           'carry ABS identity in owned FIFO report padding')
    b.edit(R.REPORT_FIFO_SITE,
           assemble(f'bl #{publish:#x}', R.runtime(R.REPORT_FIFO_SITE)),
           'publish ABS marker before linking native FIFO report')
    b.edit(R.REPORT_CONSUMER_SITE,
           assemble(f'bl #{consumer:#x}', R.runtime(R.REPORT_CONSUMER_SITE)),
           'difference and commit ABS only after native USB queue acceptance')
    return dict(state_bytes=5, valid=R.ABS_VALID, x=R.ABS_X, y=R.ABS_Y,
                queue_capacity=R.QUEUE_CAPACITY, jump_limit=R.ABS_JUMP_LIMIT,
                relative_preserved=True, receiver_first=True)
