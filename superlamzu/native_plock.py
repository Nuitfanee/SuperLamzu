"""Target-native 1 MHz split-compare LOCK generators.

The caller owns timer lifecycle hooks, storage allocation and clock eligibility.
Only the existing heap reserve is writable; radio IRQs never allocate storage.
"""
from . import advanced as A


CONTROL_OFFSET = 308
PERIOD, EXPECTED, PENDING, COUNTDOWN, FLAGS = 0, 2, 4, 6, 7
SPLIT, CALIBRATED, PENDING_VALID, AWAIT_WRAP, DISCARD_FIRST = 1, 2, 4, 8, 16
RELOAD, RECHECK, DEADBAND, OUTLIER, AGREE = 64, 8, 8, 16, 8
SENTINEL = 0xFFFF


def _timer(reg, target):
    pointer = getattr(target, 'REPORT_TIMER_POINTER', None)
    return (A.addr(reg, pointer) + [f'ldr {reg},[{reg}]'] if pointer is not None
            else A.addr(reg, target.REPORT_TIMER))


def _control(reg, target):
    return A.snapshot_pointer(reg, 'r0', 'r1', target=target) + [
        f'cmp {reg},#0', 'it ne', f'addne.w {reg},{reg},#{CONTROL_OFFSET}']


def _wrap(reg, period, scratch, label):
    # Inputs are within two periods; branch loops also handle boundary equality.
    return [f'lsrs {scratch},{period},#1', f'{label}_hi:', f'cmp {reg},{scratch}',
            f'blt {label}_lo', f'subs {reg},{reg},{period}', f'b {label}_hi',
            f'{label}_lo:', f'rsbs {scratch},{scratch},#0', f'cmp {reg},{scratch}',
            f'bge {label}_done', f'adds {reg},{reg},{period}',
            f'lsrs {scratch},{period},#1', f'b {label}_lo', f'{label}_done:']


def _capture_lines():
    """r0=timer, r1=channel, r2=also CLEAR; returns u16 or SENTINEL."""
    return ['add.w r3,r0,r1,lsl #2', 'movw r1,#65535',
            'str.w r1,[r3,#0x540]', 'movs r1,#1', 'str r1,[r3,#0x40]',
            'cmp r2,#0', 'beq poll', 'str r1,[r0,#12]', 'poll:',
            'movs r2,#8', 'wait:', 'ldrh.w r0,[r3,#0x540]', 'movw r1,#65535',
            'cmp r0,r1', 'bne out', 'subs r2,#1', 'bne wait', 'out:', 'bx lr']


def _apply_lines(target):
    """r0=base period, r1=eligibility, r2=running. Preserve r0 and ABI/mask."""
    return (['cmp r0,#0', 'bne enter', 'bx lr', 'enter:',
             'push {r4,r5,r6,r7,lr}', 'sub sp,#12', 'mov r4,r0',
             'mov r5,r1', 'mov r6,r2'] + _control('r7', target)
        + ['cmp r7,#0', 'beq.w out', '.hword 0xf3ef,0x8010', 'str r0,[sp]', 'cpsid i',
           'cmp r6,#0', 'beq.w stopped'] + _timer('r3', target)
        + ['mov r1,r4', 'movs r2,#1', 'cmp r5,#0', 'beq native']
        + A.addr('r0', target.ADV_RAM)
        + ['ldrb r5,[r0,#2]', 'cmp r5,#0', 'beq native',
           'ldrh r5,[r0,#4]', 'cmp r5,#0', 'bne lead', 'movs r5,#80', 'lead:',
           'cmp r4,#250', 'beq rate', 'cmp.w r4,#500', 'beq rate',
           'cmp.w r4,#1000', 'bne native', 'rate:']
        + A.addr('r0', target.REPORT_DIVIDER)
        + ['ldrb r0,[r0]', 'cmp r0,#1', 'bne native', 'lsrs r0,r4,#1',
           'subs r0,#8', 'cmp r5,r0', 'bhi native',
           'subs r1,r4,r5', 'movs r2,#2', 'native:',
           'ldrb r5,[r7,#7]', 'tst r5,#1', 'bne compare',
           'cmp r2,#1', 'bne migrate', 'ldr.w r0,[r3,#0x200]',
           'cmp r0,#2', 'bne.w unlock', 'b migrate', 'compare:',
           'cmp r2,#2', 'bne migrate', 'ldr.w r0,[r3,#0x200]',
           'cmp r0,r2', 'bne migrate', 'ldr.w r0,[r3,#0x544]',
           'cmp r0,r4', 'bne migrate', 'ldr.w r0,[r3,#0x540]',
           'cmp r0,r1', 'beq unlock', 'migrate:',
           'movs r0,#1', 'str r0,[r3,#4]', 'str.w r1,[r3,#0x540]',
           'str.w r4,[r3,#0x544]', 'str.w r2,[r3,#0x200]',
           'movs r5,#0', 'str.w r5,[r3,#0x144]', 'str r0,[r3,#12]',
           'str r5,[r7]', 'str r5,[r7,#4]', 'cmp r2,#2', 'bne owned',
           'strh r4,[r7]', f'movs r5,#{SPLIT|AWAIT_WRAP|DISCARD_FIRST}',
           'strb r5,[r7,#7]', 'movs r5,#1', 'owned:']
        + A.addr('r1', target.ADV_RAM)
        + ['strb r5,[r1,#12]', 'movs r5,#0', 'strh r5,[r1,#6]',
           'str r0,[r3]', 'b unlock', 'stopped:', 'movs r0,#0',
           'str r0,[r7]', 'str r0,[r7,#4]'] + A.addr('r1',target.ADV_RAM)
        + ['strb r0,[r1,#12]', 'strh r0,[r1,#6]', 'unlock:', 'ldr r0,[sp]',
           '.hword 0xf380,0x8810', 'out:', 'mov r0,r4', 'add sp,#12',
           'pop {r4,r5,r6,r7,pc}'])


def _phase_lines(capture, target, telemetry):
    """r0=control, r1=entry capture, r2=pre-state/slot/queue bits."""
    call = lambda fn: A.call(fn, target=target)
    L = ['push {r4,r5,r6,r7,lr}', 'sub sp,#12', 'mov r4,r0',
         'str r1,[sp]', 'str r2,[sp,#4]', 'ldrh r6,[r4]',
         'ldrb r7,[r4,#7]', 'tst r7,#1', 'beq.w out']
    L += _timer('r5', target)
    L += A.addr('r3', target.RADIO_STATE) + [
        'ldrb r0,[r3,#1]', 'cmp r0,#0', 'beq.w lost',
        'ldrb r0,[r3,#2]', 'cmp r0,#0', 'beq.w lost',
        'tst r2,#0x100', 'beq.w out', 'tst r2,#0x200', 'beq.w out',
        f'tst r7,#{AWAIT_WRAP}', 'beq reference',
        'ldr.w r0,[r5,#0x144]', 'cmp r0,#0', 'beq.w out',
        'movs r0,#0', 'str.w r0,[r5,#0x144]',
        f'tst r7,#{DISCARD_FIRST}', 'beq wrapped',
        f'bic r7,r7,#{DISCARD_FIRST}', 'strb r7,[r4,#7]', 'b.w out',
        'wrapped:', f'bic r7,r7,#{AWAIT_WRAP}', 'strb r7,[r4,#7]',
        'reference:', 'and r0,r2,#255', 'cmp r0,#8', 'bne.w out',
        'ldrb.w r0,[r3,#0x186]', 'tst r2,#0x400', 'beq idle',
        'cmp r0,#4', 'bne.w out', 'movs r0,#1', 'b sample',
        'idle:', 'cmp r0,#8', 'bne.w out']
    L += A.addr('r0', target.SMOOTHING_STATE) + [
        'ldrb r0,[r0]', 'tst r0,#128', 'beq.w out', 'movs r0,#0',
        'sample:', 'str r0,[sp,#8]', 'ldr r0,[sp]', 'cmp r0,r6', 'bhs.w fail',
        'mov r0,r5', 'movs r1,#3', 'movs r2,#0'] + call(capture)
    L += ['cmp r0,r6', 'bhs.w fail'] + A.addr('r1', target.ADV_RAM)
    L += ['strh r0,[r1,#6]', 'ldr r1,[sp,#8]', 'cmp r1,#0', 'bne decide',
          'lsrs r1,r6,#2', 'cmp r0,r1', 'bls decide', 'subs r0,r6,r0',
          'cmp r0,r1', 'bhi.w out', 'decide:', 'ldr r0,[sp]',
          f'tst r7,#{CALIBRATED}', 'beq.w act', 'ldrsh r1,[r4,#2]',
          'subs r0,r0,r1']
    L += _wrap('r0','r6','r1','error')
    L += ['movs r2,r0', 'bpl size', 'rsbs r2,r2,#0', 'size:',
          f'cmp r2,#{DEADBAND}', 'blo stable', f'cmp r2,#{OUTLIER}',
          'bls act', f'tst r7,#{PENDING_VALID}', 'beq pending',
          'ldrsh r1,[r4,#4]', 'str r0,[sp,#8]', 'subs r0,r0,r1']
    L += _wrap('r0','r6','r1','agree')
    L += ['cmp r0,#0', 'bge positive', 'rsbs r0,r0,#0', 'positive:',
          f'cmp r0,#{AGREE}', 'bls act', 'ldr r0,[sp,#8]',
          'pending:', 'strh r0,[r4,#4]', f'orr r7,r7,#{PENDING_VALID}',
          'strb r7,[r4,#7]', f'movs r0,#{RECHECK}', 'strb r0,[r4,#6]',
          'b out', 'stable:', f'bic r7,r7,#{PENDING_VALID}',
          'strb r7,[r4,#7]', f'movs r0,#{RELOAD}', 'strb r0,[r4,#6]',
          'b out', 'act:', 'ldr.w r0,[r5,#0x140]', 'cmp r0,#0', 'bne out',
          f'bic r7,r7,#{CALIBRATED|PENDING_VALID}',
          f'orr r7,r7,#{AWAIT_WRAP|DISCARD_FIRST}', 'strb r7,[r4,#7]',
          'movs r0,#0', 'strb r0,[r4,#6]', 'mov r0,r5', 'movs r1,#2',
          'movs r2,#1'] + call(capture)
    L += ['cmp r0,r6', 'bhs fail', 'ldr r1,[sp]', 'subs r0,r1,r0']
    L += _wrap('r0','r6','r1','expected')
    L += ['strh r0,[r4,#2]', f'orr r7,r7,#{CALIBRATED}', 'strb r7,[r4,#7]']
    if telemetry:
        L += A.addr('r1',target.ADV_RAM) + A.inc('lock_adjust','r1','r0')
    L += ['b out', 'lost:', f'and r7,r7,#{SPLIT|AWAIT_WRAP|DISCARD_FIRST}',
          'strb r7,[r4,#7]', 'movs r0,#0', 'strb r0,[r4,#6]', 'b out', 'fail:']
    if telemetry:
        L += A.addr('r1',target.ADV_RAM) + A.inc('capture_fail','r1','r0')
    L += ['out:', 'add sp,#12', 'pop {r4,r5,r6,r7,pc}']
    return _wide(L)


def _wide(lines):
    import re
    return [re.sub(r'^(b(?:eq|ne|lo|hi|hs|ls|lt|gt|ge|le|mi|pl)?) ([a-z_][a-z0-9_]*)$',
                   r'\1.w \2', line) for line in lines]


def _compact(lines):
    """Use literal addresses, retaining fixed-width branches around the pool."""
    import re
    result=[]
    index=0
    while index<len(lines):
        first=re.fullmatch(r'movw (\w+),#(\d+)',lines[index])
        second=re.fullmatch(r'movt (\w+),#(\d+)',lines[index+1]) if index+1<len(lines) else None
        if first and second and first[1]==second[1]:
            result.append(f'ldr {first[1]},={int(first[2])|(int(second[2])<<16):#x}')
            index+=2
        else:
            result.append(lines[index]);index+=1
    return result+['.ltorg']


def install_control(builder, *, target=None, telemetry=True):
    target = target or builder.target
    capture = builder.code('native_plock_capture', _capture_lines())
    apply = builder.code('native_plock_apply', _compact(_wide(_apply_lines(target))))
    phase = builder.code('native_plock_phase', _compact(_phase_lines(capture,target,telemetry)))
    return dict(apply=apply, phase=phase, capture=capture, offset=CONTROL_OFFSET,
                telemetry=bool(telemetry))


def _radio_lines(control, legacy_lock, legacy_count, target, telemetry):
    call = lambda fn: A.call(fn,target=target)
    L = A.addr('r0',target.ADV_RAM) + ['ldrb r1,[r0,#2]']
    if telemetry:
        L += ['ldrb r2,[r0,#1]', 'orrs r2,r1', 'beq.w passthru']
    else:
        L += ['cbnz r1,enabled', 'passthru:', 'movs r0,#0']
        L += A.tail(target.RADIO_IRQ,target=target)
        L += ['enabled:'] + _control('r2',target)
        L += ['cmp r2,#0', 'beq full', 'ldrb r1,[r2,#7]', 'tst r1,#1',
              'beq full', 'ldrb r1,[r2,#6]', 'cmp r1,#0', 'beq full',
              'subs r1,#1', 'strb r1,[r2,#6]', 'b.w passthru']
    L += ['full:', 'push {r4,r5,r6,r7,lr}', 'sub sp,#12']
    L += A.addr('r4',target.ADV_RAM) + A.addr('r5',target.RADIO_STATE)
    L += ['ldrb.w r6,[r5,#0x186]'] + A.addr('r1',target.RADIO_QUEUE2)
    L += ['ldrb r1,[r1,#1]', 'cmp r1,#0', 'it eq', 'orreq r6,r6,#0x400']
    L += A.addr('r1',target.RADIO_EVENT) + ['ldr r1,[r1]', 'cmp r1,#0',
        'it ne', 'orrne r6,r6,#0x100', 'ldrb r1,[r5,#1]', 'cmp r1,#0',
        'it ne', 'orrne r6,r6,#0x200']
    if telemetry:
        L += A.addr('r1',target.HOP_INDEX) + ['ldrb r1,[r1]', 'orr r6,r6,r1,lsl #16']
    L += _control('r0',target) + ['str r0,[sp]', 'movs r7,#0',
        'cmp r0,#0', 'beq native', 'ldrb r1,[r0,#7]', 'tst r1,#1',
        'beq native', 'movs r7,#2', 'ldrb r1,[r0,#6]', 'cmp r1,#0',
        'beq entry', 'subs r1,#1', 'strb r1,[r0,#6]', 'b native',
        'entry:', 'movs r7,#1'] + _timer('r1',target)
    L += ['movw r0,#65535', 'str.w r0,[r1,#0x548]', 'movs r0,#1',
          'str r0,[r1,#0x48]', 'native:', 'movs r0,#0'] + call(target.RADIO_IRQ)
    L += ['str r0,[sp,#4]', 'cmp r7,#0', 'bne split'] + call(legacy_lock)
    L += ['b counts', 'split:', 'cmp r7,#1', 'bne counts', 'ldr r0,[sp]']
    L += _timer('r1',target) + ['ldrh.w r1,[r1,#0x548]', 'mov r2,r6'] + call(control['phase'])
    L += ['counts:']
    if telemetry and legacy_count is not None:
        L += call(legacy_count)
    L += ['ldr r0,[sp,#4]', 'add sp,#12', 'pop {r4,r5,r6,r7,pc}']
    if telemetry:
        L += ['passthru:', 'movs r0,#0'] + A.tail(target.RADIO_IRQ,target=target)
    return _wide(L)


def install_radio(builder, control, legacy_lock, legacy_count=None, *, target=None,
                  telemetry=True):
    target = target or builder.target
    return builder.code('native_plock_radio',
        _compact(_radio_lines(control,legacy_lock,legacy_count,target,telemetry)))


def install(builder, legacy_lock, legacy_count=None, *, target=None, telemetry=True):
    control = install_control(builder,target=target,telemetry=telemetry)
    control['radio'] = install_radio(builder,control,legacy_lock,legacy_count,
                                    target=target,telemetry=telemetry)
    return control
