"""THORN configuration and native timer boundaries for the 1 MHz controller."""

from . import advanced as A, native_clock as N, native_plock as P, target as T


def install(builder, storage, clock, legacy_release):
    control = P.install_control(builder, telemetry=False)
    stop = builder.code('native_plock_stopped', [
        'cmp r0,#0', 'beq out', 'addw r1,r0,#308', 'movs r2,#0',
        'str r2,[r1]', 'str r2,[r1,#4]', 'out:',
    ] + A.addr('r1', T.ADV_RAM) + [
        'movs r2,#0', 'strb r2,[r1,#12]', 'strh r2,[r1,#6]', 'bx lr',
    ])
    # Recheck the clock publication while masked. A PM OFF between reconcile
    # and this transaction must select legacy before returning its reference.
    select = builder.code('native_plock_select', [
        'push {r4,r5,r6,r7,lr}', 'sub sp,#4', 'mov r4,r0', 'mov r5,r1',
        '.hword 0xf3ef,0x8610', 'cpsid i',
    ] + A.addr('r7', T.ADV_RAM) + [
        'ldrb r0,[r7,#2]', 'cmp r0,#0', 'bne clock',
        'cmp r4,#0', 'beq release', 'ldrb.w r0,[r4,#315]',
        'tst r0,#1', 'bne clock', 'release:',
    ] + A.call(legacy_release) + [
        'clock:', 'cmp r4,#0', 'beq ineligible', 'cmp r5,#0', 'beq ineligible',
        f'ldrb r0,[r4,#{N.OFFSET + N.PHASE}]', f'cmp r0,#{N.HELD}',
        'bne ineligible', f'ldrb r0,[r4,#{N.OFFSET + N.FLAGS}]',
        f'and r0,r0,#{N.INITIALIZED | N.WANTED | N.BUSY | N.STALE}',
        f'cmp r0,#{N.INITIALIZED | N.WANTED}', 'bne ineligible',
    ] + A.addr('r0', T.TRANSPORT_STATE) + [
        'ldrb r0,[r0]', 'cmp r0,#1', 'beq period',
        'ineligible:', 'movs r5,#0', 'period:',
    ] + A.addr('r0', T.TICKS_PER_MS) + [
        'ldrb r1,[r0]', 'movw r0,#1000', 'cmp r1,#0', 'beq ready',
        '.hword 0xfbb0,0xf0f1', 'cmp r1,#8', 'it eq', 'moveq r0,#115', 'ready:',
    ] + A.addr('r2', T.NATIVE_CLOCK_READY) + [
        'ldrb r2,[r2]', 'mov r1,r5',
    ] + A.call(control['apply']) + [
        '.hword 0xf386,0x8810', 'add sp,#4', 'pop {r4,r5,r6,r7,pc}',
    ])
    ensure = builder.code('native_plock_prepare', [
        'push {r4,lr}',
    ] + A.addr('r0', T.ADV_RAM) + [
        'ldrb r0,[r0,#2]', 'cmp r0,#0', 'beq existing',
    ] + A.call(storage) + ['b settle', 'existing:']
        + A.snapshot_pointer('r0', 'r1', 'r2') + [
        'settle:', 'mov r4,r0', 'cmp r4,#0', 'beq out',
        f'ldrb.w r1,[r4,#{N.OFFSET + N.FLAGS}]', f'tst r1,#{N.INITIALIZED}',
        'bne reconcile',
    ] + A.addr('r1', T.RADIO_QUEUE0 + 4) + [
        'ldrb r1,[r1]', 'cmp r1,#24', 'bne out',
    ] + A.addr('r1', T.TRANSPORT_STATE) + [
        'ldrb r1,[r1]', 'cmp r1,#1', 'bne out',
    ] + A.call(clock['bootstrap']) + ['b out', 'reconcile:']
        + A.call(clock['reconcile']) + ['out:', 'mov r0,r4', 'pop {r4,pc}'])
    configure = builder.code('native_plock_configure', [
        'push {r4,lr}',
    ] + A.call(ensure) + ['movs r1,#1'] + A.call(select) + ['pop {r4,pc}'])
    start = builder.code('native_plock_started', ['movs r1,#1'] + A.tail(select))
    off = builder.code('native_plock_clock_off', ['movs r1,#0'] + A.tail(select))
    rate = builder.code('native_plock_set_period', [
        'cmp r0,#0', 'bne configure', 'bx lr',
        'configure:', 'push {r4,r5,r6,r7,lr}', 'sub sp,#4', 'mov r4,r0',
    ] + A.call(ensure) + [
        'mov r5,r0', '.hword 0xf3ef,0x8610', 'cpsid i',
    ] + A.addr('r0', T.NATIVE_CLOCK_READY) + [
        'ldrb r7,[r0]', 'cmp r7,#0', 'beq native',
    ] + A.addr('r0', T.REPORT_TIMER) + [
        'movs r1,#1', 'str r1,[r0,#4]', 'str.w r1,[r0,#0x200]',
        'native:',
    ] + A.addr('r3', T.REPORT_TIMER) + [
        'movs r0,#1', 'str r0,[r3,#12]', 'mov r1,r4', 'cmp r4,#125',
        'it eq', 'moveq r1,#115', 'str.w r1,[r3,#0x540]',
        'movw r0,#1000', '.hword 0xfbb0,0xf0f4',
    ] + A.addr('r1', T.TICKS_PER_MS) + [
        'strb r0,[r1]', 'mov r0,r5',
    ] + A.call(stop) + ['mov r0,r5', 'movs r1,#1'] + A.call(select) + [
        'cmp r7,#0', 'beq out',
    ] + A.addr('r0', T.REPORT_TIMER) + [
        'ldr.w r1,[r0,#0x200]', 'cmp r1,#1', 'bne out', 'str r1,[r0]',
        'out:', '.hword 0xf386,0x8810', 'mov r0,r4',
        'add sp,#4', 'pop {r4,r5,r6,r7,pc}',
    ])
    for site, original in T.REPORT_TIMER_PERIOD_CALLS.items():
        if builder.image.get(site, 4) != original:
            raise ValueError(f'native report period call changed at {site:#x}')
        builder.bl(site, rate, 'select native 1 MHz LOCK layout after rate configuration')
    control.update(configure=configure, prepare=ensure, select=select,
                   start=start, stop=stop, clock_off=off, rate=rate)
    return control
