"""MAYA configuration and native TIMER20 boundaries for the shared plock."""
import struct

from superlamzu import advanced as A, native_plock as P

from . import target as T


def install(builder, control, storage, legacy_release):
    def call(value):
        return A.call(value, target=T)

    # The native IRQ enable bit, rather than sensor-ready, owns timer running.
    # R0=0 derives the current native period; nonzero is a just-applied period.
    configure = builder.code('maya_plock_configure', P._compact(P._wide([
        'push {r4,r5,r6,lr}', 'mov r4,r0', 'cmp r4,#0', 'bne period',
        *A.addr('r0', T.TICKS_PER_MS), 'ldrb r0,[r0]', 'cmp r0,#0',
        'beq out', 'cmp r0,#8', 'beq eight', 'cmp r0,#1', 'beq derive',
        'cmp r0,#2', 'beq derive', 'cmp r0,#4', 'bne out',
        'derive:', 'movw r4,#1000',
        'lsrs r0,#1', 'lsr r4,r4,r0', 'b period', 'eight:', 'movs r4,#120',
        'period:', 'cmp r4,#125', 'it eq', 'moveq r4,#120',
        *A.addr('r0', T.REPORT_IRQ_ENABLE), 'ldr r2,[r0]',
        'ubfx r2,r2,#10,#1', *A.addr('r0', T.REPORT_TRANSPORT),
        'ldrb r1,[r0]', 'cmp r1,#1', 'ite eq', 'moveq r1,#1',
        'movne r1,#0', 'mov r0,r4', *call(control['apply']),
        *A.addr('r0', T.ADV_RAM), 'ldrb r0,[r0,#2]', 'cmp r0,#0',
        'bne out', *call(legacy_release), 'out:', 'pop {r4,r5,r6,pc}'])))
    prepare = builder.code('maya_plock_prepare', P._compact([
        'push {r4,lr}', 'mov r4,r0', *A.addr('r0', T.ADV_RAM),
        'ldrb r0,[r0,#2]', 'cmp r0,#0', 'beq apply', *call(storage),
        'apply:', 'mov r0,r4', 'pop {r4,lr}', *A.tail(configure, target=T)]))
    # Shared SET invokes this without a period argument.
    setting = builder.code('maya_plock_setting', [
        'movs r0,#0', *A.tail(prepare, target=T)])
    start = builder.code('maya_plock_timer_start', [
        'push {r4,lr}', *call(T.REPORT_INIT), 'mov r4,r0',
        'movw r0,#1000', *call(configure), 'mov r0,r4', 'pop {r4,pc}'])
    stop = builder.code('maya_plock_timer_stop', P._compact([
        'push {r4,lr}', *call(T.REPORT_STOP), 'mov r4,r0',
        'movw r0,#1000', 'movs r1,#0', 'movs r2,#0',
        *call(control['apply']), 'mov r0,r4', 'pop {r4,pc}']))
    rate = builder.code('maya_plock_timer_rate', P._compact(P._wide([
        'cmp r0,#0', 'bne enter', 'bx lr', 'enter:',
        'push {r4,r5,r6,lr}', 'mov r4,r0',
        *A.addr('r0', T.ADV_RAM), 'ldrb r0,[r0,#2]', 'cmp r0,#0',
        'beq native', *call(storage), 'native:',
        '.hword 0xf3ef,0x8510', 'cpsid i', 'mov r0,r4',
        *A.addr('r3', T.REPORT_TIMER_POINTER), 'ldr r3,[r3]',
        'movs r2,#1', 'str r2,[r3,#12]', 'cmp r0,#125',
        'ite eq', 'moveq r2,#120', 'movne r2,r0', 'str.w r2,[r3,#0x540]',
        # Native UDIV r3,r3,r0; retain its verified opcode.
        'movw r3,#1000', '.hword 0xfbb3,0xf3f0',
        *A.addr('r2', T.TICKS_PER_MS), 'strb r3,[r2]',
        'mov r0,r4', *call(configure),
        '.hword 0xf385,0x8810', 'mov r0,r4', 'pop {r4,r5,r6,pc}'])))
    for native, raw in T.REPORT_TIMER_PREIMAGES.items():
        if builder.image.get(T.flash_source(native), len(raw)) != raw:
            raise ValueError(f'MAYA native timer owner changed at {native:#x}')
    for veneer, native, replacement in (
            (T.REPORT_INIT_VENEER, T.REPORT_INIT, start),
            (T.REPORT_STOP_VENEER, T.REPORT_STOP, stop),
            (T.REPORT_RATE_VENEER, T.REPORT_RATE_NATIVE, rate)):
        if builder.image.get(veneer, 8) != bytes.fromhex('5ff800f0') + struct.pack('<I', native | 1):
            raise ValueError(f'MAYA native timer veneer changed at {veneer:#x}')
        builder.edit(veneer + 4, struct.pack('<I', replacement | 1),
                     'MAYA native timer lifecycle and split LOCK configuration')
    return dict(configure=configure, prepare=prepare, setting=setting,
                start=start, stop=stop, rate=rate)
