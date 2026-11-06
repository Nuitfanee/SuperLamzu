"""188B ABI and receiver-window outcomes on MAYA's native radio state machine."""
import struct

from superlamzu import advanced as A
from superlamzu.common import assemble

from . import target as T
from .absolute import send_lines


def install(builder, *, channels=None, absolute=None, motion=False, worker=None, init=None, telemetry=True):
    def call(value):
        return A.call(value, target=T)

    def tail(value):
        return A.tail(value, target=T)

    def literal_pc_jump(site, target, padding_halfwords):
        # RAM and reclaimed Flash are outside Thumb B/BL range. Both the
        # inline target word and the helper's return literal are immutable;
        # no writable code/vector state or MPU change is needed.
        code=assemble(['ldr.w pc,[pc,#4]']+['nop']*padding_halfwords,site)
        literal=site+len(code)
        pc_base=(site+4)&~3
        if literal&3 or literal-pc_base!=4:
            raise ValueError(f'MAYA literal jump layout changed at {site:#x}')
        return code+struct.pack('<I',target|1)

    def pointer(site, original, replacement):
        source=T.flash_source(site)
        if builder.image.get(source,4) != struct.pack('<I',original|1):
            raise ValueError(f'MAYA statistics pointer changed at {site:#x}')
        builder.edit(site,struct.pack('<I',replacement|1),'MAYA native statistics owner')

    tick_lines=[
        'push {r0,r1,r4,lr}', *A.addr('r4',T.ADV_RAM),
        # Sensor sampling has its own IRQ, independent of the report timer.
        # A worker-owned sample or full handoff ring must block acquisition
        # before burst/decode, not merely defer report submission afterwards.
        *([] if not motion else [
            *A.addr('r1',T.MOTION_STATE),'ldrb r0,[r1]','tst r0,#32','bne deferred',
            'tst r0,#16','bne available',
            *A.snapshot_pointer('r0','r1','r2',target=T),'cmp r0,#0','beq available',
            f'ldrb.w r1,[r0,#{T.MOTION_RING_OFFSET+2}]','cmp r1,#8','blo available',
            'deferred:','pop {r0,r1,r4,pc}','available:']),
        'ldrb r0,[r4,#1]','cmp r0,#0','beq go',*A.inc('ticks'),
        *A.addr('r1',T.SENSOR_READY),'ldrb r0,[r1]','cmp r0,#0','beq notready',
        *A.addr('r1',0x2000A3A8),'ldr r0,[r1]','cmp r0,#0','bne notready',
        *A.addr('r1',0x2000A380),'ldr r0,[r1]','cmp r0,#0','bne notready',
        *A.addr('r1',0x2000D234),'ldrb r0,[r1]','and r0,r0,#0xf7',
        'cmp r0,#0xb7','bne unhealthy','ldrb r0,[r1,#1]','cmp r0,#1','bne go',
        'unhealthy:',*A.inc('health_skip'),*A.inc('health_trip'),
        *A.addr('r1',0x2000D234),'ldrh r0,[r1]',f'str r0,[r4,#{A.OFF["last_bad_status"]}]',
        'b go','notready:',*A.inc('not_ready'),
        'go:','pop {r0,r1,r4,lr}',*tail(T.SENSOR_TICK)]
    if not telemetry:
        del tick_lines[tick_lines.index('ldrb r0,[r4,#1]'):tick_lines.index('go:')]
        del tick_lines[1:3]  # no diagnostic base load; retain the motion ownership guard
    tick=builder.code('advanced_tick',tick_lines)
    burst=builder.code('advanced_burst',[
        'push {r4,lr}',*call(T.SENSOR_BURST),*A.addr('r4',T.ADV_RAM),
        'ldrb r1,[r4,#1]','cmp r1,#0','beq out','cmp r0,#0','beq fail',
        *A.inc('reads_started','r4','r1'),*A.inc('spi_ok','r4','r1'),'b out',
        'fail:',*A.inc('read_start_fail','r4','r1'),*A.inc('spi_bad','r4','r1'),
        'out:','pop {r4,pc}']) if telemetry else None
    motion_callback=builder.symbols.get('advanced_motion') or (builder.code('advanced_motion',[
        'push {r0,r1,r4,lr}',*A.addr('r4',T.ADV_RAM),
        'ldrb r1,[r4,#1]','cmp r1,#0','beq go',*A.inc('samples','r4','r1'),
        'ldrb r1,[r0]','cmp r1,#0','beq go',*A.inc('samples_motion','r4','r1'),
        'go:','pop {r0,r1,r4,lr}',*tail(T.MOTION_NATIVE)]) if telemetry else T.MOTION_NATIVE)
    if not telemetry:
        builder.symbols['advanced_motion']=T.MOTION_NATIVE
    reinit=builder.code('advanced_reinit',[
        'push {r0,r1,r4,lr}',*A.addr('r4',T.ADV_RAM),
        'ldrb r1,[r4,#1]','cmp r1,#0','beq go',*A.inc('reinit','r4','r1'),
        'go:','pop {r0,r1,r4,lr}',*tail(0x173CC)]) if telemetry else None
    pointer(T.SENSOR_TICK_POINTER,T.SENSOR_TICK,tick)
    if telemetry:
        pointer(T.SENSOR_BURST_POINTER,T.SENSOR_BURST,burst)
    if motion:
        from .motion import install as install_motion
        core=getattr(builder,'motion',None) or install_motion(builder,motion_callback)
        builder.motion=core
        pointer(T.MOTION_CALLBACK_POINTER,T.MOTION_NATIVE,core['route'])
        pointer(T.REPORT_POINTER,T.REPORT_NATIVE,core['report'])
        # Optional motion delivery has its own semaphore and priority6 thread.
        # The native configuration worker's lock gate remains byte-identical.
        builder.branch(T.SENSOR_MESSAGE_SITE,worker,'MAYA snapshot and native message dispatch retain original lock pair')
    else:
        pointer(T.MOTION_CALLBACK_POINTER,T.MOTION_NATIVE,motion_callback)
    # All Flash literal callers and five internal RAM calls reach this one
    # native entry. Relocate its PC-relative load and CBZ explicitly, preserving
    # the exact original prologue, stack, flags and disabled-radio return path.
    if builder.image.get(T.flash_source(T.RADIO_SEND),10) != bytes.fromhex('38b51a4b0c461a785ab3'):
        raise ValueError('MAYA native send prologue changed')
    native=builder.code('maya_send_native',[
        'push {r3,r4,r5,lr}',*A.addr('r3',T.RADIO_STATE),'mov r4,r1',
        'ldrb r2,[r3]','cbnz r2,enabled',*tail(0x200053BA),
        'enabled:',*tail(0x20005362)])
    dispatch=builder.code('advanced_send',[
        'push {r4,r5,r6,lr}','mov r5,r0',
        *([] if absolute is None else send_lines(absolute['pointer'])),
        *call(native),*([*A.addr('r4',T.ADV_RAM),
        'ldrb r1,[r4,#1]','cmp r1,#0','beq out','cmp r5,#9','bne out',
        'cmp r0,#1','beq queued','cmp r0,#6','bne out',*A.inc('tx_full','r4','r1'),
        'b out','queued:',*A.inc('tx_queued','r4','r1')] if telemetry else []),
        'out:','pop {r4,r5,r6,pc}'])
    code=assemble(A.addr('r12',dispatch|1)+['bx r12'],T.RADIO_SEND)
    builder.edit(T.RADIO_SEND,code,
                 'MAYA send entry counts native op9 queue result')
    if not telemetry:
        return dict(tick=tick,motion=motion_callback,send=dispatch,telemetry=False)
    for site in (0x177F8,0x1784C):
        builder.bl(site,reinit,'MAYA actual sensor reinitialization counter')
    decision=builder.code('maya_stats_window_decision',[
        'push {r4,lr}',*A.addr('r4',T.ADV_RAM),'ldrb r0,[r4,#1]',
        'cmp r0,#0','beq channel',*A.inc('tx_attempts'),'cmp r2,#0','bne missed',
        *A.inc('acked'),'movs r0,#0',f'str r0,[r4,#{A.OFF["miss_run"]}]','b channel',
        'missed:',*A.inc('no_ack'),*A.inc('miss_run'),
        f'ldr r1,[r4,#{A.OFF["max_miss_run"]}]','cmp r0,r1','it hi',
        f'strhi r0,[r4,#{A.OFF["max_miss_run"]}]','channel:',
        *([] if channels is None else call(channels)), 'pop {r4,pc}'])

    receive=builder.code('maya_stats_receive_accepted',[
        f'ldrb.w r5,[r4,#{T.MOTION_STATE-T.RADIO_STATE}]',
        f'ubfx r5,r5,#7,#1','cbz r5,replay',
        'push {r0,r2,r4,lr}','mrs r7,apsr',
        'ldrb r0,[r4,#2]','cbz r0,done',
        'ldrb r0,[r4,#1]','cbz r0,done',
        'movs r2,#0',*call(decision),
        'done:','msr APSR_nzcvq,r7','pop {r0,r2,r4,lr}',
        'replay:','ldr r5,=0x200064E8','ldr r7,=0x37322',
        'ldrh r3,[r5,#2]','ldr r1,=0x2000E8BB',
        'adds r3,#1',f'ldr.w pc,={T.RADIO_RX_ACCEPT_CONTINUE|1:#x}'])
    accept_source=T.flash_source(T.RADIO_RX_ACCEPT_SITE)
    if builder.image.get(accept_source,len(T.RADIO_RX_ACCEPT_PREIMAGE)) != T.RADIO_RX_ACCEPT_PREIMAGE:
        raise ValueError('MAYA state6 accepted-receive continuation changed')
    builder.edit(T.RADIO_RX_ACCEPT_SITE,
        literal_pc_jump(T.RADIO_RX_ACCEPT_SITE,receive,1),
        'MAYA accepted addressed state6 receive; replay all displaced native instructions')

    timeout=builder.code('maya_stats_receive_timeout',[
        # R3 is overwritten by the native UXTB below. Inactive telemetry
        # does not save a stack frame, call helpers or mask interrupts.
        f'ldrb.w r3,[r4,#{T.MOTION_STATE-T.RADIO_STATE}]',
        'lsls r3,r3,#24','bpl replay','cmp r2,#6','bne replay',
        # The native entry already excludes inactive radio. Byte +1 is
        # connected, not a received-event flag; disconnected retries do not
        # belong to receiver-window-v1.
        'ldrb r3,[r4,#1]','cbz r3,replay',
        'push {r0,r1,r2,r4,r5,lr}','movs r2,#1',*call(decision),
        'pop {r0,r1,r2,r4,r5,lr}',
        'replay:','uxtb r3,r2','cmp r2,#6','beq common',
        'cmp r3,#8','beq state8','cmp r3,#4','bne other',
        'common:',f'ldr.w pc,={T.RADIO_SLOT_STATE4_6_CONTINUE|1:#x}',
        'state8:',f'ldr.w pc,={T.RADIO_SLOT_STATE8_CONTINUE|1:#x}',
        'other:',f'ldr.w pc,={T.RADIO_SLOT_OTHER_CONTINUE|1:#x}'])
    timeout_source=T.flash_source(T.RADIO_SLOT_DECISION)
    if builder.image.get(timeout_source,len(T.RADIO_SLOT_DECISION_PREIMAGE)) != T.RADIO_SLOT_DECISION_PREIMAGE:
        raise ValueError('MAYA native slot-decision entry changed')
    slot_dispatch_source=T.flash_source(T.RADIO_SLOT_DISPATCH_SITE)
    if builder.image.get(slot_dispatch_source,len(T.RADIO_SLOT_DISPATCH_PREIMAGE)) != T.RADIO_SLOT_DISPATCH_PREIMAGE:
        raise ValueError('MAYA native slot-state dispatch changed')
    builder.edit(T.RADIO_SLOT_DISPATCH_SITE,
        literal_pc_jump(T.RADIO_SLOT_DISPATCH_SITE,timeout,2),
        'MAYA slot-end outcome check with native state dispatch preserved')
    for site,raw in T.RADIO_STATE4_PREIMAGES.items():
        if builder.image.get(T.flash_source(site),len(raw)) != raw:
            raise ValueError(f'MAYA state4 transition changed at {site:#x}')
    return dict(tick=tick,burst=burst,motion=motion_callback,send=dispatch,
                reinit=reinit,receive=receive,timeout=timeout,decision=decision)
