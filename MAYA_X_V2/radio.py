"""Fixed-dev LOCK/tracking on MAYA's actual timer and native IRQ owner.

Keep the stock ISR and five-channel hopping unchanged. The original vector
points to a RAM wrapper, outside Flash BL range; replace the vector with an
equivalent alignment entry instead of truncating a far branch.
"""
import struct

from superlamzu import advanced as A, protocol as P, native_plock

from . import target as T


def install(builder, *, storage, telemetry=True):
    if builder.image.get(T.RADIO_VECTOR, 4) != struct.pack('<I', 0x20005A61):
        raise ValueError('MAYA native radio vector changed')
    original = bytes.fromhex('684620f007018d4601b50020fff774ffbde8014085467047')
    if builder.image.get(T.flash_source(0x20005A60), len(original)) != original:
        raise ValueError('MAYA native radio alignment entry changed')
    diagnostic = (lambda lines: lines) if telemetry else A.without_diagnostic_counters
    idle = builder.code('advanced_idle_tracking', diagnostic(A._idle_lines(target=T)))
    lock = builder.code('advanced_phase_lock', diagnostic(A._lock_lines(idle, target=T)))
    count = builder.code('advanced_radio_count', A._radio_count_lines(target=T)) if telemetry else None
    release = builder.code('advanced_lock_release', A._release_lines(target=T))
    control = native_plock.install(builder, lock, count, target=T, telemetry=telemetry)
    radio = control['radio']
    builder.symbols['advanced_radio_irq'] = radio
    from .native_timing import install as install_timing
    timing = install_timing(builder, control, storage, release)
    entry = builder.code('maya_radio_irq_entry', [
        'mov r0,sp', 'bic r1,r0,#7', 'mov sp,r1', 'push {r0,lr}',
        'movs r0,#0', *A.call(radio, target=T), 'pop {r0,lr}',
        'mov sp,r0', 'bx lr'])
    builder.edit(T.RADIO_VECTOR, struct.pack('<I', entry | 1),
                 'MAYA native aligned radio vector with LOCK/tracking')
    return dict(idle=idle, lock=lock, radio_count=count, radio=radio,
                release=release, entry=entry, plock=control, timing=timing)


def tracking(builder, getter, setter):
    """The shared smoothing byte keeps stock/reduced and tracking independent."""
    get = builder.code('maya_tracking_get', [
        'cmp r5,#9', 'beq ours', *A.tail(getter, target=T), 'ours:',
        'cmp r6,#0', 'bne bad', 'ldrb r0,[r4,#3]', 'cmp r0,#2', 'bne bad',
        *A.addr('r1', T.SMOOTHING_STATE), 'ldrb r0,[r1]', 'lsrs r0,r0,#7',
        'strb r0,[r4,#8]', 'movs r0,#3', 'strb r0,[r4,#3]',
        'movs r0,#1', 'bx lr', 'bad:', 'movs r0,#0', 'bx lr'])
    set = builder.code('maya_tracking_set', [
        'cmp r5,#9', 'beq ours', *A.tail(setter, target=T), 'ours:',
        'cmp r6,#0', 'bne bad', 'ldrb r0,[r4,#3]', 'cmp r0,#3', 'bne bad',
        'ldrb r0,[r4,#8]', 'cmp r0,#1', 'bhi bad',
        *A.addr('r1', T.SMOOTHING_STATE), '.hword 0xf3ef,0x8c10', 'cpsid i',
        'ldrb r2,[r1]', 'and r2,r2,#127', 'orr r0,r2,r0,lsl #7',
        'strb r0,[r1]', '.hword 0xf38c,0x8810',
        'movs r0,#2', 'strb r0,[r4,#3]', *A.tail(get, target=T),
        'bad:', 'movs r0,#0', 'bx lr'])
    return dict(get=get, set=set, flags=P.F_LOCK | P.F_IDLE_TRACKING)
