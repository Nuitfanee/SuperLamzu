"""THORN native FLL ownership; called only at existing thread boundaries.

All public helpers preserve r4-r11, SP and the caller's interrupt masks.
bootstrap(heap): initialize the private region once at wireless queue startup,
then reconcile. A zero heap is a no-op. Snapshot creation must not call it.
intent(heap, action, expected_generation): action 2 queries; action 0 publishes
OFF; action 1 publishes ON only if the generation still matches and the native
timer is ready. Returns (r0=generation, r1=initialized), never calls a driver.
reconcile(heap): settle one native operation and, if needed, its cancellation;
returns 1 only for a completed, current, wanted and owned high-accuracy request.

The timer wrapper publishes OFF before stopping, then reconciles after STOP.
It queries before native START and publishes ON afterward with that generation.
No helper allocates storage or runs from a report/radio/SPI IRQ.
"""

from . import target as T


OFFSET, BYTES = 28, 32
CLIENT, SPEC, PHASE, FLAGS, ERROR, GENERATION = 0, 16, 24, 25, 26, 28
EMPTY, PENDING, HELD, DRAINING, CLEANUP_ERROR = range(5)
INITIALIZED, WANTED, BUSY, STALE = 1, 2, 4, 8


def _addr(reg, value):
    return [f'movw {reg},#{value & 65535}', f'movt {reg},#{value >> 16}']


def _call(value):
    return [f'bl #{value:#x}']


def _intent_lines(target):
    return [
        'cmp r0,#0', 'beq.w absent', f'adds r0,#{OFFSET}',
        'mrs r12,primask', 'cpsid i', f'ldrb r3,[r0,#{FLAGS}]',
        f'tst r3,#{INITIALIZED}', 'beq.w uninitialized',
        'cmp r1,#2', 'beq.w query', 'cmp r1,#0', 'beq.w off',
        f'ldr r1,[r0,#{GENERATION}]', 'cmp r1,r2', 'bne.w query',
    ] + _addr('r2', target.NATIVE_CLOCK_READY) + [
        'ldrb r2,[r2]', 'cmp r2,#0', 'beq.w query',
        f'tst r3,#{WANTED}', 'bne.w query', f'orr r3,r3,#{WANTED}',
        'b.w advance', 'off:', f'bic r3,r3,#{WANTED}',
        f'orr r3,r3,#{STALE}', f'ldr r1,[r0,#{GENERATION}]',
        'advance:', 'adds r1,#1', f'str r1,[r0,#{GENERATION}]',
        f'strb r3,[r0,#{FLAGS}]', 'query:', f'ldr r0,[r0,#{GENERATION}]',
        'movs r1,#1', 'msr primask,r12', 'bx lr',
        'uninitialized:', 'msr primask,r12', 'absent:',
        'movs r0,#0', 'movs r1,#0', 'bx lr',
    ]


def _cleanup_lines(target):
    # Called by the sole BUSY owner with r0 pointing at the clock subregion.
    return ['push {r4,r5,r6,lr}', 'mov r4,r0',
            f'add r1,r4,#{SPEC}'] + _addr('r0', target.NATIVE_CLOCK_DEVICE) + _call(target.NATIVE_CLOCK_MANAGER) + [
        'cmp r0,#0', 'beq.w no_manager', 'mov r1,r4',
    ] + _call(target.NATIVE_CLOCK_CANCEL) + [
        'cmp r0,#0', 'bge.w empty', 'cmn r0,#120', 'bne.w error',
        'ldr r1,[r4,#8]', 'cmp r1,#0', 'bne.w release',
        'dmb sy', 'ldr r0,[r4,#12]', 'cmp r0,#0', 'blt.w failed',
        'release:', f'add r1,r4,#{SPEC}',
    ] + _addr('r0', target.NATIVE_CLOCK_DEVICE) + _call(target.NATIVE_CLOCK_RELEASE) + [
        'cmp r0,#0', 'blt.w release_error', 'ldr r1,[r4,#8]',
        'cmp r1,#0', 'beq.w empty', f'movs r0,#{DRAINING}', 'b.w done',
        'release_error:', 'mov r5,r0', 'ldr r1,[r4,#8]', 'cmp r1,#0',
        'bne.w restore_error', 'dmb sy', 'ldr r0,[r4,#12]',
        'cmp r0,#0', 'blt.w failed', 'restore_error:', 'mov r0,r5',
        'error:', f'strh r0,[r4,#{ERROR}]', f'movs r0,#{CLEANUP_ERROR}', 'b.w done',
        'no_manager:', 'mvn r0,#21', 'b.w error',
        'failed:', f'strh r0,[r4,#{ERROR}]',
        'empty:', f'movs r0,#{EMPTY}',
        'done:', f'strb r0,[r4,#{PHASE}]', 'pop {r4,r5,r6,pc}',
    ]


def _reconcile_lines(target, cleanup):
    return [
        'push {r4,r5,r6,r7,lr}', 'sub sp,#4', 'mov r4,r0',
        'cmp r4,#0', 'beq.w inactive', f'adds r4,#{OFFSET}',
        'mrs r7,primask', 'cpsid i', f'ldrb r5,[r4,#{FLAGS}]',
        f'tst r5,#{INITIALIZED}', 'beq.w unclaimed',
        f'tst r5,#{BUSY}', 'bne.w unclaimed', f'orr r5,r5,#{BUSY}',
        f'strb r5,[r4,#{FLAGS}]', 'msr primask,r7',
        f'ldrb r6,[r4,#{PHASE}]', f'cmp r6,#{EMPTY}', 'beq.w request',
        f'cmp r6,#{CLEANUP_ERROR}', 'beq.w cleanup',
        f'cmp r6,#{HELD}', 'beq.w finish',
        'ldr r0,[r4,#8]', 'cmp r0,#0', 'bne.w finish', 'dmb sy',
        f'cmp r6,#{DRAINING}', 'beq.w empty',
        'ldr r0,[r4,#12]', 'cmp r0,#0', 'blt.w failed',
        f'movs r6,#{HELD}', f'strb r6,[r4,#{PHASE}]', 'b.w finish',
        'request:', f'ldrb r5,[r4,#{FLAGS}]', f'tst r5,#{WANTED}', 'beq.w finish',
        # No previous native request may write this client in EMPTY.
        'mrs r7,primask', 'cpsid i', f'ldrb r5,[r4,#{FLAGS}]',
        f'tst r5,#{WANTED}', 'beq.w request_canceled',
        f'bic r5,r5,#{STALE}', f'strb r5,[r4,#{FLAGS}]',
        'movs r0,#0', 'str r0,[r4]', 'str r0,[r4,#4]', 'str r0,[r4,#12]',
        f'strh r0,[r4,#{ERROR}]', 'movs r0,#1', 'str r0,[r4,#8]',
        'msr primask,r7', 'mov r2,r4', f'add r1,r4,#{SPEC}',
    ] + _addr('r0', target.NATIVE_CLOCK_DEVICE) + _call(target.NATIVE_CLOCK_REQUEST) + [
        'cmp r0,#0', 'blt.w failed', f'movs r6,#{PENDING}',
        f'strb r6,[r4,#{PHASE}]', 'ldr r0,[r4,#8]', 'cmp r0,#0',
        'bne.w finish', 'dmb sy', 'ldr r0,[r4,#12]', 'cmp r0,#0',
        'blt.w failed', f'movs r6,#{HELD}', f'strb r6,[r4,#{PHASE}]', 'b.w finish',
        'request_canceled:', 'msr primask,r7', 'b.w finish',
        'failed:', f'strh r0,[r4,#{ERROR}]',
        'empty:', f'movs r6,#{EMPTY}', f'strb r6,[r4,#{PHASE}]',
        'finish:', 'mrs r7,primask', 'cpsid i', f'ldrb r5,[r4,#{FLAGS}]',
        f'ldrb r6,[r4,#{PHASE}]', f'cmp r6,#{PENDING}', 'beq.w owned',
        f'cmp r6,#{HELD}', 'bne.w unlock',
        'owned:', f'and r0,r5,#{WANTED | STALE}', f'cmp r0,#{WANTED}',
        'beq.w unlock', 'msr primask,r7',
        'cleanup:', 'mov r0,r4',
    ] + _call(cleanup) + [
        'b.w finish',
        'unlock:', f'bic r5,r5,#{BUSY}', f'cmp r6,#{EMPTY}', 'it eq',
        f'biceq r5,r5,#{STALE}', f'strb r5,[r4,#{FLAGS}]',
        'movs r0,#0', f'cmp r6,#{HELD}', 'it eq', 'moveq r0,#1',
        'msr primask,r7', 'b.w out',
        'unclaimed:', 'msr primask,r7', 'inactive:', 'movs r0,#0',
        'out:', 'add sp,#4', 'pop {r4,r5,r6,r7,pc}',
    ]


def _bootstrap_lines(target, reconcile):
    return [
        'push {r4,r5,r6,lr}', 'mov r4,r0', 'cmp r0,#0', 'beq.w done',
        f'adds r0,#{OFFSET}', 'mrs r6,primask', 'cpsid i',
        f'ldrb r1,[r0,#{FLAGS}]', f'tst r1,#{INITIALIZED}', 'bne.w sync',
        'movs r1,#0', 'str r1,[r0]', 'str r1,[r0,#4]', 'str r1,[r0,#8]',
        'str r1,[r0,#12]', f'str r1,[r0,#{SPEC}]', f'str r1,[r0,#{PHASE}]',
        f'str r1,[r0,#{GENERATION}]', 'movs r1,#30', f'str r1,[r0,#{SPEC + 4}]',
    ] + _addr('r2', target.NATIVE_CLOCK_READY) + [
        'ldrb r2,[r2]', 'cmp r2,#0', 'ite eq', f'moveq r1,#{INITIALIZED}',
        f'movne r1,#{INITIALIZED | WANTED}', f'strb r1,[r0,#{FLAGS}]',
        'b.w unlock', 'sync:',
    ] + _addr('r2', target.NATIVE_CLOCK_READY) + [
        'ldrb r2,[r2]', 'cmp r2,#0', 'bne.w unlock',
        f'tst r1,#{WANTED}', 'beq.w unlock', f'bic r1,r1,#{WANTED}',
        f'orr r1,r1,#{STALE}', f'strb r1,[r0,#{FLAGS}]',
        f'ldr r1,[r0,#{GENERATION}]', 'adds r1,#1', f'str r1,[r0,#{GENERATION}]',
        'unlock:', 'msr primask,r6', 'done:', 'mov r0,r4',
        'pop {r4,r5,r6,lr}', f'b.w #{reconcile:#x}',
    ]


def install(b, *, target=T):
    """Allocate pure helpers; the existing timer/queue owners install wrappers."""
    for address, original in target.NATIVE_CLOCK_PREIMAGES.items():
        if b.image.get(target.flash_source(address), len(original)) != original:
            raise ValueError(f'native clock preimage changed at {address:#x}')
    def code(name, lines):
        masks = {
            'mrs r12,primask': '.hword 0xf3ef,0x8c10',
            'msr primask,r12': '.hword 0xf38c,0x8810',
            'mrs r7,primask': '.hword 0xf3ef,0x8710',
            'msr primask,r7': '.hword 0xf387,0x8810',
            'mrs r6,primask': '.hword 0xf3ef,0x8610',
            'msr primask,r6': '.hword 0xf386,0x8810',
        }
        return b.code(name, [masks.get(line, line) for line in lines])

    cleanup = code('native_clock_cleanup', _cleanup_lines(target))
    intent = code('native_clock_intent', _intent_lines(target))
    reconcile = code('native_clock_reconcile', _reconcile_lines(target, cleanup))
    bootstrap = code('native_clock_bootstrap', _bootstrap_lines(target, reconcile))
    return dict(bootstrap=bootstrap, intent=intent, reconcile=reconcile, cleanup=cleanup,
                offset=OFFSET, bytes=BYTES, phase_offset=OFFSET + PHASE,
                flags_offset=OFFSET + FLAGS, generation_offset=OFFSET + GENERATION)


def install_hooks(b, entries, *, after_start=None, after_stop=None,
                  before_hfxo_off=None, target=T):
    """Share the real native timer/PM boundaries with the layout controller."""
    from .advanced import call, snapshot_pointer
    for address, original in target.NATIVE_CLOCK_HOOK_PREIMAGES.items():
        if b.image.get(target.flash_source(address), len(original)) != original:
            raise ValueError(f'native clock hook preimage changed at {address:#x}')
    pointer = snapshot_pointer('r4', 'r0', 'r1', target=target)
    def invoke(address):
        return call(address, target=target)
    def callback(address):
        return ['mov r0,r4'] + invoke(address) if address is not None else []
    start = b.code('native_clock_timer_start', [
        'push {r4,r5,r6,lr}', 'push {r0,r1,r2,r3}',
    ] + pointer + ['mov r0,r4', 'movs r1,#2'] + invoke(entries['intent']) + [
        'mov r5,r0', 'pop {r0,r1,r2,r3}',
    ] + invoke(target.REPORT_TIMER_INIT) + [
        'mov r6,r0', 'mov r2,r5', 'mov r0,r4', 'movs r1,#1',
    ] + invoke(entries['intent']) + callback(entries['reconcile'])
      + callback(after_start) + ['mov r0,r6', 'pop {r4,r5,r6,pc}'])
    stop = b.code('native_clock_timer_stop', [
        'push {r4,r5,r6,lr}', 'push {r0,r1,r2,r3}',
    ] + pointer + ['mov r0,r4', 'movs r1,#0'] + invoke(entries['intent']) + [
        'pop {r0,r1,r2,r3}',
    ] + invoke(target.REPORT_TIMER_STOP) + ['mov r6,r0']
      + callback(after_stop) + callback(entries['reconcile'])
      + ['mov r0,r6', 'pop {r4,r5,r6,pc}'])
    off = b.code('native_clock_hfxo_off', [
        'push {r4,lr}', 'push {r0,r1,r2,r3}',
    ] + pointer + ['mov r0,r4', 'movs r1,#0'] + invoke(entries['intent'])
      + callback(before_hfxo_off) + callback(entries['reconcile']) + [
        'pop {r0,r1,r2,r3}', 'pop {r4,lr}',
    ] + [f'b.w #{target.HFXO_OFF:#x}'])
    for site in target.REPORT_TIMER_INIT_CALLS:
        b.bl(site, start, 'native high-accuracy clock after report timer START')
    b.bl(target.REPORT_TIMER_STOP_CALL, stop, 'native clock OFF before report timer STOP')
    b.bl(target.HFXO_OFF_CALL, off, 'return native FLL reference before HFXO OFF')
    entries.update(timer_start=start, timer_stop=stop, hfxo_off=off)
    return entries
