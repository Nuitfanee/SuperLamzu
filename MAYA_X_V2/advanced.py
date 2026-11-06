"""MAYA FULL/SUPER owners using shared FPS/snapshot/settings generators.

Intermediate builders remain internal feature fixtures. Only full.build_pair
and the verified paired export entry publish complete profile candidates.
"""
import struct

from superlamzu import advanced as A, protocol as P
from superlamzu.settings import _apply_lines

from . import target as T
from .configuration import install as install_configuration
from .memory import evidence
from .sensor import build_foundation


def call(value):
    return A.call(value, target=T)


def tail(value):
    return A.tail(value, target=T)


def install(builder, *, radio=False, stats=False, channels=False, persistence=False, optical=False, absolute=False, motion=False, telemetry=True):
    if channels and not stats:
        raise ValueError('MAYA CHAN requires the single native statistics decision hook')
    diagnostic = (lambda lines: lines) if telemetry else A.without_diagnostic_counters
    memory = evidence(builder.image)
    if builder.image.get(T.DISPATCH_POINTER, 4) != struct.pack('<I', T.RECIPE_DISPATCH | 1):
        raise ValueError('MAYA recipe dispatch pointer changed')
    if builder.image.get(T.SENSOR_MESSAGE_SITE, 4) != bytes.fromhex('019b013b'):
        raise ValueError('MAYA native sensor dispatch changed')
    if builder.image.get(T.NATIVE_ALLOC, 20) != bytes.fromhex('02460021014b024809f011bd150903004c750020'):
        raise ValueError('MAYA native heap wrapper changed')
    if builder.image.get(T.NATIVE_FREE, len(T.NATIVE_FREE_PREIMAGE)) != T.NATIVE_FREE_PREIMAGE:
        raise ValueError('MAYA native heap release wrapper changed')
    heap_source = T.flash_source(T.NATIVE_HEAP)
    if builder.image.get(heap_source, 12) != struct.pack('<III', 0, T.NATIVE_HEAP_START, T.NATIVE_HEAP_BYTES):
        raise ValueError('MAYA native heap owner changed')
    table = builder.alloc('advanced_fps_table', bytes(v for _, u, s, f in A.PRESETS[1:] for v in (u, s, f)))
    custom = builder.code('advanced_custom_fps_apply', diagnostic(A._custom_fps_lines(target=T)))
    fps = builder.code('advanced_fps_apply', diagnostic(A._fps_lines(table, custom, target=T)))
    smoothing = builder.code('settings_smoothing_apply', _apply_lines(target=T))
    base_get = builder.code('advanced_get', A._get_lines(target=T,telemetry=telemetry))
    storage = builder.code('advanced_snapshot_storage', A._snapshot_storage_lines(target=T))
    if radio:
        from .radio import install as install_radio
        radio_hooks = install_radio(builder,storage=storage,telemetry=telemetry)
        release = radio_hooks['release']
    else:
        release = builder.code('advanced_lock_pending', ['bx lr'])
    base_set = builder.code('advanced_set', A._set_lines(base_get, release, target=T,telemetry=telemetry,
        apply=radio_hooks['timing']['setting'] if radio else None))
    snapshot = builder.code('advanced_snapshot_worker', A._snapshot_worker_lines(target=T))
    snapshot_request = builder.code('advanced_snapshot_request', A._snapshot_request_lines(base_get, storage, target=T))
    getter = builder.code('maya_sensor_get', [
        *([] if radio else ['cmp r5,#3', 'beq bad']),
        *([] if stats else ['cmp r5,#4', 'beq bad']), 'cmp r5,#7', 'beq smooth',
        *tail(base_get), 'smooth:', 'cmp r6,#0', 'bne bad',
        'ldrb r0,[r4,#3]', 'cmp r0,#2', 'bne bad', *A.addr('r1', T.SMOOTHING_STATE),
        'ldrb r0,[r1]', 'and r0,r0,#127', 'strb r0,[r4,#8]',
        'movs r0,#3', 'strb r0,[r4,#3]', 'movs r0,#1', 'bx lr',
        'bad:', 'movs r0,#0', 'bx lr'])
    setter = builder.code('maya_sensor_set', [
        *([] if radio else ['cmp r5,#3', 'beq bad']),
        *([] if stats else ['cmp r5,#4', 'beq bad']), 'cmp r5,#7', 'beq smooth',
        'cmp r5,#6', 'beq snapshot', *tail(base_set),
        'snapshot:', *tail(snapshot_request), 'smooth:',
        'push {r7,lr}', 'cmp r6,#0', 'bne invalid',
        'ldrb r0,[r4,#3]', 'cmp r0,#3', 'bne invalid',
        'ldrb r0,[r4,#8]', 'cmp r0,#1', 'bhi invalid',
        *A.addr('r1', T.SMOOTHING_STATE), '.hword 0xf3ef,0x8c10', 'cpsid i',
        'ldrb r2,[r1]', 'and r2,r2,#128', 'orrs r0,r2', 'orr r0,r0,#2', 'strb r0,[r1]',
        '.hword 0xf38c,0x8810', *A.addr('r0', T.SENSOR_MODE), 'ldrb r0,[r0]', *call(T.SET_SENSOR_MODE),
        'movs r0,#2', 'strb r0,[r4,#3]', *call(getter), 'pop {r7,pc}',
        'invalid:', 'movs r0,#0', 'pop {r7,pc}', 'bad:', 'movs r0,#0', 'bx lr'])
    dispatch = builder.code('advanced_recipe_dispatch', [
        'push {r4,r5,r6,lr}', 'mov r4,r0', 'mov r5,r1', *call(T.RECIPE_DISPATCH),
        'mov r6,r0', 'mov r0,r4', 'mov r1,r5', *call(smoothing),
        'cmp r4,#2', 'beq apply', 'cmp r4,#3', 'beq apply', 'cmp r4,#4', 'beq apply',
        'cmp r4,#6', 'beq apply', 'cmp r4,#7', 'bne done', 'apply:', *call(fps),
        'done:', 'mov r0,r6', 'pop {r4,r5,r6,pc}'])
    worker = builder.code('advanced_snapshot_dispatch', [
        'ldr r3,[sp,#4]', f'cmp r3,#{T.SNAP_MESSAGE}', 'bne native', *call(snapshot),
        *tail(T.SENSOR_MESSAGE_DONE), 'native:', 'subs r3,#1', *tail(T.SENSOR_MESSAGE_CONTINUE)])
    if not motion:
        builder.branch(T.SENSOR_MESSAGE_SITE, worker, 'MAYA snapshot message 15 inside native sensor lock')
    builder.edit(T.DISPATCH_POINTER, struct.pack('<I', dispatch | 1), 'MAYA worker recipe dispatch and reapply')
    init = builder.code('advanced_queue_init', [
        'push {r4,lr}', 'mov r4,r0', *call(T.QUEUE_INIT), 'cmp r4,#0', 'bne out',
        *A.addr('r1', T.ADV_RAM), 'movs r2,#47', 'movs r3,#0',
        'zero:', 'str r3,[r1],#4', 'subs r2,#1', 'bne zero',
        *A.addr('r1', T.ADV_RAM), 'movs r3,#1', 'strb r3,[r1]',
        *A.snapshot_pointer('r2','r0','r1',target=T),
        'cmp r2,#0','beq tags','mov r1,r2','movs r0,#0','movs r3,#7',
        'snapshot_zero:','str r0,[r1],#4','subs r3,#1','bne snapshot_zero',
        'add.w r1,r2,#308','str r0,[r1]','str r0,[r1,#4]',
        'add.w r1,r2,#316','movs r3,#9',
        'channel_zero:','str r0,[r1],#4','subs r3,#1','bne channel_zero',
        # A done thread is allocated once per boot. Reset its ring header
        # without losing the existing runtime pointer in the next word.
        *([] if not motion else [f'str.w r0,[r2,#{T.MOTION_RING_OFFSET}]']),
        'movs r0,#1','strb r0,[r2]',
        'tags:',*A.addr('r1', T.SNAPSHOT_POINTER),
        'ldrb r3,[r1,#2]','and r3,r3,#15',
        *([] if not motion else ['orr r3,r3,#16']),
        'strb r3,[r1,#2]','movs r3,#0',
        *A.addr('r1', T.SMOOTHING_STATE), 'strb r3,[r1]',
        # Native startup iterates queue0..6. Saved ABS is loaded after this
        # helper returns for queue0, so queue2 must not retain old SRAM here.
        'movs r0,#2', *call(T.QUEUE_INIT), 'out:', 'pop {r4,pc}'])
    if radio:
        from .radio import tracking
        router = tracking(builder, getter, setter)
        getter, setter = router['get'], router['set']
    from .optical import stock
    builder.optical = stock(builder)
    absolute_core = None
    if absolute:
        from .absolute import install as install_absolute, router as absolute_router
        absolute_core = install_absolute(builder)
        absolute_routes = absolute_router(builder,getter,setter,storage)
        getter, setter = absolute_routes['get'], absolute_routes['set']
        absolute_core.update(absolute_routes)
        builder.absolute = absolute_core
    settings = None
    if motion:
        from .motion import install as install_motion, router as motion_router
        callback = T.MOTION_NATIVE
        if telemetry:
            callback = builder.code('advanced_motion',[
                'push {r0,r1,r4,lr}',*A.addr('r4',T.ADV_RAM),
                'ldrb r1,[r4,#1]','cmp r1,#0','beq go',*A.inc('samples','r4','r1'),
                'ldrb r1,[r0]','cmp r1,#0','beq go',*A.inc('samples_motion','r4','r1'),
                'go:','pop {r0,r1,r4,lr}',*tail(T.MOTION_NATIVE)])
        builder.motion = install_motion(builder,callback)
        routes = motion_router(builder, builder.motion, getter, setter, storage)
        getter, setter = routes['get'], routes['set']
    if persistence:
        from .persistence import install as install_persistence
        settings = install_persistence(builder, getter, setter, init, storage=storage,
                                       motion=motion, absolute=absolute_core,
                                       motion_core=getattr(builder,'motion',None))
        getter, setter, init = settings['get'], settings['set'], settings['init']
    if motion:
        init = builder.code('motion_queue_init',[
            'push {r4,lr}','mov r4,r0',*call(init),'cmp r4,#0','bne out',
            *call(storage),
            *([] if not radio else ['movs r0,#0',*call(radio_hooks['timing']['configure'])]),
            'out:','pop {r4,pc}'])
    elif radio:
        init = builder.code('maya_plock_queue_init',[
            'push {r4,lr}','mov r4,r0',*call(init),'cmp r4,#0','bne out',
            'movs r0,#0',*call(radio_hooks['timing']['prepare']),'out:','pop {r4,pc}'])
    builder.bl(T.QUEUE_STARTUP_SITE, init, 'MAYA extension initialization before native radio startup')
    builder.advanced = dict(get=getter, set=setter,
        flags=P.F_FPS | P.F_FPS_CUSTOM | P.F_SENSOR_SNAPSHOT | P.F_SMOOTHING,
        preset_count=len(A.PRESETS), ram=memory, persistence=False,telemetry=telemetry,
        hooks=dict(fps=fps, custom_fps=custom, dispatch=dispatch, snapshot=snapshot,
                   snapshot_dispatch=worker), storage=storage, init=init, smoothing=smoothing)
    if radio:
        builder.advanced['flags'] |= router['flags']
        builder.advanced['hooks'].update(radio_hooks)
    if settings:
        builder.advanced['persistence'] = settings
        builder.advanced['flags'] |= settings['flags']
    if absolute_core:
        builder.advanced['flags'] |= P.F_ABS
    if stats:
        from .stats import install as install_stats
        channel_count = None
        if channels:
            from .channels import install as install_channels
            channel = install_channels(builder, getter, setter, storage)
            builder.advanced.update(get=channel['get'], set=channel['set'], channels=channel)
            builder.advanced['flags'] |= channel['flags']
            channel_count = channel['count']
        builder.advanced['hooks'].update(install_stats(builder, channels=channel_count, absolute=absolute_core,
                                                     motion=motion, worker=worker, init=init))
        def outcomes_refresh():
            # Pointer decoding masks the whole high nibble; all pointer,
            # motion-owner and ABS writers preserve unrelated flag bits.
            # Publish only on a successful session-only STATS/CHAN SET.
            lines=['push {r4,lr}',*A.addr('r4',T.ADV_RAM),
                'ldrb r0,[r4,#1]','cmp r0,#0','bne active']
            if channels:
                lines += [*A.snapshot_pointer('r0','r1','r3',target=T),
                    'cmp r0,#0','beq inactive',
                    f'ldrb r0,[r0,#{T.CHAN_OFFSET}]','cmp r0,#0','bne active']
            lines += ['inactive:','movs r2,#0','b publish',
                'active:','movs r2,#1','publish:',
                *A.addr('r4',T.MOTION_STATE),'.hword 0xf3ef,0x8310','cpsid i',
                'ldrb r0,[r4]',f'bic r0,r0,#{T.RADIO_OUTCOMES_ACTIVE_MASK}',
                'orr r0,r0,r2,lsl #7','strb r0,[r4]',
                '.hword 0xf383,0x8810','pop {r4,pc}']
            return builder.code('maya_radio_outcomes_refresh',lines)

        refresh=outcomes_refresh()
        previous_set=builder.advanced['set']
        setter=builder.code('maya_radio_outcomes_set',[
            'push {r4,r5,r6,lr}',*call(previous_set),'mov r6,r0',
            'cmp r6,#0','beq out','cmp r5,#4','beq update',
            *(['b out'] if not channels else ['cmp r5,#13','bne out']),
            'update:',*call(refresh),'out:','mov r0,r6','pop {r4,r5,r6,pc}'])
        builder.advanced['set']=setter
        builder.advanced['hooks'].update(outcomes_refresh=refresh,outcomes_set=setter)
        if channels:
            channel['set']=setter
            builder.advanced['channels']=channel
        if motion:
            builder.advanced['flags'] |= P.F_MOTION_PATH
        builder.advanced['flags'] |= P.F_STATS | P.F_RADIO_OUTCOMES
        builder.advanced['stats_fields'] = A.OFF
    elif motion or absolute:
        from .stats import install as install_data_path
        builder.advanced['hooks'].update(install_data_path(builder,absolute=absolute_core,
            motion=motion,worker=worker,init=init,telemetry=False))
        if motion:
            builder.advanced['flags'] |= P.F_MOTION_PATH
    return builder.advanced


def build_sensor_settings():
    builder = build_foundation()
    advanced = install(builder)
    install_configuration(builder, advanced)
    return builder


def build_radio_settings():
    builder = build_foundation()
    advanced = install(builder, radio=True)
    install_configuration(builder, advanced)
    return builder


def build_statistics():
    builder = build_foundation()
    advanced = install(builder, radio=True, stats=True)
    install_configuration(builder, advanced)
    return builder


def build_channels():
    builder = build_foundation()
    advanced = install(builder, radio=True, stats=True, channels=True)
    install_configuration(builder, advanced)
    return builder


def build_saved_settings():
    builder = build_foundation()
    advanced = install(builder, radio=True, stats=True, channels=True, persistence=True)
    install_configuration(builder, advanced)
    return builder


def build_optical():
    """Compatibility build entry; optical input uses the native debounce path."""
    return build_saved_settings()


def build_absolute_stage():
    """Internal integration only: ABS has no public cap until RX is paired."""
    builder = build_foundation()
    advanced = install(builder, radio=True, stats=True, channels=True,
                       persistence=True, absolute=True)
    install_configuration(builder, advanced)
    return builder


def build_motion_stage(profile='FULL'):
    from superlamzu.profiles import telemetry
    enabled=telemetry(profile)
    builder = build_foundation()
    builder.profile=profile
    advanced = install(builder, radio=True, stats=enabled, channels=enabled,
                       persistence=True, absolute=True, motion=True,telemetry=enabled)
    install_configuration(builder, advanced)
    return builder
