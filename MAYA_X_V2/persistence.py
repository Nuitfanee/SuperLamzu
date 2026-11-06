"""Explicit native-RRAM save, shared v1..v5 checksum and boot migration.

Each integration enables only its installed motion/ABS owners. Historical
optical-direct records remain readable, but their retired click bit is ignored.
"""
from superlamzu import advanced as A, protocol as P
from superlamzu.settings import _save_lines, _validate_lines

from . import target as T


def evidence(image):
    for address, original in {**T.STORAGE_PREIMAGES, **T.STORAGE_OWNER_PREIMAGES}.items():
        if image.get(address, len(original)) != original:
            raise ValueError(f'MAYA native storage owner changed at {address:#x}')
    aliases = [a for a in range(image.base,image.end-3)
               if T.NATIVE_STORAGE_OFFSET+T.SETTINGS_BYTES <= image.u32(a) < 0x110800]
    if aliases:
        raise ValueError(f'MAYA native profile-tail aliases changed: {aliases}')
    if not T.NATIVE_STORAGE_OFFSET+T.SETTINGS_BYTES <= T.ADV_STORAGE < T.ADV_STORAGE+16 <= 0x110800:
        raise ValueError('MAYA advanced record overlaps a native owner')
    return dict(storage=T.ADV_STORAGE, bytes=16, driver=T.STORAGE_DRIVER,
                native_profile=[0x110000,0x1102C4], cpi=[0x110800,0x110852],
                macros=[0x111000,0x111857], system=[0x10F000,0x10F048],
                profile_bank=[0x12B000,0x12B110],
                lifecycle='explicit save; bounded native profile save/reset; direct RRAM copy, no page erase',
                load='after queue0 extension clear, before radio startup',
                evidence='IDA all native storage call spans; exact driver, save/reset and table guards')


def install(builder, getter, setter, init, *, optical=None, storage=None, motion=False, absolute=None,
            motion_core=None):
    memory = evidence(builder.image)
    def call(value):
        return A.call(value,target=T)
    def tail(value):
        return A.tail(value,target=T)
    accepted=1 | 8 | (2 if motion else 0) | (4 if absolute else 0)
    base_validate = builder.code('settings_record_validate',_validate_lines(len(A.PRESETS)))
    validate = builder.code('settings_validate',[
        'push {r4,lr}', 'mov r4,r0', *call(base_validate), 'cmp r0,#0','beq out',
        'ldrb r1,[r4,#11]',f'ands r1,r1,#{255^accepted}',
        'beq out','movs r0,#0','out:','pop {r4,pc}'])
    save = builder.code('settings_save',_save_lines(target=T))
    restore = builder.code('settings_restore',[
        'push {r4,lr}','add r4,r4,#9',*A.addr('r0',T.ADV_STORAGE),
        'mov r1,r4','movs r2,#16',*call(T.STORAGE_WRITE),'cmp r0,#0','bne bad',
        *A.addr('r1',T.ADV_STORAGE),'movs r2,#16',
        'compare:','ldrb r0,[r1],#1','ldrb r3,[r4],#1','cmp r0,r3','bne bad',
        'subs r2,#1','bne compare','movs r0,#1','pop {r4,pc}',
        'bad:','movs r0,#0','pop {r4,pc}'])
    load = builder.code('settings_load',[
        'push {r4,r5,r6,lr}',*A.addr('r4',T.ADV_STORAGE),'mov r0,r4',
        *call(validate),'cmp r0,#0','beq out',*A.addr('r5',T.ADV_RAM),
        'ldrb r0,[r4,#6]','strb r0,[r5,#3]','ldrb r0,[r4,#7]','strb r0,[r5,#2]',
        'ldrh r0,[r4,#12]','strh r0,[r5,#4]','ldrb r0,[r4,#8]','strb r0,[r5,#13]',
        'ldrb r0,[r4,#9]','strb r0,[r5,#14]','ldrb r0,[r4,#10]','strb r0,[r5,#15]',
        'movs r0,#1','strb r0,[r5,#9]',*A.addr('r5',T.SMOOTHING_STATE),
        'ldrb r0,[r4,#5]','ldrb r1,[r4,#11]','orr r0,r0,r1,lsl #7',
        'orr r0,r0,#2','strb r0,[r5]',
        *([] if not motion else [
            *call(storage),'cmp r0,#0','beq no_motion',
            *A.addr('r1',T.MOTION_STATE),'ldrb r2,[r1]','ldrb r0,[r4,#11]',
            'ubfx r0,r0,#1,#1','bic r2,r2,#16','orr r2,r2,r0,lsl #4','strb r2,[r1]',
            *([] if motion_core is None else [
                'cmp r0,#0','bne no_motion',*call(storage),*call(motion_core['initialize']),
                'cmp r0,#0','bne no_motion',
                # No independent thread exists: expose the actual direct path.
                *A.addr('r1',T.MOTION_STATE),'ldrb r2,[r1]','orr r2,r2,#16','strb r2,[r1]']),
            'no_motion:']),
        *([] if absolute is None else [
            'ldrb r0,[r4,#11]','ubfx r0,r0,#2,#1',*call(absolute['enable'])]),
        *A.addr('r0',T.SENSOR_READY),
        'ldrb r0,[r0]','cmp r0,#0','beq out',*A.addr('r0',T.SENSOR_MODE),
        'ldrb r0,[r0]',*call(T.SET_SENSOR_MODE),'out:','pop {r4,r5,r6,pc}'])
    get = builder.code('settings_get',[
        'cmp r5,#8','beq ours',*tail(getter),'ours:','push {r7,lr}',
        'cmp r6,#0','bne bad','ldrb r0,[r4,#3]','cmp r0,#2','bne bad',
        *A.addr('r0',T.ADV_STORAGE),*call(validate),'strb r0,[r4,#8]',
        'add r2,r4,#9',*A.addr('r1',T.ADV_STORAGE),'movs r3,#16',
        'copy:','ldrb r0,[r1],#1','strb r0,[r2],#1','subs r3,#1','bne copy',
        'movs r0,#19','strb r0,[r4,#3]','movs r0,#1','pop {r7,pc}',
        'bad:','movs r0,#0','pop {r7,pc}'])
    set_ = builder.code('settings_set',[
        'cmp r5,#8','beq ours',*tail(setter),'ours:','push {r7,lr}',
        'cmp r6,#0','bne bad','ldrb r0,[r4,#3]','cmp r0,#19','beq restore',
        'cmp r0,#3','bne bad','ldrb r0,[r4,#8]','cmp r0,#1','bne bad',
        *call(save),'b checked','restore:','ldrb r0,[r4,#8]','cmp r0,#2','bne bad',
        *call(restore),'checked:','cmp r0,#0','beq bad','movs r0,#2',
        'strb r0,[r4,#3]',*call(get),'pop {r7,pc}',
        'bad:','movs r0,#0','pop {r7,pc}'])
    startup = builder.code('settings_queue_init',[
        'push {r4,lr}','mov r4,r0',*call(init),'cmp r4,#0','bne out',
        *call(load),'out:','pop {r4,pc}'])
    return dict(get=get,set=set_,load=load,save=save,restore=restore,
                validate=validate,init=startup,memory=memory,flags=P.F_ADV_SAVED,
                accepted_record_flags=accepted,ignored_record_flags=8)
