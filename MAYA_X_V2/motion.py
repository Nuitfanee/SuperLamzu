"""MAYA native synchronous delivery and an independent optional done thread.

The stock target has no done thread. Direct preserves that synchronous path.
Explicit thread mode owns a priority6 consumer and a binary semaphore, allocated
once from the native heap. It never posts work to the sensor configuration FIFO.
The target-owned eight-sample ring survives the decoder's stack copy.
Wired delivery keeps the stock synchronous callback. No allocator runs in IRQ.
"""
from superlamzu import advanced as A, protocol as P
from superlamzu.common import assemble

from . import target as T

DIRECT, OWNER = 0x10, 0x20
THREAD_TCB, THREAD_STACK, THREAD_BYTES = 32, 192, 1216


def install(builder, callback):
    for address,original in T.MOTION_RUNTIME_PREIMAGES.items():
        if builder.image.get(address,len(original)) != original:
            raise ValueError(f'MAYA motion runtime API preimage changed at {address:#x}')
    def call(value):return A.call(value,target=T)
    def tail(value):return A.tail(value,target=T)
    if builder.image.get(T.flash_source(T.MOTION_TAIL_SITE),len(T.MOTION_TAIL_PREIMAGE))!=T.MOTION_TAIL_PREIMAGE:
        raise ValueError('MAYA motion tail preimage changed')
    pointer=builder.code('motion_pointer',A.snapshot_pointer('r0','r1','r2',target=T)+[
        'cmp r0,#0','it ne',f'addwne r0,r0,#{T.MOTION_RING_OFFSET}','bx lr'])
    # Owner spans pop and the callback's shared-data transaction, not its
    # schedulable lift tail. Six bytes are copied before publication.
    drain=builder.code('motion_drain',[
        'push {r4,r5,r6,r7,lr}','sub sp,#12',*call(pointer),'cmp r0,#0','beq out',
        'mov r4,r0',*A.addr('r5',T.MOTION_STATE),
        'next:','.hword 0xf3ef,0x8710','cpsid i','ldrb r6,[r5]',
        f'tst r6,#{OWNER}','bne unlock','ldrb r0,[r4,#2]','cmp r0,#0','beq unlock',
        f'orr r1,r6,#{OWNER}','strb r1,[r5]','movs r1,#1','strb r1,[r4,#3]',
        'ldrb r1,[r4]','movs r2,#6','muls r2,r1','add r2,r4,r2','adds r2,#8',
        'ldr r3,[r2]','str r3,[sp]','ldrh r3,[r2,#4]','strh r3,[sp,#4]',
        'adds r1,#1','and r1,r1,#7','strb r1,[r4]','subs r0,#1','strb r0,[r4,#2]',
        '.hword 0xf387,0x8810','mov r0,sp',*call(callback),
        '.hword 0xf3ef,0x8710','cpsid i','ldrb r0,[r5]',f'bic r0,r0,#{OWNER}',
        'strb r0,[r5]','movs r0,#0','strb r0,[r4,#3]','.hword 0xf387,0x8810','b next',
        'unlock:','.hword 0xf387,0x8810','out:','add sp,#12','pop {r4,r5,r6,r7,pc}'])
    consume=drain
    thread=builder.code('motion_done_thread',[
        'push {r4,lr}','mov r4,r0',
        'wait:','mov r0,r4','movs r1,#0','mov.w r2,#0xffffffff',
        'mov.w r3,#0xffffffff',*call(T.MOTION_SEM_TAKE),
        *call(drain),'b wait'])
    initialize=builder.code('motion_thread_init',[
        'push {r4,r5,r6,r7,lr}','sub sp,#36','mov r4,r0',
        'cmp r4,#0','beq fail',f'addw r4,r4,#{T.MOTION_RING_OFFSET}',
        'ldr r0,[r4,#4]','cmp r0,#0','bne out',
        f'movw r0,#{THREAD_BYTES+8}',*call(T.NATIVE_ALLOC),'cmp r0,#0','beq fail',
        'adds r0,#7','bic r5,r0,#7','mov r1,r5','movs r2,#0',
        f'movw r3,#{THREAD_BYTES//4}',
        'zero:','str r2,[r1],#4','subs r3,#1','bne zero',
        # Native semaphore list/count/limit, verified against give/take.
        'str r5,[r5]','str r5,[r5,#4]','movs r0,#1','str r0,[r5,#12]',
        'str r5,[sp]','str r2,[sp,#4]','str r2,[sp,#8]',
        'movs r0,#6','str r0,[sp,#12]','str r2,[sp,#16]',
        'str r2,[sp,#20]','mov.w r0,#0xffffffff','str r0,[sp,#24]','str r0,[sp,#28]',
        f'add r0,r5,#{THREAD_TCB}',f'add r1,r5,#{THREAD_STACK}',
        'movw r2,#1024',*A.addr('r3',thread|1),*call(T.MOTION_THREAD_CREATE),
        # Create suspended, then publish a complete object before start.
        'str r5,[r4,#4]',f'add r0,r5,#{THREAD_TCB}',*call(T.MOTION_THREAD_START),
        'mov r0,r5','b out','fail:','movs r0,#0',
        'out:','add sp,#36','pop {r4,r5,r6,r7,pc}'])
    owned=builder.code('motion_owned',[
        'push {r4,r5,r6,lr}',*A.addr('r4',T.MOTION_STATE),
        '.hword 0xf3ef,0x8510','cpsid i','ldrb r6,[r4]',f'orr r1,r6,#{OWNER}',
        'strb r1,[r4]','.hword 0xf385,0x8810',*call(callback),
        '.hword 0xf3ef,0x8510','cpsid i','ldrb r1,[r4]',f'bic r1,r1,#{OWNER}',
        f'and r6,r6,#{OWNER}','orrs r1,r6','strb r1,[r4]',
        '.hword 0xf385,0x8810','pop {r4,r5,r6,pc}'])
    route=builder.code('motion_route',[
        'push {r4,r5,r6,r7,lr}','sub sp,#12','mov r4,r0',
        *A.addr('r6',T.MOTION_STATE),'ldrb r0,[r6]',f'tst r0,#{DIRECT}','bne direct',
        *call(pointer),
        'cmp r0,#0','beq stock','mov r5,r0',*A.addr('r6',T.MOTION_STATE),
        'ldrb r0,[r6]',f'tst r0,#{OWNER}','bne append',
        # Only initialized thread mode publishes samples to the ring.
        'ldr r0,[r5,#4]','cmp r0,#0','beq immediate',
        # Transport changes do not cancel an older consumer's lift tail.
        # Keep transition samples in its order until the full callback ends.
        'ldrb r0,[r5,#3]','cmp r0,#0','bne append',
        # Transport accessor is the original one, not a Thorn state address.
        *call(0x20005E08),'cmp r0,#1','beq wireless',
        'ldrb r0,[r5,#2]','cmp r0,#0','bne append','b immediate',
        'wireless:',
        'ldrb r0,[r5,#2]','cmp r0,#8','blo append',
        # Backpressure executes older samples first rather than overwrite.
        *call(drain),
        'append:','.hword 0xf3ef,0x8710','cpsid i',
        'ldrb r0,[r5,#1]','movs r1,#6','muls r1,r0','add r1,r5,r1','adds r1,#8',
        'ldr r2,[r4]','str r2,[r1]','ldrh r2,[r4,#4]','strh r2,[r1,#4]',
        'adds r0,#1','and r0,r0,#7','strb r0,[r5,#1]','ldrb r0,[r5,#2]',
        'adds r0,#1','strb r0,[r5,#2]',
        'cmp r0,#1','bne queued','.hword 0xf387,0x8810',
        'ldr r0,[r5,#4]',*call(T.MOTION_SEM_GIVE),'b out',
        'queued:','.hword 0xf387,0x8810','b out',
        'immediate:',*call(drain),'direct:','stock:','mov r0,r4',*call(owned),
        'out:','add sp,#12','pop {r4,r5,r6,r7,pc}'])
    # The registered native report dispatches driver+0x43 (sensor tick),
    # rather than consuming accumulators itself. Do not claim OWNER before
    # that delegation: advanced_tick would reject our own sampling request.
    # If sampling is blocked by its ring/native locks, retry older deltas
    # through the original fallback, retaining its divider and exact frame.
    if builder.image.get(T.flash_source(T.REPORT_NATIVE),len(T.REPORT_PREFIX))!=T.REPORT_PREFIX:
        raise ValueError('MAYA report divider/prologue changed')
    if builder.image.u32(T.REPORT_DRIVER_TABLE+0x43)!=T.SENSOR_TICK|1:
        raise ValueError('MAYA registered report-to-sampler contract changed')
    accum=builder.code('motion_report_accum',[
        'push {r4,r5,r6,r7,lr}',*A.addr('r2',T.REPORT_COUNTER),
        *A.addr('r1',T.REPORT_DIVIDER),'ldrb r3,[r2]','ldrb r1,[r1]',
        'adds r3,#1','uxtb r3,r3','cmp r3,r1','sub sp,#76','strb r3,[r2]',
        'blo out','cmp r1,#0','beq out','movs r3,#0','strb r3,[r2]',
        *tail(T.REPORT_FALLBACK),'out:','add sp,#76','pop {r4,r5,r6,r7,pc}'])
    report=builder.code('motion_report',[
        'push {r4,r5,r6,lr}',*A.addr('r4',T.MOTION_STATE),
        'ldrb r6,[r4]',f'tst r6,#{OWNER}','bne.w out',
        # Match the native driver validity predicate, including its accepted
        # low-Flash/RAM pointer ranges and non-null callback. No new policy.
        *A.addr('r0',T.REPORT_DRIVER_MAGIC),
        *A.addr('r1',T.REPORT_SENTINELS[0]),'ldr r1,[r1]','cmp r0,r1','bne native',
        *A.addr('r1',T.REPORT_SENTINELS[1]),'ldr r1,[r1]','cmp r0,r1','bne native',
        *A.addr('r1',T.REPORT_DRIVER),'ldr r1,[r1]','cmp r1,#0','beq native',
        'cmp r1,#0x200000','blo registered',
        'add r2,r1,#0xe0000000','cmp r2,#0x80000','bhs native',
        'registered:','ldr.w r1,[r1,#67]','cmp r1,#0','beq native',
        *A.addr('r0',T.SENSOR_READY),'ldrb r0,[r0]','cmp r0,#0','beq accumulated',
        *A.addr('r0',0x2000A3A8),'ldr r0,[r0]','cmp r0,#0','bne accumulated',
        *A.addr('r0',0x2000A380),'ldr r0,[r0]','cmp r0,#0','bne accumulated',
        *call(pointer),'cmp r0,#0','beq sample',
        'ldrb r0,[r0,#2]','cmp r0,#8','bhs accumulated',
        # These are read-only routing checks. A concurrent owner can only
        # defer the delegated tick. Mask only when claiming shared deltas.
        'sample:','pop {r4,r5,r6,lr}',*tail(T.REPORT_NATIVE),
        'native:',*A.addr('r3',T.REPORT_NATIVE|1),'b owned',
        'accumulated:',*A.addr('r3',accum|1),
        'owned:','.hword 0xf3ef,0x8510','cpsid i','ldrb r6,[r4]',
        f'tst r6,#{OWNER}','bne unlock',f'orr r1,r6,#{OWNER}','strb r1,[r4]',
        '.hword 0xf385,0x8810','blx r3',
        '.hword 0xf3ef,0x8510','cpsid i','ldrb r1,[r4]',
        f'bic r1,r1,#{OWNER}','strb r1,[r4]',
        'unlock:','.hword 0xf385,0x8810','out:','pop {r4,r5,r6,pc}'])
    # Capture lift before releasing the shared sample. Both native lift
    # helpers may wake another thread and request PendSV; OWNER must already
    # be clear then. Keep native r4, PRIMASK, lift calls and epilogue intact.
    release=builder.code('motion_tail_release',[
        'ldrb r4,[r5,#1]',*A.addr('r1',T.MOTION_STATE),
        '.hword 0xf3ef,0x8c10','cpsid i','ldrb r2,[r1]',
        f'bic r2,r2,#{OWNER}','strb r2,[r1]','.hword 0xf38c,0x8810',
        'cmp r4,#0','beq lower',*call(T.MOTION_LIFT_UP),'movs r4,#1',
        *tail(T.MOTION_TAIL_CONTINUE),'lower:',*call(T.MOTION_LIFT_DOWN),
        *tail(T.MOTION_TAIL_CONTINUE)])
    veneer=assemble(A.addr('r12',release|1)+['bx r12','nop'],T.MOTION_TAIL_SITE)
    if len(veneer)!=len(T.MOTION_TAIL_PREIMAGE):
        raise ValueError('MAYA motion tail veneer size changed')
    builder.edit(T.MOTION_TAIL_SITE,veneer,'release MAYA motion ownership before native lift scheduling')
    return dict(route=route,drain=drain,consume=consume,report=report,accum=accum,pointer=pointer,owned=owned,
                release=release,release_site=T.MOTION_TAIL_SITE,
                initialize=initialize,thread=thread,thread_bytes=THREAD_BYTES,
                default='direct',wired='native synchronous',capacity=8,
                worker_lock='independent priority6 done thread',queued_wake_capacity=1,
                backpressure='drain older samples in order; never overwrite')


def router(builder,core,getter,setter,storage):
    def call(value):return A.call(value,target=T)
    def tail(value):return A.tail(value,target=T)
    get=builder.code('settings_motion_get',[
        'cmp r5,#10','beq ours',*tail(getter),'ours:','cmp r6,#0','bne bad',
        'ldrb r0,[r4,#3]','cmp r0,#2','bne bad',*A.addr('r1',T.MOTION_STATE),
        'ldrb r0,[r1]','ubfx r0,r0,#4,#1','strb r0,[r4,#8]',
        'movs r0,#3','strb r0,[r4,#3]','movs r0,#1','bx lr',
        'bad:','movs r0,#0','bx lr'])
    set_=builder.code('settings_motion_set',[
        'cmp r5,#10','beq ours',*tail(setter),'ours:','push {r7,lr}',
        'cmp r6,#0','bne bad','ldrb r0,[r4,#3]','cmp r0,#3','bne bad',
        'ldrb r0,[r4,#8]','cmp r0,#1','bhi bad',*call(storage),'cmp r0,#0','beq bad',
        'mov r7,r0',
        'ldrb r0,[r4,#8]','cmp r0,#0','bne publish','mov r0,r7',
        *call(core['initialize']),'cmp r0,#0','beq bad',
        'publish:',
        *A.addr('r1',T.MOTION_STATE),'.hword 0xf3ef,0x8c10','cpsid i',
        'ldrb r2,[r1]','ldrb r0,[r4,#8]','ubfx r3,r2,#4,#1','cmp r3,r0','beq success',
        f'tst r2,#{OWNER}','bne busy',f'addw r3,r7,#{T.MOTION_RING_OFFSET}',
        'ldrb r0,[r3,#2]','cmp r0,#0','bne busy',
        'ldrb r0,[r3,#3]','cmp r0,#0','bne busy',
        'bic r2,r2,#16','ldrb r0,[r4,#8]',
        'orr r2,r2,r0,lsl #4','strb r2,[r1]',
        'success:','.hword 0xf38c,0x8810',
        'movs r0,#2','strb r0,[r4,#3]',*call(get),'pop {r7,pc}',
        'busy:','.hword 0xf38c,0x8810',
        'bad:','movs r0,#0','pop {r7,pc}'])
    return dict(get=get,set=set_,flags=P.F_MOTION_PATH)
