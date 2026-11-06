"""MAYA receiver identity and bounded paired FULL integration.

Reclaim only the three native queue writers after consolidating their ring
mechanics. Their entry points, masks, capacity and copy semantics remain.
"""
import struct

from superlamzu.common import Builder, assemble
from superlamzu.emulation import MemoryLayout

from . import target as M

NAME, STOCK = M.RECEIVER.name, M.RECEIVER.source
BASE, SP, RESET, SPAN = 0x15000, 0x2000DBA8, 0x1A1BD, 97160
COPIES = ((0x15000,0x20000800,0x4C8), (0x28F4C,0x20000CE0,0x2500),
          (0x2B44C,0x200031E0,0x1738), (0x154C8,0x2007ABE0,0xCD8))
PROTECTED_SOURCES = M.PROTECTED_SOURCES
QUEUE_BASE, QUEUE_STRIDE, QUEUE_HEADER, QUEUE_RECORD, QUEUE_CAPACITY = 0x20006E38,640,12,25,25
QUEUE_INIT, QUEUE_RAW, QUEUE_PREFIX, QUEUE_OBJECT = 0x198E4,0x20002EBC,0x20002F34,0x200030E8
QUEUE_POP, QUEUE_COUNT, MEMCPY = 0x20003018,0x200030A4,0x27438
ABS_VALID, ABS_X, ABS_Y = QUEUE_BASE+637,QUEUE_BASE+638,QUEUE_BASE+640+638
ABS_JUMP_LIMIT = 0x4000
PARSER, REPORT, REPORT_POINTER = 0x200019D0,0x20001128,0x20001C18
USB_QUEUE_PUT, USB_QUEUE_PUT_POINTER = 0x20001588,0x200011D0
LAYOUT = MemoryLayout(ram_regions=((0x20000000,0x80000),),stack=SP,stop=0x2007F000,copies=COPIES)


def flash_source(address):
    for source,run,size in COPIES:
        if run<=address<run+size:return source+address-run
    return address


def runtime(address):
    for source,run,size in COPIES:
        if source<=address<source+size:return run+address-source
    return address


def call(value):
    return [f'movw r12,#{(value|1)&65535}',f'movt r12,#{value>>16}','blx r12']


def tail(value):
    return [f'movw r12,#{(value|1)&65535}',f'movt r12,#{value>>16}','bx r12']


class ReceiverBuilder(Builder):
    def __init__(self):
        import sys
        M.RECEIVER.inspect()
        super().__init__(STOCK,target=sys.modules[__name__])

    def code(self,name,source):
        if name in self.symbols:raise ValueError(f'duplicate symbol {name}')
        for i,(start,end) in enumerate(self.pools):
            start=(start+1)&~1
            data=assemble(source,runtime(start))
            if start+len(data)<=end:
                self.edit(start,data,name)
                self.pools[i]=(start+len(data),end)
                self.symbols[name]=runtime(start)
                self.allocations.append(dict(name=name,address=hex(start),runtime=hex(runtime(start)),bytes=len(data)))
                return runtime(start)
        raise ValueError(f'no proven receiver code pool fits {name}')


def consolidate(builder):
    # Exact original body+literal guards live in target data, never derive a
    # preimage from whatever candidate is being patched.
    from .receiver_facts import QUEUE_PREIMAGES
    for site,raw in QUEUE_PREIMAGES.items():
        if builder.image.get(flash_source(site),len(raw))!=raw:
            raise ValueError(f'MAYA receiver queue original changed at {site:#x}')
    for lo,hi in ((0x20002EBC,0x20002F34),(0x20002F34,0x20002FB4),(0x200030E8,0x20003154)):
        builder.pools.append((flash_source(lo+4),flash_source(hi)))
    core=builder.code('queue_core',[
        'push {r4,r5,r6,lr}',f'ldr r4,={QUEUE_BASE:#x}',
        'add.w r0,r0,r0,lsl #2','add.w r4,r4,r0,lsl #7',
        'ldrb r0,[r4]','cbnz r0,fail','ldrb r0,[r4,#2]',
        'movs r5,#25','mla r0,r0,r5,r4','adds r0,#12',
        'cmp r3,#0','blt copy','strb r3,[r0]','adds r0,#1',
        'copy:',f'ldr r12,={MEMCPY|1:#x}','blx r12',
        'ldrb r0,[r4,#2]','adds r0,#1','uxtb r0,r0',
        'ldrb r1,[r4,#4]','cmp r1,r0','it ls','movls r0,#0',
        'ldrb r1,[r4,#3]','strb r0,[r4,#2]','cmp r1,r0','itt eq',
        'moveq r1,#1','strbeq r1,[r4]','movs r0,#0','strb r0,[r4,#1]',
        'movs r0,#1','pop {r4,r5,r6,pc}','fail:','movs r0,#0',
        'pop {r4,r5,r6,pc}','.ltorg'])
    # BASEPRI_MAX is preserved for raw/prefix; object remains unmasked as stock.
    masked=builder.code('queue_mask',[
        'push {r4,lr}','.hword 0xf3ef,0x8411','mov.w r12,#96','.hword 0xf38c,0x8812','isb',
        f'bl #{core:#x}','.hword 0xf384,0x8811','isb','pop {r4,pc}'])
    raw=builder.code('queue_raw',['mov.w r3,#-1',f'b.w #{masked:#x}'])
    prefix=builder.code('queue_prefix',['mov r3,r2',f'b.w #{masked:#x}'])
    obj=builder.code('queue_object',['ldrb r12,[r1]','mov r1,r2','mov r2,r3','mov r3,r12',f'b.w #{core:#x}'])
    for site,dest in ((QUEUE_RAW,raw),(QUEUE_PREFIX,prefix),(QUEUE_OBJECT,obj)):
        builder.branch(site,dest,'shared native queue writer; retain ABI and masking')
    return dict(core=core,raw=raw,prefix=prefix,object=obj,mask=masked)


def build_queue_stage():
    builder=ReceiverBuilder()
    builder.queue=consolidate(builder)
    return builder


def install_absolute(builder):
    from .receiver_facts import ABS_ADMISSION_PREIMAGES
    for site,raw in ABS_ADMISSION_PREIMAGES.items():
        if builder.image.get(flash_source(site),len(raw))!=raw:
            raise ValueError(f'MAYA receiver ABS admission contract changed at {site:#x}')
    if builder.image.u32(flash_source(REPORT_POINTER)) != REPORT|1:
        raise ValueError('MAYA native motion report callback changed')
    if builder.image.u32(flash_source(USB_QUEUE_PUT_POINTER)) != USB_QUEUE_PUT|1:
        raise ValueError('MAYA native motion USB queue writer changed')
    if builder.image.get(QUEUE_INIT,12) != bytes.fromhex('4ff420734ff480715843054b'):
        raise ValueError('MAYA native queue initializer changed')
    # Queue0 owns this parser session. Invalidate before its original init,
    # including warm reinitialization; queue1..6 must not reset a live baseline.
    # X/Y need not be cleared because VALID gates their first use.
    init=builder.code('receiver_abs_init',[
        'cmp r0,#0','bne native',f'ldr r3,={ABS_VALID:#x}',
        'movs r2,#0','strb r2,[r3]','native:','mov.w r3,#640',
        'mov.w r1,#256','muls r0,r3',f'ldr r3,={QUEUE_BASE:#x}',
        *tail(QUEUE_INIT+12),'.ltorg'])
    # Flash cannot B.W to RAM. Preserve the original entry ABI with a far
    # scratch-register veneer, replaying all displaced native instructions.
    builder.edit(QUEUE_INIT,assemble(tail(init)+['nop'],QUEUE_INIT),
                 'ABS baseline lifetime follows native queue0 initialization')
    # Called after the original parser has assembled its six-byte USB sample.
    # r7 is the parser-owned type-bit3 (not a global mode or stale frame byte).
    finish=builder.code('receiver_abs_finish',[
        'sxth r0,r0','sxth r1,r1',f'cmp.w r0,#{ABS_JUMP_LIMIT}', 'bge zero',
        f'cmn.w r0,#{ABS_JUMP_LIMIT}','ble zero',
        f'cmp.w r1,#{ABS_JUMP_LIMIT}','bge zero',
        f'cmn.w r1,#{ABS_JUMP_LIMIT}','bgt store',
        'zero:','movs r0,#0','movs r1,#0','store:',
        'strh r0,[r4,#2]','strh r1,[r4,#4]','mov r0,r4',
        f'bl #{REPORT:#x}','pop {r4,r5,r6,pc}'])
    main=builder.code('receiver_abs',[
        'cmp r7,#0','bne absolute',f'b.w #{REPORT:#x}',
        'absolute:',
        'push {r4,r5,r6,lr}','mov r4,r0',f'ldr r5,={ABS_VALID:#x}',
        'ldrh r0,[r4,#2]','ldrh r1,[r4,#4]',
        'orr r6,r0,r1,lsl #16',
        'ldrb r2,[r5]','cmp r2,#0','beq first',
        'ldrh.w r2,[r5,#1]','subs r0,r2',
        'ldrh.w r2,[r5,#641]','subs r1,r2',f'b.w #{finish:#x}',
        'first:','movs r0,#0','movs r1,#0',f'b.w #{finish:#x}', '.ltorg'])
    # All three native REPORT callers are this parser's motion cases.
    # REPORT preserves r7 and has not changed wrapper r5/r6 when it calls
    # queue_put. Commit the original total at that exact admission boundary,
    # before REPORT continues its independent endpoint/dequeue work.
    commit=builder.code('receiver_abs_commit',[
        'push {r1,r2,r3,lr}',f'bl #{USB_QUEUE_PUT:#x}',
        'cbz r0,out','cbz r7,relative','movs r1,#1','strb r1,[r5]',
        'strh.w r6,[r5,#1]','lsrs r1,r6,#16','strh.w r1,[r5,#641]',
        'out:','pop {r1,r2,r3,pc}',
        'relative:',f'ldr r1,={ABS_VALID:#x}','movs r2,#0','strb r2,[r1]',
        'b out','.ltorg'])
    builder.edit(USB_QUEUE_PUT_POINTER,struct.pack('<I',commit|1),
                 'commit MAYA ABS baseline only after native USB queue accepts the sample')
    builder.edit(REPORT_POINTER,struct.pack('<I',main|1),
                 'MAYA native parser dual-sample ABS; relative baseline invalidation')
    builder.absolute=dict(main=main,finish=finish,init=init,commit=commit,
                          valid=ABS_VALID,x=ABS_X,y=ABS_Y,
                          jump_limit=ABS_JUMP_LIMIT,first='baseline then zero')
    return builder.absolute


def build_absolute_stage():
    builder=build_queue_stage()
    install_absolute(builder)
    return builder
