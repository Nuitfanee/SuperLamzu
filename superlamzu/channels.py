"""CHAN counters at validated response and connected receive-window expiry."""
from . import target as T,protocol as P
from .advanced import addr,call,tail,inc,OFF,snapshot_pointer
from .common import assemble


def install(b,settings,storage):
    pointer=b.code('channels_pointer',snapshot_pointer('r0','r1','r2')+[
        'it ne',f'addwne r0,r0,#{T.CHAN_OFFSET}','bx lr'])
    # r2=miss (0/1); wrappers preserve every native register and condition flag.
    core=b.code('channels_count',['push {r4,r5,r6,lr}','mov r6,r2']+addr('r4',T.ADV_RAM)+[
        'ldrb r0,[r4,#1]','cmp r0,#0','beq channel']+inc('tx_attempts')+['cmp r6,#0','bne missed']+
        inc('acked')+['movs r0,#0',f'str r0,[r4,#{OFF["miss_run"]}]','b channel','missed:']+
        inc('no_ack')+inc('miss_run')+[f'ldr r1,[r4,#{OFF["max_miss_run"]}]','cmp r0,r1','it hi',f'strhi r0,[r4,#{OFF["max_miss_run"]}]',
        'channel:']+call(pointer)+['cmp r0,#0','beq out',
        'mov r4,r0','ldrb r0,[r4]','cmp r0,#0','beq out']+addr('r0',T.CHAN_FREQUENCY)+[
        'ldr r0,[r0]']+addr('r1',T.CHAN_HOPS)+['ldr r3,[r1]','str r3,[r4,#24]',
        'movs r1,#0','find:','uxtb r5,r3','cmp r5,r0','beq found','lsrs r3,#8',
        'adds r1,#1','cmp r1,#4','bne find','found:','add r4,r4,r1,lsl #1',
        'ldrh r0,[r4,#4]','adds r0,#1','strh r0,[r4,#4]','cmp r6,#0','beq out',
        'ldrh r0,[r4,#14]','adds r0,#1','strh r0,[r4,#14]','out:','pop {r4,r5,r6,pc}'])
    wrappers=[]
    for site,miss in ((T.CHAN_ACK_SITE,0),(T.CHAN_MISS_SITE,1)):
        if b.image.get(T.flash_source(site),10)!=T.CHAN_PREIMAGES[site]:
            raise ValueError(f'CHAN decision preimage changed at {site:#x}')
        # RX acceptance has already passed CRC and address checks. The deadline
        # block also handles state 4 and startup: count only connected state 6.
        displaced=(['movs r2,#2']+addr('r3',0x53022000)+addr('r1',0x2300BF80)+['str.w r2,[r3,#0x504]']
                   if miss else ['movs r2,#1']+addr('r3',0x2300D554)+[
                       'strb r2,[r3]','movs r3,#8','ldrb r2,[r1]'])
        helper=b.code('channels_miss' if miss else 'channels_ack',[
            'push {r0,r1,r2,r3,r4,lr}','mrs r4,apsr']+
            addr('r0',T.ADV_RAM+1)+['ldrb r0,[r0]','cbnz r0,active']+
            call(pointer)+[
            'cmp r0,#0','beq skip','ldrb r0,[r0]','cbz r0,skip',
            'active:']+
            (['ldr r12,[sp,#16]','ldrb.w r0,[r12,#0x186]','cmp r0,#6','bne skip']
             if miss else [])+
            ['ldr r12,[sp,#16]','ldrb r0,[r12,#1]','cbz r0,skip',
             f'movs r2,#{miss}']+call(core)+[
            'skip:','msr APSR_nzcvq,r4','pop {r0,r1,r2,r3,r4,lr}']+displaced+['bx lr'])
        veneer=assemble(addr('r12',helper|1)+['blx r12'],site)
        assert len(veneer)==10
        b.edit(site,veneer,'validated RX response / connected RX-window expiry; preserve native state')
        wrappers.append(helper)
    # A single coherent 28B payload. No allocation on GET or radio IRQ.
    get=b.code('channels_get',['cmp r5,#13','beq ours']+tail(settings['get'])+[
        'ours:','push {r7,lr}','cmp r6,#0','bne bad','ldrb r0,[r4,#3]','cmp r0,#2','bne bad',
        'add r2,r4,#8','movs r0,#0','movs r1,#26','zero:','strb r0,[r2],#1','subs r1,#1','bne zero',
        '.hword 0xf3ef,0x8710','cpsid i']+call(pointer)+[
        'cmp r0,#0','beq reply','ldrb r1,[r0]','strb r1,[r4,#8]',
        'adds r0,#4','add r2,r4,#10','movs r3,#24','copy:','ldrb r1,[r0],#1','strb r1,[r2],#1',
        'subs r3,#1','bne copy','reply:','.hword 0xf387,0x8810','movs r0,#28','strb r0,[r4,#3]',
        'movs r0,#1','pop {r7,pc}','bad:','movs r0,#0','pop {r7,pc}'])
    set=b.code('channels_set',['cmp r5,#13','beq ours']+tail(settings['set'])+[
        'ours:','push {r7,lr}','cmp r6,#0','bne bad','ldrb r0,[r4,#3]','cmp r0,#3','bne bad',
        'ldrb r0,[r4,#8]','cmp r0,#2','bhi bad']+call(storage)+['cmp r0,#0','beq bad',
        'addw r0,r0,#316','ldrb r1,[r4,#8]','cmp r1,#2','beq reset','strb r1,[r0]','b reply',
        'reset:','.hword 0xf3ef,0x8710','cpsid i','adds r0,#4','movs r1,#0','movs r2,#6',
        'clear:','str r1,[r0],#4','subs r2,#1','bne clear','.hword 0xf387,0x8810',
        'reply:','movs r0,#2','strb r0,[r4,#3]']+call(get)+['pop {r7,pc}',
        'bad:','movs r0,#0','pop {r7,pc}'])
    return dict(get=get,set=set,core=core,ack=wrappers[0],miss=wrappers[1],
                outcome_semantics=P.RADIO_OUTCOME_SEMANTICS,
                default=False,heap_offset=T.CHAN_OFFSET,heap_bytes=T.CHAN_BYTES,
                counter='u16 wrapping, first matching hop or unknown bucket 4')
