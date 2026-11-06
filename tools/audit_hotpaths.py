"""Offline instruction-count helpers for stock and current firmware tests."""
import copy
from collections import Counter

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_MCLASS, UC_HOOK_CODE
import unicorn.arm_const as C
from unicorn.arm_const import UC_ARM_REG_PRIMASK

from superlamzu import advanced as A, target as T
from superlamzu.checks import fresh, Timer
from superlamzu.motion import DIRECT, OWNER
from superlamzu.optical_checks import initialize, sample, HEAP

LEGACY_CHAN_SITES = (0x230024DC, 0x230024E8)


def image_builder(current, image, manifest=None):
    b = copy.copy(current)
    b.changes = {a:v for a,v in image.mem.items() if current.image.mem.get(a) != v}
    if manifest:
        b.allocations = manifest['allocations']
        b.symbols = {v['name']:int(v['address'],0) for v in b.allocations}
        b.optical = manifest['optical']
    return b


def measure(a, entry, args=()):
    count = masked = longest = run = 0
    a.calls.clear()

    def instruction(uc, address, size, user):
        nonlocal count, masked, longest, run
        if address in a.stubs or address in a.ends:
            return
        count += 1
        if uc.reg_read(UC_ARM_REG_PRIMASK):
            masked += 1
            run += 1
            longest = max(longest, run)
        else:
            run = 0
    handle = a.uc.hook_add(UC_HOOK_CODE, instruction)
    try:
        a.run(entry, *args, count=200000)
    finally:
        a.uc.hook_del(handle)
    return dict(instructions=count, masked_instructions=masked,
                longest_masked_instruction_run=longest,
                stub_calls=dict(Counter(f'{c[0]:#010x}' for c in a.calls)),
                final_primask=a.uc.reg_read(UC_ARM_REG_PRIMASK))


def split_lock_paths(builder):
    """Count current SUPER at the same native IRQ service boundary as legacy."""
    from superlamzu import native_plock as P
    from superlamzu.native_plock_checks import Timeline
    import struct
    results = {}
    heap = 0x23024004
    with fresh(builder) as cpu:
        timer = Timeline(cpu, T.REPORT_TIMER)
        cpu.uc.mem_write(T.SNAPSHOT_POINTER, (heap & 0xFFFFF).to_bytes(3, 'little'))
        cpu.uc.mem_write(T.REPORT_DIVIDER, b'\1')
        cpu.uc.mem_write(T.TICKS_PER_MS, b'\4')
        cpu.uc.mem_write(T.RADIO_STATE + 1, b'\1\1')
        cpu.uc.mem_write(T.ADV_RAM + 4, b'\x50\0')
        cpu.put32(T.RADIO_EVENT, 1)
        def native(c):
            c.uc.mem_write(T.RADIO_STATE + 0x186, b'\4')
            return 0x12345678
        cpu.stub(T.RADIO_IRQ, effect=native)
        for name, flags, countdown, phase, pending, fail in (
                ('off', 0, 0, 0, 0, False),
                ('legacy', 0, 0, 100, 0, False),
                ('steady_fast', P.SPLIT | P.CALIBRATED, 64, 0, 0, False),
                ('steady_check', P.SPLIT | P.CALIBRATED, 0, 0, 0, False),
                ('first_capture', P.SPLIT, 0, 100, 0, False),
                ('outlier_first', P.SPLIT | P.CALIBRATED, 0, 40, 0, False),
                ('outlier_confirm', P.SPLIT | P.CALIBRATED | P.PENDING_VALID, 0, 40, 40, False),
                ('capture_failed', P.SPLIT | P.CALIBRATED, 0, 0, 0, True)):
            cpu.uc.mem_write(T.ADV_RAM + 2, bytes((name != 'off',)))
            cpu.uc.mem_write(heap + P.CONTROL_OFFSET,
                struct.pack('<HhhBB', 250, 0, pending, countdown, flags))
            cpu.uc.mem_write(T.RADIO_STATE + 0x186, b'\10')
            cpu.put32(T.REPORT_TIMER + 0x200, 2 if flags & P.SPLIT else 1)
            cpu.put32(T.REPORT_TIMER + 0x540, 170 if flags & P.SPLIT else 250)
            cpu.put32(T.REPORT_TIMER + 0x544, 250)
            timer.count = phase
            timer.tasks.clear()
            timer.pending.clear()
            timer.fail = {2} if fail else set()
            results[name] = measure(cpu, builder.symbols['advanced_radio_irq'])
            results[name]['timer_tasks'] = list(timer.tasks)
            assert cpu.reg('r0') == 0x12345678
            assert all(address not in (T.NATIVE_CLOCK_REQUEST, T.NATIVE_CLOCK_RELEASE,
                                      T.NATIVE_ALLOC) for address, _, _ in cpu.calls)
        totals = {}
        for split in (False, True):
            cpu.uc.mem_write(T.ADV_RAM + 2, b'\1')
            cpu.uc.mem_write(heap + P.CONTROL_OFFSET, struct.pack('<HhhBB',
                250, 0, 0, 0, P.SPLIT | P.CALIBRATED if split else 0))
            cpu.put32(T.REPORT_TIMER + 0x540, 170 if split else 250)
            timer.fail.clear()
            timer.count = 0
            count = 0
            for _ in range(130):
                cpu.uc.mem_write(T.RADIO_STATE + 0x186, b'\10')
                count += measure(cpu, builder.symbols['advanced_radio_irq'])['instructions']
            totals['split' if split else 'legacy'] = count
        assert totals['split'] < totals['legacy'], totals
        results['same_130_irq_sequence'] = totals
    return results


def hotpaths(b, stock=False, chan_revision='candidate'):
    # fresh() loads builder.changes, including relocated RAM. Merely choosing
    # native entries did not make the old stock fixture an original image.
    if stock:
        b=image_builder(b,b.image)
    results = {}
    for name,native,args in (
        ('tick',0x0E07E6DC,()), ('spi_done',0x0E07E600,(0x23025000,1)),
        ('motion',T.MOTION_NATIVE,(T.MOTION_SAMPLE,)), ('report',T.REPORT_NATIVE,())):
        for stats in (0,1):
            with fresh(b) as a:
                a.uc.mem_write(A.ADV_RAM,bytes((1,stats))+bytes(186))
                a.uc.mem_write(T.SENSOR_READY,b'\1')
                a.uc.mem_write(0x2300E073,b'\xb7\0')
                a.uc.mem_write(T.MOTION_SAMPLE,b'\1\0\x13\0\xf9\xff')
                a.stub(native)
                symbol = dict(tick='advanced_tick',spi_done='advanced_spi_done',
                              motion='advanced_motion',report='motion_report')[name]
                results[f'{name}.stats{stats}'] = measure(a,native if stock else b.symbols.get(symbol,native),args)
    for stats,lock in ((0,0),(1,0),(0,1),(1,1)):
        with fresh(b) as a:
            a.uc.mem_write(A.ADV_RAM,bytes((1,stats,lock,0))+bytes(184))
            a.uc.mem_write(A.ADV_RAM+4,(80).to_bytes(2,'little'))
            a.uc.mem_write(A.RSTATE+1,b'\1\1')
            a.uc.mem_write(A.RSTATE+0x186,b'\x08')
            a.uc.mem_write(A.DIVIDER,b'\1'); a.uc.mem_write(A.TPMS,b'\4')
            a.put32(A.RADIO_EVENT,1); a.put32(A.REPORT_TIMER+0x540,250)
            timer=Timer(a); timer.count=100
            def native(cpu):
                cpu.uc.mem_write(A.RSTATE+0x186,b'\x04')
                return 0
            a.stub(A.IRQ,effect=native)
            result=measure(a,A.IRQ if stock else b.symbols['advanced_radio_irq'])
            result['timer_captures']=timer.captures
            result['heap_or_spi_calls']=sum(result['stub_calls'].get(f'{address:#010x}',0)
                                          for address in (T.WR,T.RD,T.NATIVE_ALLOC))
            results[f'radio.stats{stats}.lock{lock}']=result
    chan_sites = (LEGACY_CHAN_SITES if chan_revision == 'installed' else
                  (T.CHAN_ACK_SITE,T.CHAN_MISS_SITE))
    for miss,site in ((False,chan_sites[0]),(True,chan_sites[1])):
        for stats,chan,heap in ((0,0,0),(0,0,1),(1,0,1),(0,1,1),(1,1,1)):
            with fresh(b) as a:
                if heap: initialize(a)
                a.uc.mem_write(A.ADV_RAM+1,bytes((stats,)))
                if heap: a.uc.mem_write(HEAP+T.CHAN_OFFSET,bytes((chan,)))
                a.uc.mem_write(0x23020001,b'\1')
                a.uc.mem_write(0x23020186,b'\6')
                a.uc.mem_write(0x23020520,b'\x91')
                a.uc.mem_write(T.CHAN_HOPS,bytes((11,41,62,79)))
                a.put32(T.CHAN_FREQUENCY,41)
                a.setreg('r1',0x23020520);a.setreg('r2',0x23020500)
                a.setreg('r4',0x23020000)
                a.ends.add(site+10)
                results[f'chan.{"miss" if miss else "ack"}.stats{stats}.chan{chan}.heap{heap}']=measure(a,site)
    for mode in ('stock_idle','direct_idle','direct_press','drain_press'):
        if mode!='stock_idle' and (stock or 'request' not in b.optical):continue
        with fresh(b) as a:
            initialize(a)
            if mode!='stock_idle':
                # Retain measurement of archived installed images only.
                a.run(b.optical['request'],HEAP+T.CLICK_OFFSET,1)
                sample(a,1,1)
            a.levels=[0,1] if mode=='direct_press' else [1,1]
            if mode=='drain_press':
                sample(a,0,1)
                entry=b.optical['drain']
            else:entry=0x23001A34
            results[f'optical.{mode}']=measure(a,entry)
    if not stock:
        for state in (0,DIRECT,DIRECT|OWNER):
            with fresh(b) as a:
                a.uc.mem_write(T.MOTION_STATE,bytes((state,)))
                a.uc.mem_write(T.TRANSPORT_STATE,b'\1')
                a.put32(T.MOTION_DONE_QUEUE,0x2300A328)
                a.put32(T.MOTION_CALLBACK,b.symbols['advanced_motion']|1)
                a.stub(T.MOTION_POST);a.stub(T.MOTION_NATIVE)
                results[f'direct.state{state}']=measure(a,b.symbols['motion_post'],(T.MOTION_DONE_QUEUE,0x23025000,0,0))
    for index,entry in enumerate(T.FLASH_RECIPES):
        with fresh(b) as a:
            a.stub(T.WR,1)
            a.stub(T.RD,1,effect=lambda cpu:cpu.uc.mem_write(cpu.reg('r1'),b'\xa5'))
            result=measure(a,entry)
            result['spi_writes']=result['stub_calls'].get(f'{T.WR:#010x}',0)
            result['spi_reads']=result['stub_calls'].get(f'{T.RD:#010x}',0)
            results[f'recipe.{index+1}']=result
    for enabled in (0,1):
        for path in ('total','header','retry'):
            with fresh(b) as a:
                initialize(a)
                a.uc.mem_write(T.MOTION_STATE,bytes((2|64*enabled,)))
                a.uc.mem_write(HEAP+24,b'\x64\0\xc8\0')
                if path=='total':
                    a.uc.mem_write(0x23030002,b'\x13\0\xf9\xff')
                    entry,end,args=T.ABS_ACC_SITE,T.ABS_ACC_SITE+24,(0x12345678,)
                elif path=='header':
                    a.uc.mem_write(0x23030004,b'\0\0')
                    a.setreg('r4',0x23025000);a.setreg('r5',0)
                    entry,end,args=T.ABS_HEADER_SITE,T.ABS_HEADER_SITE+16,(2,0,1,T.RADIO_FRAME_PENDING+1)
                else:
                    a.setreg('r4',0x23025000)
                    a.uc.mem_write(0x23025006,b'\7\0\x0a'+bytes(5))
                    a.stub(T.RADIO_MEMCPY)
                    entry,end,args=T.ABS_RETX_SITE,T.ABS_RETX_SITE+16,()
                a.ends.add(end)
                results[f'abs.{path}.enabled{enabled}']=measure(a,entry,args)
    with fresh(b) as a:
        a.uc.mem_write(0x23025000,bytes(range(128)))
        results['binding_copy.128B']=measure(a,0x0E0877E0 if stock else b.optical.get('binding_copy',0x0E0877E0),
                                            (0x23026000,0x23025000,128))
        assert bytes(a.uc.mem_read(0x23026000,128))==bytes(range(128))
    if not stock:
        for preset in (0,1,37):
            with fresh(b) as a:
                a.uc.mem_write(A.ADV_RAM+3,bytes((preset,)))
                a.uc.mem_write(A.ADV_RAM+9,b'\1')
                registers={}
                a.stub(T.WR,1,effect=lambda cpu:registers.__setitem__(cpu.reg('r0'),cpu.reg('r1')))
                a.stub(T.RD,1,effect=lambda cpu:cpu.uc.mem_write(
                    cpu.reg('r1'),bytes((registers[cpu.reg('r0')],))))
                results[f'fps_apply.preset{preset}']=measure(a,b.symbols['advanced_fps_apply'])
                assert a.byte(A.ADV_RAM+8)==preset and a.byte(A.ADV_RAM+9)==0
    return results


def receiver_hotpaths():
    """Use the existing receiver check's mappings and local hook boundaries."""
    import gc
    import struct
    from superlamzu import receiver as R
    b=R.build('cpurad')
    results={}
    for label,data in (('stock',b.image.data),('audit',b.output_image())):
        u=Uc(UC_ARCH_ARM,UC_MODE_THUMB|UC_MODE_MCLASS)
        u.mem_map(b.image.base,(len(data)+4095)&~4095)
        u.mem_write(b.image.base,data)
        u.mem_map(0x23000000,0x40000)
        u.mem_write(R.CODE_RAM,data[R.CODE_SOURCE-b.image.base:R.CODE_SOURCE-b.image.base+R.CODE_BYTES])
        u.mem_write(R.DATA_RAM,data[R.DATA_SOURCE-b.image.base:R.DATA_SOURCE-b.image.base+R.DATA_BYTES])
        u.mem_map(R.SOF_TIMER,4096)
        section={}
        stop,stack=0x2303f000,0x23030000
        def count(entry,end,args=()):
            total=[0]
            def hook(uc,address,size,user):
                if address!=end:total[0]+=1
            h=u.hook_add(UC_HOOK_CODE,hook)
            try:
                u.reg_write(C.UC_ARM_REG_SP,stack)
                u.reg_write(C.UC_ARM_REG_LR,stop|1)
                for i,value in enumerate(args):u.reg_write(getattr(C,f'UC_ARM_REG_R{i}'),value)
                u.emu_start(entry|1,end,count=4000)
                assert u.reg_read(C.UC_ARM_REG_PC)==end
                assert u.reg_read(C.UC_ARM_REG_SP)==stack
            finally:u.hook_del(h)
            return dict(instructions=total[0],basepri=u.reg_read(C.UC_ARM_REG_BASEPRI))
        try:
            for state in (0,3,4):
                u.mem_write(R.SOF_STATE,bytes((0,0,0,0,state,0,0,1)))
                u.mem_write(R.SOF_COUNT,struct.pack('<H',64))
                u.mem_write(R.SOF_TIMER+0x540,struct.pack('<II',125,125))
                section[f'sof.state{state}']=count(R.runtime(R.SOF_CALLBACK),stop)
            site=R.runtime(R.RADIO_HOOKS['sof_isr'][0])
            u.mem_write(0x23020010,(0x12345678).to_bytes(4,'little'))
            u.reg_write(C.UC_ARM_REG_R4,0x23020000)
            section['sof.isr_capture']=count(site,site+4)
            site=R.runtime(R.RADIO_HOOKS['motion_copy'][0])
            for name,header,valid,x,y in (('relative',2,0,19,65529),('abs_first',10,0,19,20),
                                        ('abs_delta',10,1,119,120),('abs_duplicate',10,1,100,100),
                                        ('abs_resync',10,1,20000,100)):
                u.mem_write(stack,b'\0'*48)
                u.mem_write(stack+0x11,struct.pack('<BBHH',header,0x42,x,y))
                u.mem_write(R.ABS_VALID,bytes((valid,)))
                u.mem_write(R.ABS_X,struct.pack('<H',100));u.mem_write(R.ABS_Y,struct.pack('<H',100))
                section[name]=count(site,site+16)
            results[label]=section
        finally:
            u=None
            gc.collect()
    return results
