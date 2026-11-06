"""Offline instruction-count helpers for current MAYA firmware tests."""
import struct
from types import SimpleNamespace

from unicorn import UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_BASEPRI

from MAYA_X_V2 import target as T, receiver as R
from MAYA_X_V2.sensor import LAYOUT
from MAYA_X_V2.tests.test_absolute import AbsoluteTests, HEAP
from MAYA_X_V2.tests.test_advanced import AdvancedTests
from MAYA_X_V2.tests.test_motion import MotionTests, RING
from MAYA_X_V2.tests.test_optical import OpticalTests
from MAYA_X_V2.tests.test_radio import RadioTests
from MAYA_X_V2.tests.test_receiver import ReceiverTests
from MAYA_X_V2.tests.test_sof import SofTests
from MAYA_X_V2.tests.test_stats import StatisticsTests
from superlamzu import advanced as A
from superlamzu.checks import Timer
from superlamzu.emulation import Arm
from superlamzu.verify import patched_image
from tools.audit_hotpaths import measure as instruction_measure


def measure(cpu,entry,args=()):
    masked=longest=run=0
    def instruction(uc,address,size,user):
        nonlocal masked,longest,run
        if address in cpu.stubs or address in cpu.ends:return
        if uc.reg_read(UC_ARM_REG_BASEPRI):
            masked+=1;run+=1;longest=max(longest,run)
        else:run=0
    handle=cpu.uc.hook_add(UC_HOOK_CODE,instruction)
    try:result=instruction_measure(cpu,entry,args)
    finally:cpu.uc.hook_del(handle)
    result.update(basepri_masked_instructions=masked,
                  longest_basepri_instruction_run=longest,
                  final_basepri=cpu.uc.reg_read(UC_ARM_REG_BASEPRI))
    return result


def fixture(cls, builder, stock=False):
    result=cls()
    result.builder=builder
    result.changed=builder.image if stock else patched_image(builder)
    return result


def mouse_hotpaths(builder, stock=False):
    results={}
    stats=fixture(StatisticsTests,builder,stock)
    for name,native,args in (
            ('tick',T.SENSOR_TICK,()),('burst',T.SENSOR_BURST,(22,0x20016000,6)),
            ('motion',T.MOTION_NATIVE,(0x20016000,))):
        for counting in (0,1):
            with stats.cpu() as cpu:
                cpu.uc.mem_write(T.ADV_RAM+1,bytes((counting,)))
                cpu.uc.mem_write(T.SENSOR_READY,b'\1')
                cpu.uc.mem_write(0x2000D234,b'\xb7\0')
                cpu.uc.mem_write(0x20016000,struct.pack('<BBhh',1,0,19,-7))
                if name=='tick':
                    # Complete SUPER/FULL startup allocates the shared motion
                    # heap even when no explicit SPI snapshot was requested.
                    cpu.uc.mem_write(HEAP,bytes(T.SNAPSHOT_STORAGE_BYTES))
                    cpu.uc.mem_write(T.SNAPSHOT_POINTER,(HEAP&0xFFFFF).to_bytes(3,'little'))
                    if getattr(builder,'motion',{}).get('default')=='direct':
                        cpu.uc.mem_write(T.MOTION_STATE,bytes((cpu.byte(T.MOTION_STATE)|16,)))
                cpu.stub(native,1)
                symbol={'tick':'advanced_tick','burst':'advanced_burst','motion':'advanced_motion'}[name]
                results[f'{name}.stats{counting}']=measure(cpu,native if stock else builder.symbols.get(symbol,native),args)
    radio=fixture(RadioTests,builder,stock)
    for counting,lock in ((0,0),(1,0),(0,1),(1,1)):
        with radio.fresh() as cpu:
            cpu.uc.mem_write(T.ADV_RAM,bytes((1,counting,lock,0))+bytes(184))
            cpu.uc.mem_write(T.ADV_RAM+4,struct.pack('<H',80))
            cpu.uc.mem_write(T.RADIO_STATE+1,b'\1\1')
            cpu.uc.mem_write(T.RADIO_STATE+0x186,b'\x08')
            cpu.uc.mem_write(T.REPORT_DIVIDER,b'\1')
            cpu.uc.mem_write(T.TICKS_PER_MS,b'\4')
            cpu.put32(T.RADIO_EVENT,1)
            cpu.put32(T.REPORT_TIMER+0x540,250)
            timer=Timer(cpu,target=SimpleNamespace(REPORT_TIMER=T.REPORT_TIMER))
            timer.count=100
            cpu.stub(T.RADIO_IRQ,effect=lambda c:c.uc.mem_write(T.RADIO_STATE+0x186,b'\4') or 0)
            v=measure(cpu,T.RADIO_IRQ if stock else builder.symbols['advanced_radio_irq'])
            v['timer_captures']=timer.captures
            results[f'radio.stats{counting}.lock{lock}']=v
    optical=fixture(OpticalTests,builder,stock)
    with optical.cpu() as cpu:
        cpu.levels=[1,1]
        cpu.put32(T.CLICK_TIMER+0x140,1)
        results['optical.stock_idle']=measure(cpu,0x198F4)
    with optical.cpu() as cpu:
        # Archived candidates retain their old adapter; current builds use
        # the original memcpy with no optical wrapper.
        cpu.stubs.pop(T.NATIVE_MEMCPY,None)
        cpu.uc.mem_write(0x20019000,bytes(range(128)))
        copy=T.NATIVE_MEMCPY if stock else builder.optical.get('binding_copy',T.NATIVE_MEMCPY)
        results['binding_copy.128B']=measure(cpu,copy,
            (0x20019100,0x20019000,128))
        assert bytes(cpu.uc.mem_read(0x20019100,128))==bytes(range(128))
    for index,entry in enumerate(T.FLASH_RECIPES,1):
        with Arm(builder.image if stock else patched_image(builder),layout=LAYOUT) as cpu:
            cpu.stub(T.WR,1)
            cpu.stub(T.RD,1,effect=lambda c:c.uc.mem_write(c.reg('r1'),b'\xa5'))
            v=measure(cpu,entry)
            v['spi_writes']=v['stub_calls'].get(f'{T.WR:#010x}',0)
            v['spi_reads']=v['stub_calls'].get(f'{T.RD:#010x}',0)
            results[f'recipe.{index}']=v
    absolute=fixture(AbsoluteTests,builder,stock)
    for enabled in (0,1):
        for path in ('accumulate','frame','retry','send'):
            with absolute.cpu(bool(enabled)) as cpu:
                cpu.uc.mem_write(T.RADIO_STATE,b'\1\1')
                cpu.uc.mem_write(HEAP+24,struct.pack('<HH',100,200))
                p=0x20016000
                cpu.uc.mem_write(p,struct.pack('<BBhh',1,0,19,-7)+bytes(8))
                if path=='accumulate':
                    entry,args=T.MOTION_NATIVE,(p,)
                elif path=='frame':
                    cpu.uc.mem_write(0x2000E8C3,b'\2')
                    entry,args=T.ABS_FRAME_NATIVE,(T.ABS_FRAME_BUFFER,0)
                elif path=='retry':
                    cpu.uc.mem_write(T.ABS_TX_BUFFER,b'\x0b\0\x0a\0'+struct.pack('<HHHH',10,20,30,40))
                    cpu.uc.mem_write(T.RADIO_STATE+0x186,b'\4')
                    entry=absolute.changed.u32(T.flash_source(T.ABS_COPY_POINTER))&~1
                    args=(T.ABS_DMA_BUFFER,T.ABS_TX_BUFFER,12)
                else:entry,args=T.RADIO_SEND,(9,p)
                results[f'abs.{path}.enabled{enabled}']=measure(cpu,entry,args)
    for outcome,entry,state in (
            ('state4_tx',T.RADIO_DECISION,4),
            ('state6_receive',T.RADIO_DECISION,6),
            ('state6_timeout',T.RADIO_SLOT_DECISION,6)):
        for counting,channels,heap in (
                (0,0,0),(0,0,1),(1,0,1),(0,1,1),(1,1,1)):
            with stats.cpu() as cpu:
                cpu.uc.mem_write(T.ADV_RAM,b'\1'+bytes(187))
                cpu.uc.mem_write(T.ADV_RAM+1,bytes((counting,)))
                if heap:
                    cpu.uc.mem_write(HEAP,bytes(T.SNAPSHOT_STORAGE_BYTES))
                    cpu.uc.mem_write(T.SNAPSHOT_POINTER,(HEAP&0xFFFFF).to_bytes(3,'little'))
                    cpu.uc.mem_write(HEAP+T.CHAN_OFFSET,bytes((channels,)))
                cpu.uc.mem_write(T.RADIO_STATE+1,b'\1\1')
                cpu.uc.mem_write(T.RADIO_STATE+0x186,bytes((state,)))
                cpu.uc.mem_write(T.RADIO_ACK_FLAG,b'\0')
                cpu.uc.mem_write(T.MOTION_STATE,bytes((
                    cpu.byte(T.MOTION_STATE)|(T.RADIO_OUTCOMES_ACTIVE_MASK if counting or channels else 0),)))
                cpu.uc.mem_write(0x2000E8BE,b'\x5a')
                cpu.uc.mem_write(0x2000EA4F,b'\1')
                cpu.put32(0x200064F8,T.RADIO_TIMER)
                cpu.uc.mem_write(T.CHAN_HOPS,bytes((11,41,62,79,97)))
                cpu.put32(T.CHAN_FREQUENCY,97)
                if outcome != 'state6_timeout':
                    cpu.put32(0x5008A21C,1)
                    cpu.put32(0x5008AE0C,1)
                    cpu.put32(0x5008AE10,0x5A)
                result=measure(cpu,entry)
                result['tx_attempts']=cpu.u32(T.ADV_RAM+A.OFF['tx_attempts'])
                result['acked']=cpu.u32(T.ADV_RAM+A.OFF['acked'])
                result['no_ack']=cpu.u32(T.ADV_RAM+A.OFF['no_ack'])
                if heap:
                    result['chan_sent']=list(struct.unpack(
                        '<6H',cpu.uc.mem_read(HEAP+T.CHAN_OFFSET+4,12)))
                    result['chan_missed']=list(struct.unpack(
                        '<6H',cpu.uc.mem_read(HEAP+T.CHAN_OFFSET+16,12)))
                results[f'radio_window.{outcome}.stats{counting}.chan{channels}.heap{heap}']=result
    if not stock:
        for busy in (0,1):
            with absolute.cpu(False) as cpu:
                cpu.uc.mem_write(T.MOTION_STATE,bytes((cpu.byte(T.MOTION_STATE)|busy<<5,)))
                result=measure(cpu,builder.symbols['settings_abs_enable'],(1,))
                result['return_value']=cpu.reg('r0')
                results[f'abs_switch.busy{busy}']=result
        motion=fixture(MotionTests,builder)
        for direct,transport in ((0,1),(1,1),(0,0),(1,0)):
            with motion.cpu() as cpu:
                cpu.uc.mem_write(T.ADV_RAM+1,b'\0')
                cpu.uc.mem_write(T.MOTION_STATE,bytes((cpu.byte(T.MOTION_STATE)|direct<<4,)))
                cpu.stub(0x20005E08,transport)
                p=0x20016000
                cpu.uc.mem_write(p,struct.pack('<BBhh',1,0,19,-7))
                results[f'motion_route.direct{direct}.transport{transport}']=measure(cpu,builder.motion['route'],(p,))
                if transport and not direct:
                    results['motion_drain.one_sample']=measure(cpu,builder.motion['drain'])
        for owned,full in ((0,0),(1,0),(0,1)):
            with motion.cpu() as cpu:
                cpu.uc.mem_write(T.MOTION_STATE,bytes((cpu.byte(T.MOTION_STATE)|owned<<5,)))
                cpu.uc.mem_write(RING+2,bytes((full*8,)))
                cpu.stub(T.REPORT_NATIVE)
                results[f'motion_report.owned{owned}.full{full}']=measure(cpu,builder.motion['report'])
        advanced=fixture(AdvancedTests,builder)
        for preset in (0,1,37):
            with advanced.cpu() as cpu:
                cpu.uc.mem_write(T.ADV_RAM+3,bytes((preset,)))
                cpu.uc.mem_write(T.ADV_RAM+9,b'\1')
                advanced.spi(cpu)
                results[f'fps_apply.preset{preset}']=measure(cpu,builder.symbols['advanced_fps_apply'])
                assert cpu.byte(T.ADV_RAM+8)==preset and cpu.byte(T.ADV_RAM+9)==0
        with advanced.cpu() as cpu:
            snap=advanced.heap(cpu)
            advanced.spi(cpu)
            cpu.run(builder.symbols['advanced_snapshot_storage'])
            cpu.uc.mem_write(snap+1,b'\1')
            results['snapshot.worker']=measure(cpu,builder.symbols['advanced_snapshot_worker'])
    return results


def receiver_hotpaths(builder,stock=False):
    results={}
    f=fixture(ReceiverTests,builder,stock)
    for writer in (R.QUEUE_RAW,R.QUEUE_PREFIX,R.QUEUE_OBJECT):
        with f.cpu() as cpu:
            p=0x2000D000;cpu.uc.mem_write(p,bytes(range(25)))
            args=(0,p,p+1,24) if writer==R.QUEUE_OBJECT else (0,p,24)
            results[f'queue.{writer:#x}']=measure(cpu,writer,args)
    for label,kind,valid,x,y in (('relative',2,0,19,65529),('abs_first',10,0,19,20),
            ('abs_delta',10,1,119,120),('abs_duplicate',10,1,100,100),
            ('abs_resync',10,1,20000,100)):
        with f.cpu() as cpu:
            cpu.stub(R.REPORT)
            cpu.uc.mem_write(R.ABS_VALID,bytes((valid,)))
            cpu.uc.mem_write(R.ABS_X,struct.pack('<H',100))
            cpu.uc.mem_write(R.ABS_Y,struct.pack('<H',100))
            p=0x2000D000
            cpu.uc.mem_write(p,bytes((kind,3))+struct.pack('<HH',x,y))
            cpu.run(R.QUEUE_PREFIX,0,p,6)
            cpu.uc.mem_write(0x200092B8,b'\1\1');cpu.uc.mem_write(0x20009007,b'\1')
            results[label]=measure(cpu,R.PARSER)
    sof=fixture(SofTests,builder,stock)
    with sof.cpu(not stock) as cpu:
        results['sof.init']=measure(cpu,0x1ABE0)
        results['sof.dppi_enable']=measure(cpu,0x2007AC8C)
    return results


def radio_lifecycles(builder,stock=False):
    """Normal off/off TX -> RX (or rejection) -> timer deadline, per window."""
    results={}
    stats=fixture(StatisticsTests,builder,stock)
    for heap in (0,1):
        for rate in (1,2):
            for outcome,fast,crc,address in (('receive',0,1,0x5A),
                    ('crc_timeout',0,0,0x5A),('address_timeout',0,1,0xA5),
                    ('fast',1,1,0x5A)):
                with stats.cpu() as cpu:
                    if heap:
                        cpu.uc.mem_write(HEAP,bytes(T.SNAPSHOT_STORAGE_BYTES))
                        cpu.uc.mem_write(T.SNAPSHOT_POINTER,(HEAP&0xFFFFF).to_bytes(3,'little'))
                    cpu.uc.mem_write(T.RADIO_STATE+1,b'\1\1')
                    cpu.uc.mem_write(T.RADIO_STATE+0x186,b'\4')
                    cpu.uc.mem_write(T.RADIO_ACK_FLAG,bytes((fast,)))
                    cpu.uc.mem_write(0x2000EA4F,bytes((rate,)))
                    cpu.uc.mem_write(0x2000E8BE,b'\x5a')
                    cpu.put32(0x200064F8,T.RADIO_TIMER)
                    cpu.put32(0x5008A21C,1)
                    steps={'tx':measure(cpu,T.RADIO_DECISION)}
                    if not fast:
                        cpu.put32(0x5008A21C,1)
                        cpu.put32(0x5008AE0C,crc)
                        cpu.put32(0x5008AE10,address)
                        steps['rx']=measure(cpu,T.RADIO_DECISION)
                    cpu.put32(T.RADIO_EVENT,1)
                    steps['deadline']=measure(cpu,T.RADIO_IRQ)
                    results[f'{outcome}.rate{rate}.heap{heap}']={
                        'instructions':sum(v['instructions'] for v in steps.values()),
                        'masked_instructions':sum(v['masked_instructions'] for v in steps.values()),
                        'longest_masked_instruction_run':max(v['longest_masked_instruction_run'] for v in steps.values()),
                        'final_primask':steps['deadline']['final_primask'],
                        'final_basepri':steps['deadline']['final_basepri'],
                        'steps':steps,
                        'tx_attempts':cpu.u32(T.ADV_RAM+A.OFF['tx_attempts']),
                        'acked':cpu.u32(T.ADV_RAM+A.OFF['acked']),
                        'no_ack':cpu.u32(T.ADV_RAM+A.OFF['no_ack'])}
    return results


def nontelemetry_stage_review(before,current):
    """Keep phase regressions separate from the aggregate window budget."""
    comparisons={}
    for key,value in current.items():
        if key.startswith('radio_window.') and '.stats0.chan0.' in key:
            previous=before[key]['instructions']
            comparisons[key]=dict(before=previous,current=value['instructions'],
                                  delta=value['instructions']-previous)
    expected={f'radio_window.{phase}.stats0.chan0.heap{heap}'
              for phase in ('state4_tx','state6_receive','state6_timeout')
              for heap in (0,1)}
    if comparisons.keys()!=expected:
        raise ValueError('MAYA nontelemetry stage measurements are incomplete')
    regressions={key:value for key,value in comparisons.items() if value['delta']>0}
    return dict(result='FAIL' if regressions else 'PASS',
                criterion='Each measured off/off radio phase must not exceed previous audited FULL',
                comparisons=comparisons,regressions=regressions,
                instruction_budget_passed=not regressions)
