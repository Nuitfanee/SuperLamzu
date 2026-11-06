"""Real Thumb checks for the target-native phase controller."""
import struct

from . import native_plock as P
from .emulation import Arm, THORN_LAYOUT
from .verify import patched_image


class Timeline:
    """Existing Arm MMIO fixture with donor-style compare/capture event time."""

    def __init__(self, cpu, timer):
        from unicorn import UC_HOOK_MEM_WRITE, UC_HOOK_MEM_READ
        self.cpu, self.timer = cpu, timer
        self.now, self.origin, self.count = 0, 0, 0
        self.running, self.fail, self.lag = True, set(), 0
        self.pending, self.tasks, self.reads, self.writes = {}, [], [], []
        self.fired = None
        cpu.add_hook(UC_HOOK_MEM_WRITE,self._write,begin=timer,end=timer+0x5FF)
        cpu.add_hook(UC_HOOK_MEM_READ,self._read,begin=timer+0x540,end=timer+0x54F)

    def _write(self, uc, access, address, size, value, user):
        off = address-self.timer
        self.writes.append((off,value))
        if off in (0,4,12,0x48,0x4C) and value:
            self.tasks.append(off)
        if off == 4 and value:
            self.running=False
        elif off == 0 and value:
            self.running=True
        elif off == 12 and value:
            self.count=0
            self.origin=self.now
            self.fired=None
        elif off in (0x48,0x4C) and value:
            channel=(off-0x40)//4
            if channel not in self.fail:
                self.pending[channel]=(self.lag,int(self.count))

    def _read(self, uc, access, address, size, value, user):
        channel=(address-self.timer-0x540)//4
        if channel in self.pending:
            lag,value=self.pending[channel]
            if lag:
                self.pending[channel]=(lag-1,value)
            else:
                self.cpu.put32(self.timer+0x540+4*channel,value)
                del self.pending[channel]

    def advance(self, now):
        if not self.running:
            paused=now-self.now
            self.origin+=paused
            if self.fired is not None:
                self.fired+=paused
            self.now=now
            return
        compare=self.cpu.u32(self.timer+0x540)
        wrap=self.cpu.u32(self.timer+0x544)
        shorts=self.cpu.u32(self.timer+0x200)
        assert shorts in (1,2), shorts
        period=compare if shorts==1 else wrap
        assert compare > 0
        if shorts==2:
            assert compare < period
        while True:
            read=self.origin+compare
            if read<=now and self.fired!=self.origin:
                self.reads.append(read)
                self.cpu.put32(self.timer+0x140,1)
                self.fired=self.origin
            if 0 < wrap <= period and self.origin+wrap<=now:
                self.cpu.put32(self.timer+0x144,1)
            if self.origin+period>now:
                break
            self.origin+=period
        self.now=now
        self.count=now-self.origin


def run_checks(builder, control, *, target=None, layout=None):
    """Execute exact emitted helpers; return observed counts, never elapsed time."""
    from unicorn.arm_const import UC_ARM_REG_PRIMASK
    target=target or builder.target
    layout=layout or THORN_LAYOUT
    image=patched_image(builder)
    heap=layout.stack-0xC000+4
    ctl=heap+P.CONTROL_OFFSET
    out=dict(apply=0,phase=0,radio=0,timeline=0,native_layouts=0)

    with Arm(image,layout=layout) as cpu:
        timer=target.REPORT_TIMER
        cpu.uc.mem_map(timer&~0xFFF,0x1000)
        radio_event=target.RADIO_EVENT
        if radio_event&~0xFFF != timer&~0xFFF:
            cpu.uc.mem_map(radio_event&~0xFFF,0x1000)
        pointer=getattr(target,'REPORT_TIMER_POINTER',None)
        if pointer is not None:
            cpu.put32(pointer,timer)
        tm=Timeline(cpu,timer)

        def setup(period=250,lead=80,enabled=1,eligible=1,running=1,storage=True):
            cpu.uc.mem_write(heap,bytes(target.SNAPSHOT_STORAGE_BYTES))
            cpu.uc.mem_write(target.SNAPSHOT_POINTER,
                ((heap&0xFFFFF) if storage else 0).to_bytes(3,'little'))
            cpu.uc.mem_write(target.ADV_RAM,bytes(target.ADV_BYTES))
            cpu.uc.mem_write(target.ADV_RAM+2,bytes((enabled,)))
            cpu.uc.mem_write(target.ADV_RAM+4,struct.pack('<H',lead))
            cpu.uc.mem_write(target.REPORT_DIVIDER,b'\1')
            cpu.uc.mem_write(target.TICKS_PER_MS,bytes((1000//period,)))
            cpu.uc.mem_write(target.RADIO_STATE+1,b'\1\1')
            cpu.uc.mem_write(target.RADIO_STATE+0x186,b'\4')
            cpu.uc.mem_write(target.SMOOTHING_STATE,b'\x80')
            cpu.put32(timer+0x200,1 if running else 0)
            cpu.put32(timer+0x540,period if running else 0)
            cpu.put32(timer+0x544,0)
            cpu.put32(timer+0x140,0)
            cpu.put32(timer+0x144,0)
            tm.count=40
            tm.running=bool(running)
            tm.tasks.clear();tm.pending.clear();tm.fail.clear();tm.writes.clear()
            return period,eligible,running

        # Native COMPARE0_CLEAR does not require a configured CC1. The split
        # layout must leave its read point distinct from the clearing compare.
        for shorts,compare,wrap,reads in (
                (1,250,0,[250,500,750,1000]),
                (1,250,250,[250,500,750,1000]),
                (2,170,250,[170,420,670,920])):
            setup()
            cpu.put32(timer+0x200,shorts)
            cpu.put32(timer+0x540,compare)
            cpu.put32(timer+0x544,wrap)
            tm.now=tm.origin=tm.count=0
            tm.fired=None
            tm.reads.clear()
            tm.advance(1000)
            assert tm.reads==reads
            assert tm.count==0 and tm.origin==1000
            assert cpu.u32(timer+0x140)==1
            assert cpu.u32(timer+0x144)==int(wrap!=0)
            out['native_layouts']+=1

        for period in (115,120,250,500,1000):
            for lead in (0,1,80,117,118,124,242,243,249,492,493,499):
                for eligible in (0,1):
                    for mask in (0,1):
                        args=setup(period,lead,eligible=eligible)
                        cpu.uc.reg_write(UC_ARM_REG_PRIMASK,mask)
                        for i in range(4,12):cpu.setreg(f'r{i}',0xD00D0000+i)
                        assert cpu.run(control['apply'],*args)==period
                        split=eligible and period in (250,500,1000) and (lead or 80)<=period//2-8
                        assert cpu.u32(timer+0x200)==(2 if split else 1)
                        assert cpu.u32(timer+0x540)==period-(lead or 80) if split else cpu.u32(timer+0x540)==period
                        assert bool(cpu.byte(ctl+7)&P.SPLIT)==bool(split)
                        assert cpu.uc.reg_read(UC_ARM_REG_PRIMASK)==mask
                        assert [cpu.reg(f'r{i}') for i in range(4,12)]==[0xD00D0000+i for i in range(4,12)]
                        before=(bytes(cpu.uc.mem_read(ctl,8)),list(tm.tasks))
                        cpu.run(control['apply'],*args)
                        assert before==(bytes(cpu.uc.mem_read(ctl,8)),tm.tasks)
                        out['apply']+=1
        for running,storage in ((0,True),(1,False)):
            args=setup(running=running,storage=storage)
            before=bytes(cpu.uc.mem_read(timer,0x600))
            cpu.run(control['apply'],*args)
            assert bytes(cpu.uc.mem_read(timer,0x600))==before
            out['apply']+=1
        setup();before=bytes(cpu.uc.mem_read(timer,0x600))
        cpu.run(control['apply'],0,1,1)
        assert before==bytes(cpu.uc.mem_read(timer,0x600))
        out['apply']+=1
        for pending in (0,1):
            args=setup();cpu.put32(timer+0x140,pending)
            cpu.run(control['apply'],*args)
            assert cpu.u32(timer+0x140)==pending
            cpu.run(control['apply'],250,0,1)
            assert cpu.u32(timer+0x200)==1 and cpu.u32(timer+0x540)==250
            assert cpu.u32(timer+0x140)==pending
            out['apply']+=1

        def ready(period=250,phase=100,flags=P.SPLIT,expected=0):
            args=setup(period);cpu.run(control['apply'],*args)
            cpu.uc.mem_write(ctl,struct.pack('<HhhBB',period,expected,0,0,flags))
            tm.count=phase;tm.tasks.clear();tm.writes.clear()
            cpu.uc.mem_write(target.ADV_RAM+6,b'\0\0')

        def phase(entry=None,bits=8|0x700):
            if entry is None:entry=tm.count
            cpu.run(control['phase'],ctl,entry,bits)
            out['phase']+=1

        for period in (250,500,1000):
            for entry in (0,1,period//2-1,period//2,period-1):
                ready(period,entry)
                phase()
                assert tm.tasks.count(12)==1
                assert cpu.byte(ctl+7)&(P.CALIBRATED|P.AWAIT_WRAP)==P.CALIBRATED|P.AWAIT_WRAP
                assert cpu.byte(ctl+6)==0
        for error in (-17,-16,-8,-7,0,7,8,16,17):
            ready(flags=P.SPLIT|P.CALIBRATED,phase=error%250)
            phase()
            assert tm.tasks.count(12)==int(8<=abs(error)<=16),(error,tm.tasks)
            assert cpu.byte(ctl+6)==(64 if abs(error)<8 else 8 if abs(error)>16 else 0)
            if abs(error)>16:
                tm.count=error%250;phase()
                assert tm.tasks.count(12)==1
        # Circular outlier agreement straddles the signed +/-R/2 boundary.
        ready(1000,501,P.SPLIT|P.CALIBRATED)
        phase();assert cpu.byte(ctl+6)==8
        tm.count=499;phase();assert tm.tasks.count(12)==1
        # No reference, wrong idle parity and missing slot do not reload.
        for tracking,post,bits,entry in ((0,8,8|0x300,30),(1,8,8|0x300,100),
                                        (1,4,8|0x600,30)):
            ready(phase=entry)
            cpu.uc.mem_write(target.SMOOTHING_STATE,bytes((tracking<<7,)))
            cpu.uc.mem_write(target.RADIO_STATE+0x186,bytes((post,)))
            phase(bits=bits)
            assert 12 not in tm.tasks and cpu.byte(ctl+6)==0
        # Pending native read is consumed by its native ISR, never by LOCK.
        ready();cpu.put32(timer+0x140,1);phase()
        assert 12 not in tm.tasks and cpu.u32(timer+0x140)==1
        # First event can predate CLEAR; only a second wrap releases the guard.
        ready(flags=P.SPLIT|P.AWAIT_WRAP|P.DISCARD_FIRST)
        phase();assert 12 not in tm.tasks
        cpu.put32(timer+0x144,1);phase();assert 12 not in tm.tasks
        assert cpu.byte(ctl+7)==P.SPLIT|P.AWAIT_WRAP
        cpu.put32(timer+0x144,1);phase();assert tm.tasks.count(12)==1
        for fail in ('entry','after','clear'):
            ready()
            if fail=='entry':phase(entry=0xFFFF)
            else:
                tm.fail.add(3 if fail=='after' else 2);phase()
            assert tm.tasks.count(12)==int(fail=='clear')
            assert not cpu.byte(ctl+7)&P.CALIBRATED
        ready(flags=P.SPLIT|P.CALIBRATED|P.PENDING_VALID)
        cpu.uc.mem_write(target.RADIO_STATE+1,b'\0');phase()
        assert cpu.byte(ctl+7)==P.SPLIT and cpu.byte(ctl+6)==0

        if 'radio' in control:
            native=[]
            def irq(c):
                native.append((c.reg('r0'),c.reg('sp')))
                c.uc.mem_write(target.RADIO_STATE+0x186,b'\4')
                return 0xABC123
            cpu.stub(target.RADIO_IRQ,effect=irq)
            for count in (0,1,8,64):
                ready(flags=P.SPLIT|P.CALIBRATED,phase=0)
                cpu.uc.mem_write(ctl+6,bytes((count,)))
                cpu.uc.mem_write(target.RADIO_STATE+0x186,b'\10')
                cpu.put32(target.RADIO_EVENT,1)
                native.clear()
                assert cpu.run(control['radio'])==0xABC123
                assert len(native)==1 and native[0][0]==0
                assert cpu.byte(ctl+6)==(count-1 if count else 64)
                out['radio']+=1
            setup(enabled=0);native.clear()
            assert cpu.run(control['radio'])==0xABC123
            assert len(native)==1
            if not control['telemetry']:assert native[0][1]==layout.stack
            out['radio']+=1

        # The reviewed 249/349 double-clear counterexample, using emitted code.
        args=setup();tm.now=249;tm.origin=0;tm.count=249;tm.reads=[0]
        cpu.run(control['apply'],*args)
        tm.advance(349);phase(entry=100)
        assert tm.tasks.count(12)==1
        tm.advance(419)
        assert tm.reads==[0,419]
        cpu.put32(timer+0x140,0)
        tm.advance(499);phase(entry=0)
        assert tm.tasks.count(12)==1
        tm.advance(749);cpu.put32(timer+0x140,0);phase(entry=0)
        assert tm.tasks.count(12)==2
        assert all(b-a<420 for a,b in zip(tm.reads[1:],tm.reads[2:]))
        out['timeline']+=1
        if 'radio' in control:
            for period in (250,500,1000):
                for ppm in (-80,0,60):
                    for tracking in (0,1):
                        setup(period)
                        cpu.run(control['apply'],period,1,1)
                        tm.now=tm.origin=0
                        tm.count=0;tm.reads=[];tm.fired=None
                        cpu.uc.mem_write(target.SMOOTHING_STATE,bytes((tracking<<7,)))
                        moving=[False]
                        def slot(c):
                            c.uc.mem_write(target.RADIO_STATE+0x186,bytes((4 if moving[0] else 8,)))
                            return 0
                        cpu.stub(target.RADIO_IRQ,effect=slot)
                        fulls=clears=0
                        from unicorn import UC_HOOK_CODE
                        entries=[]
                        handle=cpu.add_hook(UC_HOOK_CODE,
                            lambda u,a,s,x:entries.append(a),
                            begin=control['phase'],end=control['phase'])
                        for k in range(1,2001):
                            now=23+k*period/2*(1+ppm*1e-6)
                            tm.advance(now)
                            # The explicit report-ISR service boundary consumes pending0.
                            cpu.put32(timer+0x140,0)
                            moving[0]=k%2==0
                            cpu.uc.mem_write(target.RADIO_STATE+0x186,b'\10')
                            cpu.uc.mem_write(target.RADIO_QUEUE2+1,bytes((0 if moving[0] else 1,)))
                            cpu.put32(target.RADIO_EVENT,1)
                            cpu.run(control['radio'])
                        gaps=[b-a for a,b in zip(tm.reads,tm.reads[1:])]
                        assert gaps and min(gaps)>=period-80 and max(gaps)<2*period-80
                        assert len(entries)<2000//4,(period,ppm,tracking,len(entries))
                        assert cpu.byte(ctl+7)&P.CALIBRATED
                        cpu.uc.hook_del(handle);cpu._hooks.remove(handle)
                        out['timeline']+=1
    return out


def native_radio_check(builder, control, *, target=None, layout=None):
    """Run the real target IRQ/slot chain, preserving native queue side effects."""
    import itertools
    target=target or builder.target
    layout=layout or THORN_LAYOUT
    image=patched_image(builder)
    is_maya=target.REPORT_TIMER==0x500CA000
    cases=0
    if is_maya:
        # Native inactive-radio paths need no driver substitutes.
        for event in (0,0x14C,0x150,0x154,0x158):
            results=[]
            for wrapped in (False,True):
                with Arm(image,layout=layout) as cpu:
                    cpu.uc.mem_map(0x50080000,0x10000)
                    cpu.uc.mem_map(target.REPORT_TIMER,0x1000)
                    cpu.put32(0x200064F8,target.RADIO_TIMER)
                    cpu.uc.mem_write(target.ADV_RAM,b'\1'+bytes(187))
                    cpu.uc.mem_write(target.RADIO_STATE,bytes(8))
                    if event:cpu.put32(target.RADIO_TIMER+event,1)
                    for i in range(4,12):cpu.setreg(f'r{i}',0xA000+i)
                    ret=cpu.run(control['radio'] if wrapped else target.RADIO_IRQ,0)
                    results.append((ret,bytes(cpu.uc.mem_read(target.RADIO_TIMER,0x600)),
                        bytes(cpu.uc.mem_read(target.RADIO_STATE,0x190)),
                        [cpu.reg(f'r{i}') for i in range(4,12)],cpu.reg('sp')))
            assert results[0]==results[1]
            cases+=1
        return cases

    from .checks import fresh
    for connected,pre,queued in itertools.product((0,1),(4,6,8),(0,1)):
        results=[]
        for wrapped in (False,True):
            with fresh(builder) as cpu:
                tm=Timeline(cpu,target.REPORT_TIMER)
                tm.count=180
                def memcpy(c):
                    c.uc.mem_write(c.reg('r0'),bytes(c.uc.mem_read(c.reg('r1'),c.reg('r2'))))
                    return c.reg('r0')
                cpu.stub(0x0E0877E0,effect=memcpy)
                cpu.stub(0x23002134,1)
                for q in range(7):cpu.run(0x0E073F0C,q)
                cpu.uc.mem_write(target.ADV_RAM,b'\1\0\1'+bytes(185))
                cpu.uc.mem_write(target.RADIO_STATE,b'\1\1\1')
                if queued:
                    cpu.uc.mem_write(0x23025000,bytes.fromhex('0000000012345678'))
                    assert cpu.run(0x0E0879D8,9,0x23025000)==1
                cpu.uc.mem_write(target.RADIO_STATE+1,bytes((connected,)))
                cpu.uc.mem_write(target.RADIO_STATE+0x186,bytes((pre,)))
                cpu.uc.mem_write(target.REPORT_DIVIDER,b'\1')
                cpu.uc.mem_write(target.TICKS_PER_MS,b'\1')
                heap=0x23024004
                cpu.uc.mem_write(target.SNAPSHOT_POINTER,(heap&0xFFFFF).to_bytes(3,'little'))
                cpu.uc.mem_write(heap+P.CONTROL_OFFSET,struct.pack('<HhhBB',1000,0,0,0,P.SPLIT))
                cpu.put32(0x2300BF7C,10000)
                cpu.put32(target.RADIO_EVENT,1)
                cpu.put32(target.REPORT_TIMER+0x540,920)
                cpu.put32(target.REPORT_TIMER+0x544,1000)
                for i in range(4,12):cpu.setreg(f'r{i}',0xCC000000+i)
                before=len(cpu.calls)
                ret=cpu.run(control['radio'] if wrapped else target.RADIO_IRQ,0,count=200000)
                def normalize(value):
                    return value+32 if wrapped and 0x2302F000<=value<0x23030000 else value
                calls=[(fn,normalize(r0),normalize(r1)) for fn,r0,r1 in cpu.calls[before:]]
                results.append((ret,
                    bytes(cpu.uc.mem_read(0x2300C900,target.SNAPSHOT_POINTER-0x2300C900)),
                    bytes(cpu.uc.mem_read(target.ADV_RAM+188,0x2300E100-target.ADV_RAM-188)),
                    bytes(cpu.uc.mem_read(0x53000000,0x100000)),calls,
                    [cpu.reg(f'r{i}') for i in range(4,12)],cpu.reg('sp')))
                if wrapped:
                    assert tm.tasks.count(12)==int(bool(connected and pre==8 and queued))
        assert results[0]==results[1],(connected,pre,queued)
        cases+=1
    return cases


def audit(output):
    """Rebuild both SUPER targets and retain exact machine code and check scope."""
    import json
    from pathlib import Path
    from types import SimpleNamespace
    import sys
    from .patch import build
    root=Path(__file__).resolve().parents[1]
    sys.path.insert(0,str(root))
    from MAYA_X_V2.full import build_pair
    from MAYA_X_V2 import target as maya
    from MAYA_X_V2.sensor import LAYOUT
    target_maya=SimpleNamespace(**dict(vars(maya),REPORT_TIMER_POINTER=0x200062B0))
    records=[]
    for name in ('THORN','MAYA'):
        b=build('SUPER') if name=='THORN' else build_pair('SUPER')[0]
        target=b.target if name=='THORN' else target_maya
        control=b.native_plock if name=='THORN' else b.advanced['hooks']['plock']
        results=run_checks(b,control,target=target,layout=THORN_LAYOUT if name=='THORN' else LAYOUT)
        results['native_radio']=native_radio_check(b,control,target=target,
            layout=THORN_LAYOUT if name=='THORN' else LAYOUT)
        image=patched_image(b)
        emitted=[dict(a,machine_code=image.get(int(a['address'],16),a['bytes']).hex())
            for a in b.allocations if a['name'].startswith('native_plock_')]
        records.append(dict(target=name,profile='SUPER',checks=results,emitted=emitted,
            remaining_code_bytes=sum(z-a for a,z in b.pools),
            largest_contiguous_code_bytes=max(z-a for a,z in b.pools)))
    path=Path(output)
    path.mkdir(parents=True,exist_ok=True)
    (path/'plock-checks.json').write_text(json.dumps(dict(
        scope='Integrated SUPER real-Thumb controller and native IRQ checks.',
        records=records),indent=2)+'\n',encoding='utf-8')
    return records


if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser()
    parser.add_argument('--output',required=True)
    args=parser.parse_args()
    print(audit(args.output))
