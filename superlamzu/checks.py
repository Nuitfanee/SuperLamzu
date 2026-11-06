"""Real Thumb verification for FULL, shared by the builder and unit tests.

External services are stubbed explicitly. The snapshot checks also enforce the
stock MPU read-only range and execute the native heap allocation wrapper.
"""
import itertools
import struct

from . import advanced as A, protocol as P, target as T
from .verify import arm, patched_image, request


def fresh(b):
    a = arm(patched_image(b))
    a.uc.mem_map(T.ADV_STORAGE & ~4095, 4096)
    a.uc.mem_write(T.ADV_STORAGE, b'\xff' * T.ADV_STORAGE_BYTES)
    a.uc.mem_map(0x53000000, 0x100000)
    a.uc.mem_map(0x5F900000, 0x100000)
    # Generic checks have no initialized kernel heap. Storage scenarios replace
    # this backend explicitly while still executing the native malloc wrapper.
    a.stub(0x0E07FAD4, 0)
    return a


class Timer:
    """Capture appears after N register reads, or never; not a sensor model."""
    def __init__(self, a, *, target=A):
        A = target
        from unicorn import UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
        self.a, self.count, self.delay, self.pending = a, 0, 0, None
        self.captures, self.clears = 0, 0
        def write(uc, access, address, size, value, user):
            if address == A.REPORT_TIMER + 0x4C and value:
                self.captures += 1
                self.pending = self.delay
            elif address == A.REPORT_TIMER + 12 and value:
                self.clears += 1
        def read(uc, access, address, size, value, user):
            if self.pending is None:
                return
            if self.pending == 0:
                a.put32(A.REPORT_TIMER+0x54C,self.count)
                self.pending = None
            else:
                self.pending -= 1
        a.add_hook(UC_HOOK_MEM_WRITE,write,begin=A.REPORT_TIMER,end=A.REPORT_TIMER+0x100)
        a.add_hook(UC_HOOK_MEM_READ,read,begin=A.REPORT_TIMER+0x54C,end=A.REPORT_TIMER+0x54F)


def queue_boundary_check(b):
    """All seven real descriptor accessors with wrap/full/empty and max payload."""
    with fresh(b) as a:
        def memcpy(a):
            a.uc.mem_write(a.reg('r0'),bytes(a.uc.mem_read(a.reg('r1'),a.reg('r2'))))
            return a.reg('r0')
        a.stub(0x0E0877E0,effect=memcpy)
        a.uc.mem_write(0x23024000,bytes(range(12)))
        a.uc.mem_write(A.ADV_RAM-3,b'\xA5'*(188+5))
        sentry = bytes(a.uc.mem_read(A.ADV_RAM-3,188+5))
        n = 0
        for push in (0x0E073F54,0x230039B8):
            for cycle in range(16):
                a.run(0x0E073F0C,2)
                for i in range(8):
                    assert a.run(push,2,0x23024000,11)==1
                    assert 0 <= a.byte(A.Q2+2) < 8
                    n+=1
                assert a.run(push,2,0x23024000,11)==0
                # Last-entry replace and every pop implementation are real target CPU.
                assert a.run(0x23003A2C,2,0x23024000,12)==1
                assert a.run(0x23003B4C,2)==7  # target full convention = cap-1
                for pop in (0x23003A8C,0x23003AE0):
                    for i in range(4):
                        result=a.run(pop,2,0x23024100,0x23024200 if pop==0x23003AE0 else 12)
                        assert result==1
                        assert 0 <= a.byte(A.Q2+3) < 8
                        n+=1
                assert a.run(0x23003A8C,2,0x23024100,12)==0
                assert bytes(a.uc.mem_read(A.ADV_RAM-3,188+5))==sentry
        return n


def initialization_check(b):
    with fresh(b) as a:
        a.uc.mem_write(A.ADV_RAM-4,b'\xA5'*196)
        before=bytes(a.uc.mem_read(A.ADV_RAM-4,196))
        a.run(b.symbols['advanced_queue_init'],1)
        assert bytes(a.uc.mem_read(A.ADV_RAM-4,196))==before
        # Cold BSS has no heap pointer; a live pointer is preserved on restart.
        a.uc.mem_write(A.SNAP_PTR,bytes(3))
        a.run(b.symbols['advanced_queue_init'],0)
        assert bytes(a.uc.mem_read(A.ADV_RAM,188))==b'\x01'+bytes(187)
        assert bytes(a.uc.mem_read(A.ADV_RAM-4,4))==b'\xA5'+bytes(3)
        assert bytes(a.uc.mem_read(A.ADV_RAM+188,4))==b'\0'+b'\xA5'*3
        # Other queue initializers must not reset runtime configuration.
        a.uc.mem_write(A.ADV_RAM+2,b'\x01\x0a')
        for q in range(1,7):a.run(b.symbols['advanced_queue_init'],q)
        assert bytes(a.uc.mem_read(A.ADV_RAM+2,2))==b'\x01\x0a'
        return 8


def native_send_check(b):
    """Run the real op9 dispatcher and queue, not a guessed bool-result stub."""
    with fresh(b) as a:
        def memcpy(a):
            a.uc.mem_write(a.reg('r0'),bytes(a.uc.mem_read(a.reg('r1'),a.reg('r2'))))
            return a.reg('r0')
        a.stub(0x0E0877E0,effect=memcpy)
        a.run(b.symbols['advanced_queue_init'],0)
        a.run(0x0E073F0C,2)
        a.uc.mem_write(A.ADV_RAM+1,b'\x01')
        packet=0x23025000
        a.uc.mem_write(packet,bytes.fromhex('00 00 00 00 12 34 56 78'))
        before=bytes(a.uc.mem_read(A.ADV_RAM,188))
        a.uc.mem_write(A.RSTATE,b'\x00\x00')
        assert a.run(0x0E0879D8,9,packet)==3
        a.uc.mem_write(A.RSTATE,b'\x01\x00')
        assert a.run(0x0E0879D8,9,packet)==7
        assert bytes(a.uc.mem_read(A.ADV_RAM,188))==before
        a.uc.mem_write(A.RSTATE,b'\x01\x01')
        for i in range(8):
            assert a.run(0x0E0879D8,9,packet)==1
            assert bytes(a.uc.mem_read(A.Q2+10+i*12,4))==bytes.fromhex('12 34 56 78')
        assert a.run(0x0E0879D8,9,packet)==6
        enabled=b.advanced.get('telemetry',True)
        assert a.u32(A.ADV_RAM+A.OFF['tx_queued'])==(8 if enabled else 0)
        assert a.u32(A.ADV_RAM+A.OFF['tx_full'])==int(enabled)
        expected=bytes(12*4)+struct.pack('<II',8,1)+bytes(29*4) if enabled else bytes(172)
        assert bytes(a.uc.mem_read(A.ADV_RAM+16,172))==expected
        return 11


def protocol_check(b):
    from unicorn.arm_const import UC_ARM_REG_PRIMASK
    with fresh(b) as a:
        a.run(b.symbols['advanced_queue_init'],0)
        posted=[];a.stub(0x0E07E568,effect=lambda a: posted.append(a.reg('r0')))
        a.uc.mem_write(A.MODE,b'\x06')
        assert request(a,P.GET,(0,P.FPS))==(0xA0,bytes([0,2,0,0,0,len(A.PRESETS)]))
        assert request(a,P.GET,(0,P.LOCK))==(0xA0,bytes([0,3,0,0,0,80,0]))
        n=0
        for preset in range(len(A.PRESETS)):
            reply=request(a,P.SET,(0,2,preset))
            assert reply==(0xA0,bytes([0,2,preset,0,1,len(A.PRESETS)])),reply
            assert posted[-1]==6;n+=1
        for enabled,lead in itertools.product((0,1),(0,1,80,124,249,499)):
            body=bytes([0,3,enabled])+struct.pack('<H',lead)
            assert request(a,P.SET,body)==(0xA0,body+struct.pack('<H',lead or 80))
            assert a.byte(A.ADV_RAM+2)==enabled;n+=1
        # Preserve configuration and recovery bytes exactly on counter-only reset.
        diagnostic=b.advanced.get('telemetry',True)
        for primask in (0,1):
            a.uc.reg_write(UC_ARM_REG_PRIMASK,primask)
            a.uc.mem_write(A.ADV_RAM+16,b'\xAB'*172)
            header=bytes(a.uc.mem_read(A.ADV_RAM,16))
            reply=request(a,P.SET,(0,4,2))
            assert reply==(0xA0,b'\x00\x04\x00') if diagnostic else reply[0]==0xA2
            assert bytes(a.uc.mem_read(A.ADV_RAM,16))==header
            assert bytes(a.uc.mem_read(A.ADV_RAM+16,168))==(bytes(168) if diagnostic else b'\xAB'*168)
            assert bytes(a.uc.mem_read(A.ADV_RAM+184,4))==b'\xAB'*4
            assert a.uc.reg_read(UC_ARM_REG_PRIMASK)==primask;n+=1
        for action in (1,0):
            reply=request(a,P.SET,(0,4,action))
            assert reply==(0xA0,bytes([0,4,action])) if diagnostic else reply[0]==0xA2
            n+=1
        a.uc.mem_write(A.ADV_RAM,bytes(range(188)))
        for page in range(6):
            before=bytes(a.uc.mem_read(A.ADV_RAM,188))
            reply=request(a,P.GET,(0,4,page))
            assert reply==(0xA0,bytes([0,4,page])+before[page*32:min(page*32+32,188)]) if diagnostic else reply[0]==0xA2
            assert bytes(a.uc.mem_read(A.ADV_RAM,188))==before;n+=1
            assert a.uc.reg_read(UC_ARM_REG_PRIMASK)==primask
        bad=[(P.GET,(1,2),None),(P.GET,(0,2,0),None),(P.GET,(0,3,0),None),
             (P.GET,(0,4,6),None),(P.GET,(0,4),None),(P.SET,(0,2,len(A.PRESETS)),None),
             (P.SET,(0,3,2,0,0),None),(P.SET,(0,3,1,244,1),None),
             (P.SET,(0,4,3),None),(P.SET,(0,2,1),2),(P.SET,(1,4,2),None)]
        for cmd,body,length in bad:
            before=bytes(a.uc.mem_read(A.ADV_RAM,188));prev=len(posted)
            assert request(a,cmd,body,length)[0]==0xA2
            assert before==bytes(a.uc.mem_read(A.ADV_RAM,188))
            assert len(posted)==prev;n+=1
        # Handler ABI independent of the outer dispatcher, for both success/failure.
        for symbol,op,payload in [('advanced_get',2,(0,2)),('advanced_get',9,(0,9)),
                                  ('advanced_set',3,(0,3,0,80,0))]:
            packet=bytearray(64);packet[3]=len(payload);packet[6:6+len(payload)]=bytes(payload)
            a.uc.mem_write(T.PACKET,bytes(packet))
            values={f'r{i}':0x12210000+i for i in range(4,12)}
            values.update(r4=T.PACKET,r5=op,r6=0)
            for reg,val in values.items():a.setreg(reg,val)
            a.run(b.symbols[symbol]);assert a.reg('sp')==0x23030000
            assert all(a.reg(reg)==v for reg,v in values.items());n+=1
            assert a.uc.reg_read(UC_ARM_REG_PRIMASK)==primask
        return n


def fps_check(b):
    from .emulation import sensor_run as run
    image=patched_image(b);cases=0
    for mode,variant,preset in itertools.product((2,3,4,6,7),(1,2,3),range(len(A.PRESETS))):
        with fresh(b) as a:
            a.uc.mem_write(A.ADV_RAM+3,bytes([preset]))
            page=[0];writes=[];regs={};reads=[]
            def wr(a):
                reg,val=a.reg('r0')&255,a.reg('r1')&255
                if reg==127:page[0]=val
                else:regs[page[0],reg]=val
                writes.append((page[0],reg,val))
                for reg in ('r1','r2','r3','r12'):a.setreg(reg,0xDEADBEEF)
                return 1
            def rd(a):
                key=(page[0],a.reg('r0')&255);reads.append(key)
                a.uc.mem_write(a.reg('r1'),bytes((regs.get(key,0xA5),)));return 1
            a.stub(T.WR,effect=wr);a.stub(T.RD,effect=rd)
            # Native mode4 inline recipe waits on a hardware cycle counter.
            # Stub only that peripheral boundary, as the recipe comparison does.
            a.stub(0x0E086F46)
            a.run(b.symbols['advanced_recipe_dispatch'],mode,variant,count=100000)
            original=run(image,A.DISPATCH,T.WR,T.RD,args=(mode,variant),mapped=True)
            ref=[(e['page'],e['reg'],e['value']) for e in original if e['op']=='write']
            extra=[]
            if preset:
                _,k,slow,fast=A.PRESETS[preset]
                extra=[(6,127,6),(6,0x53,slow),(6,0x62,fast),(7,127,7),(7,0x42,k),(0,127,0)]
            assert writes==ref+extra,(mode,variant,preset,writes[-7:],ref[-7:])
            if preset:
                assert reads[-3:]==[(6,0x53),(6,0x62),(7,0x42)]
            assert a.byte(A.ADV_RAM+8)==preset
            assert a.byte(A.ADV_RAM+9)==0
            # Exact companion values/stock discrepancy remain in complete prefix.
            cases+=1
    # Failed SPI never claims preset applied and still restores page zero.
    with fresh(b) as a:
        a.uc.mem_write(A.ADV_RAM+3,b'\x01')
        calls=[];a.stub(T.WR,effect=lambda a:calls.append((a.reg('r0'),a.reg('r1'))) or 0)
        a.run(b.symbols['advanced_fps_apply'])
        assert a.byte(A.ADV_RAM+8)==0 and a.byte(A.ADV_RAM+9)==1
        assert a.u32(A.ADV_RAM+A.OFF['fps_fail'])==int(b.advanced.get('telemetry',True)) and calls[-1]==(127,0)
    # A new SET arriving during an old SPI sequence stays pending; the old
    # snapshot is reported applied, not falsely reported as the newer request.
    with fresh(b) as a:
        a.uc.mem_write(A.ADV_RAM+3,b'\x01');a.uc.mem_write(A.ADV_RAM+9,b'\x01')
        def interrupt_request(a):
            a.uc.mem_write(A.ADV_RAM+3,b'\x02');return 1
        a.stub(T.WR,effect=interrupt_request)
        a.stub(T.RD,effect=lambda a:a.uc.mem_write(a.reg('r1'),bytes((20 if a.reg('r0')==0x42 else 2,))) or 1)
        a.run(b.symbols['advanced_fps_apply'])
        assert a.byte(A.ADV_RAM+3)==2 and a.byte(A.ADV_RAM+8)==1 and a.byte(A.ADV_RAM+9)==1
        return cases+2


def fps_publish_interleaves(b, *, target=T, factory=fresh):
    """A newer HID SET cannot land between comparison and pending clear.

    Execute the real SET at both sides of the publication critical section,
    using the existing second-stack preemption fixture. Masked stores
    must stay in the same critical section; SPI remains outside it.
    """
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
    from unicorn import UC_HOOK_CODE
    from unicorn.arm_const import UC_ARM_REG_PRIMASK
    image = patched_image(b)
    entry = b.symbols['advanced_fps_apply']
    allocation = next(v for v in b.allocations if v['name']=='advanced_fps_apply')
    instructions = list(Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_MCLASS).disasm(
        image.get(entry,allocation['bytes']),entry))
    publish = next(v.address for v in instructions
                   if v.mnemonic=='strb' and v.op_str=='r5, [r4, #8]')
    restore = next(v.address for v in instructions if v.address>publish and v.mnemonic=='msr')
    boundaries = [v.address for v in instructions if publish<=v.address<=restore]
    cases = 0
    for preset in (0,1,37):
        for mask in (0,1):
            with factory(b) as a:
                a.uc.mem_write(target.ADV_RAM+3,bytes((preset,)))
                a.uc.mem_write(target.ADV_RAM+9,b'\1')
                a.uc.reg_write(UC_ARM_REG_PRIMASK,mask)
                def spi(cpu):
                    assert cpu.uc.reg_read(UC_ARM_REG_PRIMASK)==mask
                    return 1
                a.stub(target.WR,effect=spi)
                a.stub(target.RD,effect=lambda a:a.uc.mem_write(a.reg('r1'),
                    bytes((A.PRESETS[preset][{0x42:1,0x53:2,0x62:3}[a.reg('r0')]],))) or 1)
                seen=[]
                def check(uc,address,size,user):
                    if address in boundaries:
                        seen.append(address)
                        assert uc.reg_read(UC_ARM_REG_PRIMASK)==1,(hex(address),preset)
                a.add_hook(UC_HOOK_CODE,check)
                a.run(entry)
                assert seen and a.byte(target.ADV_RAM+9)==0
                assert a.uc.reg_read(UC_ARM_REG_PRIMASK)==mask
                cases+=1
        # SET immediately before the atomic publication must remain pending;
        # a SET immediately afterwards publishes its own pending flag too.
        for at in (publish-6,restore+4):
            with factory(b) as a:
                a.uc.mem_write(target.ADV_RAM+3,bytes((preset,)))
                a.uc.mem_write(target.ADV_RAM+9,b'\1')
                a.stub(target.WR,1);a.stub(target.SET_SENSOR_MODE)
                a.stub(target.RD,effect=lambda a:a.uc.mem_write(a.reg('r1'),
                    bytes((A.PRESETS[preset][{0x42:1,0x53:2,0x62:3}[a.reg('r0')]],))) or 1)
                packet=bytearray(64)
                packet[0]=0xA0;packet[3:6]=bytes((3,1,P.SET))
                packet[6:9]=bytes((0,P.FPS,2))
                a.uc.mem_write(target.PACKET,bytes(packet))
                assert a.preempt((entry,()),(target.GROUP1,()),at)
                assert a.byte(target.ADV_RAM+3)==2
                assert a.byte(target.ADV_RAM+8)==preset
                assert a.byte(target.ADV_RAM+9)==1
                assert a.uc.reg_read(UC_ARM_REG_PRIMASK)==0
                cases+=1
    return cases


def fps_readback_failure_check(b, *, target=T, factory=fresh):
    """A queued preset is applied only after all three SPI readbacks match."""
    from unicorn import UC_HOOK_CODE
    from unicorn.arm_const import UC_ARM_REG_PRIMASK
    cases = 0
    for mask, failure in itertools.product((0, 1), (*range(1, 10), 'slow', 'fast', 'unit')):
        with factory(b) as a:
            a.uc.reg_write(UC_ARM_REG_PRIMASK, mask)
            a.uc.mem_write(target.ADV_RAM + 8, b'\2')
            a.stub(target.SET_SENSOR_MODE)
            state = dict(page=0, registers={}, calls=0, active=False, failure=failure)
            def entered(uc, address, size, user):
                if address == b.symbols['advanced_fps_apply']:
                    state['active'] = True
            a.add_hook(UC_HOOK_CODE, entered)
            def transaction():
                if not state['active']:
                    return True
                state['calls'] += 1
                return state['calls'] != state['failure']
            def wr(a):
                reg, value = a.reg('r0') & 255, a.reg('r1') & 255
                if not transaction():
                    return 0
                if reg == 127:
                    state['page'] = value
                else:
                    state['registers'][state['page'], reg] = value
                return 1
            def rd(a):
                reg = a.reg('r0') & 255
                if not transaction():
                    return 0
                value = state['registers'].get((state['page'], reg), 0xA5)
                if state['active'] and state['failure'] == {0x53:'slow', 0x62:'fast', 0x42:'unit'}.get(reg):
                    value ^= 1
                a.uc.mem_write(a.reg('r1'), bytes((value,)))
                return 1
            for address in {target.WR, getattr(target, 'NATIVE_WR', target.WR)}:
                a.stub(address, effect=wr)
            for address in {target.RD, getattr(target, 'NATIVE_RD', target.RD)}:
                a.stub(address, effect=rd)
            for delay in a.layout.delays:
                a.stub(delay)
            assert request(a, P.SET, (0, P.FPS, 1), target=target)[0] == 0xA0
            assert state['calls'] == 0
            a.run(b.symbols['advanced_recipe_dispatch'], 6, 2, count=100000)
            assert a.byte(target.ADV_RAM + 8) == 2
            assert a.byte(target.ADV_RAM + 9) == 1
            assert state['page'] == 0
            assert a.uc.reg_read(UC_ARM_REG_PRIMASK) == mask
            # The same legal request can recover through the existing worker.
            state.update(calls=0, active=False, failure=None)
            assert request(a, P.SET, (0, P.FPS, 1), target=target)[0] == 0xA0
            a.run(b.symbols['advanced_recipe_dispatch'], 6, 2, count=100000)
            assert a.byte(target.ADV_RAM + 8) == 1
            assert a.byte(target.ADV_RAM + 9) == 0
            assert state['calls'] == 9 and state['page'] == 0
            assert a.uc.reg_read(UC_ARM_REG_PRIMASK) == mask
            cases += 1
    return cases


def custom_fps_check(b):
    from unicorn.arm_const import UC_ARM_REG_PRIMASK
    cases = 0
    # Every encoding of each byte, plus all boundaries and representative dynamics.
    recipes = {(u, 2, 2) for u in range(1, 256)}
    recipes |= {(47, m, m) for m in range(1, 256)}
    recipes |= {(25, 255, m) for m in range(1, 256)}
    recipes |= {(47, 1, 1), (1, 1, 1), (255, 255, 255)}
    for u, slow, fast in sorted(recipes):
        with fresh(b) as a:
            a.run(b.symbols['advanced_queue_init'], 0)
            posted = []; a.stub(0x0E07E568, effect=lambda a: posted.append(a.reg('r0')))
            page = [0]; regs = {}; writes = []; reads = []
            def wr(a):
                reg, val = a.reg('r0') & 255, a.reg('r1') & 255
                if reg == 127: page[0] = val
                else: regs[page[0], reg] = val
                writes.append((page[0], reg, val))
                return 1
            def rd(a):
                key = (page[0], a.reg('r0') & 255); reads.append(key)
                a.uc.mem_write(a.reg('r1'), bytes([regs.get(key, 0)])); return 1
            a.stub(T.WR, effect=wr); a.stub(T.RD, effect=rd)
            body = (0, P.FPS_CUSTOM, u, slow, fast)
            reply = request(a, P.SET, body)
            assert reply == (0xA0, bytes((0, 5, 255, 0, 1, u, slow, fast, 0, 0, 0, 0))), reply
            assert posted and not writes and not reads  # HID handler never touches SPI.
            a.run(b.symbols['advanced_fps_apply'])
            assert reads == [(6, 0x53), (6, 0x62), (7, 0x42)]
            assert regs == {(6, 0x53): slow, (6, 0x62): fast, (7, 0x42): u}
            assert page[0] == 0
            assert request(a, P.GET, (0, 5)) == (0xA0, bytes((0, 5, 255, 255, 0, u, slow, fast, u, slow, fast, 1)))
            header = bytes(a.uc.mem_read(A.ADV_RAM, 16))
            request(a, P.SET, (0, 4, 2))
            assert bytes(a.uc.mem_read(A.ADV_RAM, 16)) == header
            assert bytes(a.uc.mem_read(A.ADV_RAM + 184, 4)) == bytes((u, slow, fast, 1))
            cases += 1
            if (u, slow, fast) == max(recipes):
                # Rejections must preserve an already applied/read-back recipe,
                # not just a fresh pending request. Keep its CPU alive here.
                for body in ((0, 5), (0, 5, 1), (0, 5, 1, 1, 0), (0, 5, 0, 1, 1),
                             (0, 5, 1, 0, 1), (0, 5, 1, 1, 2), (1, 5, 1, 1, 1), (0, 5, 1, 1, 1, 0)):
                    before = bytes(a.uc.mem_read(A.ADV_RAM, 188)); n = len(posted)
                    assert request(a, P.SET, body)[0] == 0xA2
                    assert bytes(a.uc.mem_read(A.ADV_RAM, 188)) == before and len(posted) == n
                    cases += 1
    # SPI write fail, read fail, mismatched register, and concurrent custom SET.
    for failure in ('write', 'read', 'mismatch', 'concurrent'):
        with fresh(b) as a:
            a.run(b.symbols['advanced_queue_init'], 0)
            a.uc.mem_write(A.ADV_RAM + 3, b'\xff'); a.uc.mem_write(A.ADV_RAM + 13, bytes((47, 1, 1)))
            page = [0]; regs = {}; changed = [False]
            def wr(a):
                reg, val = a.reg('r0') & 255, a.reg('r1') & 255
                if reg == 127: page[0] = val
                else: regs[page[0], reg] = val
                if failure == 'concurrent' and not changed[0]:
                    a.uc.mem_write(A.ADV_RAM + 13, bytes((48, 3, 2))); changed[0] = True
                return int(failure != 'write')
            def rd(a):
                key = (page[0], a.reg('r0') & 255)
                a.uc.mem_write(a.reg('r1'), bytes([0 if failure == 'mismatch' else regs.get(key, 0)]))
                return int(failure != 'read')
            a.stub(T.WR, effect=wr); a.stub(T.RD, effect=rd)
            a.uc.reg_write(UC_ARM_REG_PRIMASK, 1)
            a.run(b.symbols['advanced_fps_apply'])
            assert a.uc.reg_read(UC_ARM_REG_PRIMASK) == 1 and page[0] == 0
            assert a.byte(A.ADV_RAM + 9) == 1
            if failure == 'concurrent':
                assert bytes(a.uc.mem_read(A.ADV_RAM + 184, 4)) == bytes((47, 1, 1, 1))
                assert regs == {(6, 0x53): 1, (6, 0x62): 1, (7, 0x42): 47}
            else:
                assert a.byte(A.ADV_RAM + 187) == 0 and a.byte(A.ADV_RAM + 8) == 0
                assert a.u32(A.ADV_RAM + A.OFF['fps_fail']) == int(b.advanced.get('telemetry',True))
            cases += 1
    return cases


def sensor_snapshot_check(b):
    from unicorn import UC_HOOK_MEM_WRITE
    from unicorn.arm_const import UC_ARM_REG_PRIMASK
    cases = 0
    snap = 0x23024004
    def heap_fixture(a):
        # Execute the real target allocation wrapper; stub only the heap backend.
        a.stub(0x0E07FAD4, snap-4)
        a.uc.mem_write(snap-5, b'\xA5'*(T.SNAPSHOT_STORAGE_BYTES+6))
        a.uc.mem_write(A.SNAP_PTR-1, b'\xA5'+bytes(3))
        def no_code_writes(uc, access, address, size, value, user):
            raise AssertionError(f'write to native MPU read-only code at {address:#x}')
        a.add_hook(UC_HOOK_MEM_WRITE, no_code_writes, begin=0x23000C60, end=0x2300583F)
    values = (37, 1, 1, 0xA8, 0x90, 0x40, 0, 0x80)
    for failure in range(14):  # success, or each of the 13 SPI transactions
        with fresh(b) as a:
            heap_fixture(a)
            a.run(b.symbols['advanced_queue_init'], 0)
            assert bytes(a.uc.mem_read(A.SNAP_PTR, 3)) == bytes(3)
            assert bytes(a.uc.mem_read(snap, 24)) == b'\xA5'*24
            assert a.byte(A.SNAP_PTR-1) == 0xA5
            a.uc.mem_write(A.SENSOR_READY, b'\x01')
            a.uc.mem_write(A.MODE, b'\x04')
            a.uc.mem_write(A.VARIANT, b'\x03')
            a.uc.mem_write(T.SENSOR_CPI_X, struct.pack('<H', 2300))
            a.uc.mem_write(T.SENSOR_CPI_Y, struct.pack('<H', 2400))
            a.uc.mem_write(A.ADV_RAM+184, b'\x1F\x03\x03\x01')
            original = bytes(a.uc.mem_read(A.ADV_RAM, 188))
            messages = []
            a.stub(0x0E086F68, effect=lambda a: messages.append(
                (a.reg('r0'), bytes(a.uc.mem_read(a.reg('r1'), 12)), a.reg('r2'), a.reg('r3'))) or 0)
            writes, reads = [], []
            page, transactions = [0], [0]
            def wr(a):
                transactions[0] += 1
                reg, val = a.reg('r0'), a.reg('r1')
                writes.append((reg, val, a.reg('sp') & 7))
                assert reg == 127  # Never a timing/control/CPI data write.
                if transactions[0] == failure:
                    return 0
                page[0] = val
                for reg in ('r1', 'r2', 'r3', 'r12'):
                    a.setreg(reg, 0xDEADBEEF)
                return 1
            def rd(a):
                transactions[0] += 1
                key = (page[0], a.reg('r0'))
                reads.append(key)
                assert a.reg('sp') & 7 == 0
                if transactions[0] == failure:
                    return 0
                a.uc.mem_write(a.reg('r1'), bytes([values[P.SENSOR_REGISTERS.index(key)]]))
                for reg in ('r1', 'r2', 'r3', 'r12'):
                    a.setreg(reg, 0xDEADBEEF)
                return 1
            a.stub(T.WR, effect=wr); a.stub(T.RD, effect=rd)
            empty = request(a, P.GET, (0, P.SENSOR_SNAPSHOT))
            assert empty == (0xA0, bytes((0, 6, 1))+bytes(23))
            a.uc.reg_write(UC_ARM_REG_PRIMASK, failure % 2)
            assert request(a, P.SET, (0, 6, 0x34, 0x12))[0] == 0xA0
            assert not writes and not reads  # HID handler must never touch SPI.
            assert messages == [(A.SENSOR_QUEUE, struct.pack('<III', 11, 0, 0), 0, 0)]
            assert a.byte(snap+1) == 1
            assert bytes(a.uc.mem_read(A.SNAP_PTR, 3)) == struct.pack('<I', snap)[:3]
            assert request(a, P.SET, (0, 6, 0x34, 0x12))[0] == 0xA0
            assert len(messages) == 1  # Identical retry does not enqueue twice.
            for body in ((0, 6), (0, 6, 1), (0, 6, 0, 0), (1, 6, 1, 0),
                         (0, 6, 1, 0, 0), (0, 6, 0x35, 0x12)):
                before = bytes(a.uc.mem_read(snap, 24))
                assert request(a, P.SET, body)[0] == 0xA2
                assert bytes(a.uc.mem_read(snap, 24)) == before
                cases += 1
            registers = {f'r{i}': 0xAABB0000+i for i in range(4, 12)}
            for reg, value in registers.items():
                a.setreg(reg, value)
            a.run(b.symbols['advanced_snapshot_worker'])
            assert all(a.reg(reg) == value for reg, value in registers.items())
            assert a.reg('sp') == 0x23030000
            assert a.uc.reg_read(UC_ARM_REG_PRIMASK) == failure % 2
            assert bytes(a.uc.mem_read(A.ADV_RAM, 188)) == original
            raw = request(a, P.GET, (0, 6))[1][2:]
            assert raw[0] == 1 and raw[1] == (3 if failure else 2)
            assert raw[4:8] == bytes.fromhex('34123412')
            assert raw[8:12] == bytes((4, 3, 0, 0))
            assert raw[12:20] == (bytes(8) if failure else bytes(values))
            assert raw[20:24] == struct.pack('<HH', 2300, 2400)
            assert page[0] == 0 and writes[-1][:2] == (127, 0)
            assert bool(raw[2]) == bool(failure)
            if not failure:
                assert reads == list(P.SENSOR_REGISTERS)
            saved = bytes(a.uc.mem_read(snap, 24))
            request(a, P.SET, (0, 4, 2))
            assert bytes(a.uc.mem_read(snap, 24)) == saved
            assert len([c for c in a.calls if c[0] == 0x0E07FAD4]) == 1
            assert bytes(a.uc.mem_read(snap+24, 4)) == bytes(4)
            assert a.byte(snap-5) == a.byte(snap+T.SNAPSHOT_STORAGE_BYTES) == 0xA5
            cases += 1
    # Not-ready rejection, queue-full error, and no work on an empty mailbox.
    with fresh(b) as a:
        heap_fixture(a); a.run(b.symbols['advanced_queue_init'], 0)
        a.stub(T.WR, effect=lambda a: (_ for _ in ()).throw(AssertionError('unexpected SPI')))
        a.run(b.symbols['advanced_snapshot_worker'])
        assert request(a, P.SET, (0, 6, 1, 0))[0] == 0xA2
        a.uc.mem_write(A.SENSOR_READY, b'\x01')
        a.stub(0x0E086F68, 1)
        assert request(a, P.SET, (0, 6, 1, 0))[0] == 0xA0
        assert bytes(a.uc.mem_read(snap+1, 2)) == b'\x03\xFF'
    # Heap exhaustion leaves both the pointer and the sensor untouched.
    with fresh(b) as a:
        heap_fixture(a); a.run(b.symbols['advanced_queue_init'], 0)
        a.uc.mem_write(A.SENSOR_READY, b'\x01')
        a.stub(0x0E07FAD4, 0)
        assert request(a, P.SET, (0, 6, 1, 0))[0] == 0xA2
        assert bytes(a.uc.mem_read(A.SNAP_PTR, 3)) == bytes(3)
        assert request(a, P.GET, (0, 6)) == (0xA0, bytes((0, 6, 1))+bytes(23))
    # Execute the native thread from its actual prologue, through queue receive,
    # semaphore acquisition and native busy guard, to the new message branch.
    with fresh(b) as a:
        a.run(b.symbols['advanced_queue_init'], 0)
        a.uc.mem_write(A.SNAP_PTR, struct.pack('<I', snap)[:3])
        a.uc.mem_write(snap+1, b'\x01')
        a.uc.mem_write(snap+4, b'\x01\x00')
        semaphores = []
        def receive(a):
            a.uc.mem_write(a.reg('r1'), struct.pack('<III', 11, 0, 0))
            return 0
        a.stub(0x0E07CBE4, effect=receive)
        a.stub(0x0E086F6C, effect=lambda a: semaphores.append((a.reg('r0'), a.reg('r1'))) or 0)
        a.stub(T.WR, 1)
        a.stub(T.RD, effect=lambda a: a.uc.mem_write(a.reg('r1'), b'\x33') or 1)
        a.ends.add(0x0E07EC16)
        a.run(0x0E07EAD0, count=100000)
        assert a.byte(snap+1) == 2 and semaphores[0][1] == 1
        return cases+4


def sensor_snapshot_cpi_check(b):
    """Preserve X/Y from native CPI publication and worker through snapshot GET."""
    cases = 0
    for x, y in ((2300, 12000), (12000, 2300), (1, 40000), (40000, 1)):
        with fresh(b) as a:
            a.run(b.symbols['advanced_queue_init'], 0)
            a.uc.mem_write(T.SENSOR_READY, b'\1')
            a.uc.mem_write(T.SENSOR_MODE, b'\6')
            a.uc.mem_write(T.SENSOR_VARIANT, b'\0')
            posted = []
            a.stub(0x0E086F68, effect=lambda a: posted.append(
                bytes(a.uc.mem_read(a.reg('r1'), 12))) or 0)
            a.run(T.SENSOR_CPI_POST, x, y, 1)
            assert posted == [struct.pack('<III', 2, x, y)]
            message = posted[0]
            a.stub(0x0E07CBE4, effect=lambda a:a.uc.mem_write(a.reg('r1'), message) or 0)
            a.stub(0x0E086F6C)
            a.stub(0x0E086F46)
            page, registers, writes = [0], {}, []
            def wr(a):
                reg, value = a.reg('r0') & 255, a.reg('r1') & 255
                writes.append((page[0], reg, value))
                if reg == 127:
                    page[0] = value
                else:
                    registers[page[0], reg] = value
                return 1
            def rd(a):
                value = registers.get((page[0], a.reg('r0') & 255), 0xA5)
                a.uc.mem_write(a.reg('r1'), bytes((value,)))
                return 1
            a.stub(T.WR, effect=wr); a.stub(T.RD, effect=rd)
            a.ends.add(0x0E07EC16)
            a.run(0x0E07EAD0, count=100000)
            assert int.from_bytes(a.uc.mem_read(T.SENSOR_CPI_X, 2), 'little') == x
            assert int.from_bytes(a.uc.mem_read(T.SENSOR_CPI_Y, 2), 'little') == y
            assert writes[:5] == [(0, 0x48, (x-1)&255), (0, 0x49, (x-1)>>8),
                                  (0, 0x4A, (y-1)&255), (0, 0x4B, (y-1)>>8), (0, 0x47, 1)]
            assert a.byte(T.SENSOR_VARIANT) == (1 if x <= 4000 else 2 if x <= 10000 else 3)
            a.stub(0x0E07FAD4, 0x23024000)
            assert request(a, P.SET, (0, P.SENSOR_SNAPSHOT, 1, 0))[0] == 0xA0
            a.run(b.symbols['advanced_snapshot_worker'])
            status, raw = request(a, P.GET, (0, P.SENSOR_SNAPSHOT))
            assert status == 0xA0 and raw[3] == 2
            assert raw[22:26] == struct.pack('<HH', x, y)
            cases += 1
    return cases


def worker_check(b):
    """Native mode/DPI branches reach the shared hook; reinit reposts mode."""
    cases=0
    for mode,variant,branch in itertools.product((2,3,4,6,7),(1,2,3),('mode','dpi')):
        with fresh(b) as a:
            writes=[];page=[0];registers={}
            a.uc.mem_write(A.ADV_RAM+3,b'\x12')
            a.uc.mem_write(A.MODE,bytes([mode]))
            a.uc.mem_write(A.VARIANT,bytes([0 if branch=='dpi' else variant]))
            a.uc.mem_write(0x2300CAF6,struct.pack('<HH',800,800))
            a.put32(0x23030008,mode if branch=='mode' else 800)
            a.put32(0x2303000C,variant if branch=='mode' else 800)
            def wr(a):
                reg,value=a.reg('r0')&255,a.reg('r1')&255
                writes.append((reg,value))
                if reg==127:page[0]=value
                else:registers[page[0],reg]=value
                return 1
            def rd(a):
                a.uc.mem_write(a.reg('r1'),bytes((registers.get((page[0],a.reg('r0')&255),0xA5),)))
                return 1
            a.stub(T.WR,effect=wr);a.stub(T.RD,effect=rd)
            a.stub(0x0E086F46)
            a.stub(0x0E085080,variant)
            a.ends.add(0x0E07EC16)
            a.run(0x0E07EC26 if branch=='mode' else 0x0E07EB58,count=100000)
            assert a.byte(A.ADV_RAM+8)==18 and a.byte(A.ADV_RAM+9)==0
            assert a.byte(A.MODE)==mode and a.byte(A.VARIANT)==variant
            assert a.u32(A.ADV_RAM+A.OFF['fps_apply'])==int(b.advanced.get('telemetry',True))
            # Native CPI and LOD restoration follows the advanced recipe hook.
            cpi=[(0x48,31),(0x49,3),(0x4A,31),(0x4B,3),(0x47,1)]
            assert any(writes[i:i+5]==cpi for i in range(len(writes)-4)),(mode,variant,branch,writes[-12:])
            cases+=1
    for ok in (0,1):
        with fresh(b) as a:
            a.uc.mem_write(A.ADV_RAM,b'\x01\x01\x00\x12'+bytes(184))
            a.uc.mem_write(A.MODE,b'\x06');a.uc.mem_write(A.VARIANT,b'\x02')
            a.stub(0x0E07E798,ok)
            a.stub(0x0E086F6C)
            for fn in (0x0E07E524,0x0E07E4EC,0x0E07E4B4,0x0E07E444,
                       0x0E07E40C,0x0E07E47C,0x0E07E3D4):a.stub(fn)
            posted=[]
            a.stub(0x0E086F68,effect=lambda a:posted.append(bytes(a.uc.mem_read(a.reg('r1'),12))) or 0)
            assert a.run(0x0E07EA30)==ok
            assert a.u32(A.ADV_RAM+A.OFF['reinit'])==int(b.advanced.get('telemetry',True))
            assert len(posted)==ok
            # Native post_mode recomputes variant from the restored CPI (default800),
            # rather than trusting a stale cached variant from before reinit.
            if ok:assert struct.unpack('<III',posted[0])==(3,6,1),posted[0].hex()
            assert a.byte(A.ADV_RAM+3)==18 and a.byte(A.ADV_RAM+2)==0
            cases+=1
    return cases


def tick_check(b):
    cases=0
    for ready,busy1,busy2,status,fault in itertools.product((0,1),(0,1),(0,1),(0xB7,0xBF,0),(0,1)):
        with fresh(b) as a:
            a.uc.mem_write(A.ADV_RAM,b'\x01\x01'+bytes(186))
            a.uc.mem_write(0x2300E07E,bytes([ready]))
            a.put32(0x2300CA64,busy1);a.put32(0x2300CA6C,busy2)
            a.uc.mem_write(0x2300E073,bytes([status,fault]))
            a.stub(0x0E07E6DC,0x76543210)
            assert a.run(b.symbols['advanced_tick'])==0x76543210
            nr=not ready or busy1 or busy2
            unhealthy=not nr and ((status&0xF7)!=0xB7 or fault==1)
            assert a.u32(A.ADV_RAM+A.OFF['ticks'])==1
            assert a.u32(A.ADV_RAM+A.OFF['not_ready'])==bool(nr)
            assert a.u32(A.ADV_RAM+A.OFF['health_skip'])==unhealthy
            assert a.u32(A.ADV_RAM+A.OFF['health_trip'])==unhealthy
            assert a.u32(A.ADV_RAM+A.OFF['last_bad_status'])==(status+fault*256 if unhealthy else 0)
            cases+=1
    return cases


def lock_check(b, *, A=A, fresh=fresh):
    from unicorn import UC_HOOK_MEM_WRITE
    with fresh(b) as a:
        timer=Timer(a, target=A);n=0
        # Run the actual post-ISR lock with target state offsets, all rate gates.
        a.setreg('r4',A.ADV_RAM);a.setreg('r5',A.RSTATE)
        cc=A.REPORT_TIMER+0x540
        for tpms,div,lead,phase,delay,conn,post,pre,queued,pending in itertools.product(
                (1,2,4,8),(1,2),(0,80,249,499),(20,180,1200),(0,2,None),
                (0,1),(4,8),(4,8),(0,1),(0,1)):
            a.uc.mem_write(A.ADV_RAM,bytes(188));a.uc.mem_write(A.ADV_RAM+2,b'\x01')
            a.uc.mem_write(A.ADV_RAM+4,struct.pack('<HH',lead,100))
            a.uc.mem_write(A.DIVIDER,bytes([div]));a.uc.mem_write(A.TPMS,bytes([tpms]))
            a.uc.mem_write(A.RSTATE+1,bytes([conn,1]));a.uc.mem_write(A.RSTATE+0x186,bytes([post]))
            a.setreg('r6',pre|(0x200 if conn else 0)|(0x100 if pending else 0)|(0x400 if queued else 0))
            timer.count,timer.delay,timer.pending=phase,delay,None
            timer.captures=timer.clears=0;a.put32(cc,500)
            a.run(b.symbols['advanced_phase_lock'])
            eligible=tpms in (1,2,4) and div==1 and conn and pending
            R=1000//tpms
            effective=lead or 80
            wantcc=500;last=100;adjust=skip=rescue=0
            if eligible and delay is not None:
                if phase>500:wantcc=R;last=0;rescue=1
                else:
                    last=phase
                    if phase<100 and phase<R//2:wantcc=R
                    if queued and pre==8 and post==4:
                        if effective>=R//2:skip=1
                        else:wantcc=phase+R-effective;adjust=1
            elif eligible:skip=1
            assert a.u32(cc)==wantcc,(tpms,div,lead,phase,delay,conn,post,pre,queued,pending,a.u32(cc),wantcc)
            diagnostic=b.advanced.get('telemetry',True)
            assert a.u32(A.ADV_RAM+A.OFF['lock_adjust'])==(adjust if diagnostic else 0)
            assert a.u32(A.ADV_RAM+A.OFF['lock_skip'])==(skip if diagnostic else 0)
            assert a.u32(A.ADV_RAM+A.OFF['lock_rescue'])==(rescue if diagnostic else 0)
            assert timer.clears==rescue and bool(timer.captures)==bool(eligible)
            assert int.from_bytes(a.uc.mem_read(A.ADV_RAM+6,2),'little')==last
            n+=1
        return n


def idle_tracking_check(b, *, A=A, T=T, fresh=fresh, request=request):
    """Target post-ISR gate, dev phase rule and shared timer ownership."""
    n = 0
    with fresh(b) as a:
        timer = Timer(a, target=A)
        cc = A.REPORT_TIMER + 0x540
        a.setreg('r4', A.ADV_RAM); a.setreg('r5', A.RSTATE)
        for tpms, lead, remain, selected in itertools.product(
                (1, 2, 4), (0, 1, 80, 124, 249, 499),
                (0, 1, 15, 16, 17, 40, 45, 46, 49, 50, 51, 79, 80, 81, 170, 420, 921), (0, 1)):
            a.uc.mem_write(A.ADV_RAM, bytes(188))
            a.uc.mem_write(A.ADV_RAM+2, b'\1')
            a.uc.mem_write(A.ADV_RAM+4, struct.pack('<HH', lead, 100))
            a.uc.mem_write(T.SMOOTHING_STATE, bytes((selected << 7,)))
            a.uc.mem_write(A.DIVIDER, b'\1'); a.uc.mem_write(A.TPMS, bytes((tpms,)))
            a.uc.mem_write(A.RSTATE+1, b'\1\1'); a.uc.mem_write(A.RSTATE+0x186, b'\x08')
            a.setreg('r6', 8 | 0x300)
            phase = 100
            timer.count, timer.delay, timer.pending = phase, 0, None
            timer.captures = timer.clears = 0
            a.put32(cc, phase + remain)
            a.run(b.symbols['advanced_phase_lock'])
            half, effective = 500//tpms, lead or 80
            want = remain
            if selected and remain >= 16 and effective < half:
                error = (remain + effective) % half
                if error <= half//2 and error >= 4 and remain >= error+16:
                    want -= error
                elif (error > half//2 or error >= 4 and remain < error+16) and half-error >= 4:
                    want += half-error
            assert a.u32(cc) == phase+want, (tpms,lead,remain,selected,a.u32(cc),phase+want)
            assert a.byte(A.ADV_RAM+12) == int(want != remain)
            if want != remain:
                assert want >= 16 and (want+effective) % half == 0
                # LOCK off releases an idle-owned interval through the same path.
                request(a, P.SET, (0, P.LOCK, 0, 80, 0))
                assert a.u32(cc) == 1000//tpms and a.byte(A.ADV_RAM+12) == 0
            assert a.u32(A.ADV_RAM+A.OFF['lock_adjust']) == 0
            n += 1
        # Every target gate; no motion queued is essential to idle ownership.
        for enabled, div, tpms, connected, ready, pending, queued, pre, post in itertools.product(
                (0,1), (1,2), (1,8), (0,1), (0,1), (0,1), (0,1), (4,8), (4,8)):
            a.uc.mem_write(A.ADV_RAM, bytes(188)); a.uc.mem_write(A.ADV_RAM+2, bytes((enabled,)))
            a.uc.mem_write(A.ADV_RAM+4, struct.pack('<HH',80,100))
            a.uc.mem_write(T.SMOOTHING_STATE,b'\x80')
            a.uc.mem_write(A.DIVIDER,bytes((div,))); a.uc.mem_write(A.TPMS,bytes((tpms,)))
            a.uc.mem_write(A.RSTATE+1,bytes((connected,ready))); a.uc.mem_write(A.RSTATE+0x186,bytes((post,)))
            a.setreg('r6',pre | connected<<9 | pending<<8 | queued<<10)
            timer.count,timer.delay,timer.pending=100,0,None; a.put32(cc,400)
            a.run(b.symbols['advanced_phase_lock'])
            eligible = enabled and div==1 and tpms==1 and connected and ready and pending
            motion = eligible and queued and pre==8 and post==4
            idle = eligible and not queued and pre==8 and post==8
            assert a.u32(cc) == (1020 if motion else 520 if idle else 400)
            assert a.byte(A.ADV_RAM+12) == bool(motion or idle)
            n += 1
        # Counter rollover restores the native period before any new adjustment.
        a.uc.mem_write(A.ADV_RAM,b'\1\0\1'+bytes(185)); a.uc.mem_write(A.ADV_RAM+4,struct.pack('<HH',80,400))
        a.uc.mem_write(A.ADV_RAM+12,b'\1'); a.uc.mem_write(T.SMOOTHING_STATE,b'\x80')
        a.uc.mem_write(A.DIVIDER,b'\1'); a.uc.mem_write(A.TPMS,b'\1')
        a.uc.mem_write(A.RSTATE+1,b'\1\1'); a.uc.mem_write(A.RSTATE+0x186,b'\x08')
        a.setreg('r6',8|0x300); a.put32(cc,520); timer.count,timer.pending=80,None
        a.run(b.symbols['advanced_phase_lock'])
        assert a.u32(cc)==1000 and a.byte(A.ADV_RAM+12)==0
        n += 1
    return n


def lock_release_check(b, *, A=A, fresh=fresh, request=request):
    # Restore only owned intervals; don't overwrite native 8k115us/rate changes.
    from unicorn.arm_const import UC_ARM_REG_PRIMASK
    n=0
    for owned,tpms,div,primask in itertools.product((0,1),(1,2,4,8),(1,2),(0,1)):
        with fresh(b) as a:
            timer=Timer(a, target=A)
            a.uc.mem_write(A.ADV_RAM,b'\x01\x00\x01'+bytes(185))
            a.uc.mem_write(A.ADV_RAM+12,bytes([owned]))
            a.uc.mem_write(A.DIVIDER,bytes([div]));a.uc.mem_write(A.TPMS,bytes([tpms]))
            cc=115 if tpms==8 else 777;a.put32(A.REPORT_TIMER+0x540,cc)
            a.uc.reg_write(UC_ARM_REG_PRIMASK,primask)
            assert request(a,P.SET,(0,3,0,80,0))==(0xA0,bytes([0,3,0,80,0,80,0]))
            restore=owned and tpms in (1,2,4) and div==1
            assert a.u32(A.REPORT_TIMER+0x540)==(1000//tpms if restore else cc)
            assert timer.clears==bool(restore) and timer.captures==0
            assert a.byte(A.ADV_RAM+12)==0
            assert a.uc.reg_read(UC_ARM_REG_PRIMASK)==primask
            n+=1
    return n


def radio_check(b):
    """Original RAM ISR is run once; disabled wrapper state/result matches it."""
    # Real target ISR with each peripheral event, original service stubs at the
    # peripheral boundary. LOCK wrapper itself is never stubbed.
    # Same off/off bypass as fixed dev: no slot snapshot, capture or helper
    # work when both controls are disabled, even if tracking remains selected.
    from unicorn import UC_HOOK_CODE
    diagnostic=b.advanced.get('telemetry',True)
    with fresh(b) as a:
        instructions=[]
        a.add_hook(UC_HOOK_CODE,lambda u,ea,size,user:instructions.append(ea))
        a.stub(A.IRQ,0x12345678)
        assert a.run(b.symbols['advanced_radio_irq'])==0x12345678
        # Keep the functional bypass check; FULL has no instruction budget.
        assert not any(ea==b.symbols[name] for ea in instructions
                       for name in ('advanced_phase_lock','advanced_radio_count') if name in b.symbols)
    cases=1
    for event in (0,0x14C,0x150,0x154,0x158):
        results=[]
        for advanced in (False,True):
            with fresh(b) as a:
                a.uc.mem_write(A.ADV_RAM,b'\x01'+bytes(187))
                for fn in (0x23003254,0x23002DFC):a.stub(fn,0x12345678)
                if event:a.put32(0x53028000+event,1)
                for reg in range(4,12):a.setreg(f'r{reg}',0xA000+reg)
                ret=a.run(b.symbols['advanced_radio_irq'] if advanced else A.IRQ,0)
                results.append((ret,bytes(a.uc.mem_read(0x53028000,0x600)),
                                bytes(a.uc.mem_read(A.RSTATE,0x190)),
                                [(x[0],x[1],x[2]) for x in a.calls],
                                [a.reg(f'r{i}') for i in range(4,12)],a.reg('sp')))
        assert results[0]==results[1],(hex(event),results);cases+=1
    # Classification across radio state transition, reconnect, capture outcomes.
    for connected_before,connected_after,active,pending,pre,post,delay in itertools.product(
            (0,1),(0,1),(0,1),(0,1),(4,6,8),(4,8),(0,2,None)):
        with fresh(b) as a:
            timer=Timer(a);timer.count=300;timer.delay=delay
            a.uc.mem_write(A.ADV_RAM,b'\x01\x01'+bytes(186))
            a.uc.mem_write(A.RSTATE+1,bytes([connected_before,active]))
            a.uc.mem_write(A.RSTATE+0x186,bytes([pre]))
            a.put32(A.RADIO_EVENT,pending);a.put32(A.REPORT_TIMER+0x540,1000)
            def orig(a):
                assert a.reg('r0')==0
                a.uc.mem_write(A.RSTATE+1,bytes([connected_after,active]))
                a.uc.mem_write(A.RSTATE+0x186,bytes([post]))
                return 0x87654321
            a.stub(A.IRQ,effect=orig)
            assert a.run(b.symbols['advanced_radio_irq'],0)==0x87654321
            assert sum(x[0]==A.IRQ for x in a.calls)==1
            assert a.u32(A.ADV_RAM+A.OFF['slot_ends'])==int(bool(pending and active and diagnostic))
            expected_phase=bool(pending and active and pre==8 and post==4 and delay is not None)
            assert a.u32(A.ADV_RAM+A.OFF['phase_count'])==bool(expected_phase and diagnostic)
            assert a.u32(A.REPORT_TIMER+0x540)==1000
            cases+=1
    # Enabled LOCK must leave pairing/reconnect alone; established links use
    # fresh capture and preserve the actual original ISR's return value.
    for before,after,delay,tpms in itertools.product((0,1),(0,1),(0,2,None),(1,8)):
        with fresh(b) as a:
            timer=Timer(a);timer.count=180;timer.delay=delay
            a.uc.mem_write(A.ADV_RAM,b'\x01\x00\x01'+bytes(185))
            a.uc.mem_write(A.RSTATE+1,bytes([before,1]));a.uc.mem_write(A.RSTATE+0x186,b'\x08')
            a.uc.mem_write(A.Q2+1,b'\x00');a.put32(A.RADIO_EVENT,1)
            a.uc.mem_write(A.DIVIDER,b'\x01');a.uc.mem_write(A.TPMS,bytes([tpms]))
            a.put32(A.REPORT_TIMER+0x540,115 if tpms==8 else 1000)
            def transition(a):
                a.uc.mem_write(A.RSTATE+1,bytes([after,1]));a.uc.mem_write(A.RSTATE+0x186,b'\x04')
                return 0x87654321
            a.stub(A.IRQ,effect=transition)
            assert a.run(b.symbols['advanced_radio_irq'])==0x87654321
            eligible=before and after and tpms==1
            adjusted=eligible and delay is not None
            assert a.u32(A.REPORT_TIMER+0x540)==(1100 if adjusted else 115 if tpms==8 else 1000)
            assert timer.captures==bool(eligible)
            assert a.u32(A.ADV_RAM+A.OFF['lock_adjust'])==bool(adjusted and diagnostic)
            assert a.u32(A.ADV_RAM+A.OFF['capture_fail'])==bool(eligible and delay is None and diagnostic)
            cases+=1
    return cases


def native_radio_check(b):
    """Full original IRQ + slot-end + queue paths, without a slot-end stub."""
    cases=0
    for connected,pre,queued in itertools.product((0,1),(4,6,8),(0,1)):
        runs=[]
        for wrapped in (False,True):
            with fresh(b) as a:
                timer=Timer(a);timer.count=180
                def memcpy(a):
                    a.uc.mem_write(a.reg('r0'),bytes(a.uc.mem_read(a.reg('r1'),a.reg('r2'))))
                    return a.reg('r0')
                a.stub(0x0E0877E0,effect=memcpy)
                a.stub(0x23002134,1)  # frequency register transaction boundary
                for q in range(7):a.run(0x0E073F0C,q)
                a.uc.mem_write(A.ADV_RAM,b'\x01\x01\x01'+bytes(185))
                a.uc.mem_write(A.RSTATE,b'\x01\x01\x01')
                if queued:
                    a.uc.mem_write(0x23025000,bytes.fromhex('0000000012345678'))
                    assert a.run(0x0E0879D8,9,0x23025000)==1
                a.uc.mem_write(A.RSTATE+1,bytes([connected]))
                a.uc.mem_write(A.RSTATE+0x186,bytes([pre]))
                a.uc.mem_write(A.DIVIDER,b'\x01');a.uc.mem_write(A.TPMS,b'\x01')
                a.put32(0x2300BF7C,10000)  # no hop in these single-slot cases
                a.put32(A.RADIO_EVENT,1);a.put32(A.REPORT_TIMER+0x540,1000)
                for i in range(4,12):a.setreg(f'r{i}',0xCC000000+i)
                before=len(a.calls)
                result=a.run(b.symbols['advanced_radio_irq'] if wrapped else A.IRQ,0,count=200000)
                # An ordinary wrapper adds 24 bytes of stack; memcpy's local-buffer
                # pointer shifts by that amount, while native RAM results must match.
                def normalize(value):
                    frame = 32 if hasattr(b, 'native_plock') else 24
                    return value+frame if wrapped and 0x2302F000<=value<0x23030000 else value
                calls=[(fn,normalize(r0),normalize(r1)) for fn,r0,r1 in a.calls[before:]]
                # Compare all native radio/queue state, apart from the owned record.
                runs.append((result,bytes(a.uc.mem_read(0x2300C900,A.ADV_RAM-0x2300C900)),
                             bytes(a.uc.mem_read(A.ADV_RAM+188,0x2300E100-A.ADV_RAM-188)),
                             bytes(a.uc.mem_read(0x53000000,0x100000)),calls,
                             [a.reg(f'r{i}') for i in range(4,12)],a.reg('sp')))
                if wrapped:
                    adjusted=connected and pre==8 and queued
                    assert a.u32(A.REPORT_TIMER+0x540)==(1100 if adjusted else 1000)
                    diagnostic=b.advanced.get('telemetry',True)
                    assert a.u32(A.ADV_RAM+A.OFF['lock_adjust'])==bool(adjusted and diagnostic)
                    assert a.u32(A.ADV_RAM+A.OFF['slot_ends'])==int(diagnostic)
                    # Only a connected receive window expiring is a timeout;
                    # TX completion and idle-to-TX transitions are not losses.
                    expired=int(connected and pre==6 and diagnostic)
                    assert a.u32(A.ADV_RAM+A.OFF['tx_attempts'])==expired
                    assert a.u32(A.ADV_RAM+A.OFF['no_ack'])==expired
        assert runs[0]==runs[1],(connected,pre,queued,
            [(i,(x,y) if not isinstance(x,bytes) else
              [(j,u,v) for j,(u,v) in enumerate(zip(x,y)) if u!=v][:12])
             for i,(x,y) in enumerate(zip(runs[0],runs[1])) if x!=y])
        cases+=1
    return cases


def wrapper_check(b):
    # Exact underlying return/argument ABI and bounds for the instrumentation.
    n=0
    for sym,original,args,counter in [
        ('advanced_burst',0x0E06CFE8,(0x16,6),'reads_started'),
        ('advanced_spi_done',0x0E07E600,(0x23025000,1),'spi_ok'),
        ('advanced_motion',0x0E071DC0,(0x23025000,),'samples'),
        ('advanced_reinit',0x0E07E798,(),'reinit'),
        ('advanced_send',0x23002D54,(9,0x23025000),'tx_queued')]:
        for enabled,ret in itertools.product((0,1),(0,1,0x76543210)):
            with fresh(b) as a:
                a.uc.mem_write(A.ADV_RAM,b'\x01'+bytes([enabled])+bytes(186))
                a.uc.mem_write(0x23025000,b'\x01\x00\x00\x00\x00\x00')
                a.stub(original,ret)
                for i in range(4,12):a.setreg(f'r{i}',0xAABB0000+i)
                result=a.run(b.symbols[sym],*args)
                assert result==ret and len(a.calls)==1
                assert tuple(a.calls[0][1:])==tuple((args+(0,0))[:2]) if len(args)>1 else True
                assert [a.reg(f'r{i}') for i in range(4,12)]==[0xAABB0000+i for i in range(4,12)]
                expected=bool(enabled and (sym!='advanced_burst' or ret))
                if sym=='advanced_send':expected=enabled and ret==1
                assert a.u32(A.ADV_RAM+A.OFF[counter])==expected,(sym,enabled,ret)
                n+=1
    return n


def run_checks(b):
    from .settings_checks import persistence_check, smoothing_check, tracking_protocol_check
    from .motion_checks import verify as motion_check, ownership_boundary_sweep
    from .mouse_abs_checks import verify as abs_check
    checks = (
        ('initialization', initialization_check), ('queue_accessors', queue_boundary_check),
        ('protocol', protocol_check), ('fps_modes', fps_check),
        ('fps_publish_interleaves', fps_publish_interleaves),
        ('fps_readback_failures', fps_readback_failure_check), ('custom_fps', custom_fps_check),
        ('sensor_snapshot', sensor_snapshot_check), ('sensor_snapshot_cpi', sensor_snapshot_cpi_check),
        ('lock_cases', lock_check),
        ('radio_cases', radio_check), ('wrappers', wrapper_check),
        ('native_send', native_send_check), ('worker_paths', worker_check),
        ('tick_cases', tick_check), ('native_radio_slots', native_radio_check),
        ('lock_disable', lock_release_check),
        ('settings_persistence', persistence_check), ('smoothing', smoothing_check),
        ('idle_tracking', idle_tracking_check), ('tracking_protocol', tracking_protocol_check),
        ('motion_path', motion_check),
        ('motion_ownership_boundaries', ownership_boundary_sweep),
        ('abs_motion', abs_check),
    )
    omitted={'tick_cases','wrappers'} if not b.advanced.get('telemetry',True) else set()
    result = {name: check(b) for name, check in checks if name not in omitted}
    if hasattr(b, 'native_plock'):
        from .native_timing_checks import verify as timing_check
        from .native_clock_checks import verify as clock_check
        result['native_clock'] = clock_check(b)
        result['native_plock'] = timing_check(b)
    return dict(result, result='PASS', hardware='not run')
