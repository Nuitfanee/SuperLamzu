"""Target Thumb checks for cumulative motion; no USB or report-rate sampler."""
import itertools
import struct

from . import advanced as A, protocol as P, target as T
from .checks import fresh
from .mouse_abs import ENABLED
from .motion import DIRECT, OWNER
from .settings import decode_record, encode_record
from .verify import request


def verify(b):
    from unicorn.arm_const import UC_ARM_REG_IPSR, UC_ARM_REG_PRIMASK
    cases = 0
    heap, frame = 0x23024004, 0x23025000

    def allocate(a):
        a.stub(0x0E07FAD4, heap-4)
        a.uc.mem_write(heap-5, b'\xA5'*(T.SNAPSHOT_STORAGE_BYTES+6))
        a.uc.mem_write(T.MOTION_STATE, bytes((DIRECT,)))
        assert request(a, P.SET, (0, P.ABS_MOTION, 1)) == (0xA0, b'\0\x0b\1')
        assert a.byte(T.MOTION_STATE) == 2 | DIRECT | ENABLED
        assert a.byte(heap-5) == a.byte(heap+T.SNAPSHOT_STORAGE_BYTES) == 0xA5
        assert bytes(a.uc.mem_read(heap+24, 4)) == bytes(4)

    with fresh(b) as a:
        allocate(a)
        for primask, enabled in itertools.product((0,1), (0,1)):
            a.uc.reg_write(UC_ARM_REG_PRIMASK, primask)
            assert request(a, P.SET, (0,11,enabled)) == (0xA0, bytes((0,11,enabled)))
            assert a.byte(T.MOTION_STATE) == 2 | DIRECT | enabled*ENABLED
            assert a.uc.reg_read(UC_ARM_REG_PRIMASK) == primask
            cases += 1
        assert len([c for c in a.calls if c[0] == 0x0E07FAD4]) == 1
        a.uc.mem_write(heap+24, b'\x12\x34\x56\x78')
        a.uc.mem_write(T.SENSOR_READY,b'\1')
        a.stub(T.MOTION_POST)
        assert request(a,P.SET,(0,6,1,0))[0] == 0xA0
        a.stub(T.WR,1)
        a.stub(T.RD,effect=lambda c: c.uc.mem_write(c.reg('r1'),b'\x33') or 1)
        a.run(b.symbols['advanced_snapshot_worker'])
        assert bytes(a.uc.mem_read(heap+24,4)) == b'\x12\x34\x56\x78'
        assert len(request(a,P.GET,(0,6))[1]) == 26
        a.uc.reg_write(UC_ARM_REG_PRIMASK,0)
        a.stub(T.STORAGE_WRITE, effect=lambda c: c.uc.mem_write(T.ADV_STORAGE,
               bytes(c.uc.mem_read(c.reg('r1'),16))) or 0)
        saved = request(a,P.SET,(0,8,1))[1][3:]
        assert decode_record(saved)['abs_motion'] == 1
        a.run(b.symbols['advanced_queue_init'],0)
        assert request(a,P.GET,(0,11)) == (0xA0,b'\0\x0b\1')
        assert bytes(a.uc.mem_read(heap+24,4)) == bytes(4)
        assert bytes(a.uc.mem_read(T.ADV_STORAGE,16)) == saved
        for version in (1,2,3):
            a.uc.mem_write(T.ADV_STORAGE,encode_record(version=version))
            a.run(b.symbols['advanced_queue_init'],0)
            assert request(a,P.GET,(0,11)) == (0xA0,b'\0\x0b\0')
            cases += 1
        for command, payload in ((P.SET,(0,11)),(P.SET,(0,11,2)),(P.SET,(1,11,1)),
                                  (P.SET,(0,11,1,0)),(P.GET,(1,11)),(P.GET,(0,11,1))):
            before=bytes(a.uc.mem_read(T.SNAPSHOT_POINTER,3))
            assert request(a,command,payload)[0] == 0xA2
            assert bytes(a.uc.mem_read(T.SNAPSHOT_POINTER,3)) == before
            cases += 1
        cases += 2
    with fresh(b) as a:
        a.stub(0x0E07FAD4,0)
        assert request(a,P.SET,(0,11,1))[0] == 0xA2
        assert request(a,P.GET,(0,11)) == (0xA0,b'\0\x0b\0')
        a.uc.mem_write(T.ADV_STORAGE,encode_record(abs_motion=1))
        a.run(b.symbols['advanced_queue_init'],0)
        assert request(a,P.GET,(0,11)) == (0xA0,b'\0\x0b\0')
        cases += 2
    # Execute the replaced native instructions with post-transform stack data.
    with fresh(b) as a:
        allocate(a)
        for enabled, x, y in itertools.product((0,1), (0,19,65535,32768), (0,65529,32767)):
            a.uc.mem_write(T.MOTION_STATE,bytes((2 | ENABLED*enabled,)))
            a.uc.mem_write(0x23030002,struct.pack('<HH',x,y))
            a.uc.mem_write(T.MOTION_ACC_Y,struct.pack('<HH',500,65530))
            a.uc.mem_write(heap+24,struct.pack('<HH',65533,100))
            a.ends.add(T.ABS_ACC_SITE+24)
            result=a.run(T.ABS_ACC_SITE,0x12345678)
            a.ends.clear()
            assert result == 0x12345678 and a.reg('sp') == 0x23030000
            assert bytes(a.uc.mem_read(T.MOTION_ACC_Y,4)) == struct.pack('<HH',(500+y)&65535,(65530+x)&65535)
            assert bytes(a.uc.mem_read(heap+24,4)) == struct.pack('<HH',
                (65533+x*enabled)&65535,(100+y*enabled)&65535)
            cases += 1
        # Every native frame/retry hook executes from the copied RAM address.
        for enabled, present, x, y in itertools.product((0,1), (0,1), (0,19,65535), (0,65529)):
            a.uc.mem_write(T.MOTION_STATE,bytes((2 | ENABLED*enabled,)))
            a.uc.mem_write(heap+24,struct.pack('<HH',210,320))
            a.uc.mem_write(0x23030000,bytes((present,)))
            a.uc.mem_write(0x23030008,struct.pack('<HH',210,320))
            a.uc.mem_write(0x23030004,struct.pack('<H',x))
            a.setreg('r4',frame);a.setreg('r5',y)
            a.ends.add(T.ABS_HEADER_SITE+16)
            a.run(T.ABS_HEADER_SITE,2,0xABCDEF,1,T.RADIO_FRAME_PENDING+1)
            a.ends.clear()
            expected=(210,320) if enabled and not present else (x,y)
            assert bytes(a.uc.mem_read(frame+4,4)) == struct.pack('<HH',*expected)
            assert a.byte(frame+2) == 2 | enabled*8
            assert a.byte(T.RADIO_FRAME_PENDING) == 1
            assert a.byte(T.RADIO_FRAME_PENDING+1) == 2
            assert a.reg('r0') == 2 and a.reg('r1') == 0xABCDEF
            cases += 1
        copied=[]
        def memcpy(c):
            assert c.reg('sp') & 7 == 0
            data=bytes(c.uc.mem_read(c.reg('r1'),c.reg('r2')))
            c.uc.mem_write(c.reg('r0'),data);copied.append(data)
            return c.reg('r0')
        a.stub(T.RADIO_MEMCPY,effect=memcpy)
        for enabled, length, header in itertools.product((0,1),(3,7),(2,10,0xFA)):
            a.uc.mem_write(T.MOTION_STATE,bytes((2 | ENABLED*enabled,)))
            staged=bytes((length,0,header,31))+struct.pack('<HH',5,9)
            a.uc.mem_write(T.RADIO_STATE+6,staged)
            a.setreg('r4',T.RADIO_STATE)
            a.ends.add(T.ABS_RETX_SITE+16);a.run(T.ABS_RETX_SITE);a.ends.clear()
            wanted=bytearray(staged)
            if enabled and length==7 and header&15==10:wanted[4:8]=struct.pack('<HH',210,320)
            assert copied[-1] == wanted[:length+1] and a.reg('r3') == 1
            cases += 1
    # Native decode -> direct callback -> real message 9 -> original queue2.
    with fresh(b) as a:
        allocate(a)
        a.uc.mem_write(T.MOTION_STATE,bytes((2 | DIRECT | ENABLED,)))
        a.stub(0x0E0877E0,effect=lambda c: c.uc.mem_write(c.reg('r0'),
            bytes(c.uc.mem_read(c.reg('r1'),c.reg('r2')))) or c.reg('r0'))
        a.run(0x0E073F0C,2)
        a.uc.mem_write(T.TRANSPORT_STATE,b'\1');a.uc.mem_write(T.SENSOR_READY,b'\1')
        a.uc.mem_write(A.RSTATE,b'\1\1')
        a.put32(T.MOTION_DONE_QUEUE,0x2300A328)
        a.put32(T.MOTION_CALLBACK,b.symbols['advanced_motion']|1)
        for service in (0x0E06CA2C,0x0E068E38,0x0E068E70,0x0E086F6C):a.stub(service)
        a.uc.reg_write(UC_ARM_REG_IPSR,20)
        x,y=0,0
        for i,(dx,dy) in enumerate(((19,-7),(-2,30),(32760,-32760))):
            a.uc.mem_write(frame,b'\x80\xb7'+struct.pack('<hh',dx,dy))
            a.run(0x0E07E600,frame,1)
            x,y=(x+dx)&65535,(y+dy)&65535
            assert bytes(a.uc.mem_read(heap+24,4)) == struct.pack('<HH',x,y)
            assert bytes(a.uc.mem_read(A.Q2+10+i*12,4)) == struct.pack('<HH',x,y)
            cases += 1
    return (cases + total_fast_path_check(b) + busy_switch_check(b) + pending_switch_check(b)
            + retransmit_order_check(b) + retransmit_producer_interleave_check(b))


def total_fast_path_check(b):
    """Count the relocated helper while checking its native ABI and XY store."""
    from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
    from unicorn.arm_const import UC_ARM_REG_BASEPRI, UC_ARM_REG_PRIMASK
    heap = 0x23024004
    cases = 0
    for enabled, present in ((False, False), (False, True), (True, True)):
        for mask, tags in itertools.product((0, 1), (0, 0x10, 0x20, 0x30, 0x80, 0xB0)):
            with fresh(b) as a:
                stack = a.layout.stack
                packed = ((heap & 0xFFFFF) if present else 0) | ((tags | (64 if enabled else 0)) << 16)
                a.uc.mem_write(T.SNAPSHOT_POINTER-1, b'\xa5' + packed.to_bytes(3, 'little'))
                a.uc.mem_write(heap, b'\xa5' * T.SNAPSHOT_STORAGE_BYTES)
                a.uc.mem_write(heap+24, struct.pack('<HH', 65533, 100))
                a.uc.mem_write(stack+2, struct.pack('<HH', 19, 65529))
                a.uc.mem_write(T.MOTION_ACC_Y, struct.pack('<HH', 500, 65530))
                a.uc.reg_write(UC_ARM_REG_PRIMASK, mask)
                a.uc.reg_write(UC_ARM_REG_BASEPRI, 0x60)
                preserved = list(range(4, 13))
                for register in preserved:
                    a.setreg(f'r{register}', 0xA000 + register)
                reads, heap_reads, writes, executed = [], [], [], []
                def read(uc, access, address, size, value, user):
                    reads.append((address, size))
                def heap_read(uc, access, address, size, value, user):
                    heap_reads.append((address, size))
                def write(uc, access, address, size, value, user):
                    writes.append((address, size))
                def instruction(uc, address, size, user):
                    if address not in a.ends:
                        executed.append(address)
                        assert uc.reg_read(UC_ARM_REG_PRIMASK) == mask
                        assert uc.reg_read(UC_ARM_REG_BASEPRI) == 0x60
                a.add_hook(UC_HOOK_MEM_READ, read, begin=T.SNAPSHOT_POINTER-1, end=T.MOTION_STATE)
                a.add_hook(UC_HOOK_MEM_READ, heap_read, begin=heap, end=heap+T.SNAPSHOT_STORAGE_BYTES-1)
                a.add_hook(UC_HOOK_MEM_WRITE, write)
                a.add_hook(UC_HOOK_CODE, instruction)
                a.ends.add(T.ABS_ACC_SITE+24)
                assert a.run(b.symbols['abs_total'], 0x12345678) == 0x12345678
                assert a.reg('sp') == stack and a.reg('lr') == (a.stop | 1)
                assert [a.reg(f'r{r}') for r in preserved] == [0xA000 + r for r in preserved]
                assert (a.reg('r1'), a.reg('r2'), a.reg('r3')) == (65529, T.MOTION_ACC_Y, 66029)
                assert reads == [(T.SNAPSHOT_POINTER-1, 4)]
                assert heap_reads == ([(heap+24, 4)] if enabled else [])
                assert len(executed) <= (27 if enabled else 16)
                assert struct.unpack('<HH', a.uc.mem_read(T.MOTION_ACC_Y, 4)) == (493, 13)
                assert struct.unpack('<HH', a.uc.mem_read(heap+24, 4)) == (
                    (65533 + 19 * enabled) & 65535, 100 - 7 * enabled)
                heap_writes = [(address, size) for address, size in writes
                               if heap <= address < heap + T.SNAPSHOT_STORAGE_BYTES]
                assert heap_writes == ([(heap+24, 4)] if enabled else [])
                assert all((T.MOTION_ACC_Y <= address and address+size <= T.MOTION_ACC_Y+4)
                           or (enabled and stack-16 <= address and address+size <= stack)
                           or (enabled and address == heap+24 and size == 4)
                           for address, size in writes)
                assert bytes(a.uc.mem_read(heap, 24)) == b'\xa5' * 24
                assert bytes(a.uc.mem_read(heap+28, T.SNAPSHOT_STORAGE_BYTES-28)) == b'\xa5' * (T.SNAPSHOT_STORAGE_BYTES-28)
                cases += 1
    return cases


def retransmit_order_check(b, *, retry=True):
    """A retry must not overtake older queued totals or reinterpret zero totals."""
    heap, packet, frame = 0x23024004, 0x23025000, T.RADIO_STATE+6
    cases = 0
    for totals in ((10, 20, 30), (10, 0, 30), (65530, 0, 10)):
        with fresh(b) as a:
            a.stub(0x0E07FAD4, heap-4)
            a.run(b.symbols['advanced_queue_init'], 0)
            assert request(a, P.SET, (0, P.ABS_MOTION, 1))[0] == 0xA0
            a.uc.mem_write(A.RSTATE, b'\1\1')
            def memcpy(c):
                c.uc.mem_write(c.reg('r0'), bytes(c.uc.mem_read(c.reg('r1'), c.reg('r2'))))
                return c.reg('r0')
            a.stub(0x0E0877E0, effect=memcpy)
            a.stub(T.RADIO_MEMCPY, effect=memcpy)
            for x in totals:
                a.uc.mem_write(heap+24, struct.pack('<HH', x, 0))
                a.uc.mem_write(packet, bytes(8))
                assert a.run(0x0E0879D8, 9, packet) == 1
            emitted = []
            for index, x in enumerate(totals):
                assert a.run(0x230030F0, frame) == 1
                emitted.append(struct.unpack('<HH', a.uc.mem_read(frame+4, 4))[0])
                assert emitted[-1] == x, ('queued total changed', totals, emitted)
                if index == 0 and retry:
                    a.setreg('r4', T.RADIO_STATE)
                    a.ends.add(T.ABS_RETX_SITE+16)
                    a.run(T.ABS_RETX_SITE)
                    a.ends.clear()
                    retried = struct.unpack('<HH', a.uc.mem_read(frame+4, 4))[0]
                    assert retried == x, ('retry overtook backlog', totals, retried)
                    cases += 1
            # With no older queued sample, catch-up to a newer unsent total
            # remains valid and is still supported.
            a.uc.mem_write(heap+24, struct.pack('<HH', 40, 50))
            a.setreg('r4', T.RADIO_STATE)
            a.ends.add(T.ABS_RETX_SITE+16)
            a.run(T.ABS_RETX_SITE)
            a.ends.clear()
            assert bytes(a.uc.mem_read(frame+4, 4)) == struct.pack('<HH', 40, 50)
            cases += 2
    return cases


def pending_switch_check(b):
    """Reject format changes until unsent XY drains; never block reporting."""
    from unicorn.arm_const import UC_ARM_REG_PRIMASK
    cases = 0
    for enabled, mask, pending in itertools.product((0, 1), (0, 1),
                                                   ((110, 0), (0, -220), (110, -220))):
        with fresh(b) as a:
            a.stub(T.NATIVE_ALLOC, 0x23024004)
            a.run(b.symbols['advanced_queue_init'], 0)
            assert request(a, P.SET, (0, P.ABS_MOTION, enabled))[0] == 0xA0
            a.uc.mem_write(T.MOTION_ACC_X, struct.pack('<h', pending[0]))
            a.uc.mem_write(T.MOTION_ACC_Y, struct.pack('<h', pending[1]))
            a.uc.reg_write(UC_ARM_REG_PRIMASK, mask)
            assert request(a, P.SET, (0, P.ABS_MOTION, enabled))[0] == 0xA0
            assert request(a, P.SET, (0, P.ABS_MOTION, 1-enabled))[0] == 0xA2
            assert request(a, P.GET, (0, P.ABS_MOTION))[1][2] == enabled
            assert a.uc.reg_read(UC_ARM_REG_PRIMASK) == mask
            assert struct.unpack('<hh', a.uc.mem_read(T.MOTION_ACC_Y, 4)) == pending[::-1]
            a.stub(0x0E06F530, 1)
            a.stub(0x0E0879D0, 8)
            a.stub(0x0E07F786, 0)
            a.stub(0x0E06CA2C)
            a.uc.mem_write(T.REPORT_DIVIDER, b'\1')
            sends = []
            a.stub(0x23002D54, effect=lambda c: sends.append(
                tuple(struct.unpack('<hh', c.uc.mem_read(c.reg('r1')+4, 4)))) or 1)
            a.run(b.symbols['motion_report'])
            assert len(sends) == 1
            if not enabled:
                assert sends == [pending], sends
            assert bytes(a.uc.mem_read(T.MOTION_ACC_Y, 4)) == bytes(4)
            assert request(a, P.SET, (0, P.ABS_MOTION, 1-enabled))[0] == 0xA0
            assert a.uc.reg_read(UC_ARM_REG_PRIMASK) == mask
            cases += 1
    return cases


def retransmit_producer_interleave_check(b):
    """A producer may publish between retry's empty check and total read."""
    from unicorn import UC_HOOK_CODE
    from unicorn.arm_const import UC_ARM_REG_PRIMASK
    from .common import assemble
    from .advanced import addr
    heap,packet,producer=0x23024004,0x23025000,0x23029000
    def fixture():
        a=fresh(b)
        a.stub(0x0E07FAD4,heap-4)
        a.run(b.symbols['advanced_queue_init'],0)
        assert request(a,P.SET,(0,P.ABS_MOTION,1))[0]==0xA0
        a.uc.mem_write(A.RSTATE,b'\1\1')
        def memcpy(c):
            c.uc.mem_write(c.reg('r0'),bytes(c.uc.mem_read(c.reg('r1'),c.reg('r2'))))
            return c.reg('r0')
        a.stub(0x0E0877E0,effect=memcpy);a.stub(T.RADIO_MEMCPY,effect=memcpy)
        a.uc.mem_write(heap+24,struct.pack('<HH',10,0))
        a.uc.mem_write(T.RADIO_STATE+6,b'\7\0\x0a\0'+struct.pack('<HH',10,0))
        a.uc.mem_write(producer,assemble(['push {r4,lr}']+addr('r3',heap+24)
            +['movs r2,#20','str r2,[r3]']+addr('r1',packet)
            +['movs r0,#9']+addr('r12',0x0E0879D9)+['blx r12']
            +addr('r3',heap+24)+['movs r2,#30','str r2,[r3]','pop {r4,pc}'],producer))
        a.setreg('r4',T.RADIO_STATE)
        return a
    ranges=[(int(v['address'],0),int(v['address'],0)+v['bytes'])
            for v in b.allocations if v['name'] in ('abs_retransmit','abs_frame_pop','abs_header','abs_pointer')]
    ranges.append((T.ABS_FRAME_NATIVE,0x2300320C))
    cases=0
    for name,start,args in (('retry',b.symbols['abs_retransmit'],()),
                             ('frame',T.ABS_FRAME_NATIVE,(T.RADIO_STATE+6,))):
        with fixture() as a:
            a.uc.mem_write(0x2300D55D,b'\2')
            boundaries=[];seen={}
            def trace(uc,ad,size,user):
                if any(lo<=ad<hi for lo,hi in ranges):
                    seen[ad]=seen.get(ad,0)+1
                    if not uc.reg_read(UC_ARM_REG_PRIMASK):boundaries.append((ad,seen[ad]))
            a.add_hook(UC_HOOK_CODE,trace);a.run(start,*args)
        for boundary,nth in boundaries:
            with fixture() as a:
                a.uc.mem_write(0x2300D55D,b'\2')
                assert a.preempt((start,args),(producer,()),boundary,nth)
                retried=struct.unpack('<H',a.uc.mem_read(T.RADIO_STATE+10,2))[0]
                assert retried in (10,20),(name,'overtook concurrent queue',hex(boundary),retried)
                if a.byte(A.Q2) or a.byte(A.Q2+2)!=a.byte(A.Q2+3):
                    assert a.run(T.ABS_FRAME_NATIVE,T.RADIO_STATE+6)==1
                    assert struct.unpack('<H',a.uc.mem_read(T.RADIO_STATE+10,2))[0]==20
                cases+=1
    return cases


def busy_switch_check(b):
    """Keep queued relative/ABS samples in their original interpretation."""
    from unicorn.arm_const import UC_ARM_REG_PRIMASK
    cases=0
    for enabled,mask,count in itertools.product((0,1),(0,1),(1,8)):
        with fresh(b) as a:
            a.stub(0x0E07FAD4,0x23024000)
            a.stub(0x0E0877E0,effect=lambda c:c.uc.mem_write(c.reg('r0'),
                bytes(c.uc.mem_read(c.reg('r1'),c.reg('r2')))) or c.reg('r0'))
            a.run(b.symbols['advanced_queue_init'],0)
            a.uc.mem_write(A.RSTATE,b'\1\1')
            assert request(a,P.SET,(0,P.ABS_MOTION,enabled))[0]==0xA0
            p=0x23025000;a.uc.mem_write(p,bytes(4)+struct.pack('<hh',10,20))
            for _ in range(count):assert a.run(0x0E0879D8,9,p)==1
            before=bytes(a.uc.mem_read(A.Q2,106))
            a.uc.reg_write(UC_ARM_REG_PRIMASK,mask)
            assert request(a,P.SET,(0,P.ABS_MOTION,enabled))[0]==0xA0
            assert request(a,P.SET,(0,P.ABS_MOTION,1-enabled))[0]==0xA2
            assert bytes(a.uc.mem_read(A.Q2,106))==before
            assert request(a,P.GET,(0,P.ABS_MOTION))[1][2]==enabled
            assert a.uc.reg_read(UC_ARM_REG_PRIMASK)==mask
            for _ in range(count):assert a.run(0x23003A8C,2,p,12)==1
            assert request(a,P.SET,(0,P.ABS_MOTION,1-enabled))[0]==0xA0
            cases+=1
    for enabled,mask in itertools.product((0,1),(0,1)):
        with fresh(b) as a:
            a.stub(0x0E07FAD4,0x23024000)
            a.run(b.symbols['advanced_queue_init'],0)
            a.run(b.symbols['advanced_snapshot_storage'])
            assert request(a,P.SET,(0,P.ABS_MOTION,enabled))[0]==0xA0
            state=a.byte(T.MOTION_STATE)|DIRECT|OWNER
            a.uc.mem_write(T.MOTION_STATE,bytes((state,)))
            a.uc.reg_write(UC_ARM_REG_PRIMASK,mask)
            assert request(a,P.SET,(0,P.ABS_MOTION,enabled))[0]==0xA0
            assert request(a,P.SET,(0,P.ABS_MOTION,1-enabled))[0]==0xA2
            assert a.byte(T.MOTION_STATE)==state
            assert a.uc.reg_read(UC_ARM_REG_PRIMASK)==mask
            cases+=1
    # Boot loading occurs before native queue2 init in the outer startup loop.
    with fresh(b) as a:
        a.stub(0x0E07FAD4,0x23024000)
        record=encode_record(abs_motion=1)
        a.uc.mem_write(T.ADV_STORAGE,record)
        a.uc.mem_write(A.Q2,b'\xa5'*6)
        a.run(b.symbols['advanced_queue_init'],0)
        assert request(a,P.GET,(0,P.ABS_MOTION))[1][2]==1
        assert bytes(a.uc.mem_read(T.ADV_STORAGE,16))==record
        cases+=1
    return cases
