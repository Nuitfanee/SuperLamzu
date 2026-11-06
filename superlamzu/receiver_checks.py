"""Receiver real-Thumb checks; timer capture events are explicit peripherals."""
import gc
import itertools
import struct

from . import receiver as R


def verify(builder):
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_MCLASS, UC_HOOK_MEM_WRITE
    import unicorn.arm_const as C
    if builder.source == R.CORES[0].source.resolve():
        assert not builder.changes
        return dict(result='PASS', cpuapp_unchanged=True, hardware='not run')
    stock, patched = builder.image.data, builder.output_image()
    base = R.CORES[1].base
    allowed = (set(range(R.SOF_CALLBACK,R.SOF_BLOCK_END))
               | set(range(R.RADIO_HOOKS['sof_isr'][0],R.RADIO_HOOKS['sof_isr'][0]+4))
               | set(range(R.QUEUE_RAW,R.QUEUE_BLOCK_END))
               | set(range(R.RECEIVE_REPORT_SITE,R.RECEIVE_REPORT_SITE+4))
               | set(range(R.REPORT_FIFO_SITE,R.REPORT_FIFO_SITE+4))
               | set(range(R.REPORT_CONSUMER_SITE,R.REPORT_CONSUMER_SITE+4)))
    assert set(builder.changes) <= allowed
    assert patched[:8] == stock[:8]
    engines = []
    for data in (stock, patched):
        u = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
        u.mem_map(base, (len(data)+4095)&~4095); u.mem_write(base,data)
        u.mem_map(0x23000000,0x40000)
        u.mem_write(R.CODE_RAM,data[R.CODE_SOURCE-base:R.CODE_SOURCE-base+R.CODE_BYTES])
        u.mem_write(R.DATA_RAM,data[R.DATA_SOURCE-base:R.DATA_SOURCE-base+R.DATA_BYTES])
        u.mem_map(R.SOF_TIMER,4096)
        engines.append(u)
    stop, stack = 0x2303F000, 0x23030000
    capture = [125]
    def on_write(u, access, address, size, value, _):
        if value and address in (R.SOF_TIMER+0x40,R.SOF_TIMER+0x44):
            slot = (address-R.SOF_TIMER-0x40)//4
            u.mem_write(R.SOF_TIMER+0x540+slot*4,struct.pack('<I',capture[0]))
    handles=[u.hook_add(UC_HOOK_MEM_WRITE,on_write,begin=R.SOF_TIMER,end=R.SOF_TIMER+0x4f) for u in engines]
    def run(u,entry):
        u.reg_write(C.UC_ARM_REG_SP,stack); u.reg_write(C.UC_ARM_REG_LR,stop|1)
        for i in range(4,12):u.reg_write(getattr(C,'UC_ARM_REG_R'+str(i)),0x1100+i)
        u.emu_start(entry|1,stop,count=2000)
        assert u.reg_read(C.UC_ARM_REG_PC)==stop
        assert u.reg_read(C.UC_ARM_REG_SP)==stack
        assert all(u.reg_read(getattr(C,'UC_ARM_REG_R'+str(i)))==0x1100+i for i in range(4,12))
    cases = 0
    try:
        startup_cases = _startup_checks(engines)
        # All native acquisition states including wrap, thresholds and disabled.
        for enabled,state,acquiring,count,value in itertools.product(
                (0,1), range(6), (0,1), (0,63,64,65,65535), (0,122,123,127,128,997,998,1002,1003)):
            capture[0]=value
            results=[]
            for u in engines:
                u.mem_write(0x23007000,b'\xA5'*4096);u.mem_write(R.SOF_TIMER,bytes(4096))
                u.mem_write(R.SOF_STATE,bytes((0x33,0x44,0xAA,0x55,state,0,acquiring,enabled)))
                u.mem_write(R.SOF_COUNT,struct.pack('<H',count))
                u.mem_write(R.SOF_TIMER+0x544,struct.pack('<II',0x1234,0x5678))
                run(u,R.runtime(R.SOF_CALLBACK))
                results.append((bytearray(u.mem_read(0x23007000,4096)),bytearray(u.mem_read(R.SOF_TIMER,4096))))
            (rs,ts),(rp,tp)=results
            if state==3 and enabled:
                assert rp[R.SOF_STATE-0x23007000+2:R.SOF_STATE-0x23007000+4]==b'\x78\x34'
                assert ts[0x40:0x44]==b'\1\0\0\0' and tp[0x40:0x44]==bytes(4)
                rs[R.SOF_STATE-0x23007000+2:R.SOF_STATE-0x23007000+4]=rp[R.SOF_STATE-0x23007000+2:R.SOF_STATE-0x23007000+4]
                ts[0x40:0x44]=tp[0x40:0x44];ts[0x540:0x544]=tp[0x540:0x544]
            assert rs==rp and ts==tp,(enabled,state,acquiring,count,value)
            cases+=1
        # Actual patched IRQ callsite runs helper, returns to displaced successor.
        u=engines[1];isr=R.RADIO_HOOKS['sof_isr'][0];prev=0xEE
        for now in (0,1,124,249,0,25,0xFFFFFFFF):
            capture[0]=now
            u.mem_write(R.SOF_TIMER,bytes(4096));u.mem_write(R.SOF_TIMER+0x544,struct.pack('<I',prev))
            u.mem_write(0x23020010,struct.pack('<I',0x12345678))
            for i in range(13):u.reg_write(getattr(C,'UC_ARM_REG_R'+str(i)),0x200+i)
            u.reg_write(C.UC_ARM_REG_R4,0x23020000);u.reg_write(C.UC_ARM_REG_SP,stack)
            u.emu_start(isr|1,isr+4,count=100)
            assert u.reg_read(C.UC_ARM_REG_PC)==isr+4
            assert u.reg_read(C.UC_ARM_REG_R2)==0x12345678 and u.reg_read(C.UC_ARM_REG_R3)==5
            assert all(u.reg_read(getattr(C,'UC_ARM_REG_R'+str(i)))==0x200+i for i in (0,1,5,6,7,8,9,10,11))
            assert bytes(u.mem_read(R.SOF_TIMER+0x544,8))==struct.pack('<II',now,prev)
            assert bytes(u.mem_read(R.SOF_TIMER+0x40,4))==bytes(4)
            prev=now
        abs_results = _abs_checks(builder, engines)
        from .receiver_delivery_checks import verify as delivery_check
        delivery = delivery_check(builder)
        return dict(result='PASS',callback_cases=cases,irq_cases=7,new_ram_bytes=0,
                    startup_cases=startup_cases,
                    **abs_results,
                    delivery=delivery,
                    native_acquisition_preserved=True,relative_unchanged=True,hardware='not run')
    finally:
        for u,h in zip(engines,handles):u.hook_del(h)
        engines.clear();gc.collect()


def _startup_checks(engines):
    """Execute the evidenced native BSS clear before native queue setup.

    Queue init only owns headers; a dirty tail alone is not a cold-start
    reproduction. The real startup clear covers every ABS baseline byte.
    See receiver-startup.json and receiver-queue-ownership.json.
    """
    import unicorn.arm_const as C
    start, end = 0x23004280, 0x23007C00
    stack, stop = 0x23030000, 0x2303F000
    cases = 0
    for u in engines:
        for dirty in (0xA5, 0xFF):
            u.mem_write(start-4, bytes((dirty,)) * (end-start+8))
            u.reg_write(C.UC_ARM_REG_SP, stack)
            u.reg_write(C.UC_ARM_REG_LR, stop|1)
            u.emu_start(0x0E0BBBC9, stop, count=100000)
            assert u.reg_read(C.UC_ARM_REG_PC) == stop
            assert u.reg_read(C.UC_ARM_REG_SP) == stack
            assert bytes(u.mem_read(start, end-start)) == bytes(end-start)
            for boundary in (start-4, end):
                assert bytes(u.mem_read(boundary, 4)) == bytes((dirty,))*4
            for index in range(R.QUEUE_COUNT):
                u.reg_write(C.UC_ARM_REG_R0, index)
                u.reg_write(C.UC_ARM_REG_LR, stop|1)
                u.emu_start(0x0E0B4D1D, stop, count=2000)
                assert u.reg_read(C.UC_ARM_REG_PC) == stop
                header = R.QUEUE_BASE + index*R.QUEUE_STRIDE
                assert bytes(u.mem_read(header, 6)) == bytes((0,1,0,0,25,25))
            assert bytes(u.mem_read(R.ABS_VALID, 3)) == bytes(3)
            assert bytes(u.mem_read(R.ABS_Y, 2)) == bytes(2)
            cases += 1
    return cases


def _abs_checks(builder, engines):
    """Same native queues and dev RXABS model, on the actual target bytes."""
    import random
    from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    import unicorn.arm_const as C
    stop, stack, source, obj = 0x2303F000, 0x23030000, 0x23020000, 0x23021000
    queue_bytes = R.QUEUE_COUNT * R.QUEUE_STRIDE
    rng = random.Random(23)
    queue_ram = bytes(rng.getrandbits(8) for _ in range(queue_bytes))
    queue_cases = 0

    def reg(u, name):
        return u.reg_read(getattr(C, 'UC_ARM_REG_' + name.upper()))

    def run(u, entry, args, end=stop):
        u.reg_write(C.UC_ARM_REG_SP, stack)
        u.reg_write(C.UC_ARM_REG_LR, stop | 1)
        for i, value in enumerate(args):
            u.reg_write(getattr(C, 'UC_ARM_REG_R' + str(i)), value)
        for i in range(4, 12):
            u.reg_write(getattr(C, 'UC_ARM_REG_R' + str(i)), 0x1100 + i)
        u.emu_start(entry | 1, end, count=4000)
        assert reg(u, 'pc') == end, (hex(entry), hex(reg(u, 'pc')))
        assert reg(u, 'sp') == stack
        assert all(reg(u, 'r' + str(i)) == 0x1100 + i for i in range(4, 12))
        return reg(u, 'r0')

    # The object-prefix adapter starts at 6AB4, after the preceding literal.
    # Preserve it even though current direct callers only use the other two.
    for entry, index, write, full, length, basepri in itertools.product(
            (R.QUEUE_RAW, R.QUEUE_PREFIX, R.QUEUE_OBJECT), range(R.QUEUE_COUNT),
            (0, 24), (0, 1), (0, 1, 8, 24), (0, 0x20, 0x80)):
        outcomes = []
        for u in engines:
            u.mem_write(R.QUEUE_BASE, queue_ram)
            header = R.QUEUE_BASE + index * R.QUEUE_STRIDE
            u.mem_write(header, bytes((full, 0, write, 0, 25, 25, 0, 0)))
            u.mem_write(source, bytes(range(32)))
            u.mem_write(obj, b'\xCA')
            u.reg_write(C.UC_ARM_REG_BASEPRI, basepri)
            args = ((index, obj, source, length) if entry == R.QUEUE_OBJECT
                    else (index, source, length))
            value = run(u, R.runtime(entry), args)
            assert reg(u, 'basepri') == basepri
            outcomes.append((value, bytes(u.mem_read(R.QUEUE_BASE, queue_bytes))))
        assert outcomes[0] == outcomes[1], (hex(entry), index, write, full, length, basepri)
        queue_cases += 1
    for entry in (R.QUEUE_RAW, R.QUEUE_PREFIX, R.QUEUE_OBJECT):
        invalid = (((0, 0, source, 8), (0, obj, 0, 8), (0, obj, source, 0))
                   if entry == R.QUEUE_OBJECT else ((0, 0, 8), (0, source, 0)))
        for args in invalid:
            results = []
            for u in engines:
                u.mem_write(R.QUEUE_BASE, queue_ram)
                u.mem_write(source, bytes(range(32)))
                u.mem_write(obj, b'\xCA')
                results.append((run(u, R.runtime(entry), args),
                                bytes(u.mem_read(R.QUEUE_BASE, queue_bytes))))
            assert results[0] == results[1], (hex(entry), args)
            queue_cases += 1

    # Model from fixed dev rx_abs_patch.py: uint16 totals, first-frame baseline,
    # relative invalidation, and a >=0x4000 signed step resynchronises both axes.
    def model(valid, bx, by, header, x, y):
        if not header & 8:
            return False, bx, by, x, y
        if not valid:
            return True, x, y, 0, 0
        dx, dy = (x - bx) & 65535, (y - by) & 65535
        sx = dx - 65536 if dx & 32768 else dx
        sy = dy - 65536 if dy & 32768 else dy
        if abs(sx) >= R.ABS_JUMP_LIMIT or abs(sy) >= R.ABS_JUMP_LIMIT:
            dx = dy = 0
        return True, x, y, dx, dy

    frames = [(0x0A, 65530, 2), (0x0A, 4, 65534), (0x1A, 4, 65534),
              (0x02, 17, 65520), (0x0A, 500, 600)]
    x, y = 500, 600
    for step in (0x3FFF, 0x4000, 0x4001, -0x3FFF, -0x4000, -0x4001, 32768):
        for axis in (0, 1):
            x, y = ((x + step) & 65535, y) if axis == 0 else (x, (y + step) & 65535)
            frames.append((0x0A, x, y))
    for _ in range(600):
        x, y = (x + rng.randrange(-3000, 3001)) & 65535, (y + rng.randrange(-3000, 3001)) & 65535
        frames.append((rng.choice((0x02, 0x0A, 0x0A, 0x1A)), x, y))

    u = engines[1]
    u.mem_write(R.QUEUE_BASE, bytes(queue_bytes))
    state_addresses = {R.ABS_VALID, R.ABS_X, R.ABS_X + 1, R.ABS_Y, R.ABS_Y + 1}
    writes = []
    h = u.hook_add(UC_HOOK_MEM_WRITE,
                   lambda u, a, address, size, value, _: writes.append((address, size)))
    valid, bx, by = False, 0, 0
    usb_queue = 0x23005618 + 2 * 640
    def submit(header, x, y):
        u.mem_write(usb_queue, bytes((0,1,0,0,25,25)))
        u.mem_write(source, struct.pack('<BBHHBB',3,0,x,y,0,0) + bytes((header & 8,)))
        assert run(u, builder.symbols['abs_usb_report'], (2,source,8)) == 1
        return bytes(u.mem_read(usb_queue+18,4))
    def wake(u, address, size, _):
        if address == R.runtime(0x0E0C6C84):
            u.reg_write(C.UC_ARM_REG_R0, 0)
            u.reg_write(C.UC_ARM_REG_PC, reg(u, 'lr'))
    wake_hook = u.hook_add(UC_HOOK_CODE, wake)
    try:
        for header, x, y in frames:
            valid, bx, by, dx, dy = model(valid,bx,by,header,x,y)
            assert submit(header,x,y) == struct.pack('<HH',dx,dy)
            assert bool(u.mem_read(R.ABS_VALID, 1)[0]) == valid
            assert bytes(u.mem_read(R.ABS_X, 2)) == struct.pack('<H', bx)
            assert bytes(u.mem_read(R.ABS_Y, 2)) == struct.pack('<H', by)
        for address, size in writes:
            assert (stack - 256 <= address and address + size <= stack
                    or source <= address and address + size <= source + 9
                    or usb_queue <= address and address + size <= usb_queue + 640
                    or set(range(address, address + size)) <= state_addresses), (hex(address), size)
    finally:
        u.hook_del(h)

    # Exercise the native dispatcher, local FIFO report and USB acceptance.
    # The queued payload is still cumulative until the native FIFO consumer.
    sent, current, allocation_ok = [], [b''], [True]
    heap = 0x23022000

    def services(u, address, size, _):
        if address == R.runtime(R.RX_QUEUE_GET):
            destination = struct.unpack('<I', bytes(u.mem_read(reg(u, 'r0'), 4)))[0]
            u.mem_write(destination, current[0])
            value = 1
        elif address == R.runtime(R.NATIVE_ALLOC):
            value = heap if allocation_ok[0] else 0
        elif address == R.runtime(R.FIFO_PUT):
            sent.append(bytes(u.mem_read(reg(u, 'r1') + 6, 18)))
            value = 0
        else:
            return
        u.reg_write(C.UC_ARM_REG_R0, value)
        u.reg_write(C.UC_ARM_REG_PC, reg(u, 'lr'))

    h = u.hook_add(UC_HOOK_CODE, services)
    dispatch_cases = acceptance_cases = 0
    try:
        for ucase in (engines[0], engines[1]):
            ucase.mem_write(0x23007924, b'\1')
        u.mem_write(R.ABS_VALID, b'\0')
        valid, bx, by = False, 0, 0
        for header, x, y in frames[:80]:
            current[0] = struct.pack('<BBBHH', 7, header, rng.getrandbits(8), x, y)
            previous = valid,bx,by
            valid, bx, by, dx, dy = model(*previous,header,x,y)
            sent.clear()
            assert run(u, R.runtime(R.RECEIVE_DISPATCH), ()) == 1
            assert len(sent) == 1
            assert sent[0][0] == current[0][2] & 31
            assert sent[0][2:6] == struct.pack('<HH', x, y)
            assert sent[0][8] == header & 8
            assert bool(u.mem_read(R.ABS_VALID,1)[0]) == previous[0]
            assert submit(header,x,y) == struct.pack('<HH',dx,dy)
            assert bool(u.mem_read(R.ABS_VALID, 1)[0]) == valid
            assert bytes(u.mem_read(R.ABS_X, 2)) == struct.pack('<H', bx)
            assert bytes(u.mem_read(R.ABS_Y, 2)) == struct.pack('<H', by)
            dispatch_cases += 1
        # A rejected report must leave the last accepted cumulative point
        # intact. Later ABS reports recover that displacement without a new
        # retry mechanism, including when a relative report was refused.
        attempts = [
            (0x0A, 100, 200, 1, False),
            (0x0A, 110, 190, 1, True),
            (0x0A, 117, 184, 0, True),
            (0x0A, 122, 178, 1, False),
            (0x0A, 129, 170, 1, True),
            (0x02, 5, 65530, 1, False),
            (0x0A, 135, 168, 1, True),
            (0x02, 4, 65528, 0, True),
            (0x0A, 140, 167, 1, True),
            (0x02, 4, 65528, 1, True),
            (0x0A, 0, 0, 1, True),
            (0x0A, 3, 65534, 1, True),
        ]
        for basepri in (0, 0x20, 0x80):
            u.mem_write(R.ABS_VALID, b'\0')
            u.mem_write(R.ABS_X, bytes(2))
            u.mem_write(R.ABS_Y, bytes(2))
            valid, bx, by = False, 0, 0
            accepted = []
            for header, x, y, active, allocate in attempts:
                u.reg_write(C.UC_ARM_REG_BASEPRI, basepri)
                u.mem_write(0x23007924, bytes((active,)))
                current[0] = struct.pack('<BBBHH', 7, header, 3, x, y)
                allocation_ok[0] = allocate
                previous = valid, bx, by
                next_valid, next_x, next_y, dx, dy = model(*previous, header, x, y)
                sent.clear()
                assert run(u, R.runtime(R.RECEIVE_DISPATCH), ()) == (1 if active else 2)
                if active and allocate:
                    valid, bx, by = next_valid, next_x, next_y
                    assert len(sent) == 1
                    assert sent[0][2:6] == struct.pack('<HH', x, y)
                    assert submit(header,x,y) == struct.pack('<HH',dx,dy)
                    if header & 8:
                        accepted.append((dx, dy))
                else:
                    assert not sent
                assert bool(u.mem_read(R.ABS_VALID, 1)[0]) == valid
                assert bytes(u.mem_read(R.ABS_X, 2)) == struct.pack('<H', bx)
                assert bytes(u.mem_read(R.ABS_Y, 2)) == struct.pack('<H', by)
                assert reg(u, 'basepri') == basepri
                acceptance_cases += 1
            assert accepted == [(0, 0), (19, 65516), (6, 65534), (5, 65535),
                                (0, 0), (3, 65534)]
    finally:
        u.hook_del(h)
        u.hook_del(wake_hook)
    return dict(queue_contract_cases=queue_cases, abs_cases=len(frames),
                abs_dispatch_cases=dispatch_cases, abs_acceptance_cases=acceptance_cases,
                queue_padding_bytes=5,
                queue_capacity=R.QUEUE_CAPACITY, abs_link_table_untouched=True)
