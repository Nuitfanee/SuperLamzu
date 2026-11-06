"""MAYA absolute stage: native saturation and dual-sample radio ownership."""
import itertools
import struct
import unittest
from unicorn import UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_PRIMASK

from MAYA_X_V2 import target as T
from MAYA_X_V2.advanced import build_absolute_stage
from MAYA_X_V2.sensor import LAYOUT
from superlamzu.emulation import Arm
from superlamzu.verify import patched_image

HEAP = T.NATIVE_HEAP_START+0x404


class AbsoluteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.builder = build_absolute_stage()
        cls.changed = patched_image(cls.builder)

    def cpu(self, enabled=True, patched=True):
        cpu = Arm(self.changed if patched else self.builder.image, layout=LAYOUT)
        cpu.uc.mem_write(T.SETTINGS, self.changed.get(T.SETTINGS_DEFAULT,T.SETTINGS_BYTES))
        cpu.uc.mem_write(HEAP,bytes(T.SNAPSHOT_STORAGE_BYTES))
        cpu.uc.mem_write(T.SNAPSHOT_POINTER,(HEAP&0xFFFFF).to_bytes(3,'little'))
        cpu.uc.mem_write(T.MOTION_STATE,bytes((cpu.byte(T.MOTION_STATE)|(64 if enabled else 0),)))
        cpu.uc.mem_write(T.ADV_RAM,b'\1'+bytes(187))
        cpu.stub(0x2A550)
        cpu.stub(0x2A4E8)
        cpu.stub(0x20005D10)
        cpu.stub(0x20005E08,2)
        cpu.stub(0x20002E48)
        cpu.stub(0x20002E80)
        def memcpy(c):
            c.uc.mem_write(c.reg('r0'),bytes(c.uc.mem_read(c.reg('r1'),c.reg('r2'))))
            return c.reg('r0')
        cpu.stub(T.NATIVE_MEMCPY,effect=memcpy)
        for queue in range(7):cpu.run(T.QUEUE_INIT,queue)
        # queue0..6 native init must not destroy the verified queue2 tail.
        return cpu

    def test_native_accumulation_saturates_but_totals_wrap_after_transform(self):
        for enabled,acc,delta in itertools.product((False,True),(0,32760,-32760),(100,-100,32767,-32768)):
            results=[]
            for patched in (False,True):
                with self.cpu(enabled,patched) as cpu:
                    sample=0x20016000
                    cpu.uc.mem_write(sample,struct.pack('<BBhh',1,0,delta,-delta if delta!=-32768 else 32767))
                    cpu.uc.mem_write(T.MOTION_ACC_X,struct.pack('<h',acc))
                    cpu.uc.mem_write(T.MOTION_ACC_Y,struct.pack('<h',-acc))
                    cpu.uc.mem_write(HEAP+24,struct.pack('<HH',65530,5))
                    cpu.run(T.MOTION_NATIVE,sample,count=100000)
                    dx,dy=struct.unpack('<hh',bytes(cpu.uc.mem_read(sample+2,4)))
                    results.append((bytes(cpu.uc.mem_read(T.MOTION_ACC_Y,4)),cpu.reg('sp')))
                    if patched:
                        self.assertEqual(struct.unpack('<HH',bytes(cpu.uc.mem_read(HEAP+24,4))),
                            ((65530+dx)&65535,(5+dy)&65535) if enabled else (65530,5))
            self.assertEqual(results[0],results[1])

    def test_enqueue_time_totals_and_native_ordered_two_sample_assembly(self):
        with self.cpu() as cpu:
            cpu.uc.mem_write(T.RADIO_STATE,b'\1\1')
            packet=0x20016000
            for totals in ((10,20),(30,45)):
                cpu.uc.mem_write(HEAP+24,struct.pack('<HH',*totals))
                cpu.uc.mem_write(packet,b'\0'*4+struct.pack('<hh',1,2))
                self.assertEqual(cpu.run(T.RADIO_SEND,9,packet),1)
            frame=0x20016100
            self.assertEqual(cpu.run(T.ABS_FRAME_NATIVE,frame,1),1)
            self.assertEqual(bytes(cpu.uc.mem_read(frame,12)),b'\x0b\0\x0a\0'+struct.pack('<HHHH',10,20,30,45))
            self.assertEqual(cpu.run(T.QUEUE_COUNT,2),0)

    def test_total_fast_path_cost_atomic_publication_and_native_abi(self):
        from unicorn import UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
        from unicorn.arm_const import UC_ARM_REG_BASEPRI
        from tools.audit_hotpaths import measure

        for enabled, present, mask, tags in itertools.product(
                (False, True), (False, True), (0, 1), (0, 0x10, 0x20, 0x30, 0x80, 0xB0)):
            with self.subTest(enabled=enabled, present=present, mask=mask, tags=tags), self.cpu(enabled) as cpu:
                stack = cpu.layout.stack
                packed = ((HEAP & 0xFFFFF) if present else 0) | ((tags | (64 if enabled else 0)) << 16)
                cpu.uc.mem_write(T.SNAPSHOT_POINTER-1, b'\xa5' + packed.to_bytes(3, 'little'))
                cpu.uc.mem_write(HEAP, b'\xa5' * T.SNAPSHOT_STORAGE_BYTES)
                cpu.uc.mem_write(HEAP+24, struct.pack('<HH', 65533, 100))
                cpu.uc.mem_write(stack+14, struct.pack('<HH', 19, 65529))
                cpu.uc.mem_write(T.MOTION_ACC_X, struct.pack('<h', -100))
                cpu.uc.reg_write(UC_ARM_REG_PRIMASK, mask)
                cpu.uc.reg_write(UC_ARM_REG_BASEPRI, 0x60)
                preserved = list(range(4, 13))
                for register in preserved:
                    cpu.setreg(f'r{register}', 0xA000 + register)
                reads, heap_reads, writes = [], [], []
                def read(uc, access, address, size, value, user):
                    reads.append((address, size))
                def heap_read(uc, access, address, size, value, user):
                    heap_reads.append((address, size))
                def write(uc, access, address, size, value, user):
                    writes.append((address, size))
                def instruction(uc, address, size, user):
                    self.assertEqual(uc.reg_read(UC_ARM_REG_PRIMASK), mask)
                    self.assertEqual(uc.reg_read(UC_ARM_REG_BASEPRI), 0x60)
                cpu.add_hook(UC_HOOK_MEM_READ, read, begin=T.SNAPSHOT_POINTER-1, end=T.MOTION_STATE)
                cpu.add_hook(UC_HOOK_MEM_READ, heap_read, begin=HEAP, end=HEAP+T.SNAPSHOT_STORAGE_BYTES-1)
                cpu.add_hook(UC_HOOK_MEM_WRITE, write)
                cpu.add_hook(UC_HOOK_CODE, instruction)
                cost = measure(cpu, self.builder.absolute['total'], (0x12345678,))
                self.assertEqual(cpu.reg('r0'), 0x12345678)
                self.assertEqual(cpu.reg('sp'), stack)
                self.assertEqual(cpu.reg('lr'), cpu.stop | 1)
                self.assertEqual([cpu.reg(f'r{r}') for r in preserved], [0xA000 + r for r in preserved])
                self.assertEqual(cpu.reg('r1'), 19)
                self.assertEqual(cpu.reg('r2'), T.MOTION_ACC_X)
                self.assertEqual(cpu.reg('r3'), (-81) & 0xFFFFFFFF)
                self.assertEqual(reads, [(T.SNAPSHOT_POINTER-1, 4)])
                self.assertLessEqual(cost['instructions'], 23 if enabled and present else 15 if enabled else 11)
                active = enabled and present
                self.assertEqual(heap_reads, [(HEAP+24, 4)] if active else [])
                self.assertEqual(struct.unpack('<HH', cpu.uc.mem_read(HEAP+24, 4)),
                                 ((65533 + 19 * active) & 65535, 100 - 7 * active))
                self.assertEqual(bytes(cpu.uc.mem_read(T.MOTION_ACC_X, 2)), struct.pack('<h', -100))
                self.assertEqual([(a, n) for a, n in writes if HEAP <= a < HEAP+T.SNAPSHOT_STORAGE_BYTES],
                                 [(HEAP+24, 4)] if active else [])
                self.assertTrue(all((enabled and stack-16 <= a and a+n <= stack)
                                    or (active and a == HEAP+24 and n == 4) for a, n in writes))
                self.assertEqual(bytes(cpu.uc.mem_read(HEAP, 24)), b'\xa5' * 24)
                self.assertEqual(bytes(cpu.uc.mem_read(HEAP+28, T.SNAPSHOT_STORAGE_BYTES-28)),
                                 b'\xa5' * (T.SNAPSHOT_STORAGE_BYTES-28))

    def test_button_only_and_real_retransmit_copy_refresh_without_double_add(self):
        with self.cpu() as cpu:
            cpu.uc.mem_write(T.RADIO_STATE,b'\1\1')
            cpu.uc.mem_write(HEAP+24,struct.pack('<HH',123,456))
            cpu.uc.mem_write(0x2000E8C3,b'\x02')
            self.assertEqual(cpu.run(T.ABS_FRAME_NATIVE,T.ABS_FRAME_BUFFER,0),1)
            self.assertEqual(bytes(cpu.uc.mem_read(T.ABS_FRAME_BUFFER+2,6)),b'\x0a\x02'+struct.pack('<HH',123,456))
            for length,state in itertools.product((7,11),(4,6,8)):
                old=bytes((length,0,10,0))+struct.pack('<HHHH',100,200,300,400)
                cpu.uc.mem_write(T.ABS_TX_BUFFER,old)
                cpu.uc.mem_write(T.RADIO_STATE+0x186,bytes((state,)))
                cpu.run(self.changed.u32(T.flash_source(T.ABS_COPY_POINTER))&~1,
                        T.ABS_DMA_BUFFER,T.ABS_TX_BUFFER,length+1)
                expected=(bytes((length,0,10,0))+struct.pack('<HHHH',123,456,123,456)) if state in (4,6) else old
                self.assertEqual(bytes(cpu.uc.mem_read(T.ABS_DMA_BUFFER,length+1)),expected[:length+1])
                self.assertEqual(bytes(cpu.uc.mem_read(HEAP+24,4)),struct.pack('<HH',123,456))

    def test_relative_native_frame_and_copy_remain_byte_identical(self):
        for count,dual in itertools.product((0,1,2),(0,1)):
            results=[]
            for patched in (False,True):
                with self.cpu(False,patched) as cpu:
                    cpu.uc.mem_write(0x2000E8C3,b'\x01')
                    for i in range(count):
                        p=0x20016000
                        cpu.uc.mem_write(p,struct.pack('<hh',123+i,-456-i))
                        cpu.run(T.QUEUE_WRITE_RAW,2,p,4)
                    frame=0x20016100
                    result=cpu.run(T.ABS_FRAME_NATIVE,frame,dual)
                    results.append((result,bytes(cpu.uc.mem_read(frame,12)),cpu.run(T.QUEUE_COUNT,2)))
            self.assertEqual(results[0],results[1])

    def test_abs_pointer_reads_one_tagged_word_without_clobbering_send_arguments(self):
        for pointer,tags in itertools.product((0,HEAP),(0,0x10,0x20,0x40,0xD0,0xE0,0xF0)):
            with self.cpu() as cpu:
                cpu.uc.mem_write(T.SNAPSHOT_POINTER-1,b'\xa5'+
                    ((pointer&0xFFFFF)|(tags<<16)).to_bytes(3,'little'))
                expected=pointer if tags&0x40 else 0
                cpu.run(self.builder.absolute['pointer'],0x10203040,0x50607080,0x90A0B0C0)
                self.assertEqual(cpu.reg('r3'),expected,(pointer,tags))
                self.assertEqual([cpu.reg(f'r{i}') for i in range(3)],
                                 [0x10203040,0x50607080,0x90A0B0C0])
                self.assertEqual(cpu.reg('sp'),T.SP)

    def test_relative_retry_fast_path_reaches_native_copy_without_stack_or_heap(self):
        from tools.audit_hotpaths import measure
        for tags in (0,0x10,0x20,0x80,0xB0):
            with self.cpu(False) as cpu:
                cpu.uc.mem_write(T.MOTION_STATE,bytes((tags,)))
                source,destination=0x20016000,0x20016100
                payload=bytes(range(25))
                cpu.uc.mem_write(source,payload)
                cpu.setreg('r12',0xA00C)
                calls=[]
                def native_copy(c):
                    calls.append(([c.reg(f'r{i}') for i in range(3)],c.reg('sp'),c.reg('r12')))
                    c.uc.mem_write(c.reg('r0'),bytes(c.uc.mem_read(c.reg('r1'),c.reg('r2'))))
                    return c.reg('r0')
                cpu.stub(T.NATIVE_MEMCPY,effect=native_copy)
                cost=measure(cpu,self.builder.absolute['copy'],(destination,source,len(payload)))
                self.assertEqual(calls,[([destination,source,len(payload)],T.SP,0xA00C)])
                self.assertEqual(bytes(cpu.uc.mem_read(destination,len(payload))),payload)
                self.assertLessEqual(cost['instructions'],8)
                self.assertEqual(cost['masked_instructions'],0)

    def test_frame_reuses_count_snapshot_and_reduces_relative_and_absolute_work(self):
        from tools.audit_hotpaths import measure
        for enabled,maximum in ((False,151),(True,171)):
            with self.cpu(enabled) as cpu:
                cpu.uc.mem_write(0x2000E8C3,b'\x02')
                cpu.uc.mem_write(HEAP+24,struct.pack('<HH',123,456))
                cost=measure(cpu,T.ABS_FRAME_NATIVE,(T.ABS_FRAME_BUFFER,0))
                self.assertLessEqual(cost['instructions'],maximum)
                self.assertEqual(cost['masked_instructions'],0)
                self.assertEqual(cpu.byte(T.ABS_FRAME_BUFFER+2),10 if enabled else 2)
                self.assertEqual(struct.unpack('<HH',cpu.uc.mem_read(T.ABS_FRAME_BUFFER+4,4)),
                                 (123,456) if enabled else (0,0))
                self.assertEqual(cpu.reg('sp'),T.SP)

    def test_frame_without_heap_stays_relative_and_preserves_callee_saved_registers(self):
        for enabled in (False,True):
            with self.cpu(enabled) as cpu:
                cpu.uc.mem_write(T.SNAPSHOT_POINTER,b'\0\0'+bytes((64 if enabled else 0,)))
                cpu.uc.mem_write(0x2000E8C3,b'\x02')
                for register in range(4,12):cpu.setreg(f'r{register}',0xA000+register)
                self.assertEqual(cpu.run(T.ABS_FRAME_NATIVE,T.ABS_FRAME_BUFFER,0),1)
                self.assertEqual(cpu.byte(T.ABS_FRAME_BUFFER+2),2)
                self.assertEqual(bytes(cpu.uc.mem_read(T.ABS_FRAME_BUFFER+4,4)),bytes(4))
                self.assertEqual([cpu.reg(f'r{i}') for i in range(4,12)],
                                 [0xA000+i for i in range(4,12)])
                self.assertEqual(cpu.run(T.ABS_FRAME_NATIVE,0,0),0)
                self.assertEqual(cpu.reg('sp'),T.SP)

    def test_retransmit_does_not_overtake_queued_dual_sample_totals(self):
        with self.cpu() as cpu:
            cpu.uc.mem_write(T.RADIO_STATE,b'\1\1')
            packet=0x20016000
            for x in (10,20,30,40,50):
                cpu.uc.mem_write(HEAP+24,struct.pack('<HH',x,0))
                cpu.uc.mem_write(packet,bytes(8))
                self.assertEqual(cpu.run(T.RADIO_SEND,9,packet),1)
            self.assertEqual(cpu.run(T.ABS_FRAME_NATIVE,T.ABS_TX_BUFFER,1),1)
            first=bytes(cpu.uc.mem_read(T.ABS_TX_BUFFER,12))
            self.assertEqual(struct.unpack('<HHHH',first[4:]),(10,0,20,0))
            for state in (4,6):
                cpu.uc.mem_write(T.RADIO_STATE+0x186,bytes((state,)))
                cpu.run(self.builder.absolute['copy'],T.ABS_DMA_BUFFER,T.ABS_TX_BUFFER,12)
                self.assertEqual(bytes(cpu.uc.mem_read(T.ABS_DMA_BUFFER,12)),first,
                                 'retry must not overtake queued totals 30/40/50')
            self.assertEqual(cpu.run(T.ABS_FRAME_NATIVE,T.ABS_FRAME_BUFFER,1),1)
            self.assertEqual(struct.unpack('<HHHH',cpu.uc.mem_read(T.ABS_FRAME_BUFFER+4,8)),(30,0,40,0))
            self.assertEqual(cpu.run(T.ABS_FRAME_NATIVE,T.ABS_FRAME_BUFFER,1),1)
            self.assertEqual(struct.unpack('<HH',cpu.uc.mem_read(T.ABS_FRAME_BUFFER+4,4)),(50,0))
            cpu.uc.mem_write(HEAP+24,struct.pack('<HH',60,70))
            cpu.run(self.builder.absolute['copy'],T.ABS_DMA_BUFFER,T.ABS_TX_BUFFER,12)
            self.assertEqual(struct.unpack('<HHHH',cpu.uc.mem_read(T.ABS_DMA_BUFFER+4,8)),(60,70,60,70))

    def test_abs_switch_rejects_queued_other_format_without_losing_samples(self):
        from superlamzu import protocol as P
        from superlamzu.verify import request
        from unicorn.arm_const import UC_ARM_REG_PRIMASK
        for initially,mask,count in itertools.product((False,True),(0,1),(1,8)):
            with self.cpu(initially) as cpu:
                cpu.uc.mem_write(T.RADIO_STATE,b'\1\1')
                cpu.uc.mem_write(HEAP+24,struct.pack('<HH',1000,2000))
                p=0x20016000
                cpu.uc.mem_write(p,b'\0'*4+struct.pack('<hh',10,20))
                for _ in range(count):
                    self.assertEqual(cpu.run(T.RADIO_SEND,9,p),1)
                queue=bytes(cpu.uc.mem_read(T.RADIO_QUEUE2,T.QUEUE_HEADER+8*12))
                cpu.uc.reg_write(UC_ARM_REG_PRIMASK,mask)
                # Idempotent writes remain valid even while motion is queued.
                self.assertEqual(request(cpu,P.SET,(0,P.ABS_MOTION,int(initially)),target=T)[0],0xA0)
                self.assertEqual(request(cpu,P.SET,(0,P.ABS_MOTION,int(not initially)),target=T)[0],0xA2)
                self.assertEqual(cpu.uc.reg_read(UC_ARM_REG_PRIMASK),mask)
                self.assertEqual(bytes(cpu.uc.mem_read(T.RADIO_QUEUE2,len(queue))),queue)
                self.assertEqual(request(cpu,P.GET,(0,P.ABS_MOTION),target=T)[1][2],int(initially))
                for _ in range((count+1)//2):
                    self.assertEqual(cpu.run(T.ABS_FRAME_NATIVE,T.ABS_FRAME_BUFFER,1),1)
                    self.assertEqual(cpu.byte(T.ABS_FRAME_BUFFER+2),10 if initially else 2)
                    self.assertEqual(struct.unpack('<HH',cpu.uc.mem_read(T.ABS_FRAME_BUFFER+4,4)),
                                     (1000,2000) if initially else (10,20))
                self.assertEqual(request(cpu,P.SET,(0,P.ABS_MOTION,int(not initially)),target=T)[0],0xA0)

    def test_producer_preempts_retry_and_empty_frame_without_reordering(self):
        from superlamzu.common import assemble
        from superlamzu.advanced import addr
        producer,packet=0x20025000,0x20016000
        def fixture():
            cpu=self.cpu();cpu.uc.mem_write(T.RADIO_STATE,b'\1\1')
            cpu.uc.mem_write(HEAP+24,struct.pack('<HH',10,0))
            cpu.uc.mem_write(T.ABS_TX_BUFFER,b'\7\0\x0a\0'+struct.pack('<HH',10,0))
            cpu.uc.mem_write(T.RADIO_STATE+0x186,b'\4')
            code=['push {r4,lr}',*addr('r3',HEAP+24),'movs r2,#20','str r2,[r3]',
                  *addr('r1',packet),'movs r0,#9',*addr('r12',T.RADIO_SEND|1),'blx r12',
                  *addr('r3',HEAP+24),'movs r2,#30','str r2,[r3]','pop {r4,pc}']
            cpu.uc.mem_write(producer,assemble(code,producer))
            return cpu
        for key,args in (('copy',(T.ABS_DMA_BUFFER,T.ABS_TX_BUFFER,8)),
                         ('frame',(T.ABS_FRAME_BUFFER,1))):
            start=self.builder.absolute[key]
            ranges=[(int(x['address'],0),int(x['address'],0)+x['bytes'])
                    for x in self.builder.allocations if x['name'] in
                    ('abs_copy','abs_pointer','abs_frame','abs_frame_count','maya_frame_native')]
            ranges.append((T.ABS_FRAME_CONTINUE,0x200046D0))
            with fixture() as cpu:
                boundaries=[];seen={}
                def trace(uc,a,s,u):
                    if any(lo<=a<hi for lo,hi in ranges):
                        seen[a]=seen.get(a,0)+1
                        if not uc.reg_read(UC_ARM_REG_PRIMASK):boundaries.append((a,seen[a]))
                cpu.add_hook(UC_HOOK_CODE,trace)
                # Force a button-only frame so both pre/post-native paths run.
                cpu.uc.mem_write(0x2000E8C3,b'\2')
                cpu.run(start,*args)
            for boundary,nth in boundaries:
                with self.subTest(path=key,boundary=hex(boundary)),fixture() as cpu:
                    cpu.uc.mem_write(0x2000E8C3,b'\2')
                    self.assertTrue(cpu.preempt((start,args),(producer,()),boundary,nth))
                    frame=T.ABS_DMA_BUFFER if key=='copy' else T.ABS_FRAME_BUFFER
                    first=struct.unpack('<H',cpu.uc.mem_read(frame+4,2))[0]
                    self.assertIn(first,(10,20))
                    if cpu.run(T.QUEUE_COUNT,2):
                        self.assertEqual(cpu.run(T.ABS_FRAME_NATIVE,T.ABS_FRAME_BUFFER,1),1)
                        self.assertEqual(struct.unpack('<H',cpu.uc.mem_read(T.ABS_FRAME_BUFFER+4,2))[0],20)

    def test_abs_switch_rejects_unsent_xy_without_blocking_native_retry(self):
        from superlamzu import protocol as P
        from superlamzu.verify import request
        from unicorn.arm_const import UC_ARM_REG_PRIMASK
        for enabled, mask, pending in itertools.product((False, True), (0, 1),
                                                       ((110, 0), (0, -220), (110, -220))):
            with self.cpu(enabled) as cpu:
                cpu.uc.mem_write(T.MOTION_ACC_X, struct.pack('<h', pending[0]))
                cpu.uc.mem_write(T.MOTION_ACC_Y, struct.pack('<h', pending[1]))
                cpu.uc.reg_write(UC_ARM_REG_PRIMASK, mask)
                self.assertEqual(request(cpu, P.SET, (0, P.ABS_MOTION, int(enabled)), target=T)[0], 0xA0)
                self.assertEqual(request(cpu, P.SET, (0, P.ABS_MOTION, int(not enabled)), target=T)[0], 0xA2)
                self.assertEqual(bytes(cpu.uc.mem_read(T.MOTION_ACC_Y, 4)), struct.pack('<hh', *pending[::-1]))
                self.assertEqual(cpu.uc.reg_read(UC_ARM_REG_PRIMASK), mask)
                # Execute the native report, not a synthetic accumulator clear.
                cpu.stub(0x20005E08, 1)
                cpu.stub(0x200052D4, 8)
                cpu.stub(0x2007B410)
                cpu.stub(0x20005CB8)
                cpu.uc.mem_write(T.REPORT_DIVIDER, b'\1')
                cpu.uc.mem_write(T.RADIO_STATE, b'\1\1')
                cpu.run(T.REPORT_NATIVE, count=100000)
                self.assertEqual(bytes(cpu.uc.mem_read(T.MOTION_ACC_Y, 4)), bytes(4))
                # Pop the actual queued payload before changing its format.
                self.assertEqual(cpu.run(T.QUEUE_COUNT, 2), 1)
                self.assertEqual(request(cpu, P.SET, (0, P.ABS_MOTION, int(not enabled)), target=T)[0], 0xA2)
                for _ in range(cpu.run(T.QUEUE_COUNT, 2)):
                    cpu.run(T.QUEUE_READ_RAW, 2, 0x20016000, 12)
                    self.assertEqual(struct.unpack('<hh', cpu.uc.mem_read(0x20016000, 4)),
                                     (0, 0) if enabled else pending)
                self.assertEqual(request(cpu, P.SET, (0, P.ABS_MOTION, int(not enabled)), target=T)[0], 0xA0)
                self.assertEqual(cpu.uc.reg_read(UC_ARM_REG_PRIMASK), mask)

    def test_abs_switch_preserves_inflight_owner_and_shared_motion_bits(self):
        from superlamzu import protocol as P
        from superlamzu.verify import request
        from unicorn.arm_const import UC_ARM_REG_PRIMASK
        for enabled,mask in itertools.product((0,1),(0,1)):
            with self.cpu(bool(enabled)) as cpu:
                state=cpu.byte(T.MOTION_STATE)|0x30
                cpu.uc.mem_write(T.MOTION_STATE,bytes((state,)))
                cpu.uc.reg_write(UC_ARM_REG_PRIMASK,mask)
                self.assertEqual(request(cpu,P.SET,(0,P.ABS_MOTION,1-enabled),target=T)[0],0xA2)
                self.assertEqual(cpu.byte(T.MOTION_STATE),state)
                self.assertEqual(cpu.uc.reg_read(UC_ARM_REG_PRIMASK),mask)
                cpu.uc.mem_write(T.MOTION_STATE,bytes((state&~0x20,)))
                self.assertEqual(request(cpu,P.SET,(0,P.ABS_MOTION,1-enabled),target=T)[0],0xA0)
                self.assertEqual(cpu.byte(T.MOTION_STATE),(state&~0x60)|((1-enabled)<<6))

    def test_host_observes_busy_abs_rejection_then_can_retry(self):
        from superlamzu import cfg
        with self.cpu(False) as cpu:
            class Device:
                def set_report(self,packet):
                    cpu.uc.mem_write(T.PACKET,packet)
                    cpu.uc.mem_write(T.PACKET,b'\xa0')
                    cpu.run(T.GROUP1)
                    result=bytearray(cpu.uc.mem_read(T.PACKET,64))
                    if result[0]==0xA0:result[0]=0xA1
                    self.reply=bytes(result)
                def get_report(self):return b'\0'+self.reply
            mouse=cfg.Mouse(cfg.Link(Device(),delay=0),0,1)
            cpu.uc.mem_write(T.MOTION_STATE,bytes((cpu.byte(T.MOTION_STATE)|32,)))
            with self.assertRaises(cfg.CfgRejected):mouse.abs_motion(True)
            self.assertFalse(mouse.abs_motion()['enabled'])
            cpu.uc.mem_write(T.MOTION_STATE,bytes((cpu.byte(T.MOTION_STATE)&~32,)))
            self.assertTrue(mouse.abs_motion(True)['enabled'])


if __name__=='__main__':unittest.main()
