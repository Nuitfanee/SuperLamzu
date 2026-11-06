"""Native synchronous and independent done-thread Thumb acceptance."""
import struct
import unittest
from dataclasses import replace

from unicorn import UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_PRIMASK

from MAYA_X_V2 import target as T
from MAYA_X_V2.advanced import build_motion_stage
from MAYA_X_V2.sensor import LAYOUT
from superlamzu import protocol as P
from superlamzu.emulation import Arm
from superlamzu.verify import patched_image, request
from superlamzu.settings import encode_record, decode_record

HEAP=T.NATIVE_HEAP_START+0x404
RING=HEAP+T.MOTION_RING_OFFSET
DONE=(HEAP+0x407)&~7


class MotionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.builder=build_motion_stage('SUPER')
        cls.changed=patched_image(cls.builder)

    def cpu(self):
        cpu=Arm(self.changed,layout=LAYOUT)
        cpu.uc.mem_write(T.SETTINGS,self.changed.get(T.SETTINGS_DEFAULT,T.SETTINGS_BYTES))
        cpu.uc.mem_write(HEAP,bytes(T.SNAPSHOT_STORAGE_BYTES))
        cpu.uc.mem_write(T.SNAPSHOT_POINTER,(HEAP&0xFFFFF).to_bytes(3,'little'))
        cpu.uc.mem_write(T.ADV_RAM,b'\1\1'+bytes(186))
        # Real native queue init/put/get; only scheduler reschedule service
        # is bounded. Empty wait list exercises real buffered message owner.
        cpu.run(0x34920,T.SENSOR_QUEUE,T.SENSOR_QUEUE+40,12,10)
        cpu.stub(0x2A550)
        cpu.stub(0x20005E08,1)
        cpu.stub(T.SET_SENSOR_MODE)
        cpu.stub(0x3089E,effect=lambda c: HEAP-4 if c.reg('r1')==T.SNAPSHOT_STORAGE_BYTES+4 else DONE-4)
        cpu.stub(T.MOTION_THREAD_START)
        if 'initialize' in self.builder.motion:
            cpu.run(self.builder.motion['initialize'],HEAP,count=100000)
        else:
            # Archived audit candidates used the native configuration queue.
            cpu.stub(T.MOTION_SEM_GIVE)
        cpu.events=[]
        cpu.stub(T.MOTION_NATIVE,effect=lambda c:cpu.events.append(
            (bytes(c.uc.mem_read(c.reg('r0'),6)),c.byte(T.MOTION_STATE)&32)))
        return cpu

    def sample(self,cpu,n):
        p=0x20016000
        raw=struct.pack('<BBhh',1,n&1,n,-n)
        cpu.uc.mem_write(p,raw)
        cpu.run(self.builder.motion['route'],p,count=100000)
        # Verify caller's stack-backed input can immediately be reused.
        cpu.uc.mem_write(p,b'\xa5'*6)
        return raw

    def run_done(self,cpu):
        """Run the installed consumer through real semaphore takes to idle."""
        runtime=cpu.u32(RING+4)
        cpu.stubs.pop(T.MOTION_SEM_TAKE,None)
        wait=self.builder.motion['thread']+4
        def idle(uc,address,size,user):
            if not cpu.u32(runtime+8):uc.emu_stop()
        handle=cpu.uc.hook_add(UC_HOOK_CODE,idle,begin=wait,end=wait)
        try:
            cpu.setreg('sp',runtime+192+1024-64)
            cpu.setreg('r0',runtime)
            cpu.uc.emu_start(self.builder.motion['thread']|1,cpu.stop,count=200000)
            self.assertEqual(cpu.reg('pc'),wait)
        finally:cpu.uc.hook_del(handle)

    def registered_cpu(self,via,direct,kind):
        cpu=self.cpu()
        cpu.run(0x16130)
        cpu.put32(T.REPORT_DRIVER,T.REPORT_DRIVER_TABLE)
        cpu.uc.mem_write(T.MOTION_STATE,bytes((cpu.byte(T.MOTION_STATE)|16*direct,)))
        cpu.stub(0x20005E08,via)
        cpu.stubs.pop(T.MOTION_NATIVE)
        for address in (0x20005D10,0x20002E48,0x20002E80,0x20005CB8):cpu.stub(address)
        cpu.stub(0x200052D4,8)
        cpu.stub(0x2007B410,effect=lambda c:c.u32(c.reg('r0')))
        def clear(c):
            value=c.u32(c.reg('r0'))&c.reg('r1')
            c.put32(c.reg('r0'),value)
            return value
        cpu.stub(0x2007B400,effect=clear)
        cpu.uc.mem_write(T.SENSOR_READY,b'\1')
        cpu.uc.mem_write(T.SETTINGS+705,b'\1')
        cpu.uc.mem_write(T.REPORT_DIVIDER,b'\1')
        wheel={'xy':0,'wheel_up':1,'wheel_down':-1}[kind]
        cpu.uc.mem_write(0x2000E540,bytes((wheel&255,)))
        cpu.put32(0x2000C32C,2 if wheel else 0)
        cpu.put32(0x2000B5D4,0)
        cpu.put32(T.MOTION_CALLBACK,self.changed.u32(T.MOTION_CALLBACK_POINTER))
        cpu.bursts=[];cpu.submits=[]
        def burst(c):
            self.assertEqual(c.reg('r2'),6)
            cpu.bursts.append(c.byte(T.MOTION_STATE))
            raw=bytes((0xA4 if kind=='xy' else 0x24,0xB7))
            c.uc.mem_write(c.reg('r1'),raw+struct.pack('<hh',*( (123,-45) if kind=='xy' else (0,0))))
            return 1
        def submit(c):
            op,p=c.reg('r0'),c.reg('r1')
            result=dict(op=op)
            if not via:
                self.assertEqual(op,3)
                result['wheel']=struct.unpack('<b',bytes(c.uc.mem_read(p+1,1)))[0]
                result['xy']=struct.unpack('<hh',bytes(c.uc.mem_read(p+2,4)))
            elif op==9:result['xy']=struct.unpack('<hh',bytes(c.uc.mem_read(p+4,4)))
            else:
                self.assertEqual(op,8)
                result['wheel']=struct.unpack('<b',bytes(c.uc.mem_read(p+3,1)))[0]
            cpu.submits.append(result)
            return 1
        cpu.stub(T.SENSOR_BURST,effect=burst)
        cpu.stub(T.RADIO_SEND if via else 0x20003720,effect=submit)
        return cpu

    def test_registered_periodic_report_samples_and_delivers_xy_and_both_wheel_directions(self):
        self.assertEqual(self.changed.u32(T.REPORT_DRIVER_TABLE+0x43),self.builder.symbols['advanced_tick']|1)
        for via in (0,1):
            for direct in (0,1):
                for kind in ('xy','wheel_up','wheel_down'):
                    with self.subTest(via=via,direct=direct,kind=kind),self.registered_cpu(via,direct,kind) as cpu:
                        cpu.run(self.builder.motion['report'],count=100000)
                        cpu.run(self.builder.motion['drain'],count=100000)
                        self.assertEqual(len(cpu.bursts),1)
                        self.assertFalse(cpu.bursts[0]&32)
                        if kind=='xy':self.assertTrue(any(v.get('xy')==(123,-45) for v in cpu.submits))
                        else:self.assertTrue(any(v.get('wheel')==({'wheel_up':1,'wheel_down':-1}[kind]) for v in cpu.submits))
                        self.assertEqual(cpu.byte(T.MOTION_STATE)&32,0)
                        self.assertEqual(cpu.byte(RING+2),0)

    def test_registered_report_retries_accumulated_motion_when_sampler_is_unavailable(self):
        for via in (0,1):
            for busy in ('ring','worker','burst','not_ready'):
                with self.subTest(via=via,busy=busy),self.registered_cpu(via,0,'xy') as cpu:
                    if busy=='ring':cpu.uc.mem_write(RING+2,b'\x08')
                    elif busy=='worker':cpu.put32(0x2000A3A8,1)
                    elif busy=='burst':cpu.put32(0x2000A380,1)
                    else:cpu.uc.mem_write(T.SENSOR_READY,b'\0')
                    cpu.uc.mem_write(T.MOTION_ACC_X,struct.pack('<h',110))
                    cpu.uc.mem_write(T.MOTION_ACC_Y,struct.pack('<h',220))
                    cpu.run(self.builder.motion['report'],count=100000)
                    self.assertEqual(cpu.bursts,[])
                    self.assertTrue(any(v.get('xy')==(110,220) for v in cpu.submits))
                    self.assertEqual(cpu.byte(T.MOTION_STATE)&32,0)
                    self.assertEqual(bytes(cpu.uc.mem_read(T.MOTION_ACC_Y,4)),bytes(4))

    def test_registered_report_preserves_divider_primask_and_defers_existing_owner(self):
        for busy in (False,True):
            for mask in (0,1):
                with self.subTest(busy=busy,mask=mask),self.registered_cpu(0,0,'xy') as cpu:
                    cpu.uc.reg_write(UC_ARM_REG_PRIMASK,mask)
                    cpu.uc.mem_write(T.REPORT_DIVIDER,b'\x03')
                    if busy:cpu.put32(0x2000A3A8,1)
                    cpu.uc.mem_write(T.MOTION_ACC_X,struct.pack('<h',10))
                    cpu.run(self.builder.motion['report'],count=100000)
                    cpu.run(self.builder.motion['report'],count=100000)
                    self.assertEqual(cpu.submits,[])
                    self.assertEqual(cpu.bursts,[])
                    cpu.run(self.builder.motion['report'],count=100000)
                    self.assertEqual(len(cpu.submits),1)
                    self.assertEqual(len(cpu.bursts),int(not busy))
                    self.assertEqual(cpu.uc.reg_read(UC_ARM_REG_PRIMASK),mask)
                    cpu.uc.mem_write(T.MOTION_STATE,bytes((cpu.byte(T.MOTION_STATE)|32,)))
                    before=(cpu.byte(T.REPORT_COUNTER),len(cpu.submits),len(cpu.bursts))
                    cpu.run(self.builder.motion['report'],count=100000)
                    self.assertEqual((cpu.byte(T.REPORT_COUNTER),len(cpu.submits),len(cpu.bursts)),before)
                    self.assertEqual(cpu.byte(T.MOTION_STATE)&32,32)

    def test_independent_thread_and_direct_switch_require_complete_backlog(self):
        with self.cpu() as cpu:
            expected=[self.sample(cpu,n) for n in range(4)]
            self.assertEqual(cpu.events,[])
            self.assertEqual(cpu.byte(RING+2),4)
            self.assertEqual(cpu.u32(T.SENSOR_QUEUE+32),0)
            self.run_done(cpu)
            self.assertEqual([x[0] for x in cpu.events],expected)
            self.assertTrue(all(owner==32 for _,owner in cpu.events))
            self.assertEqual(cpu.byte(RING+2),0)
            cpu.events.clear()
            expected=[self.sample(cpu,10),self.sample(cpu,11)]
            self.assertEqual(request(cpu,P.SET,(0,P.MOTION_PATH,1),target=T)[0],0xA2)
            self.run_done(cpu)
            self.assertEqual(request(cpu,P.SET,(0,P.MOTION_PATH,1),target=T),(0xA0,b'\0\x0a\1'))
            expected.append(self.sample(cpu,12))
            self.assertEqual([x[0] for x in cpu.events],expected)
            self.assertEqual(cpu.byte(T.MOTION_STATE)&48,16)

    def test_queue_full_failure_and_ring_backpressure_never_overwrite(self):
        with self.cpu() as cpu:
            # A full configuration FIFO does not own or reject motion wakes.
            p=0x20016100
            cpu.uc.mem_write(p,bytes(12))
            for _ in range(10):self.assertEqual(cpu.run(T.SENSOR_POST,T.SENSOR_QUEUE,p,0,0),0)
            raw=self.sample(cpu,20)
            self.assertEqual(cpu.events,[])
            self.run_done(cpu)
            self.assertEqual([x[0] for x in cpu.events],[raw])
            self.assertEqual(cpu.byte(RING+2),0)
        with self.cpu() as cpu:
            expected=[self.sample(cpu,n) for n in range(9)]
            cpu.run(self.builder.motion['drain'],count=100000)
            self.assertEqual([x[0] for x in cpu.events],expected)
            self.assertEqual(cpu.byte(RING+2),0)

    def test_wired_native_delivery_mask_and_owner_preserve(self):
        for mask in (0,1):
            with self.cpu() as cpu:
                cpu.uc.reg_write(UC_ARM_REG_PRIMASK,mask)
                cpu.stub(0x20005E08,0)
                raw=self.sample(cpu,30)
                self.assertEqual(cpu.events,[(raw,32)])
                self.assertEqual(cpu.byte(RING+2),0)
                self.assertEqual(cpu.uc.reg_read(UC_ARM_REG_PRIMASK),mask)
                self.assertEqual(cpu.reg('sp'),T.SP)

    def test_report_timer_defers_owner_but_retries_accumulators_with_full_ring(self):
        for owned,full,expected in ((0,0,1),(1,0,0),(0,1,1),(1,1,0)):
            with self.cpu() as cpu:
                cpu.uc.mem_write(T.MOTION_STATE,bytes((cpu.byte(T.MOTION_STATE)|32*owned,)))
                cpu.uc.mem_write(RING+2,bytes((8*full,)))
                seen=[]
                cpu.stub(T.REPORT_NATIVE,effect=lambda c:seen.append(True))
                cpu.run(self.builder.motion['report'])
                self.assertEqual(len(seen),expected)

    def test_real_worker_callback_and_report_callsite_interleaves(self):
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
        for report_first in (False,True):
            with self.cpu() as cpu:
                expected=self.sample(cpu,13)
                seen=[]
                cpu.stub(T.REPORT_NATIVE,effect=lambda c:seen.append(True))
                symbol='motion_report' if report_first else 'motion_drain'
                native=T.REPORT_NATIVE if report_first else self.builder.symbols['advanced_motion']
                allocation=next(v for v in self.builder.allocations if v['name']==symbol)
                start=self.builder.symbols[symbol]
                code=list(Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_MCLASS).disasm(
                    self.changed.get(start,allocation['bytes']),start))
                # MAYA uses far BLX calls to native RAM services, and direct
                # BL for its Flash callback. Stop on the call, not the stub.
                if report_first or not self.builder.advanced.get('telemetry',True):
                    boundary=next(v.address for v in code if v.mnemonic=='blx')
                else:
                    boundary=next(v.address for v in code if v.mnemonic=='bl'
                                  and int(v.op_str.lstrip('#'),0)==native)
                first=(start,())
                second=(self.builder.motion['drain' if report_first else 'report'],())
                self.assertTrue(cpu.preempt(first,second,boundary))
                self.assertEqual(len(seen),int(report_first))
                self.assertEqual(cpu.events,[] if report_first else [(expected,32)])
                self.assertEqual(cpu.byte(T.MOTION_STATE)&32,0)
                cpu.run(self.builder.motion['drain'])
                self.assertEqual(cpu.events,[(expected,32)])

    def test_report_owns_accumulators_against_sampling_irq_and_preserves_mask(self):
        for mask in (0,1):
            with self.cpu() as cpu:
                cpu.uc.reg_write(UC_ARM_REG_PRIMASK,mask)
                cpu.ends.add(T.REPORT_NATIVE)
                cpu.run(self.builder.motion['report'])
                self.assertEqual(cpu.byte(T.MOTION_STATE)&32,32)
                saved=cpu.uc.context_save();layout=cpu.layout
                cpu.layout=replace(layout,stack=cpu.reg('sp')-0x100)
                cpu.ends.clear();seen=[]
                cpu.stub(T.SENSOR_TICK,effect=lambda c:seen.append(True))
                cpu.run(self.builder.symbols['advanced_tick'])
                self.assertEqual(seen,[])
                cpu.layout=layout;cpu.uc.context_restore(saved)
                cpu.stub(T.REPORT_NATIVE)
                cpu.uc.emu_start(cpu.reg('pc')|1,cpu.stop,count=100000)
                self.assertEqual(cpu.byte(T.MOTION_STATE)&32,0)
                self.assertEqual(cpu.uc.reg_read(UC_ARM_REG_PRIMASK),mask)
                self.assertEqual(cpu.reg('sp'),T.SP)

    def test_real_worker_motion_consumer_never_acquires_sensor_configuration_locks(self):
        with self.cpu() as cpu:
            expected=[self.sample(cpu,n) for n in range(3)]
            calls=[]
            cpu.stub(0x2F3D6,effect=lambda c:calls.append(c.reg('r0')) or 0)
            self.run_done(cpu)
            self.assertEqual([v[0] for v in cpu.events],expected)
            self.assertEqual(calls,[])
            self.assertEqual(cpu.u32(0x2000A3A8),0)
            self.assertEqual(cpu.u32(0x2000A380),0)
            self.assertEqual(cpu.byte(RING+2),0)
            self.assertEqual(cpu.byte(RING+3),0)

    def test_binary_motion_wake_does_not_depend_on_configuration_fifo(self):
        with self.cpu() as cpu:
            expected=[self.sample(cpu,n) for n in range(8)]
            self.assertEqual(cpu.u32(T.SENSOR_QUEUE+32),0)
            self.assertEqual(cpu.u32(cpu.u32(RING+4)+8),1)
            self.run_done(cpu)
            self.assertEqual([v[0] for v in cpu.events],expected)
            self.assertEqual(cpu.u32(T.SENSOR_QUEUE+32),0)
            self.assertEqual(cpu.byte(RING+3),0)
            self.sample(cpu,9)
            self.assertEqual(cpu.u32(cpu.u32(RING+4)+8),1)
        with self.cpu() as cpu:
            message=0x20016100;cpu.uc.mem_write(message,bytes(12))
            for _ in range(10):self.assertEqual(cpu.run(T.SENSOR_POST,T.SENSOR_QUEUE,message,0,0),0)
            self.sample(cpu,10)
            self.assertEqual(cpu.byte(RING+3),0)
            self.assertEqual(cpu.byte(RING+2),1)
            self.assertEqual(cpu.run(0x2A22C,T.SENSOR_QUEUE,message,0,0),0)
            self.sample(cpu,11)
            self.assertEqual(cpu.byte(RING+3),0)
            self.assertEqual(cpu.byte(RING+2),2)
            self.run_done(cpu)
            self.assertEqual(cpu.byte(RING+2),0)

    def test_configuration_and_snapshot_messages_keep_original_lock_pair(self):
        for message in (0,T.SNAP_MESSAGE,17):
            with self.subTest(message=message),self.cpu() as cpu:
                calls=[]
                def receive(c):
                    c.uc.mem_write(c.reg('r1'),struct.pack('<III',message,0,0))
                    c.ends.add(T.SENSOR_WORKER_WAIT)
                    return 0
                cpu.stub(0x2A22C,effect=receive)
                cpu.stub(0x2F3D6,effect=lambda c:calls.append(c.reg('r0')) or 0)
                cpu.stub(self.builder.symbols['advanced_snapshot_worker'])
                cpu.run(0x17484,count=100000)
                self.assertEqual(calls,[0x2000A3A8,0x2000A380,0x2000A3A8])

    def test_dequeued_consumer_preempted_by_producer_keeps_one_reliable_next_wake(self):
        with self.cpu() as cpu:
            expected=[self.sample(cpu,n) for n in range(3)]
            runtime=cpu.u32(RING+4)
            self.assertEqual(cpu.run(T.MOTION_SEM_TAKE,runtime,0,0,0),0)
            raw=struct.pack('<BBhh',1,0,9,-9)
            cpu.uc.mem_write(0x20016000,raw)
            # The binary wake has been consumed; another producer before drain
            # starts remains in the ring and is processed by that same drain.
            self.assertTrue(cpu.preempt((self.builder.motion['consume'],()),
                (self.builder.motion['route'],(0x20016000,)),self.builder.motion['drain']))
            self.assertEqual([v[0] for v in cpu.events],expected+[raw])
            self.assertEqual(cpu.byte(RING+2),0)
            self.assertEqual(cpu.byte(RING+3),0)
            self.assertEqual(cpu.u32(T.SENSOR_QUEUE+32),0)
            cpu.run(self.builder.motion['consume'],count=100000)
            self.assertEqual(cpu.byte(RING+3),0)
            self.assertEqual(cpu.u32(T.SENSOR_QUEUE+32),0)
            self.assertEqual([v[0] for v in cpu.events],expected+[raw])

    def test_native_configuration_gate_is_not_a_motion_hook(self):
        self.assertEqual(self.changed.get(T.SENSOR_WORKER_GATE_SITE,4),
                         self.builder.image.get(T.SENSOR_WORKER_GATE_SITE,4))

    def test_lazy_thread_creation_exact_native_abi_and_owned_bounds(self):
        from MAYA_X_V2.motion import THREAD_TCB,THREAD_STACK,THREAD_BYTES
        from unicorn import UC_HOOK_MEM_WRITE
        with self.cpu() as cpu:
            cpu.uc.mem_write(RING+4,bytes(4))
            cpu.uc.mem_write(DONE-16,b'\xa5'*(THREAD_BYTES+48))
            allocations=[];created=[];starts=[];writes=[]
            cpu.stub(0x3089E,effect=lambda c:allocations.append((c.reg('r0'),c.reg('r1'))) or DONE-4)
            def create(uc,address,size,user):
                sp=cpu.reg('sp')
                created.append(dict(args=[cpu.reg(f'r{i}') for i in range(4)],
                    stack=list(struct.unpack('<8I',bytes(cpu.uc.mem_read(sp,32)))),
                    published=cpu.u32(RING+4)))
            cpu.add_hook(UC_HOOK_CODE,create,begin=T.MOTION_THREAD_CREATE,end=T.MOTION_THREAD_CREATE)
            cpu.add_hook(UC_HOOK_MEM_WRITE,lambda uc,access,address,size,value,user:writes.append((address,size)),
                         begin=DONE,end=DONE+THREAD_BYTES+7)
            cpu.stub(T.MOTION_THREAD_START,effect=lambda c:starts.append((c.reg('r0'),c.u32(RING+4))))
            self.assertEqual(cpu.run(self.builder.motion['initialize'],HEAP),DONE)
            self.assertEqual(allocations,[(T.NATIVE_HEAP,THREAD_BYTES+12)])
            self.assertEqual(created,[dict(args=[DONE+THREAD_TCB,DONE+THREAD_STACK,1024,
                self.builder.motion['thread']|1],stack=[DONE,0,0,6,0,0,0xffffffff,0xffffffff],published=0)])
            self.assertEqual(starts,[(DONE+THREAD_TCB,DONE)])
            self.assertEqual(cpu.u32(DONE),DONE)
            self.assertEqual(cpu.u32(DONE+4),DONE)
            self.assertEqual((cpu.u32(DONE+8),cpu.u32(DONE+12)),(0,1))
            self.assertEqual(cpu.byte(DONE+THREAD_TCB+14),6)
            self.assertEqual(cpu.u32(DONE+THREAD_TCB+112),DONE+THREAD_STACK)
            self.assertEqual(cpu.u32(DONE+THREAD_TCB+116),1024)
            self.assertEqual(cpu.u32(DONE+THREAD_TCB+120),16)
            self.assertEqual(cpu.u32(DONE+THREAD_TCB+80),DONE+THREAD_BYTES-48)
            self.assertTrue(all(DONE<=a and a+n<=DONE+THREAD_BYTES for a,n in writes))
            self.assertEqual(cpu.u32(DONE-4),T.NATIVE_HEAP)
            self.assertEqual(bytes(cpu.uc.mem_read(DONE+THREAD_BYTES,8)),b'\xa5'*8)
            cpu.run(self.builder.motion['initialize'],HEAP)
            self.assertEqual(len(allocations),1)
            self.assertEqual(len(starts),1)

    def test_thread_exhaustion_rejects_set_without_changing_direct(self):
        with self.cpu() as cpu:
            cpu.uc.mem_write(RING+4,bytes(4))
            cpu.uc.mem_write(T.MOTION_STATE,bytes((cpu.byte(T.MOTION_STATE)|16,)))
            cpu.stub(0x3089E,0)
            before=bytes(cpu.uc.mem_read(T.MOTION_STATE,1))
            self.assertEqual(request(cpu,P.SET,(0,P.MOTION_PATH,0),target=T)[0],0xA2)
            self.assertEqual(bytes(cpu.uc.mem_read(T.MOTION_STATE,1)),before)
            self.assertEqual(cpu.u32(RING+4),0)
            raw=self.sample(cpu,1)
            self.assertEqual([v[0] for v in cpu.events],[raw])

    def test_default_direct_boot_never_creates_done_runtime(self):
        with self.cpu() as cpu:
            cpu.uc.mem_map(0x110000,0x1000)
            allocations=[];starts=[]
            cpu.stub(0x3089E,effect=lambda c:allocations.append(c.reg('r1')) or HEAP-4)
            cpu.stub(T.MOTION_THREAD_START,effect=lambda c:starts.append(True))
            cpu.uc.mem_write(T.ADV_STORAGE,b'\xff'*16)
            # This scenario begins after native cold-boot BSS clear, rather
            # than reinitializing the live done runtime made by cpu().
            cpu.uc.mem_write(T.SNAPSHOT_POINTER,bytes(3))
            cpu.run(self.builder.symbols['motion_queue_init'],0)
            self.assertEqual(cpu.byte(T.MOTION_STATE)&16,16)
            self.assertEqual(cpu.u32(RING+4),0)
            self.assertEqual(allocations,[T.SNAPSHOT_STORAGE_BYTES+4])
            self.assertEqual(starts,[])

    def test_saved_thread_exhaustion_reports_actual_direct_without_rewriting_record(self):
        with self.cpu() as cpu:
            cpu.uc.mem_map(0x110000,0x1000)
            record=encode_record(motion_path=0)
            cpu.uc.mem_write(T.ADV_STORAGE,record)
            cpu.uc.mem_write(T.SNAPSHOT_POINTER,bytes(3))
            cpu.stub(0x3089E,effect=lambda c:HEAP-4 if c.reg('r1')==T.SNAPSHOT_STORAGE_BYTES+4 else 0)
            cpu.run(self.builder.symbols['motion_queue_init'],0)
            self.assertEqual(request(cpu,P.GET,(0,P.MOTION_PATH),target=T)[1][2],1)
            self.assertEqual(bytes(cpu.uc.mem_read(T.ADV_STORAGE,16)),record)

    def test_runtime_api_preimages_reject_target_drift(self):
        from copy import copy
        from MAYA_X_V2.motion import install
        for address in T.MOTION_RUNTIME_PREIMAGES:
            builder=copy(self.builder);builder.image=copy(builder.image)
            builder.image.mem=dict(builder.image.mem);builder.image.mem[address]^=1
            builder.image.__dict__.pop('data',None)
            with self.subTest(address=hex(address)),self.assertRaisesRegex(ValueError,'runtime API'):
                install(builder,T.MOTION_NATIVE)

    def test_done_consumer_progresses_while_configuration_worker_is_busy(self):
        with self.cpu() as cpu:
            expected=[self.sample(cpu,n) for n in range(8)]
            # The configuration worker may be inside an unrelated command.
            # Its busy flags still inhibit new SPI, but cannot inhibit drain.
            cpu.put32(0x2000A3A8,1);cpu.put32(0x2000A380,1)
            cpu.stub(T.SENSOR_POST,effect=lambda c:self.fail('motion posted configuration work'))
            self.run_done(cpu)
            self.assertEqual([v[0] for v in cpu.events],expected)
            self.assertEqual(cpu.byte(RING+2),0)
            self.assertEqual((cpu.u32(0x2000A3A8),cpu.u32(0x2000A380)),(1,1))

    def test_native_binary_give_wakes_its_waiter_without_sensor_fifo(self):
        with self.cpu() as cpu:
            runtime=cpu.u32(RING+4)
            waiter=runtime+32
            current=0x20022000
            cpu.put32(runtime,waiter);cpu.put32(runtime+4,waiter)
            cpu.put32(waiter,runtime);cpu.put32(waiter+4,runtime)
            cpu.uc.mem_write(waiter+13,b'\x02')
            cpu.put32(0x2000CAE8+8,current)
            cpu.put32(0x2000CAE8+0x14,waiter)
            ready=[]
            cpu.stub(0x34F7E)
            cpu.stub(0x34D7A,effect=lambda c:ready.append(c.reg('r0')))
            # IRQ-exit scheduling is a service boundary; give's wait-list,
            # count, thread-unpend and ready publication execute natively.
            cpu.stub(0x2AE10)
            self.sample(cpu,4)
            self.assertEqual(ready,[waiter])
            self.assertEqual((cpu.u32(runtime),cpu.u32(runtime+4)),(runtime,runtime))
            self.assertEqual(cpu.u32(runtime+8),0)
            self.assertEqual(cpu.byte(waiter+13)&2,0)
            self.assertEqual(cpu.u32(waiter+0x88),0)
            self.assertEqual(cpu.u32(T.SENSOR_QUEUE+32),0)
            cpu.run(self.builder.motion['drain'])
            self.assertEqual([v[0] for v in cpu.events],[struct.pack('<BBhh',1,0,4,-4)])

    def test_real_decoder_stack_copy_native_callback_registration_and_motion_count(self):
        with self.cpu() as cpu:
            cpu.uc.mem_write(T.SENSOR_READY,b'\1')
            cpu.uc.mem_write(T.SETTINGS+705,b'\1')
            cpu.uc.mem_write(0x2000D234,b'\xb7\0')
            cpu.put32(T.MOTION_CALLBACK,self.changed.u32(T.MOTION_CALLBACK_POINTER))
            def burst(c):
                self.assertEqual(c.reg('r2'),6)
                c.uc.mem_write(c.reg('r1'),b'\xa4\xb7\x7b\0\x38\xfe')
                return 1
            cpu.stub(T.SENSOR_BURST,effect=burst)
            cpu.run(self.builder.symbols['advanced_tick'],count=100000)
            self.assertEqual(cpu.events,[])
            cpu.run(self.builder.motion['drain'],count=100000)
            self.assertEqual(cpu.events,[(b'\1\0\x7b\0\x38\xfe',32)])

    def test_worker_pop_interrupted_by_sensor_and_report_irqs_direct_switch_order(self):
        with self.cpu() as cpu:
            expected=[self.sample(cpu,n) for n in range(8)]
            cpu.ends.add(T.MOTION_NATIVE)
            cpu.run(self.builder.motion['drain'],count=100000)
            self.assertEqual(cpu.byte(RING+2),7)
            self.assertEqual(cpu.byte(T.MOTION_STATE)&32,32)
            saved=cpu.uc.context_save()
            # Hardware IRQ frames grow below the interrupted SP, not from
            # the fixture's top-of-thread stack. Preserve its local sample.
            layout=cpu.layout
            cpu.layout=replace(layout,stack=cpu.reg('sp')-0x100)
            cpu.ends.clear()
            seen=[]
            cpu.stub(T.SENSOR_TICK,effect=lambda c:seen.append('tick'))
            cpu.stub(T.REPORT_NATIVE,effect=lambda c:seen.append('report'))
            # An in-flight callback cannot switch execution contexts.
            self.assertEqual(request(cpu,P.SET,(0,P.MOTION_PATH,1),target=T)[0],0xA2)
            expected.append(self.sample(cpu,8))
            self.assertEqual(cpu.byte(RING+2),8)
            for _ in range(3):
                cpu.run(self.builder.symbols['advanced_tick'])
                cpu.run(self.builder.motion['report'])
            self.assertEqual(seen,[])
            self.assertEqual(cpu.events,[])
            cpu.layout=layout
            cpu.uc.context_restore(saved)
            cpu.uc.emu_start(cpu.reg('pc')|1,cpu.stop,count=200000)
            self.assertEqual(cpu.reg('pc'),cpu.stop)
            self.assertEqual([x[0] for x in cpu.events],expected)
            self.assertEqual(cpu.byte(RING+2),0)
            self.assertEqual(cpu.byte(T.MOTION_STATE)&48,0)
            self.assertEqual(request(cpu,P.SET,(0,P.MOTION_PATH,1),target=T)[0],0xA0)
            cpu.run(self.builder.symbols['advanced_tick'])
            self.assertEqual(seen,['tick'])

    def test_explicit_full_settings_and_all_versions_real_driver_boot_load(self):
        with self.cpu() as cpu:
            cpu.uc.mem_map(0x10F000,0x1D000)
            cpu.uc.mem_map(0x5004E000,0x1000)
            cpu.uc.mem_write(T.ADV_STORAGE,b'\xff'*16)
            for path,absolute in ((0,0),(1,0),(0,1),(1,1)):
                self.assertEqual(request(cpu,P.SET,(0,P.MOTION_PATH,path),target=T)[0],0xA0)
                self.assertEqual(request(cpu,P.SET,(0,P.ABS_MOTION,absolute),target=T)[0],0xA0)
                saved=request(cpu,P.SET,(0,P.SAVE_ADVANCED,1),target=T)
                self.assertEqual(saved[0],0xA0)
                fields=decode_record(saved[1][3:])
                self.assertEqual((fields['motion_path'],fields['abs_motion']),(path,absolute))
            for version in range(1,6):
                path=int(version>=3);absolute=int(version>=4);click=int(version>=5)
                record=encode_record(version=version,motion_path=path,abs_motion=absolute,optical_click=click)
                cpu.uc.mem_write(T.ADV_STORAGE,record)
                cpu.run(self.builder.symbols['motion_queue_init'],0)
                self.assertEqual(request(cpu,P.GET,(0,P.MOTION_PATH),target=T)[1][2],path)
                self.assertEqual(request(cpu,P.GET,(0,P.ABS_MOTION),target=T)[1][2],absolute)
                self.assertEqual(request(cpu,P.GET,(0,P.OPTICAL_CLICK),target=T)[0],0xA2)
                self.assertEqual(bytes(cpu.uc.mem_read(T.ADV_STORAGE,16)),record)
            saved=request(cpu,P.SET,(0,P.SAVE_ADVANCED,1),target=T)
            self.assertEqual(saved[0],0xA0)
            self.assertEqual(decode_record(saved[1][3:])['optical_click'],0)
            cpu.uc.mem_write(T.SNAPSHOT_POINTER,bytes(3));cpu.stub(0x3089E,0)
            for op in (P.MOTION_PATH,P.ABS_MOTION,P.OPTICAL_CLICK):
                self.assertEqual(request(cpu,P.SET,(0,op,1),target=T)[0],0xA2)


if __name__=='__main__':unittest.main()
