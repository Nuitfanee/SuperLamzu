"""Native lift wakeup must not strand MAYA's accumulated motion reports."""
import itertools
import struct
import unittest

from unicorn import UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_BASEPRI, UC_ARM_REG_IPSR, UC_ARM_REG_PRIMASK

from MAYA_X_V2 import target as T
from MAYA_X_V2.advanced import build_motion_stage
from MAYA_X_V2.tests import test_motion as fixtures
from superlamzu.verify import patched_image,request
from superlamzu import advanced as A,protocol as P
from superlamzu.common import assemble


def scheduled_motion_reports(builder, *, direct=0, via=1, lift=0, absolute=False,
                             full_ring=False, native_queue=False, reports=64,
                             registered=False, fresh_samples=False):
    """Pause actual worker callback after the native PendSV request.

    Native lift helpers, semaphore and scheduling decision execute unchanged.
    Queue submission, peripheral/coordinate services, ready-list operations and
    unsupported acquire/release instructions are explicit service boundaries.
    No elapsed-time, physical RF, or full NVIC model is implied.
    """
    fixture=fixtures.MotionTests()
    fixture.builder,fixture.changed=builder,patched_image(builder)
    with fixture.cpu() as cpu:
        if registered:
            cpu.run(0x16130)
            cpu.put32(T.REPORT_DRIVER,T.REPORT_DRIVER_TABLE)
            cpu.put32(T.MOTION_CALLBACK,fixture.changed.u32(T.MOTION_CALLBACK_POINTER))
            cpu.uc.mem_write(T.SETTINGS+705,b'\1')
        cpu.stubs.pop(T.MOTION_NATIVE)
        cpu.stubs.pop(0x2A4E8,None)
        cpu.uc.mem_map(0xE000E000,0x1000)
        # First enqueue through the real wireless thread route, then exercise
        # the queued worker across either path/transport choice.
        sample=struct.pack('<BBhh',1,lift,10,20)
        source=0x20016000
        cpu.uc.mem_write(source,sample)
        cpu.run(builder.motion['route'],source,count=100000)
        cpu.uc.mem_write(T.MOTION_STATE,bytes((cpu.byte(T.MOTION_STATE)|direct|(0x40 if absolute else 0),)))
        cpu.stub(0x20005E08,via)
        cpu.stub(0x20005D10)
        cpu.stub(0x200052D4,8)
        cpu.stub(0x2007B410)
        cpu.stub(0x20005CB8)
        cpu.stub(0x30252,effect=lambda c:c.u32(c.reg('r0')))
        cpu.stub(0x302B6,effect=lambda c:c.put32(c.reg('r0'),c.reg('r1')))
        cpu.stub(0x2F3D6,effect=lambda c:c.put32(c.reg('r0'),c.reg('r1')))
        # Sampling IRQ's unsupported inline acquire remains an explicit
        # compatibility boundary; the done thread does not use config locks.
        for address,lines in ((0x20000EB2,['ldr.w r9,[r3]']),):
            code=assemble(lines,address)
            assert len(code)==4
            cpu.uc.mem_write(address,code)
        cpu.uc.mem_write(T.SENSOR_READY,b'\1')
        waits=[]
        wait_address=builder.motion['thread']+4
        def worker_wait(uc,address,size,user):
            waits.append(address)
            if len(waits)==2:uc.emu_stop()
        cpu.add_hook(UC_HOOK_CODE,worker_wait,begin=wait_address,end=wait_address)
        cpu.stubs.pop(T.MOTION_SEM_TAKE,None)
        cpu.uc.mem_write(T.SETTINGS+4,b'\0')
        cpu.uc.mem_write(T.SETTINGS+0x16,b'\1')
        cpu.uc.mem_write(T.SETTINGS+0x5F,b'\0')
        cpu.uc.mem_write(T.MOTION_ACC_X,struct.pack('<h',100))
        cpu.uc.mem_write(T.MOTION_ACC_Y,struct.pack('<h',200))
        cpu.uc.mem_write(T.REPORT_DIVIDER,b'\1')
        cpu.put32(0x2000A46C,int(not lift))
        semaphore,waiter,current=0x2000763C,0x20022000,0x20022100
        cpu.put32(semaphore,waiter);cpu.put32(semaphore+4,waiter)
        cpu.put32(waiter,semaphore);cpu.put32(waiter+4,semaphore)
        cpu.put32(0x2000CAE8+8,current);cpu.put32(0x2000CAE8+0x14,waiter)
        cpu.stub(0x34F7E);cpu.stub(0x34D7A)
        sends=[]
        def submit(c):
            offset=4 if via else 2
            sends.append(struct.unpack('<hh',bytes(c.uc.mem_read(c.reg('r1')+offset,4))))
            return int(len(sends)>1)
        if native_queue:
            assert via==1
            def memcpy(c):
                c.uc.mem_write(c.reg('r0'),bytes(c.uc.mem_read(c.reg('r1'),c.reg('r2'))))
                return c.reg('r0')
            cpu.stub(T.NATIVE_MEMCPY,effect=memcpy)
            cpu.run(T.QUEUE_INIT,2)
            cpu.uc.mem_write(T.RADIO_STATE,b'\1\1')
            cpu.uc.mem_write(0x20023000,bytes(8))
            for _ in range(8):assert cpu.run(T.RADIO_SEND,9,0x20023000)==1
            assert cpu.run(T.QUEUE_COUNT,2)==8
            cpu.add_hook(UC_HOOK_CODE,lambda uc,address,size,user:submit(cpu),
                         begin=T.RADIO_SEND,end=T.RADIO_SEND)
        else:
            cpu.stub(T.RADIO_SEND if via else 0x20003720,effect=submit)
        boundary=0x2AA84  # Actual PendSV request complete, BASEPRI restored.
        paused=[]
        def pause(uc,address,size,user):
            paused.append(address);uc.emu_stop()
        handle=cpu.uc.hook_add(UC_HOOK_CODE,pause,begin=boundary,end=boundary)
        cpu.setreg('sp',cpu.layout.stack);cpu.setreg('lr',cpu.stop|1)
        cpu.setreg('r0',cpu.u32(fixtures.RING+4))
        cpu.uc.reg_write(UC_ARM_REG_IPSR,0)
        try:cpu.uc.emu_start(builder.motion['thread']|1,cpu.stop,count=100000)
        finally:cpu.uc.hook_del(handle)
        assert paused, f'native lift did not request PendSV: {cpu.reg("pc"):#x}'
        assert cpu.u32(0xE000ED04)&(1<<28)
        assert cpu.uc.reg_read(UC_ARM_REG_BASEPRI)==0
        assert cpu.uc.reg_read(UC_ARM_REG_PRIMASK)==0
        assert sends==[(110,220)],sends
        locks_at_switch=(cpu.u32(0x2000A3A8),cpu.u32(0x2000A380))
        assert locks_at_switch==(0,0), 'motion must not own sensor configuration locks across PendSV'
        state_at_switch=cpu.byte(T.MOTION_STATE)
        context=cpu.uc.context_save()
        if full_ring:
            # Saturation alone still provides bounded backpressure, without
            # borrowing the independent sensor configuration locks.
            cpu.uc.mem_write(fixtures.RING,bytes((0,0,8,1)))
            cpu.uc.mem_write(fixtures.RING+8,sample*8)
        cpu.uc.reg_write(UC_ARM_REG_IPSR,20)
        bursts=[]
        def burst(c):
            bursts.append(True)
            if fresh_samples:
                assert registered and via==1 and direct==0 and not full_ring
                c.uc.mem_write(c.reg('r1'),b'\xa4\xb7'+struct.pack('<hh',3,4))
                return 1
            return 0
        cpu.stub(T.SENSOR_BURST,effect=burst)
        cpu.setreg('sp',cpu.layout.stack-0x8000);cpu.setreg('lr',cpu.stop|1)
        cpu.uc.emu_start(builder.symbols['advanced_tick']|1,cpu.stop,count=100000)
        assert cpu.reg('pc')==cpu.stop
        assert len(bursts)==int(not full_ring or bool(direct))
        if native_queue:
            # Free one real radio queue entry on the interrupt stack while
            # the sensor worker remains suspended in native lift handling.
            cpu.setreg('sp',cpu.layout.stack-0x8000);cpu.setreg('lr',cpu.stop|1)
            for i,value in enumerate((2,0x20023000,4)):cpu.setreg(f'r{i}',value)
            cpu.uc.emu_start(T.QUEUE_READ_RAW|1,cpu.stop,count=100000)
            assert cpu.reg('pc')==cpu.stop and cpu.reg('r0')==1
        for _ in range(reports):
            cpu.setreg('sp',cpu.layout.stack-0x8000);cpu.setreg('lr',cpu.stop|1)
            cpu.uc.emu_start(builder.motion['report']|1,cpu.stop,count=100000)
            assert cpu.reg('pc')==cpu.stop
        submitted=len(sends)-1
        pending=tuple(struct.unpack('<h',bytes(cpu.uc.mem_read(p,2)))[0]
                      for p in (T.MOTION_ACC_X,T.MOTION_ACC_Y))
        state_after_reports=cpu.byte(T.MOTION_STATE)
        accepted_payload=(struct.unpack('<hh',bytes(cpu.uc.mem_read(T.RADIO_QUEUE2+T.QUEUE_HEADER,4)))
                          if native_queue and submitted else None)
        totals_while_suspended=struct.unpack('<HH',bytes(cpu.uc.mem_read(fixtures.HEAP+24,4)))
        samples_while_suspended=len(bursts)
        ring_while_suspended=cpu.byte(fixtures.RING+2)
        cpu.uc.context_restore(context)
        cpu.uc.emu_start(boundary|1,cpu.stop,count=200000)
        assert cpu.reg('pc')==wait_address
        assert not cpu.byte(T.MOTION_STATE)&32
        assert cpu.u32(0x2000A3A8)==cpu.u32(0x2000A380)==0
        pending_after_resume=tuple(struct.unpack('<h',bytes(cpu.uc.mem_read(p,2)))[0]
                                   for p in (T.MOTION_ACC_X,T.MOTION_ACC_Y))
        pending_after_queue_recovery=pending_after_resume
        if native_queue and fresh_samples:
            # Eight fresh samples survived while the consumer was suspended.
            # Its old retry filled the one freed native TX slot, so retain
            # those new deltas until another real queue slot becomes free.
            assert pending_after_resume==(24,32),pending_after_resume
            assert cpu.run(T.QUEUE_READ_RAW,2,0x20023000,4)==1
            cpu.uc.mem_write(T.SENSOR_READY,bytes((0,)))
            cpu.run(builder.motion['report'],count=100000)
            pending_after_queue_recovery=tuple(struct.unpack('<h',bytes(cpu.uc.mem_read(p,2)))[0]
                                               for p in (T.MOTION_ACC_X,T.MOTION_ACC_Y))
            assert pending_after_queue_recovery==(0,0)
            assert sends[-1]==(24,32)
            assert cpu.run(T.QUEUE_COUNT,2)==8
        return dict(direct=direct,transport=via,lift=lift,absolute=absolute,
                    full_ring=full_ring,native_queue=native_queue,
                    submitted_while_suspended=submitted,accepted_payload=accepted_payload,
                    totals_while_suspended=totals_while_suspended,
                    pending_while_suspended=pending,state_at_switch=state_at_switch,
                    state_after_reports=state_after_reports,sends=sends,
                    sensor_locks_at_switch=locks_at_switch,
                    samples_while_suspended=samples_while_suspended,
                    ring_while_suspended=ring_while_suspended,
                    pending_after_resume=pending_after_resume,
                    pending_after_queue_recovery=pending_after_queue_recovery)


class MotionLatencyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.builders={profile:build_motion_stage(profile) for profile in ('SUPER',)}

    def test_native_lift_suspension_does_not_starve_reports(self):
        for profile,builder in self.builders.items():
            for direct,via,lift,absolute,full in itertools.product((0,16),(0,1),(0,1),(False,True),(False,True)):
                with self.subTest(profile=profile,direct=direct,via=via,lift=lift,absolute=absolute,full=full):
                    result=scheduled_motion_reports(builder,direct=direct,via=via,lift=lift,
                                                    absolute=absolute,full_ring=full)
                    self.assertEqual(result['submitted_while_suspended'],1,result)
                    self.assertEqual(result['pending_while_suspended'],(0,0),result)
                    self.assertEqual(result['state_at_switch']&32,0,result)
                    self.assertEqual(result['state_at_switch'],result['state_after_reports'],result)
                    self.assertEqual(result['totals_while_suspended'],(10,20) if absolute else (0,0),result)

    def test_full_native_radio_queue_retries_before_worker_resumes(self):
        for profile,builder in self.builders.items():
            for direct,lift,absolute,full in itertools.product((0,16),(0,1),(False,True),(False,True)):
                with self.subTest(profile=profile,direct=direct,lift=lift,absolute=absolute,full=full):
                    result=scheduled_motion_reports(builder,direct=direct,lift=lift,absolute=absolute,
                                                    full_ring=full,native_queue=True)
                    self.assertEqual(result['submitted_while_suspended'],1,result)
                    self.assertEqual(result['pending_while_suspended'],(0,0),result)
                    self.assertEqual(result['accepted_payload'],(10,20) if absolute else (110,220),result)
                    self.assertEqual(result['totals_while_suspended'],(10,20) if absolute else (0,0),result)

    def test_registered_sampler_progresses_while_motion_worker_is_suspended(self):
        for profile,builder in self.builders.items():
            for lift in (0,1):
                with self.subTest(profile=profile,lift=lift):
                    result=scheduled_motion_reports(builder,lift=lift,registered=True,fresh_samples=True)
                    self.assertEqual(result['sensor_locks_at_switch'],(0,0),result)
                    self.assertEqual(result['samples_while_suspended'],8,result)
                    self.assertEqual(result['ring_while_suspended'],8,result)
                    self.assertEqual(result['pending_while_suspended'],(0,0),result)
                    self.assertEqual(result['sends'][:2],[(110,220)]*2,result)
                    self.assertEqual(result['sends'][2:],[(3,4)]*8,result)

    def test_registered_motion_backpressure_recovers_through_real_radio_queue(self):
        for profile,builder in self.builders.items():
            with self.subTest(profile=profile):
                result=scheduled_motion_reports(builder,registered=True,fresh_samples=True,native_queue=True)
                self.assertEqual(result['samples_while_suspended'],8,result)
                self.assertEqual(result['pending_after_resume'],(24,32),result)
                self.assertEqual(result['pending_after_queue_recovery'],(0,0),result)

    def test_release_preserves_registers_primask_lift_and_shared_tags(self):
        for profile,builder in self.builders.items():
            fixture=fixtures.MotionTests();fixture.builder=builder;fixture.changed=patched_image(builder)
            for mask,lift in itertools.product((0,1),(0,1)):
                with self.subTest(profile=profile,mask=mask,lift=lift),fixture.cpu() as cpu:
                    cpu.stubs.pop(T.MOTION_NATIVE)
                    cpu.stub(0x20005D10);cpu.stub(0x20005E08,2)
                    state=cpu.byte(T.MOTION_STATE)|0x70
                    cpu.uc.mem_write(T.MOTION_STATE,bytes((state,)))
                    seen=[]
                    cpu.stub(T.MOTION_LIFT_UP,effect=lambda c:seen.append((1,c.byte(T.MOTION_STATE))))
                    cpu.stub(T.MOTION_LIFT_DOWN,effect=lambda c:seen.append((0,c.byte(T.MOTION_STATE))))
                    cpu.uc.mem_write(0x20016000,bytes((0,lift))+bytes(4))
                    cpu.uc.reg_write(UC_ARM_REG_PRIMASK,mask)
                    for r in range(4,12):cpu.setreg(f'r{r}',0x1100+r)
                    cpu.run(builder.motion['owned'],0x20016000,count=100000)
                    self.assertEqual(seen,[(lift,state&~32)])
                    self.assertEqual(cpu.byte(T.MOTION_STATE),state)
                    self.assertEqual(cpu.uc.reg_read(UC_ARM_REG_PRIMASK),mask)
                    self.assertEqual(cpu.reg('sp'),T.SP)
                    self.assertTrue(all(cpu.reg(f'r{r}')==0x1100+r for r in range(4,12)))

    def test_report_between_release_and_lift_keeps_sample_choice_and_abs_totals(self):
        for profile,builder in self.builders.items():
            for lift in (0,1):
                fixture=fixtures.MotionTests();fixture.builder=builder;fixture.changed=patched_image(builder)
                with self.subTest(profile=profile,lift=lift),fixture.cpu() as cpu:
                    cpu.stubs.pop(T.MOTION_NATIVE)
                    cpu.stub(0x20005D10);cpu.stub(0x200052D4,8)
                    cpu.stub(0x2007B410);cpu.stub(0x20005CB8)
                    cpu.uc.mem_write(T.MOTION_STATE,bytes((cpu.byte(T.MOTION_STATE)|0x50,)))
                    cpu.uc.mem_write(0x20016000,struct.pack('<BBhh',1,lift,10,20))
                    cpu.uc.mem_write(T.REPORT_DIVIDER,b'\1')
                    sends=[];tails=[]
                    def submit(c):
                        sends.append(struct.unpack('<hh',bytes(c.uc.mem_read(c.reg('r1')+4,4))))
                        return int(len(sends)>1)
                    cpu.stub(T.RADIO_SEND,effect=submit)
                    cpu.stub(T.MOTION_LIFT_UP,effect=lambda c:tails.append(1))
                    cpu.stub(T.MOTION_LIFT_DOWN,effect=lambda c:tails.append(0))
                    second=0x20023000
                    cpu.uc.mem_write(second,assemble([
                        'push {r4,lr}',*A.addr('r4',0x20016001),f'movs r0,#{1-lift}',
                        'strb r0,[r4]',*A.addr('r12',builder.motion['report']|1),'blx r12',
                        'pop {r4,pc}'],second))
                    from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_MCLASS
                    allocation=next(a for a in builder.allocations if a['name']=='motion_tail_release')
                    code=list(Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_MCLASS).disasm(
                        fixture.changed.get(builder.motion['release'],allocation['bytes']),builder.motion['release']))
                    # Real unmasked instruction immediately after release,
                    # before the helper chooses either original lift callee.
                    boundary=next(x.address for x in code if x.mnemonic=='cmp' and x.op_str=='r4, #0')
                    self.assertTrue(cpu.preempt((builder.motion['owned'],(0x20016000,)),
                                                 (second,()),boundary))
                    self.assertEqual(tails,[lift])
                    self.assertEqual(sends,[(10,20),(10,20)])
                    self.assertEqual(struct.unpack('<HH',bytes(cpu.uc.mem_read(fixtures.HEAP+24,4))),(10,20))
                    self.assertEqual(cpu.byte(T.MOTION_STATE)&32,0)

    def test_native_tail_original_bytes_guard(self):
        from copy import copy
        from MAYA_X_V2.motion import install
        builder=copy(self.builders['SUPER']);builder.image=copy(builder.image)
        builder.image.mem=dict(builder.image.mem)
        builder.image.mem[T.flash_source(T.MOTION_TAIL_SITE)]^=1
        builder.image.__dict__.pop('data',None)
        with self.assertRaisesRegex(ValueError,'tail preimage'):
            install(builder,T.MOTION_NATIVE)

    def test_thread_to_direct_rejects_queued_and_released_but_unfinished_lift_tail(self):
        from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_MCLASS
        for profile,builder in self.builders.items():
            fixture=fixtures.MotionTests();fixture.builder=builder;fixture.changed=patched_image(builder)
            with self.subTest(profile=profile),fixture.registered_cpu(1,0,'xy') as cpu:
                for address in (T.MOTION_LIFT_UP,T.MOTION_LIFT_DOWN):cpu.stubs.pop(address,None)
                cpu.stub(0x30252,effect=lambda c:c.u32(c.reg('r0')))
                cpu.stub(0x302B6,effect=lambda c:c.put32(c.reg('r0'),c.reg('r1')))
                cpu.uc.mem_write(T.SETTINGS+0x16,b'\1');cpu.put32(0x2000A46C,1)
                cpu.uc.mem_write(0x20016000,struct.pack('<BBhh',1,1,10,20))
                cpu.run(builder.motion['route'],0x20016000)
                self.assertEqual(request(cpu,P.SET,(0,P.MOTION_PATH,1),target=T)[0],0xA2)
                allocation=next(v for v in builder.allocations if v['name']=='motion_tail_release')
                code=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_MCLASS).disasm(
                    fixture.changed.get(builder.motion['release'],allocation['bytes']),builder.motion['release'])
                boundary=next(v.address for v in code if v.mnemonic=='cmp' and v.op_str=='r4, #0')
                switch=0x20023000
                packet=bytearray(64);packet[0]=0xa0;packet[3:6]=bytes((3,1,P.SET))
                packet[6:9]=bytes((0,P.MOTION_PATH,1));cpu.uc.mem_write(T.PACKET,bytes(packet))
                cpu.uc.mem_write(switch,assemble(['push {r4,lr}',*A.addr('r12',T.GROUP1|1),
                    'blx r12',*A.addr('r12',builder.motion['report']|1),'blx r12',
                    'pop {r4,pc}'],switch))
                cpu.stub(T.MOTION_SEM_GIVE)
                self.assertTrue(cpu.preempt((builder.motion['drain'],()),(switch,()),boundary))
                self.assertEqual(cpu.byte(T.PACKET),0xa2)
                self.assertEqual(cpu.byte(T.MOTION_STATE)&16,0)
                self.assertEqual(cpu.byte(fixtures.RING+3),0)
                self.assertEqual(cpu.u32(0x2000A46C),0)
                self.assertEqual(cpu.byte(0x2000E525),0)
                self.assertEqual([v['xy'] for v in cpu.submits],[(10,20),(123,-45)])
                self.assertEqual(request(cpu,P.SET,(0,P.MOTION_PATH,1),target=T)[0],0xa0)

    def test_default_direct_delivers_512_samples_without_config_consumer_or_ring(self):
        for profile,builder in self.builders.items():
            fixture=fixtures.MotionTests();fixture.builder=builder;fixture.changed=patched_image(builder)
            with self.subTest(profile=profile),fixture.registered_cpu(1,1,'xy') as cpu:
                cpu.uc.mem_write(fixtures.RING+4,bytes(4))
                # Configuration worker is not run at all in this scenario.
                for _ in range(512):cpu.run(builder.motion['report'],count=100000)
                self.assertEqual(len(cpu.bursts),512)
                self.assertEqual([v['xy'] for v in cpu.submits],[(123,-45)]*512)
                self.assertEqual(cpu.byte(fixtures.RING+2),0)
                self.assertEqual(cpu.u32(T.SENSOR_QUEUE+32),0)
                self.assertEqual(cpu.u32(fixtures.RING+4),0)

    def test_wired_transition_cannot_overtake_unfinished_wireless_thread_lift(self):
        from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_MCLASS
        for profile,builder in self.builders.items():
            fixture=fixtures.MotionTests();fixture.builder=builder;fixture.changed=patched_image(builder)
            with self.subTest(profile=profile),fixture.registered_cpu(1,0,'xy') as cpu:
                for address in (T.MOTION_LIFT_UP,T.MOTION_LIFT_DOWN):cpu.stubs.pop(address,None)
                cpu.stub(0x30252,effect=lambda c:c.u32(c.reg('r0')))
                cpu.stub(0x302B6,effect=lambda c:c.put32(c.reg('r0'),c.reg('r1')))
                cpu.uc.mem_write(T.SETTINGS+0x16,b'\1');cpu.put32(0x2000A46C,1)
                cpu.uc.mem_write(0x20016000,struct.pack('<BBhh',1,1,10,20))
                cpu.run(builder.motion['route'],0x20016000)
                allocation=next(v for v in builder.allocations if v['name']=='motion_tail_release')
                code=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_MCLASS).disasm(
                    fixture.changed.get(builder.motion['release'],allocation['bytes']),builder.motion['release'])
                boundary=next(v.address for v in code if v.mnemonic=='cmp' and v.op_str=='r4, #0')
                # Plugging wired changes the original transport accessor
                # without going through the motion-path SET busy predicate.
                cpu.stub(0x20005E08,0)
                submissions=[]
                def wired(c):
                    self.assertEqual(c.reg('r0'),3)
                    submissions.append(struct.unpack('<hh',bytes(c.uc.mem_read(c.reg('r1')+2,4))))
                    return 1
                cpu.stub(0x20003720,effect=wired)
                cpu.stub(T.MOTION_SEM_GIVE)
                self.assertTrue(cpu.preempt((builder.motion['drain'],()),
                    (builder.motion['report'],()),boundary))
                self.assertEqual(cpu.u32(0x2000A46C),0)
                self.assertEqual(cpu.byte(0x2000E525),0)
                self.assertEqual(cpu.byte(fixtures.RING+3),0)
                self.assertEqual(cpu.byte(fixtures.RING+2),0)
                self.assertEqual(submissions,[(10,20),(123,-45)])
                # With no old callback or backlog the next wired sample is
                # synchronous again and never creates a semaphore wake.
                cpu.run(builder.motion['report'],count=100000)
                self.assertEqual(submissions,[(10,20),(123,-45),(123,-45)])
                self.assertEqual(cpu.byte(fixtures.RING+2),0)

    def test_full_ring_still_blocks_sampling_without_blocking_report_retry(self):
        for profile,builder in self.builders.items():
            fixture=fixtures.MotionTests();fixture.builder=builder;fixture.changed=patched_image(builder)
            for mask in (0,1):
                with self.subTest(profile=profile,mask=mask),fixture.cpu() as cpu:
                    cpu.uc.mem_write(fixtures.RING+2,b'\x08')
                    original=bytes(cpu.uc.mem_read(fixtures.RING,T.MOTION_RING_BYTES))
                    seen=[]
                    cpu.stub(T.SENSOR_TICK,effect=lambda c:seen.append('sample'))
                    cpu.stub(T.REPORT_NATIVE,effect=lambda c:seen.append('report'))
                    cpu.uc.reg_write(UC_ARM_REG_PRIMASK,mask)
                    cpu.run(builder.symbols['advanced_tick'])
                    cpu.run(builder.motion['report'])
                    self.assertEqual(seen,['report'])
                    self.assertEqual(bytes(cpu.uc.mem_read(fixtures.RING,T.MOTION_RING_BYTES)),original)
                    self.assertEqual(cpu.byte(T.MOTION_STATE)&32,0)
                    self.assertEqual(cpu.uc.reg_read(UC_ARM_REG_PRIMASK),mask)
            # Reachable full-ring state before the worker starts: older XY
            # must reach the actual native report, not wait for a ring pop.
            for absolute in (False,True):
                with self.subTest(profile=profile,absolute=absolute),fixture.cpu() as cpu:
                    cpu.uc.mem_write(fixtures.RING+2,b'\x08')
                    cpu.uc.mem_write(T.MOTION_STATE,bytes((cpu.byte(T.MOTION_STATE)|(0x40 if absolute else 0),)))
                    cpu.uc.mem_write(fixtures.HEAP+24,struct.pack('<HH',12,34))
                    cpu.uc.mem_write(T.MOTION_ACC_X,struct.pack('<h',100))
                    cpu.uc.mem_write(T.MOTION_ACC_Y,struct.pack('<h',200))
                    cpu.uc.mem_write(T.REPORT_DIVIDER,b'\1')
                    cpu.stub(0x200052D4,8);cpu.stub(0x2007B410);cpu.stub(0x20005CB8)
                    sent=[]
                    cpu.stub(T.RADIO_SEND,effect=lambda c:sent.append(
                        struct.unpack('<hh',bytes(c.uc.mem_read(c.reg('r1')+4,4)))) or 1)
                    cpu.run(builder.motion['report'],count=100000)
                    self.assertEqual(sent,[(100,200)])
                    self.assertEqual(bytes(cpu.uc.mem_read(T.MOTION_ACC_Y,4)),bytes(4))
                    self.assertEqual(cpu.byte(fixtures.RING+2),8)
                    self.assertEqual(struct.unpack('<HH',bytes(cpu.uc.mem_read(fixtures.HEAP+24,4))),(12,34))


if __name__=='__main__':unittest.main()
