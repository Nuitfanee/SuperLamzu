"""Native MAYA queue/parser instructions, with USB endpoint as boundary."""
import itertools
import struct
import unittest

from unicorn import UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_BASEPRI

from MAYA_X_V2 import receiver as R
from superlamzu.emulation import Arm
from superlamzu.verify import patched_image


class ReceiverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.builder=R.build_absolute_stage()
        cls.changed=patched_image(cls.builder)

    def cpu(self,patched=True):
        cpu=Arm(self.changed if patched else self.builder.image,layout=R.LAYOUT)
        # Deliberately dirty retained SRAM: real queue0 init, not fixture
        # zeros, must establish the extension's baseline lifetime.
        cpu.uc.mem_write(R.ABS_VALID,b'\xa5'*3)
        cpu.uc.mem_write(R.ABS_Y,b'\xa5'*2)
        for queue in range(7):cpu.run(R.QUEUE_INIT,queue)
        return cpu

    def test_native_queue0_init_invalidates_dirty_and_warm_absolute_baseline(self):
        with self.radio_cpu() as cpu:
            self.assertEqual(cpu.byte(R.ABS_VALID),0)
            reports=[]
            self.capture_reports(cpu,reports)
            self.frame(cpu,10,[(100,200)])
            self.assertEqual(cpu.byte(R.ABS_VALID),1)
            for queue in range(1,7):cpu.run(R.QUEUE_INIT,queue)
            self.frame(cpu,10,[(110,210)])
            self.assertEqual(struct.unpack('<hh',reports[-1][2:]),(10,10))
            cpu.run(R.QUEUE_INIT,0)
            self.assertEqual(cpu.byte(R.ABS_VALID),0)
            self.frame(cpu,10,[(1000,2000)])
            self.assertEqual(struct.unpack('<hh',reports[-1][2:]),(0,0))
            self.assertEqual(cpu.reg('sp'),R.SP)

    def test_consolidated_all_writers_full_wrap_mask_and_native_record_equivalence(self):
        for queue,writer,mask in itertools.product(range(7),(R.QUEUE_RAW,R.QUEUE_PREFIX,R.QUEUE_OBJECT),(0,0x40,0x80)):
            results=[]
            for patched in (False,True):
                with self.cpu(patched) as cpu:
                    cpu.uc.mem_write(R.ABS_VALID,b'\xa5'*3)
                    cpu.uc.mem_write(R.ABS_Y,b'\xa5'*2)
                    source=0x2000D000
                    cpu.uc.mem_write(source,bytes(range(25)))
                    cpu.uc.reg_write(UC_ARM_REG_BASEPRI,mask)
                    ret=[]
                    for i in range(26):
                        args=(queue,source,source+1,24) if writer==R.QUEUE_OBJECT else (queue,source,24)
                        ret.append(cpu.run(writer,*args))
                        self.assertEqual(cpu.uc.reg_read(UC_ARM_REG_BASEPRI),mask)
                    # Native queue count reports capacity-1 when full. Preserve
                    # this actual convention instead of normalizing to 25.
                    ret.append(cpu.run(R.QUEUE_COUNT,queue))
                    for i in range(25):
                        ret.append(cpu.run(R.QUEUE_POP,queue,source+0x40,source+0x80))
                    ret.append(cpu.run(R.QUEUE_POP,queue,source+0x40,source+0x80))
                    results.append((ret,bytes(cpu.uc.mem_read(R.QUEUE_BASE+queue*640,640)),
                        bytes(cpu.uc.mem_read(source+0x40,0x41)),cpu.reg('sp')))
                    self.assertEqual(bytes(cpu.uc.mem_read(R.ABS_VALID,3)),b'\xa5'*3)
                    self.assertEqual(bytes(cpu.uc.mem_read(R.ABS_Y,2)),b'\xa5'*2)
            self.assertEqual(results[0],results[1],(queue,writer,mask))

    def test_queue_fast_addressing_reduces_work_without_extending_basepri(self):
        from MAYA_X_V2.tests.audit_hotpaths import measure
        for writer,limit,masked_limit in ((R.QUEUE_RAW,142,133),
                (R.QUEUE_PREFIX,144,135),(R.QUEUE_OBJECT,138,0)):
            with self.cpu() as cpu:
                source=0x2000D000
                cpu.uc.mem_write(source,bytes(range(25)))
                args=(0,source,source+1,24) if writer==R.QUEUE_OBJECT else (0,source,24)
                cost=measure(cpu,writer,args)
                self.assertEqual(cpu.reg('r0'),1)
                self.assertLessEqual(cost['instructions'],limit)
                self.assertLessEqual(cost['longest_basepri_instruction_run'],masked_limit)
                self.assertEqual(cost['final_basepri'],0)

    def frame(self,cpu,kind,points,buttons=3,wheel=0):
        data=bytes((kind,buttons|wheel))+b''.join(struct.pack('<HH',x&65535,y&65535) for x,y in points)
        p=0x2000D000
        cpu.uc.mem_write(p,data)
        self.assertEqual(cpu.run(R.QUEUE_PREFIX,0,p,len(data)),1)
        cpu.uc.mem_write(0x200092B8,b'\1\1')
        cpu.uc.mem_write(0x20009007,b'\1')
        return cpu.run(R.PARSER,count=100000)

    def capture_reports(self,cpu,reports):
        cpu.add_hook(UC_HOOK_CODE,lambda uc,address,size,user:reports.append(
            bytes(cpu.uc.mem_read(cpu.reg('r0'),6))),begin=R.REPORT,end=R.REPORT)

    def test_real_parser_absolute_baseline_wrap_drop_jump_and_relative_reset(self):
        with self.radio_cpu() as cpu:
            reports=[]
            self.capture_reports(cpu,reports)
            cases=[(10,[(65530,5)],[(0,0)]),
                   (10,[(4,65530),(14,10)],[(10,-11),(10,16)]),
                   # Missing frames: next total recovers accumulated delta.
                   (10,[(114,60)],[(100,50)]),
                   (10,[(30000,30000)],[(0,0)]),
                   (10,[(30001,29999)],[(1,-1)]),
                   (2,[(40000,20000)],[(-25536,20000)]),
                   (10,[(100,100)],[(0,0)])]
            for kind,points,expected in cases:
                reports.clear()
                self.assertEqual(self.frame(cpu,kind,points,buttons=5,wheel=0x60),1)
                self.assertEqual([struct.unpack('<hh',r[2:]) for r in reports],expected)
                self.assertEqual([r[0] for r in reports],[5]*len(points))
                self.assertEqual([r[1] for r in reports],[1]+[0]*(len(points)-1))
                self.assertEqual(cpu.reg('sp'),R.SP)

    def test_real_parser_relative_frames_stock_usb_payload_equivalence(self):
        for points,wheel in itertools.product(([(12,-34)],[(12,-34),(-100,200)]),(0,0x40,0x60,0x80,0xA0)):
            results=[]
            for patched in (False,True):
                with self.radio_cpu(patched) as cpu:
                    seen=[]
                    self.capture_reports(cpu,seen)
                    result=self.frame(cpu,2,points,wheel=wheel)
                    results.append((result,seen,cpu.run(R.QUEUE_COUNT,0)))
            self.assertEqual(results[0],results[1])

    def test_relative_fast_path_leaves_baseline_to_actual_admission(self):
        from tools.audit_hotpaths import measure
        with self.cpu() as cpu:
            source=0x2000D000
            payload=struct.pack('<BBhh',5,1,-25536,20000)
            cpu.uc.mem_write(source,payload)
            cpu.uc.mem_write(R.ABS_VALID,b'\1')
            cpu.uc.mem_write(R.ABS_X,struct.pack('<H',123))
            cpu.uc.mem_write(R.ABS_Y,struct.pack('<H',456))
            cpu.setreg('r7',0)
            calls=[]
            cpu.stub(R.REPORT,effect=lambda c:calls.append(
                (c.reg('r0'),c.reg('sp'),bytes(c.uc.mem_read(c.reg('r0'),6)))))
            cost=measure(cpu,self.builder.absolute['main'],(source,))
            self.assertEqual(calls,[(source,R.SP,payload)])
            self.assertEqual(cpu.byte(R.ABS_VALID),1)
            self.assertEqual(struct.unpack('<H',cpu.uc.mem_read(R.ABS_X,2))[0],123)
            self.assertEqual(struct.unpack('<H',cpu.uc.mem_read(R.ABS_Y,2))[0],456)
            self.assertEqual(cost['instructions'],3)
            self.assertEqual(cost['masked_instructions'],0)

    def test_mouse_native_queue_frame_to_paired_receiver_real_parser(self):
        from MAYA_X_V2.tests.test_absolute import AbsoluteTests, HEAP
        from MAYA_X_V2 import target as T
        source=AbsoluteTests();source.builder=AbsoluteTests.builder if hasattr(AbsoluteTests,'builder') else None
        if source.builder is None:
            AbsoluteTests.setUpClass();source.builder=AbsoluteTests.builder
        source.changed=AbsoluteTests.changed
        with source.cpu() as mouse, self.radio_cpu() as rx:
            mouse.uc.mem_write(T.RADIO_STATE,b'\1\1')
            reports=[]
            self.capture_reports(rx,reports)
            rx.uc.mem_write(0x200092B8,b'\1\1');rx.uc.mem_write(0x20009007,b'\1')
            for totals in (((100,200),),((110,190),(125,220))):
                for xy in totals:
                    mouse.uc.mem_write(HEAP+24,struct.pack('<HH',*xy))
                    mouse.uc.mem_write(0x20016000,b'\0'*8)
                    self.assertEqual(mouse.run(T.RADIO_SEND,9,0x20016000),1)
                self.assertEqual(mouse.run(T.ABS_FRAME_NATIVE,T.ABS_FRAME_BUFFER,1),1)
                length=mouse.byte(T.ABS_FRAME_BUFFER)
                frame=bytes(mouse.uc.mem_read(T.ABS_FRAME_BUFFER+2,length-1))
                rx.uc.mem_write(0x2000D000,frame)
                self.assertEqual(rx.run(R.QUEUE_PREFIX,0,0x2000D000,len(frame)),1)
                self.assertEqual(rx.run(R.PARSER,count=100000),1)
            self.assertEqual([struct.unpack('<hh',r[2:]) for r in reports],[(0,0),(10,-10),(15,30)])

    def radio_cpu(self,patched=True):
        cpu=self.cpu(patched)
        cpu.uc.mem_map(0x50000000,0x200000)
        cpu.uc.mem_map(0xE000E000,0x2000)
        cpu.uc.mem_write(0x200092B8,b'\1\1')
        cpu.uc.mem_write(0x20009007,b'\1')
        cpu.uc.mem_write(0x20009444,b'\x80')
        cpu.put32(0x20006DE8+0x34,R.PARSER|1)
        cpu.uc.mem_write(0x200082D2,struct.pack('<H',1000))
        cpu.put32(0x50085554,100)
        # Actual USB variable-length queue (not the radio queue), initialized
        # to its original 25x25 header. Keep queue/copy/report instructions.
        cpu.uc.mem_write(0x20008335+629,b'\0\0\x19\x19')
        cpu.uc.mem_write(0x20009003,b'\2')
        cpu.uc.mem_write(0x20003574+115,b'\1')
        cpu.uc.mem_write(0x20008310,b'\1')
        cpu.stub(0x19DAC)  # Original IRQ-exit scheduler service.
        cpu.usb=[]
        cpu.stub(0x20003158,effect=lambda c:cpu.usb.append(
            bytes(c.uc.mem_read(c.reg('r2'),c.reg('r1')))) or 0)
        return cpu

    def radio_packet(self,cpu,head,kind,points,crc=1):
        raw=bytes((kind,0x65))+b''.join(struct.pack('<HH',x&65535,y&65535) for x,y in points)
        return self.radio_frame(cpu,head,raw,crc)

    def radio_frame(self,cpu,head,raw,crc=1):
        cpu.uc.mem_write(0x200092B8+390,b'\6')
        cpu.put32(0x5008A218,1)
        cpu.put32(0x5008AE0C,crc);cpu.put32(0x5008AE10,0)
        cpu.uc.mem_write(0x200093FE,bytes((len(raw)+1,head))+raw)
        cpu.put32(0x500C9000,0)
        cpu.run(0x20002EA4,count=100000)  # Original aligned radio IRQ.
        wake=cpu.u32(0x500C9000)
        if wake:
            # Hardware task START eventually raises compare0; model only
            # that external event, execute the actual IRQ/queue/parser.
            cpu.put32(0x500C9100,1)
            cpu.run(0x19234,count=100000)
        return wake

    def flush_usb(self,cpu):
        for _ in range(25):
            cpu.put32(0x20006BB8,0)
            cpu.uc.mem_write(0x20008322,b'\0')
            cpu.run(0x20000E64,count=100000)
            q=0x20008335+629
            if cpu.byte(q)==cpu.byte(q+1):break

    def test_native_radio_crc_dedup_dual_abs_to_usb_queue_and_endpoint(self):
        with self.radio_cpu() as cpu:
            self.assertEqual(self.radio_packet(cpu,0,10,[(100,200)]),1)
            self.assertEqual(self.radio_packet(cpu,0,10,[(900,900)]),0)  # duplicate
            self.assertEqual(self.radio_packet(cpu,1,10,[(800,800)],crc=0),0)
            self.assertEqual(self.radio_packet(cpu,1,10,[(110,190),(125,220)]),1)
            self.assertEqual(self.radio_packet(cpu,0,10,[(225,270)]),1)  # gap recovery
            before=len(cpu.usb)
            self.assertEqual(self.radio_packet(cpu,1,0xA8,[(0,0)]),0)
            self.assertEqual(self.radio_packet(cpu,1,0xA9,[(0,0)]),0)
            self.assertEqual(len(cpu.usb),before)
            self.flush_usb(cpu)
            self.assertEqual([struct.unpack('<hh',p[2:6]) for p in cpu.usb],
                [(0,0),(10,-10),(15,30),(100,50)])
            self.assertEqual([p[0] for p in cpu.usb],[5]*4)
            self.assertEqual([p[1] for p in cpu.usb],[1,1,0,1])
            self.assertTrue(all(len(p)==8 for p in cpu.usb))
            self.assertEqual(cpu.reg('sp'),R.SP)

    def test_native_relative_radio_to_usb_including_drops_matches_stock(self):
        results=[]
        for patched in (False,True):
            with self.radio_cpu(patched) as cpu:
                wakes=[]
                for head,crc,points in ((0,1,[(12,-34)]),(0,1,[(700,800)]),
                        (1,0,[(800,900)]),(1,1,[(-100,200),(40,-50)])):
                    wakes.append(self.radio_packet(cpu,head,2,points,crc))
                self.flush_usb(cpu)
                results.append((wakes,cpu.usb,bytes(cpu.uc.mem_read(0x200092B3,8))))
        self.assertEqual(results[0],results[1])
        self.assertEqual(results[0][0],[1,0,0,1])

    def test_usb_backpressure_keeps_relative_stock_and_recovers_absolute_motion(self):
        results=[]
        for patched,kind in ((False,2),(True,2),(True,10)):
            with self.radio_cpu(patched) as cpu:
                for index in range(31):
                    x=index if kind==10 else int(index>0)
                    self.assertEqual(self.radio_packet(cpu,index&1,kind,[(x,0)]),1)
                self.assertEqual(len(cpu.usb),1)
                self.flush_usb(cpu)
                before=sum(struct.unpack_from('<h',packet,2)[0] for packet in cpu.usb)
                if kind==10:
                    self.assertEqual(struct.unpack('<H',cpu.uc.mem_read(R.ABS_X,2))[0],24)
                self.assertEqual(self.radio_packet(cpu,1,kind,[(31 if kind==10 else 1,0)]),1)
                self.flush_usb(cpu)
                after=sum(struct.unpack_from('<h',packet,2)[0] for packet in cpu.usb)
                results.append((before,after,len(cpu.usb)))
        self.assertEqual(results,[(24,25,26),(24,25,26),(24,31,26)])

    def test_dual_absolute_frame_commits_each_accepted_sample_before_retry(self):
        with self.radio_cpu() as cpu:
            for index in range(24):
                self.assertEqual(self.radio_packet(cpu,index&1,10,[(index,0)]),1)
            # One USB queue slot remains: accept the first native parser
            # callback, refuse the second, and retain that missing step.
            self.assertEqual(self.radio_packet(cpu,0,10,[(24,0),(25,0)]),1)
            self.assertEqual(struct.unpack('<H',cpu.uc.mem_read(R.ABS_X,2))[0],24)
            self.flush_usb(cpu)
            self.assertEqual(sum(struct.unpack_from('<h',p,2)[0] for p in cpu.usb),24)
            self.assertEqual(self.radio_packet(cpu,1,10,[(25,0)]),1)
            self.flush_usb(cpu)
            self.assertEqual([struct.unpack_from('<h',p,2)[0] for p in cpu.usb],
                             [0]+[1]*25)
            self.assertEqual(cpu.reg('sp'),R.SP)

    def test_refused_relative_report_does_not_discard_accepted_absolute_baseline(self):
        with self.radio_cpu() as cpu:
            for index in range(31):
                self.assertEqual(self.radio_packet(cpu,index&1,10,[(100+index,0)]),1)
            self.assertEqual(self.radio_packet(cpu,1,2,[(5,0)]),1)
            self.assertEqual(cpu.byte(R.ABS_VALID),1)
            self.assertEqual(struct.unpack('<H',cpu.uc.mem_read(R.ABS_X,2))[0],124)
            self.flush_usb(cpu)
            self.assertEqual(sum(struct.unpack_from('<h',p,2)[0] for p in cpu.usb),24)
            self.assertEqual(self.radio_packet(cpu,0,10,[(131,0)]),1)
            self.flush_usb(cpu)
            self.assertEqual(sum(struct.unpack_from('<h',p,2)[0] for p in cpu.usb),31)

    def test_endpoint_failure_keeps_accepted_absolute_reports_in_native_usb_queue(self):
        with self.radio_cpu() as cpu:
            attempted=[]
            cpu.stub(0x20003158,effect=lambda c:attempted.append(
                bytes(c.uc.mem_read(c.reg('r2'),c.reg('r1')))) or -16)
            for index,total in enumerate((100,110,120)):
                self.assertEqual(self.radio_packet(cpu,index&1,10,[(total,0)]),1)
            self.assertTrue(attempted)
            self.assertEqual(cpu.usb,[])
            self.assertEqual(struct.unpack('<H',cpu.uc.mem_read(R.ABS_X,2))[0],120)
            cpu.stub(0x20003158,effect=lambda c:cpu.usb.append(
                bytes(c.uc.mem_read(c.reg('r2'),c.reg('r1')))) or 0)
            self.flush_usb(cpu)
            self.assertEqual([struct.unpack_from('<h',p,2)[0] for p in cpu.usb],[0,10,10])

    def test_native_report_gate_preserves_absolute_baseline_until_queue_admission(self):
        with self.radio_cpu() as cpu:
            self.assertEqual(self.radio_packet(cpu,0,10,[(100,200)]),1)
            cpu.put32(0x20006D80,1)
            cpu.stub(0x2007B1C8)  # Native deferred scheduling service.
            self.assertEqual(self.radio_packet(cpu,1,10,[(110,190)]),1)
            self.assertEqual(struct.unpack('<H',cpu.uc.mem_read(R.ABS_X,2))[0],100)
            self.assertEqual(struct.unpack('<H',cpu.uc.mem_read(R.ABS_Y,2))[0],200)
            cpu.put32(0x20006D80,0)
            self.assertEqual(self.radio_packet(cpu,0,10,[(110,190)]),1)
            self.flush_usb(cpu)
            self.assertEqual([struct.unpack_from('<hh',p,2) for p in cpu.usb],[(0,0),(10,-10)])

    def test_absolute_admission_preimages_reject_native_contract_drift(self):
        from copy import copy
        from MAYA_X_V2.receiver_facts import ABS_ADMISSION_PREIMAGES
        for site in ABS_ADMISSION_PREIMAGES:
            builder=copy(self.builder)
            builder.image=copy(builder.image)
            builder.image.mem=dict(builder.image.mem)
            builder.image.mem[R.flash_source(site)]^=1
            builder.image.__dict__.pop('data',None)
            with self.subTest(site=hex(site)),self.assertRaisesRegex(ValueError,'admission contract'):
                R.install_absolute(builder)


if __name__=='__main__':unittest.main()
