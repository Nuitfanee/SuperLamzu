"""Native optical debounce, IR lifecycle and retired-direct regression checks."""
import unittest

from unicorn import UC_HOOK_MEM_WRITE
from unicorn.arm_const import UC_ARM_REG_PRIMASK

from MAYA_X_V2 import target as T
from MAYA_X_V2.advanced import build_optical
from MAYA_X_V2.optical import stock
from MAYA_X_V2.sensor import LAYOUT
from superlamzu import protocol as P
from superlamzu.emulation import Arm
from superlamzu.settings import decode_record, encode_record
from superlamzu.verify import patched_image, request

HEAP = T.NATIVE_HEAP_START+0x404


class OpticalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.builder=build_optical()
        cls.changed=patched_image(cls.builder)

    def cpu(self,patched=True):
        cpu=Arm(self.changed if patched else self.builder.image,layout=LAYOUT)
        cpu.uc.mem_map(0x50080000,0x60000)
        cpu.uc.mem_map(0xE000E000,0x2000)
        cpu.uc.mem_map(0x110000,0x1000)
        cpu.uc.mem_map(0x5004E000,0x1000)
        cpu.uc.mem_write(T.ADV_STORAGE,b'\xff'*16)
        cpu.uc.mem_write(T.SETTINGS,self.changed.get(T.SETTINGS_DEFAULT,T.SETTINGS_BYTES))
        cpu.uc.mem_write(HEAP-4,b'\xa5'*(T.SNAPSHOT_STORAGE_BYTES+8))
        cpu.uc.mem_write(HEAP,bytes(T.SNAPSHOT_STORAGE_BYTES))
        cpu.uc.mem_write(T.SNAPSHOT_POINTER,(HEAP&0xFFFFF).to_bytes(3,'little'))
        cpu.put32(0x2000A42C,1)
        cpu.run(0x34920,T.CLICK_NATIVE_QUEUE,0x2000A4A0,10,8)
        for i,(pointer,descriptor,cache) in enumerate(zip(T.CLICK_DESCRIPTOR_PTRS,T.CLICK_DESCRIPTORS,T.CLICK_CACHES)):
            cpu.put32(pointer,descriptor)
            cpu.uc.mem_write(descriptor+6,bytes((0x82+i,)))
            cpu.uc.mem_write(cache,b'\1')
            cpu.uc.mem_write(T.CLICK_NATIVE_STATE+12*(i+2),b'\1'+bytes(8)+b'\1\0\0')
            cpu.uc.mem_write(T.CLICK_BINDINGS+16*(i+2)+2,bytes((1,0,i+1,0,0,0,0)))
        cpu.put32(0x2000A458,T.CLICK_DESCRIPTORS[1]+7)
        for index,address in enumerate((0x2000A450,0x2000A448,0x2000A444,0x2000A438)):
            cpu.put32(address,0x20006917+7*index)
        cpu.put32(0x2000A460,0x200065B0)
        cpu.put32(0x2000A45C,0x200065B0)
        cpu.put32(0x200065B0,0x500DA000)
        cpu.put32(0x2000629C,T.CLICK_TIMER)
        cpu.put32(T.CLICK_TIMER+0x548,800)
        cpu.stub(0x23440)
        cpu.stub(0x3089E,effect=lambda c:HEAP-4 if c.reg('r1')==T.SNAPSHOT_STORAGE_BYTES+4 else HEAP+0x400)
        cpu.stub(T.MOTION_THREAD_START)
        cpu.stub(T.SET_SENSOR_MODE)
        cpu.stub(0x2A550)
        cpu.stub(0x2A4E8)
        def memcpy(c):
            c.uc.mem_write(c.reg('r0'),bytes(c.uc.mem_read(c.reg('r1'),c.reg('r2'))))
            return c.reg('r0')
        cpu.stub(T.NATIVE_MEMCPY,effect=memcpy)
        cpu.levels=[1,1]
        cpu.stub(0x190B8,effect=lambda c:cpu.levels[0 if c.reg('r1')==9 else 1])
        cpu.stub(T.CLICK_TRANSPORT,1)
        cpu.stub(T.CLICK_LINK,8)
        cpu.stub(T.CLICK_FAST)
        cpu.events=[]
        cpu.stub(T.CLICK_DISPATCH,effect=lambda c:cpu.events.append(
            (c.reg('r2'),c.reg('r1'),c.reg('r0'),bytes(c.uc.mem_read(c.reg('r3'),5)))) or 0)
        return cpu

    def sample(self,cpu,left,right,valid=True):
        cpu.levels=[left,right]
        cpu.put32(0x2000A42C,int(valid))
        cpu.put32(T.CLICK_TIMER+0x140,1)
        cpu.run(0x198F4,count=100000)

    def drain(self,cpu):
        cpu.run(0x302E0,count=100000)

    def test_candidate_preserves_all_native_optical_preimages_and_has_no_direct_code(self):
        self.assertTrue(stock(self.builder)['native'])
        self.assertEqual(self.builder.optical['mode'],'stock')
        self.assertFalse(self.builder.optical['exposed'])
        self.assertFalse(self.builder.extension['flags'] & P.F_OPTICAL_CLICK)
        for address,original in T.CLICK_PREIMAGES.items():
            self.assertEqual(self.changed.get(T.flash_source(address),len(original)),original,hex(address))
        self.assertFalse(any(v['name'].startswith(('optical_','maya_optical_','settings_click_'))
                             for v in self.builder.allocations))

    def test_retired_click_requests_rejected_without_allocation_or_setting_changes(self):
        with self.cpu() as cpu:
            before=bytes(cpu.uc.mem_read(T.SETTINGS,T.SETTINGS_BYTES))
            pointer=bytes(cpu.uc.mem_read(T.SNAPSHOT_POINTER,3))
            for mode in (0,1,2):
                self.assertEqual(request(cpu,P.SET,(0,P.OPTICAL_CLICK,mode),target=T)[0],0xA2)
            self.assertEqual(request(cpu,P.GET,(0,P.OPTICAL_CLICK),target=T)[0],0xA2)
            self.assertEqual(bytes(cpu.uc.mem_read(T.SETTINGS,T.SETTINGS_BYTES)),before)
            self.assertEqual(bytes(cpu.uc.mem_read(T.SNAPSHOT_POINTER,3)),pointer)
            self.assertFalse(any(c[0]==0x3089E for c in cpu.calls))

    def test_historical_direct_bit_is_ignored_and_new_save_clears_it(self):
        with self.cpu() as cpu:
            for mask in (0,1):
                cpu.uc.reg_write(UC_ARM_REG_PRIMASK,mask)
                record=encode_record(37,1,80,(60,1,1),1,1,optical_click=1)
                cpu.uc.mem_write(T.ADV_STORAGE,record)
                cpu.run(self.builder.symbols['settings_queue_init'],0)
                self.assertEqual(cpu.byte(T.ADV_RAM+3),37)
                self.assertEqual(cpu.byte(T.SMOOTHING_STATE),131)
                self.assertEqual(request(cpu,P.GET,(0,P.OPTICAL_CLICK),target=T)[0],0xA2)
                self.assertEqual(bytes(cpu.uc.mem_read(T.ADV_STORAGE,16)),record)
                saved=request(cpu,P.SET,(0,P.SAVE_ADVANCED,1),target=T)
                self.assertEqual(saved[0],0xA0)
                self.assertEqual(decode_record(saved[1][3:])['optical_click'],0)
                self.assertEqual(cpu.uc.reg_read(UC_ARM_REG_PRIMASK),mask)
                self.assertEqual(cpu.u32(T.CLICK_TIMER+0x548),800)

    def test_complete_native_ir_dppi_start_stop_mmio_order_matches_stock(self):
        results=[]
        for patched in (False,True):
            with self.cpu(patched) as cpu:
                endpoints=[]
                cpu.stub(0x34338,0x500DA000)
                cpu.stub(0x3434E,0x500DA004)
                cpu.stub(0x33E6E,effect=lambda c:endpoints.append(
                    ('connect',c.reg('r0'),c.reg('r1'),c.reg('r2'))) or 0)
                cpu.stub(0x284DC,effect=lambda c:endpoints.append(('enable',c.reg('r0'))) or 0)
                for address in (0x23A38,0x239F4,0x239D8):cpu.stub(address)
                writes=[]
                cpu.add_hook(UC_HOOK_MEM_WRITE,
                    lambda uc,a,ad,s,v,u:writes.append((ad,s,v)),
                    begin=0x50080000,end=0x500DFFFF)
                self.assertEqual(cpu.run(0x19924,count=100000),1)
                self.assertEqual(tuple(cpu.u32(T.CLICK_TIMER+0x540+4*i) for i in range(4)),(20,40,800,0))
                self.assertEqual([e[0] for e in endpoints],['connect','enable','connect','enable'])
                self.assertEqual([e[1] for e in endpoints if e[0]=='connect'],
                    [T.CLICK_TIMER+0x148,T.CLICK_TIMER+0x144])
                cpu.run(T.CLICK_STOP,count=100000)
                self.assertEqual(tuple(cpu.u32(T.CLICK_TIMER+0x540+4*i) for i in range(4)),(0,0,0,0))
                self.assertEqual(cpu.u32(T.CLICK_TIMER+0x308),0xFFFFFFFF)
                self.assertEqual(cpu.reg('sp'),T.SP)
                results.append((writes,endpoints))
        self.assertEqual(results[0],results[1])

    def test_stock_native_timelines_retain_pre_post_lock_and_speed_click(self):
        fixtures=[((0,2,20,20),False,2,((0,0),(5000,1))),
                  ((0,2,20,20),False,2,((0,0),(30000,1))),
                  ((0,2,20,20),False,2,((0,0),(30000,1),(35000,0))),
                  ((0,2,20,20),False,2,((0,0),(5000,1),(10000,0),(15000,1))),
                  ((0,2,0,0),False,2,((0,0),(5000,1),(10000,0),(15000,1))),
                  ((5,2,20,20),False,2,((0,0),)),
                  ((5,2,20,20),True,2,((0,0),(5000,1))),
                  ((0,2,20,20),False,3,((0,0),(5000,1))),
                  ((0,2,20,20),False,2,((0,0),))]
        for timings,speed,key,inputs in fixtures:
            outputs=[]
            for patched in (False,True):
                with self.cpu(patched) as cpu:
                    cpu.uc.mem_write(T.LIVE_DB,bytes(timings))
                    cpu.uc.mem_write(T.SETTINGS+0x1B,bytes((speed,speed)))
                    now=[0];pending={};events=[]
                    cpu.stub(T.CLICK_FAST)
                    cpu.stub(T.CLICK_DISPATCH,effect=lambda c:events.append((now[0],c.reg('r2'),c.reg('r1'))) or 0)
                    def timer(c):
                        ms=c.reg('r1')
                        pending[c.reg('r0')&127]=now[0]+((31250*ms+999)//1000)*32
                        return 0
                    cpu.stub(0x20002AA0,effect=timer)
                    def advance(until):
                        for _ in range(1000):
                            if not pending:break
                            k=min(pending,key=pending.get)
                            if pending[k]>until:break
                            now[0]=pending.pop(k);cpu.run(T.CLICK_TIMERS[k-2])
                        else:raise AssertionError('native timer did not converge')
                        now[0]=until
                    for time,level in inputs:
                        advance(time)
                        self.sample(cpu,level if key==2 else 1,level if key==3 else 1)
                        self.drain(cpu)
                    advance(100000)
                    outputs.append((events,bytes(cpu.uc.mem_read(T.CLICK_NATIVE_STATE+24,24))))
                    self.assertEqual(bytes(cpu.uc.mem_read(T.SETTINGS+0x1B,2)),bytes((speed,speed)))
            self.assertEqual(outputs[0],outputs[1],(timings,speed,key,outputs))
            self.assertTrue(outputs[0][0],(timings,speed,key))


if __name__=='__main__':unittest.main()
