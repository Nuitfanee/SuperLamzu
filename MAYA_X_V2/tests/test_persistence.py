"""Existing version/checksum/save matrix through MAYA's actual RRAM driver."""
import itertools
import struct
import unittest

from unicorn import UC_HOOK_MEM_WRITE
from unicorn.arm_const import UC_ARM_REG_PRIMASK

from MAYA_X_V2 import target as T
from MAYA_X_V2.advanced import build_saved_settings
from MAYA_X_V2.persistence import evidence
from MAYA_X_V2.sensor import LAYOUT
from superlamzu import protocol as P
from superlamzu.emulation import Arm
from superlamzu.settings import encode_record
from superlamzu.verify import patched_image, request


class PersistenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.builder = build_saved_settings()
        cls.changed = patched_image(cls.builder)

    def cpu(self):
        cpu = Arm(self.changed,layout=LAYOUT)
        cpu.uc.mem_map(0x10F000,0x1D000)
        cpu.uc.mem_map(0x5004E000,0x1000)
        cpu.uc.mem_write(T.ADV_STORAGE,b'\xff'*16)
        cpu.uc.mem_write(T.SETTINGS,self.changed.get(T.SETTINGS_DEFAULT,T.SETTINGS_BYTES))
        def memcpy(cpu):
            cpu.uc.mem_write(cpu.reg('r0'),bytes(cpu.uc.mem_read(cpu.reg('r1'),cpu.reg('r2'))))
            return cpu.reg('r0')
        cpu.stub(T.NATIVE_MEMCPY,effect=memcpy)
        cpu.stub(0x2A550)
        cpu.stub(0x2A4E8)
        cpu.stub(T.MOTION_THREAD_START)
        cpu.stub(0x3089E,effect=lambda c:T.NATIVE_HEAP_START+0x400
                 if c.reg('r1')==T.SNAPSHOT_STORAGE_BYTES+4 else T.NATIVE_HEAP_START+0x800)
        cpu.stub(T.SET_SENSOR_MODE)
        cpu.run(self.builder.symbols['settings_queue_init'],0)
        return cpu

    def test_shared_save_matrix_real_driver_readback_and_cold_boot(self):
        with self.cpu() as cpu:
            native=bytes(cpu.uc.mem_read(T.SETTINGS,T.SETTINGS_BYTES))
            writes=[]
            cpu.add_hook(UC_HOOK_MEM_WRITE,lambda uc,a,address,size,value,u:
                         writes.append((address,size,value)),begin=0x5004E000,end=0x5004EFFF)
            for fps,lock,smoothing,tracking,mask in itertools.product((0,37,255),(0,1),(0,1),(0,1),(0,1)):
                expected=encode_record(fps,lock,499,(60,1,1),smoothing,tracking,
                    motion_path=int(bool(cpu.byte(T.MOTION_STATE)&16)))
                cpu.uc.mem_write(T.ADV_RAM+2,bytes((lock,fps))+struct.pack('<H',499))
                cpu.uc.mem_write(T.ADV_RAM+13,bytes((60,1,1)))
                cpu.uc.mem_write(T.SMOOTHING_STATE,bytes((smoothing|tracking<<7,)))
                cpu.uc.mem_write(T.ADV_STORAGE-16,b'\xa5'*48)
                cpu.uc.reg_write(UC_ARM_REG_PRIMASK,mask)
                result=request(cpu,P.SET,(0,8,1),target=T)
                self.assertEqual(result,(0xA0,bytes((0,8,1))+expected))
                self.assertEqual(cpu.uc.reg_read(UC_ARM_REG_PRIMASK),mask)
                self.assertEqual(bytes(cpu.uc.mem_read(T.ADV_STORAGE-16,48)),b'\xa5'*16+expected+b'\xa5'*16)
                self.assertEqual(bytes(cpu.uc.mem_read(T.SETTINGS,T.SETTINGS_BYTES)),native)
                cpu.run(self.builder.symbols['settings_queue_init'],0)
                self.assertEqual(cpu.byte(T.ADV_RAM+3),fps)
                self.assertEqual(cpu.byte(T.ADV_RAM+2),lock)
                self.assertEqual(cpu.byte(T.SMOOTHING_STATE),smoothing|2|tracking<<7)
                self.assertEqual(bytes(cpu.uc.mem_read(T.ADV_RAM+13,3)),b'\x3c\1\1')
                self.assertEqual(cpu.byte(T.ADV_RAM+9),1)
                self.assertEqual(cpu.reg('sp'),T.SP)
            control=[v for a,s,v in writes if a==0x5004E500]
            self.assertEqual(control,[257,256]*48)
            self.assertFalse(any(a==0x5004E008 for a,s,v in writes))
            self.assertIn(T.ADV_STORAGE,[args[1] for args in cpu.calls if args[0]==T.NATIVE_MEMCPY])

    def test_bad_records_and_unimplemented_fields_never_enable_stub_capabilities(self):
        valid=encode_record(255,1,80,(60,1,1),1)
        records=[bytes(16),b'\xff'*16]
        for i in range(16):
            record=bytearray(valid);record[i]^=1;records.append(record)
        for offset,value in ((4,6),(5,2),(6,254),(7,2),(8,0),(9,0),(11,2),(11,4),(11,16),(13,255)):
            record=bytearray(valid);record[offset]=value
            record[14:]=struct.pack('<H',(sum(record[:14])+0x5A5A)&65535)
            records.append(record)
        with self.cpu() as cpu:
            for record in records:
                cpu.uc.mem_write(T.ADV_STORAGE,bytes(record))
                cpu.run(self.builder.symbols['settings_queue_init'],0)
                self.assertEqual(bytes(cpu.uc.mem_read(T.ADV_RAM,188)),b'\1'+bytes(187))
                self.assertEqual(cpu.byte(T.SMOOTHING_STATE),0)
                self.assertEqual(cpu.byte(T.MOTION_STATE),0)
                self.assertEqual(request(cpu,P.GET,(0,8),target=T)[1][2],0)
            caps=P.decode_capabilities(request(cpu,P.GET,(0,0),target=T)[1])
            self.assertTrue(caps['flags']&P.F_ADV_SAVED)
            self.assertFalse(caps['flags']&(P.F_MOTION_PATH|P.F_ABS|P.F_OPTICAL_CLICK))

    def test_all_versions_migrate_without_nvm_rewrite_and_only_queue0_loads(self):
        with self.cpu() as cpu:
            for version in range(1,6):
                tracking=int(version>1)
                record=encode_record(37,1,80,(60,1,1),1,tracking,version=version)
                cpu.uc.mem_write(T.ADV_STORAGE,record)
                cpu.run(self.builder.symbols['settings_queue_init'],0)
                self.assertEqual(cpu.byte(T.SMOOTHING_STATE),3|tracking<<7)
                self.assertEqual(request(cpu,P.GET,(0,9),target=T),(0xA0,bytes((0,9,tracking))))
                self.assertEqual(bytes(cpu.uc.mem_read(T.ADV_STORAGE,16)),record)
                before=bytes(cpu.uc.mem_read(T.SNAPSHOT_POINTER,192))
                for queue in range(1,7):
                    cpu.run(self.builder.symbols['settings_queue_init'],queue)
                self.assertEqual(bytes(cpu.uc.mem_read(T.SNAPSHOT_POINTER,192)),before)
            cpu.uc.mem_write(T.SENSOR_READY,b'\1')
            cpu.uc.mem_write(T.SENSOR_MODE,b'\6')
            cpu.run(self.builder.symbols['settings_queue_init'],0)
            self.assertEqual([args[1] for args in cpu.calls if args[0]==T.SET_SENSOR_MODE],[6])

    def test_raw_recovery_failed_write_readback_and_native_profile_span(self):
        with self.cpu() as cpu:
            for record in (bytes(range(16)),b'\xff'*16,encode_record()):
                result=request(cpu,P.SET,(0,8,2,*record),target=T)
                self.assertEqual(result[0],0xA0)
                self.assertEqual(result[1][3:],record)
                self.assertEqual(bytes(cpu.uc.mem_read(T.ADV_STORAGE,16)),record)
            # Execute the original profile save with only OS/checksum and
            # unrelated CPI save services stubbed. It must not erase the tail.
            cpu.stub(0x304E0,0x1234)
            cpu.stub(0x1891C)
            cpu.uc.mem_write(T.ADV_STORAGE,b'\xa5'*16)
            cpu.run(T.NATIVE_SETTINGS_SAVE)
            self.assertEqual(bytes(cpu.uc.mem_read(T.ADV_STORAGE,16)),b'\xa5'*16)
            self.assertEqual(bytes(cpu.uc.mem_read(0x110000,T.SETTINGS_BYTES)),bytes(cpu.uc.mem_read(T.SETTINGS,T.SETTINGS_BYTES)))
            for failure in (-22,0):
                cpu.stub(T.STORAGE_WRITE,failure)
                cpu.uc.mem_write(T.ADV_STORAGE,b'\xff'*16)
                self.assertEqual(request(cpu,P.SET,(0,8,1),target=T)[0],0xA2)
            for args in ((0,8),(0,8,0),(0,8,2),(1,8,1),(0,8,1,0)):
                self.assertEqual(request(cpu,P.SET,args,target=T)[0],0xA2)

    def test_saved_abs_survives_dirty_queue2_native_startup_order(self):
        from MAYA_X_V2.full import build_pair
        from superlamzu.settings import encode_record
        for profile in ('SUPER',):
            mouse,_=build_pair(profile)
            fixture=PersistenceTests();fixture.builder=mouse;fixture.changed=patched_image(mouse)
            with self.subTest(profile=profile),fixture.cpu() as cpu:
                cpu.stub(0x3089E,T.NATIVE_HEAP_START+0x400)
                record=encode_record(abs_motion=1,motion_path=1)
                cpu.uc.mem_write(T.ADV_STORAGE,record)
                cpu.uc.mem_write(T.RADIO_QUEUE2,b'\xa5'*T.QUEUE_STRIDE)
                # Real outer initializer calls the installed hook at 30538
                # in queue0..6 order, not seven independent fixture calls.
                cpu.run(0x30530,count=100000)
                self.assertEqual(request(cpu,P.GET,(0,P.ABS_MOTION),target=T)[1][2],1)
                self.assertEqual(request(cpu,P.GET,(0,P.MOTION_PATH),target=T)[1][2],1)
                self.assertEqual(bytes(cpu.uc.mem_read(T.ADV_STORAGE,16)),record)

    def test_storage_preimage_and_alias_guards(self):
        self.assertEqual(evidence(self.builder.image)['storage'],0x1102D0)
        from copy import deepcopy
        for address in (*T.STORAGE_PREIMAGES,*T.STORAGE_OWNER_PREIMAGES):
            image=deepcopy(self.builder.image)
            image.mem[address]^=1
            # Image.get uses its data buffer, so alter both authoritative views.
            data=bytearray(image.data);data[address-image.base]^=1
            image.data=bytes(data)
            with self.assertRaises(ValueError): evidence(image)


if __name__=='__main__':
    unittest.main()
