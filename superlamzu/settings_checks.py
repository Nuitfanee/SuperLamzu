"""Real Thumb persistence and smoothing checks shared by FULL and tests."""
import itertools
import struct

from . import advanced as A, protocol as P, target as T
from .checks import fresh
from .settings import encode_record, decode_record
from .verify import request


def persistence_check(b):
    count = 0
    with fresh(b) as a:
        def memcpy(a):
            a.uc.mem_write(a.reg('r0'), bytes(a.uc.mem_read(a.reg('r1'), a.reg('r2'))))
            return a.reg('r0')
        a.stub(0x0E0877E0, effect=memcpy)
        posted = []
        a.stub(T.SET_SENSOR_MODE, effect=lambda a: posted.append(a.reg('r0')))
        before_native = bytes(a.uc.mem_read(T.SETTINGS, 704))
        for fps, lock, smoothing, tracking, path in itertools.product((0, 37, 255), (0, 1), (0, 1), (0, 1), (0,1)):
            expected = encode_record(fps, lock, 499, (60, 1, 1), smoothing, tracking, motion_path=path)
            a.uc.mem_write(T.ADV_RAM+2, bytes((lock, fps)) + struct.pack('<H',499))
            a.uc.mem_write(T.ADV_RAM+13, bytes((60,1,1)))
            a.uc.mem_write(T.SMOOTHING_STATE, bytes((smoothing | tracking << 7,)))
            a.uc.mem_write(T.MOTION_STATE, bytes((path<<4,)))
            a.uc.mem_write(T.ADV_STORAGE-16, b'\xA5'*48)
            result = request(a,P.SET,(0,P.SAVE_ADVANCED,1))
            assert result == (0xA0,bytes((0,P.SAVE_ADVANCED,1))+expected),result
            assert bytes(a.uc.mem_read(T.ADV_STORAGE,16)) == expected
            assert bytes(a.uc.mem_read(T.ADV_STORAGE-16,16)) == b'\xA5'*16
            assert bytes(a.uc.mem_read(T.ADV_STORAGE+16,16)) == b'\xA5'*16
            assert bytes(a.uc.mem_read(T.SETTINGS,704)) == before_native
            a.run(b.symbols['advanced_queue_init'],0)
            assert a.byte(T.ADV_RAM+3) == fps and a.byte(T.ADV_RAM+2) == lock
            assert a.byte(T.SMOOTHING_STATE) == smoothing|2|tracking<<7
            assert a.byte(T.MOTION_STATE) == path<<4
            assert bytes(a.uc.mem_read(T.ADV_RAM+13,3)) == bytes((60,1,1))
            assert a.byte(T.ADV_RAM+9) == 1
            count += 1
        valid = encode_record(255,1,80,(60,1,1),1)
        bad_records = [bytes(16),b'\xff'*16]
        for i in range(16):
            bad = bytearray(valid); bad[i] ^= 1; bad_records.append(bytes(bad))
        # Correct checksum cannot legitimize unknown version/flags/values.
        for off,value in ((4,6),(5,2),(6,254),(7,2),(8,0),(9,0),(11,16),(13,255)):
            bad=bytearray(valid);bad[off]=value
            bad[14:]=struct.pack('<H',(sum(bad[:14])+0x5A5A)&65535)
            bad_records.append(bytes(bad))
        for record in bad_records:
            a.uc.mem_write(T.ADV_STORAGE,record)
            a.run(b.symbols['advanced_queue_init'],0)
            assert bytes(a.uc.mem_read(T.ADV_RAM,188)) == b'\1'+bytes(187)
            assert a.byte(T.SMOOTHING_STATE) == 0
            assert a.byte(T.MOTION_STATE) == 0
            assert request(a,P.GET,(0,P.SAVE_ADVANCED))[1][2] == 0
            count += 1
        # A published v1 record migrates with tracking off, without rewriting NVM.
        for version, tracking in ((1,0), (2,1)):
            old = encode_record(37, 1, 80, (60, 1, 1), 1, tracking=tracking, version=version)
            a.uc.mem_write(T.ADV_STORAGE, old)
            a.run(b.symbols['advanced_queue_init'], 0)
            assert a.byte(T.SMOOTHING_STATE) == 3|tracking<<7
            assert request(a, P.GET, (0, P.IDLE_TRACKING)) == (0xA0, bytes((0,9,tracking)))
            assert request(a, P.GET, (0, P.MOTION_PATH)) == (0xA0, b'\0\x0a\0')
            assert bytes(a.uc.mem_read(T.ADV_STORAGE, 16)) == old
            count += 1
        # Recovery restores the actual invalid/preexisting bytes, not rebuilt defaults.
        for record in (bytes(range(16)), b'\xff'*16, valid):
            result=request(a,P.SET,(0,P.SAVE_ADVANCED,2,*record))
            assert result[0]==0xA0 and result[1][3:]==record
            assert bytes(a.uc.mem_read(T.ADV_STORAGE,16))==record
            count+=1
        # Failed write/readback never claims a saved record.
        for failure in (-22,0):
            a.stub(T.STORAGE_WRITE,failure)
            a.uc.mem_write(T.ADV_STORAGE,b'\xff'*16)
            assert request(a,P.SET,(0,P.SAVE_ADVANCED,1))[0] == 0xA2
            count += 1
        for args in ((0,8),(0,8,0),(0,8,2),(1,8,1),(0,7,2),(0,7),(1,7,0)):
            assert request(a,P.SET,args)[0] == 0xA2
            count += 1
    return count


def tracking_protocol_check(b):
    from unicorn.arm_const import UC_ARM_REG_PRIMASK
    count = 0
    with fresh(b) as a:
        posted = []
        a.stub(T.SET_SENSOR_MODE, effect=lambda a: posted.append(a.reg('r0')))
        for primask, low, enabled in itertools.product((0, 1), (0, 3, 12, 45, 67), (0, 1)):
            a.uc.reg_write(UC_ARM_REG_PRIMASK, primask)
            a.uc.mem_write(T.SMOOTHING_STATE, bytes((low | (1-enabled)<<7,)))
            assert request(a, P.SET, (0, P.IDLE_TRACKING, enabled)) == (0xA0, bytes((0, 9, enabled)))
            assert a.byte(T.SMOOTHING_STATE) == low | enabled<<7
            assert request(a, P.GET, (0, P.SMOOTHING)) == (0xA0, bytes((0, 7, low)))
            assert a.uc.reg_read(UC_ARM_REG_PRIMASK) == primask
            assert not posted  # tracking never schedules a mode change or SPI.
            count += 1
        for enabled, selected in itertools.product((0, 1), (0, 1)):
            a.uc.mem_write(T.SMOOTHING_STATE, bytes((enabled<<7,)))
            assert request(a, P.SET, (0, P.SMOOTHING, selected)) == (0xA0, bytes((0, 7, selected|2)))
            assert a.byte(T.SMOOTHING_STATE) == (enabled<<7)|selected|2
            count += 1
        for command, args in ((P.SET, (0,9)), (P.SET, (0,9,2)), (P.SET, (1,9,1)),
                              (P.SET, (0,9,1,0)), (P.GET, (1,9)), (P.GET, (0,9,0))):
            before = bytes(a.uc.mem_read(T.SMOOTHING_STATE, 1))
            assert request(a, command, args)[0] == 0xA2
            assert bytes(a.uc.mem_read(T.SMOOTHING_STATE, 1)) == before
            count += 1
    return count


def smoothing_check(b):
    count = 0
    for mode,variant,selected in itertools.product(range(1,9),range(1,4),(0,1)):
        with fresh(b) as a:
            a.uc.mem_write(T.SMOOTHING_STATE,bytes((selected|2,)))
            page=[0];values={};writes=[];reads=[]
            def wr(a):
                reg,val=a.reg('r0')&255,a.reg('r1')&255
                if reg==127:page[0]=val
                else:values[page[0],reg]=val
                writes.append((page[0],reg,val))
                return 1
            def rd(a):
                reg=a.reg('r0')&255;reads.append((page[0],reg))
                a.uc.mem_write(a.reg('r1'),bytes((values.get((page[0],reg),0xA5),)))
                return 1
            a.stub(T.WR,effect=wr);a.stub(T.RD,effect=rd);a.stub(0x0E086F46)
            a.run(b.symbols['advanced_recipe_dispatch'],mode,variant,count=100000)
            expected = 2 if variant==1 else {3:16,6:19,7:39,4:144}.get(mode,2)
            eligible = mode in (4,6,7)
            if eligible:
                assert values[12,77] == (2 if selected else expected),(mode,variant,values)
                packed=a.byte(T.SMOOTHING_STATE)
                assert packed&4 and not packed&66
                assert reads[-1] == (12,77)
            else:
                assert not a.byte(T.SMOOTHING_STATE)&4
            assert page[0] == 0
            # No change to ripple, LOD or six-byte burst; compare complete prefix.
            from .emulation import sensor_run
            original=sensor_run(b.image,T.RECIPE_DISPATCH,T.WR,T.RD,args=(mode,variant),mapped=True)
            ref=[(e['page'],e['reg'],e['value']|64 if e['page']==5 and e['reg']==68 else e['value']) for e in original if e['op']=='write']
            assert writes[:len(ref)] == ref
            assert all(reg==127 or (p,reg,val)==(12,77,2) for p,reg,val in writes[len(ref):])
            count+=1
    # Every application failure remains pending, invalid, and restores page 0.
    for failure in range(1,5):
        with fresh(b) as a:
            a.uc.mem_write(T.SMOOTHING_STATE,b'\x03');calls=[]
            def spi(a):
                calls.append(a.reg('r0'))
                if a.reg('r0')==77 and a.reg('r1')>255:a.uc.mem_write(a.reg('r1'),b'\2')
                return int(len(calls)!=failure)
            a.stub(T.WR,effect=spi);a.stub(T.RD,effect=spi)
            a.run(b.symbols['settings_smoothing_apply'],4,3)
            assert a.byte(T.SMOOTHING_STATE)==67 and calls[-1]==127
            count+=1
    # SET schedules worker only; GET is RAM-only. No SPI at HID boundary.
    with fresh(b) as a:
        posted=[];a.stub(T.SET_SENSOR_MODE,effect=lambda a:posted.append(a.reg('r0')))
        a.uc.mem_write(T.SENSOR_MODE,b'\6')
        assert request(a,P.SET,(0,P.SMOOTHING,1))==(0xA0,b'\0\7\3')
        assert posted==[6]
        assert request(a,P.GET,(0,P.SMOOTHING))==(0xA0,b'\0\7\3')
        count+=1
    return count
