"""Thorn's FPS/snapshot/smoothing acceptance scenarios on real MAYA Thumb."""
import itertools
import struct
import unittest

from unicorn import UC_HOOK_MEM_WRITE
from unicorn.arm_const import UC_ARM_REG_PRIMASK

from MAYA_X_V2 import target as T
from MAYA_X_V2.advanced import build_sensor_settings
from MAYA_X_V2.sensor import LAYOUT, run
from superlamzu import advanced as A, protocol as P
from superlamzu.emulation import Arm
from superlamzu.verify import patched_image, request


class AdvancedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.builder = build_sensor_settings()
        cls.changed = patched_image(cls.builder)

    def cpu(self):
        cpu = Arm(self.changed, layout=LAYOUT)
        cpu.uc.mem_write(T.SETTINGS, self.changed.get(T.SETTINGS_DEFAULT, T.SETTINGS_BYTES))
        cpu.run(self.builder.symbols['advanced_queue_init'], 0)
        return cpu

    def spi(self, cpu, failure=0):
        state = dict(page=0, registers={}, writes=[], reads=[], transactions=0)
        def transaction():
            state['transactions'] += 1
            return state['transactions'] != failure
        def wr(cpu):
            reg, value = cpu.reg('r0') & 255, cpu.reg('r1') & 255
            ok = transaction()
            if ok:
                if reg == 127:
                    state['page'] = value
                else:
                    state['registers'][state['page'], reg] = value
            state['writes'].append((state['page'], reg, value))
            return int(ok)
        def rd(cpu):
            key = state['page'], cpu.reg('r0') & 255
            state['reads'].append(key)
            ok = transaction()
            if ok:
                cpu.uc.mem_write(cpu.reg('r1'), bytes((state['registers'].get(key, 0xA5),)))
            return int(ok)
        for address in (T.WR, T.NATIVE_WR):
            cpu.stub(address, effect=wr)
        for address in (T.RD, T.NATIVE_RD):
            cpu.stub(address, effect=rd)
        return state

    def heap(self, cpu, success=True):
        snap = T.NATIVE_HEAP_START+0x404
        cpu.uc.mem_write(snap-5, b'\xA5'*(T.SNAPSHOT_STORAGE_BYTES+6))
        def backend(cpu):
            self.assertEqual(cpu.reg('r0'), T.NATIVE_HEAP)
            # 30914 adapts (heap, alignment, bytes) to (heap, bytes).
            self.assertEqual(cpu.reg('r1'), T.SNAPSHOT_STORAGE_BYTES+4)
            return snap-4 if success else 0
        # Native wrapper and 351A2 execute; substitute only the heap backend.
        cpu.stub(0x3089E, effect=backend)
        def readonly(uc, access, address, size, value, user):
            self.fail(f'write to native MPU code: {address:#x}')
        cpu.add_hook(UC_HOOK_MEM_WRITE, readonly, begin=T.RAM_RUN, end=T.RAM_RUN+T.RAM_LEN-1)
        return snap

    def test_capabilities_and_init_do_not_claim_radio_or_persistence(self):
        with self.cpu() as cpu:
            status, raw = request(cpu, P.GET, (0, P.CAPS), target=T)
            caps = P.decode_capabilities(raw)
            self.assertEqual(status, 0xA0)
            self.assertEqual(caps['flags'], P.F_DB | P.F_B | P.F_FPS | P.F_FPS_CUSTOM | P.F_SENSOR_SNAPSHOT | P.F_SMOOTHING)
            self.assertEqual(caps['preset_count'], 38)
            self.assertEqual(caps['stats_bytes'], 0)
            before = bytes(cpu.uc.mem_read(T.SNAPSHOT_POINTER, 192))
            for q in range(1, 7):
                cpu.run(self.builder.symbols['advanced_queue_init'], q)
            self.assertEqual(bytes(cpu.uc.mem_read(T.SNAPSHOT_POINTER, 192)), before)
            for operation in (P.LOCK, P.STATS, P.SAVE_ADVANCED, P.IDLE_TRACKING,
                              P.MOTION_PATH, P.ABS_MOTION, P.OPTICAL_CLICK, P.CHANNELS):
                self.assertEqual(request(cpu, P.GET, (0, operation), target=T)[0], 0xA2)

    def test_every_preset_preserves_native_recipe_prefix_and_companions(self):
        # Same preset/complete-prefix checks as superlamzu.checks.fps_check.
        for mode, variant in itertools.product((2, 3, 4, 6, 7), range(1, 4)):
            original = run(self.builder.image, T.RECIPE_DISPATCH, args=(mode, variant))
            prefix = [(e['page'], e['reg'], e['value'] | 64
                       if (e['page'], e['reg']) == (5, 68) else e['value'])
                      for e in original if e['op'] == 'write']
            with self.cpu() as cpu:
                for preset, (_, u, slow, fast) in enumerate(A.PRESETS):
                    spi = self.spi(cpu)
                    cpu.uc.mem_write(T.ADV_RAM+3, bytes((preset,)))
                    cpu.uc.mem_write(T.ADV_RAM+9, b'\1')
                    cpu.run(self.builder.symbols['advanced_recipe_dispatch'], mode, variant, count=100000)
                    self.assertEqual(spi['writes'][:len(prefix)], prefix, (mode, variant, preset))
                    if preset:
                        self.assertEqual([spi['registers'][key] for key in ((7,66), (6,83), (6,98))], [u,slow,fast])
                    self.assertEqual(spi['page'], 0)
                    self.assertEqual(cpu.byte(T.ADV_RAM+8), preset)
                    self.assertEqual(cpu.byte(T.ADV_RAM+9), 0)

    def test_custom_byte_coverage_protocol_and_spi_readback(self):
        recipes = {(u, 2, 2) for u in range(1, 256)}
        recipes |= {(47, m, m) for m in range(1, 256)}
        recipes |= {(25, 255, m) for m in range(1, 256)}
        recipes |= {(60, 1, 1), (1, 1, 1), (255, 255, 255)}
        with self.cpu() as cpu:
            posted = []
            cpu.stub(T.SET_SENSOR_MODE, effect=lambda a: posted.append(a.reg('r0')))
            for u, slow, fast in sorted(recipes):
                spi = self.spi(cpu)
                cpu.uc.mem_write(T.ADV_RAM+184, bytes(4))
                cpu.uc.mem_write(T.ADV_RAM+8, b'\0')
                result = request(cpu, P.SET, (0, P.FPS_CUSTOM, u, slow, fast), target=T)
                self.assertEqual(result, (0xA0, bytes((0,5,255,0,1,u,slow,fast,0,0,0,0))))
                self.assertFalse(spi['writes'] or spi['reads'])
                self.assertTrue(posted)
                cpu.run(self.builder.symbols['advanced_fps_apply'])
                self.assertEqual(spi['reads'], [(6,83), (6,98), (7,66)])
                self.assertEqual(spi['registers'], {(6,83):slow, (6,98):fast, (7,66):u})
                self.assertEqual(spi['page'], 0)
                self.assertEqual(request(cpu, P.GET, (0, P.FPS_CUSTOM), target=T),
                    (0xA0, bytes((0,5,255,255,0,u,slow,fast,u,slow,fast,1))))

    def test_fps_atomic_publication(self):
        from superlamzu.checks import fps_publish_interleaves
        self.assertEqual(fps_publish_interleaves(self.builder,target=T,
                         factory=lambda b:self.cpu()),12)

    def test_preset_readback_failures_and_retry(self):
        from superlamzu.checks import fps_readback_failure_check
        self.assertEqual(fps_readback_failure_check(self.builder, target=T,
                         factory=lambda b:self.cpu()), 24)

    def test_sensor_failures_and_concurrent_custom_requests_stay_pending(self):
        for failure in range(1, 12):
            with self.cpu() as cpu:
                spi = self.spi(cpu, failure)
                cpu.uc.mem_write(T.ADV_RAM+3, b'\xff')
                cpu.uc.mem_write(T.ADV_RAM+13, bytes((60,1,1)))
                cpu.uc.reg_write(UC_ARM_REG_PRIMASK, 1)
                cpu.run(self.builder.symbols['advanced_fps_apply'])
                self.assertEqual(cpu.byte(T.ADV_RAM+9), 1)
                self.assertEqual(cpu.byte(T.ADV_RAM+187), 0)
                self.assertEqual(spi['page'], 0)
                self.assertEqual(cpu.uc.reg_read(UC_ARM_REG_PRIMASK), 1)
        with self.cpu() as cpu:
            spi = self.spi(cpu)
            original = cpu.stubs[T.WR][1]
            def concurrent(cpu):
                cpu.uc.mem_write(T.ADV_RAM+13, bytes((48,3,2)))
                return original(cpu)
            cpu.stub(T.WR, effect=concurrent)
            cpu.uc.mem_write(T.ADV_RAM+3, b'\xff')
            cpu.uc.mem_write(T.ADV_RAM+13, bytes((60,1,1)))
            cpu.run(self.builder.symbols['advanced_fps_apply'])
            self.assertEqual(cpu.byte(T.ADV_RAM+9), 1)
            self.assertEqual(bytes(cpu.uc.mem_read(T.ADV_RAM+184,4)), bytes((60,1,1,1)))

    def test_smoothing_restores_current_maya_recipe_not_fixed_90(self):
        for mode, variant, reduced in itertools.product(range(1,9), range(1,4), (0,1)):
            with self.cpu() as cpu:
                spi = self.spi(cpu)
                cpu.uc.mem_write(T.SMOOTHING_STATE, bytes((reduced|2,)))
                cpu.run(self.builder.symbols['advanced_recipe_dispatch'], mode, variant, count=100000)
                if mode in (4,6,7):
                    expected = 2 if reduced or variant == 1 else {4:144,6:19,7:39}[mode]
                    self.assertEqual(spi['registers'][12,77], expected)
                    self.assertTrue(cpu.byte(T.SMOOTHING_STATE)&4)
                    self.assertFalse(cpu.byte(T.SMOOTHING_STATE)&66)
                else:
                    self.assertFalse(cpu.byte(T.SMOOTHING_STATE)&4)
                self.assertEqual(spi['page'], 0)
        with self.cpu() as cpu:
            spi = self.spi(cpu)
            posted = []
            cpu.stub(T.SET_SENSOR_MODE, effect=lambda a: posted.append(a.reg('r0')))
            cpu.uc.mem_write(T.SENSOR_MODE, b'\6')
            self.assertEqual(request(cpu,P.SET,(0,7,1),target=T),(0xA0,b'\0\7\3'))
            self.assertEqual(posted,[6])
            self.assertFalse(spi['writes'] or spi['reads'])

    def test_new_token_snapshot_all_spi_failures_and_heap_owner(self):
        values = (37,1,1,0xA8,0x90,0x40,0,0x80)
        for failure in range(14):
            with self.cpu() as cpu:
                snap = self.heap(cpu)
                spi = self.spi(cpu, failure)
                spi['registers'].update(dict(zip(P.SENSOR_REGISTERS,values)))
                cpu.uc.mem_write(T.SENSOR_READY, b'\1')
                posted = []
                def post(cpu):
                    self.assertEqual(cpu.reg('r0'), T.SENSOR_QUEUE)
                    posted.append(bytes(cpu.uc.mem_read(cpu.reg('r1'),12)))
                    return 0
                cpu.stub(T.SENSOR_POST,effect=post)
                cpu.uc.mem_write(T.SENSOR_MODE,b'\4')
                cpu.uc.mem_write(T.SENSOR_VARIANT,b'\3')
                cpu.uc.mem_write(T.SENSOR_CPI_X,struct.pack('<HH',3200,3200))
                result=request(cpu,P.SET,(0,6,0x34,0x12),target=T)
                self.assertEqual(result[0],0xA0)
                self.assertEqual(posted,[struct.pack('<III',T.SNAP_MESSAGE,0,0)])
                self.assertEqual(cpu.u32(snap-4),T.NATIVE_HEAP)
                self.assertEqual(cpu.byte(snap-5),0xA5)
                self.assertEqual(cpu.byte(snap+T.SNAPSHOT_STORAGE_BYTES),0xA5)
                self.assertEqual(cpu.byte(snap+1),1)
                self.assertEqual(spi['transactions'],0)
                self.assertEqual(request(cpu,P.SET,(0,6,0x35,0x12),target=T)[0],0xA2)
                cpu.run(self.builder.symbols['advanced_snapshot_worker'])
                record=bytes(cpu.uc.mem_read(snap,24))
                self.assertEqual(record[1],3 if failure else 2)
                self.assertEqual(record[4:8],b'\x34\x12\x34\x12')
                self.assertEqual(record[8:10],b'\4\3')
                self.assertEqual(record[12:20],bytes(8) if failure else bytes(values))
                self.assertEqual(record[20:24],struct.pack('<HH',3200,3200))
                self.assertEqual(spi['page'],0)
                self.assertEqual(request(cpu,P.GET,(0,6),target=T),(0xA0,b'\0\6'+record))

    def test_allocation_failure_and_queue_failure_do_not_claim_ready(self):
        with self.cpu() as cpu:
            self.heap(cpu,False)
            cpu.uc.mem_write(T.SENSOR_READY,b'\1')
            self.assertEqual(request(cpu,P.SET,(0,6,1,0),target=T)[0],0xA2)
            self.assertEqual(int.from_bytes(cpu.uc.mem_read(T.SNAPSHOT_POINTER,3),'little')&0xfffff,0)
        with self.cpu() as cpu:
            snap=self.heap(cpu)
            cpu.uc.mem_write(T.SENSOR_READY,b'\1')
            cpu.stub(T.SENSOR_POST,0xFFFFFFDD)
            self.assertEqual(request(cpu,P.SET,(0,6,1,0),target=T)[0],0xA0)
            self.assertEqual(bytes(cpu.uc.mem_read(snap+1,2)),b'\3\xff')

    def test_snapshot_reply_word_copy_is_atomic_bounded_and_mask_preserving(self):
        from unicorn import UC_HOOK_MEM_READ
        from MAYA_X_V2.tests.audit_hotpaths import measure

        record=bytes((i*17+3)&255 for i in range(24))
        for present,mask in itertools.product((False,True),(0,1)):
            with self.subTest(present=present,mask=mask),self.cpu() as cpu:
                snap=self.heap(cpu)
                cpu.uc.mem_write(T.SNAPSHOT_POINTER,
                    ((snap&0xFFFFF) if present else 0).to_bytes(3,'little'))
                cpu.uc.mem_write(snap-4,b'\xa5'*4+record+b'\xa5'*4)
                cpu.uc.reg_write(UC_ARM_REG_PRIMASK,mask)
                reads,writes=[],[]
                def observed(uc,access,address,size,value,user):
                    self.assertEqual(uc.reg_read(UC_ARM_REG_PRIMASK),1)
                    (reads if snap<=address<snap+24 else writes).append((address,size))
                cpu.add_hook(UC_HOOK_MEM_READ,observed,begin=snap,end=snap+23)
                cpu.add_hook(UC_HOOK_MEM_WRITE,observed,begin=T.PACKET+8,end=T.PACKET+31)
                expected=record if present else b'\1'+bytes(23)
                self.assertEqual(request(cpu,P.GET,(0,6),target=T),(0xA0,b'\0\6'+expected))
                self.assertEqual(reads,[(snap+off,4) for off in range(0,24,4)] if present else [])
                expected_writes=[(T.PACKET+8+off,4) for off in range(0,24,4)]
                if not present:expected_writes.append((T.PACKET+8,1))
                self.assertEqual(writes,expected_writes)
                self.assertEqual(cpu.uc.reg_read(UC_ARM_REG_PRIMASK),mask)
                self.assertEqual(bytes(cpu.uc.mem_read(snap-4,32)),b'\xa5'*4+record+b'\xa5'*4)
                reads.clear();writes.clear()
                for body in ((1,6),(0,6,0)):
                    self.assertEqual(request(cpu,P.GET,body,target=T)[0],0xA2)
                self.assertEqual((reads,writes),([],[]))
                if mask==0:
                    packet=bytearray(64);packet[0]=0xA0
                    packet[3:8]=bytes((2,1,P.GET,0,6))
                    cpu.uc.mem_write(T.PACKET,bytes(packet))
                    result=measure(cpu,T.GROUP1)
                    self.assertLessEqual(result['longest_masked_instruction_run'],40)

    def test_snapshot_runs_through_native_worker_lock_and_completion(self):
        with self.cpu() as cpu:
            snap=self.heap(cpu)
            cpu.run(self.builder.symbols['advanced_snapshot_storage'])
            cpu.uc.mem_write(snap+1,b'\1')
            spi=self.spi(cpu)
            def receive(cpu):
                cpu.uc.mem_write(cpu.reg('r1'),struct.pack('<III',T.SNAP_MESSAGE,0,0))
                return 0
            cpu.stub(0x2A22C,effect=receive)
            cpu.stub(0x2F3D6)
            # Stop at the next receive loop, after real 1702C and 17070.
            cpu.ends.add(0x1748E)
            # Start after the function's first loop anchor so the stop does not
            # fire before the first receive; preserve its actual native prologue.
            cpu.ends.clear()
            received=[False]
            def received_once(cpu):
                received[0]=True
                cpu.ends.add(0x1748E)
                return receive(cpu)
            cpu.stub(0x2A22C,effect=received_once)
            cpu.run(0x17484,count=100000)
            self.assertTrue(received[0])
            self.assertEqual(cpu.byte(snap+1),2)
            self.assertEqual(len(spi['reads']),8)
            self.assertEqual([args[1] for args in cpu.calls if args[0]==0x2F3D6],
                             [0x2000A3A8,0x2000A380,0x2000A3A8])


if __name__ == '__main__':
    unittest.main()
