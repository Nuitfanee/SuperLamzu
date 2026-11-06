"""MAYA real instruction counters and native equivalence, no radio sampler."""
import itertools
import struct
import unittest

from unicorn.arm_const import UC_ARM_REG_PRIMASK

from MAYA_X_V2 import target as T
from MAYA_X_V2.advanced import build_statistics
from MAYA_X_V2.sensor import LAYOUT
from superlamzu import advanced as A, protocol as P
from superlamzu.emulation import Arm
from superlamzu.verify import patched_image, request


class StatisticsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.builder=build_statistics()
        cls.changed=patched_image(cls.builder)

    def cpu(self,patched=True):
        cpu=Arm(self.changed if patched else self.builder.image,layout=LAYOUT)
        cpu.uc.mem_map(0x50080000,0x10000)
        cpu.uc.mem_map(0x500C9000,0x1000)
        cpu.uc.mem_map(T.REPORT_TIMER,0x1000)
        cpu.uc.mem_map(0xE000E000,0x1000)
        cpu.uc.mem_write(T.SETTINGS,self.changed.get(T.SETTINGS_DEFAULT,T.SETTINGS_BYTES))
        cpu.uc.mem_write(T.ADV_RAM,b'\1'+bytes(187))
        def memcpy(cpu):
            cpu.uc.mem_write(cpu.reg('r0'),bytes(cpu.uc.mem_read(cpu.reg('r1'),cpu.reg('r2'))))
            return cpu.reg('r0')
        cpu.stub(T.NATIVE_MEMCPY,effect=memcpy)
        return cpu

    def test_six_atomic_pages_reset_retains_custom_readback_and_config(self):
        with self.cpu() as cpu:
            for mask in (0,1):
                cpu.uc.reg_write(UC_ARM_REG_PRIMASK,mask)
                data=bytes(range(188))
                cpu.uc.mem_write(T.ADV_RAM,data)
                for page in range(6):
                    self.assertEqual(request(cpu,P.GET,(0,4,page),target=T),
                        (0xA0,bytes((0,4,page))+data[page*32:min(188,page*32+32)]))
                self.assertEqual(request(cpu,P.SET,(0,4,2),target=T),(0xA0,b'\0\4\1'))
                self.assertEqual(bytes(cpu.uc.mem_read(T.ADV_RAM,16)),data[:16])
                self.assertEqual(bytes(cpu.uc.mem_read(T.ADV_RAM+16,168)),bytes(168))
                self.assertEqual(bytes(cpu.uc.mem_read(T.ADV_RAM+184,4)),data[184:])
                self.assertEqual(cpu.uc.reg_read(UC_ARM_REG_PRIMASK),mask)
            caps=P.decode_capabilities(request(cpu,P.GET,(0,0),target=T)[1])
            self.assertEqual(caps['stats_bytes'],188)
            for command,payload in ((P.GET,(0,4,6)),(P.GET,(0,4)),(P.SET,(0,4,3)),(P.SET,(1,4,2))):
                before=bytes(cpu.uc.mem_read(T.ADV_RAM,188))
                self.assertEqual(request(cpu,command,payload,target=T)[0],0xA2)
                self.assertEqual(bytes(cpu.uc.mem_read(T.ADV_RAM,188)),before)

    def test_real_native_send_all_pointer_and_body_callers_count_once(self):
        for enabled,connected in itertools.product((0,1),repeat=2):
            with self.cpu() as cpu:
                cpu.uc.mem_write(T.ADV_RAM+1,b'\1')
                cpu.uc.mem_write(T.RADIO_STATE,bytes((enabled,connected)))
                cpu.run(T.QUEUE_INIT,2)
                packet=0x20016000
                cpu.uc.mem_write(packet,b'\0\0\0\0\x12\x34\x56\x78')
                for i in range(9):
                    ret=cpu.run(T.RADIO_SEND,9,packet)
                    self.assertEqual(ret,3 if not enabled else 7 if not connected else 1 if i<8 else 6)
                self.assertEqual(cpu.u32(T.ADV_RAM+A.OFF['tx_queued']),8*enabled*connected)
                self.assertEqual(cpu.u32(T.ADV_RAM+A.OFF['tx_full']),enabled*connected)
                self.assertEqual(cpu.reg('sp'),T.SP)
                # Literal callers are unchanged and reach the one patched body.
                for site in T.RADIO_SEND_POINTERS:
                    self.assertEqual(self.changed.u32(site),T.RADIO_SEND|1)

    def test_radio_outcome_gate_tracks_nonpersistent_stats_setting(self):
        with self.cpu() as cpu:
            self.assertEqual(cpu.byte(T.MOTION_STATE)&T.RADIO_OUTCOMES_ACTIVE_MASK,0)
            self.assertEqual(request(cpu,P.SET,(0,4,1),target=T)[0],0xA0)
            self.assertEqual(cpu.byte(T.MOTION_STATE)&T.RADIO_OUTCOMES_ACTIVE_MASK,
                             T.RADIO_OUTCOMES_ACTIVE_MASK)
            self.assertEqual(request(cpu,P.SET,(0,4,2),target=T)[0],0xA0)
            self.assertEqual(cpu.byte(T.MOTION_STATE)&T.RADIO_OUTCOMES_ACTIVE_MASK,
                             T.RADIO_OUTCOMES_ACTIVE_MASK)
            self.assertEqual(request(cpu,P.SET,(0,4,0),target=T)[0],0xA0)
            self.assertEqual(cpu.byte(T.MOTION_STATE)&T.RADIO_OUTCOMES_ACTIVE_MASK,0)

    def test_receiver_window_success_timeout_gates_and_native_equivalence(self):
        def radio_setup(cpu, *, counting, state=6, active=1, connected=1,
                        event_status=1, address=0x5A, rate=1):
            cpu.uc.mem_write(T.ADV_RAM+1,bytes((counting,)))
            cpu.uc.mem_write(T.MOTION_STATE,bytes((
                T.RADIO_OUTCOMES_ACTIVE_MASK if counting else 0,)))
            cpu.uc.mem_write(T.RADIO_STATE+2,bytes((active,)))
            cpu.uc.mem_write(T.RADIO_STATE+0x186,bytes((state,)))
            cpu.uc.mem_write(T.RADIO_STATE+1,bytes((connected,)))
            cpu.uc.mem_write(0x200064E8,b'\0\0\x35\x12\x56\x34')
            cpu.uc.mem_write(0x2000E8BE,bytes((0x5A,)))
            cpu.uc.mem_write(0x2000EA4F,bytes((rate,)))
            cpu.put32(0x200064F8,T.RADIO_TIMER)
            cpu.put32(0x5008A21C,1)
            cpu.put32(0x5008AE0C,event_status)
            cpu.put32(0x5008AE10,address)

        def native_state(cpu):
            return (bytes(cpu.uc.mem_read(T.RADIO_STATE,0x190)),
                    bytes(cpu.uc.mem_read(0x50082000,0x600)),
                    bytes(cpu.uc.mem_read(0x5008A000,0xF00)),
                    bytes(cpu.uc.mem_read(0x200064E8,16)),cpu.reg('sp'),
                    [cpu.reg(f'r{i}') for i in range(4,12)])

        for counting,rate in itertools.product((0,1),(1,2)):
            results=[]
            for patched in (False,True):
                with self.cpu(patched) as cpu:
                    radio_setup(cpu,counting=counting,rate=rate)
                    cpu.run(T.RADIO_DECISION,count=100000)
                    if patched:
                        expected=int(counting)
                        self.assertEqual(cpu.u32(T.ADV_RAM+A.OFF['tx_attempts']),expected)
                        self.assertEqual(cpu.u32(T.ADV_RAM+A.OFF['acked']),expected)
                        self.assertEqual(cpu.u32(T.ADV_RAM+A.OFF['no_ack']),0)
                    results.append(native_state(cpu))
            self.assertEqual(results[0],results[1],(counting,rate))

        for active,state,connected,event_status,address in (
                (1,4,1,1,0x5A),(0,6,1,1,0x5A),(1,6,0,1,0x5A),
                (1,6,1,0,0x5A),(1,6,1,1,0xA5)):
            with self.cpu() as cpu:
                radio_setup(cpu,counting=1,state=state,active=active,connected=connected,
                            event_status=event_status,address=address)
                cpu.run(T.RADIO_DECISION,count=100000)
                self.assertEqual(cpu.u32(T.ADV_RAM+A.OFF['tx_attempts']),0,
                                 (active,state,connected,event_status,address))
                self.assertEqual(cpu.u32(T.ADV_RAM+A.OFF['acked']),0)
                self.assertEqual(cpu.u32(T.ADV_RAM+A.OFF['no_ack']),0)

        for counting,active,state,connected in itertools.product(
                (0,1),(0,1),(4,6,8),(0,1)):
            with self.cpu() as cpu:
                radio_setup(cpu,counting=counting,state=state,active=active,connected=connected,
                            event_status=0,address=0)
                cpu.run(T.RADIO_SLOT_DECISION,count=100000)
                expected=int(counting and active and state==6 and connected)
                self.assertEqual(cpu.u32(T.ADV_RAM+A.OFF['tx_attempts']),expected)
                self.assertEqual(cpu.u32(T.ADV_RAM+A.OFF['acked']),0)
                self.assertEqual(cpu.u32(T.ADV_RAM+A.OFF['no_ack']),expected)
                # Native handling leaves state6, so a repeated expiry is gated
                # by the state transition and cannot double count.
                if expected:
                    cpu.run(T.RADIO_SLOT_DECISION,count=100000)
                    self.assertEqual(cpu.u32(T.ADV_RAM+A.OFF['tx_attempts']),expected)

    def test_sync_burst_success_failure_and_unchanged_buffer_abi(self):
        for counting,result in itertools.product((0,1),repeat=2):
            with self.cpu() as cpu:
                cpu.uc.mem_write(T.ADV_RAM+1,bytes((counting,)))
                def burst(cpu):
                    self.assertEqual((cpu.reg('r0'),cpu.reg('r2')),(22,6))
                    if result:cpu.uc.mem_write(cpu.reg('r1'),bytes(range(6)))
                    return result
                cpu.stub(T.SENSOR_BURST,effect=burst)
                buffer=0x20016000
                self.assertEqual(cpu.run(self.builder.symbols['advanced_burst'],22,buffer,6),result)
                self.assertEqual(cpu.u32(T.ADV_RAM+A.OFF['reads_started']),counting*result)
                self.assertEqual(cpu.u32(T.ADV_RAM+A.OFF['spi_ok']),counting*result)
                self.assertEqual(cpu.u32(T.ADV_RAM+A.OFF['read_start_fail']),counting*(1-result))
                self.assertEqual(cpu.u32(T.ADV_RAM+A.OFF['spi_bad']),counting*(1-result))
                if result:self.assertEqual(bytes(cpu.uc.mem_read(buffer,6)),bytes(range(6)))

    def test_native_slot_dispatch_all_states_flags_and_counters_preserved(self):
        for counting,connected,state,rate in itertools.product((0,1),(0,1),(0,3,4,6,8,255),(1,2)):
            results=[]
            for patched in (False,True):
                with self.cpu(patched) as cpu:
                    cpu.uc.mem_write(T.ADV_RAM+1,bytes((counting,)))
                    cpu.uc.mem_write(T.MOTION_STATE,bytes((0x80 if counting else 0,)))
                    cpu.uc.mem_write(T.RADIO_STATE+1,bytes((connected,1)))
                    cpu.uc.mem_write(T.RADIO_STATE+0x186,bytes((state,)))
                    cpu.uc.mem_write(0x2000EA4F,bytes((rate,)))
                    cpu.uc.mem_write(0x200064E8,b'\0\0\x35\x12\x56\x34')
                    cpu.put32(0x200064F8,T.RADIO_TIMER)
                    for i in range(4,13):cpu.setreg(f'r{i}',0xA000+i)
                    cpu.run(T.RADIO_SLOT_DECISION,count=100000)
                    results.append((bytes(cpu.uc.mem_read(T.RADIO_STATE,0x190)),
                        bytes(cpu.uc.mem_read(0x200064E8,0x18)),
                        bytes(cpu.uc.mem_read(0x50082000,0x600)),
                        bytes(cpu.uc.mem_read(0x5008A000,0xF00)),
                        [cpu.reg(f'r{i}') for i in range(13)],cpu.reg('sp')))
            self.assertEqual(results[0],results[1],(counting,connected,state,rate))

    def test_real_tick_gate_counts_and_native_six_byte_decode(self):
        for ready,busy,owned,success in itertools.product((0,1),repeat=4):
            with self.cpu() as cpu:
                cpu.uc.mem_write(T.ADV_RAM+1,b'\1')
                cpu.uc.mem_write(T.SENSOR_READY,bytes((ready,)))
                cpu.put32(0x2000A3A8,busy)
                cpu.put32(0x2000A380,owned)
                cpu.uc.mem_write(0x2000D234,b'\xb7\0')
                # Native format switch: six-byte read. Driver owns the SPI
                # completion. All original gates/decode/health work executes.
                cpu.uc.mem_write(T.SETTINGS+705,b'\1')
                samples=[]
                cpu.put32(0x2000A3A0,0x20016001)
                cpu.stub(0x20016000,effect=lambda a:samples.append(bytes(a.uc.mem_read(a.reg('r0'),6))))
                def burst(cpu):
                    self.assertEqual(cpu.reg('r2'),6)
                    cpu.uc.mem_write(cpu.reg('r1'),b'\xa4\xb7\x7b\0\x38\xfe')
                    return success
                cpu.stub(T.SENSOR_BURST,effect=burst)
                cpu.run(self.builder.symbols['advanced_tick'],count=100000)
                eligible=ready and not busy and not owned
                self.assertEqual(cpu.u32(T.ADV_RAM+A.OFF['ticks']),1)
                self.assertEqual(cpu.u32(T.ADV_RAM+A.OFF['not_ready']),int(not eligible))
                self.assertEqual(cpu.u32(T.ADV_RAM+A.OFF['spi_ok']),int(eligible and success))
                self.assertEqual(samples,[b'\1\0\x7b\0\x38\xfe'] if eligible and success else [])


if __name__=='__main__':
    unittest.main()
