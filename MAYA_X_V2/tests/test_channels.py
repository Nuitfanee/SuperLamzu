"""Fixed-dev CHAN rounds on MAYA's accepted RX and slot-expiry paths."""
import random
import struct
import unittest

from unicorn import UC_HOOK_MEM_WRITE
from unicorn.arm_const import UC_ARM_REG_PRIMASK

from MAYA_X_V2 import target as T
from MAYA_X_V2.advanced import build_channels
from MAYA_X_V2.sensor import LAYOUT
from superlamzu import advanced as A, cfg, protocol as P
from superlamzu.emulation import Arm
from superlamzu.verify import patched_image, request

HEAP = T.NATIVE_HEAP_START + 0x404
STATE = HEAP + T.CHAN_OFFSET


class ChannelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.builder = build_channels()
        cls.changed = patched_image(cls.builder)

    def cpu(self, patched=True):
        cpu = Arm(self.changed if patched else self.builder.image, layout=LAYOUT)
        for base,size in ((0x50080000,0x10000),(0x500C9000,0x1000),
                          (T.REPORT_TIMER,0x1000),(0xE000E000,0x1000)):
            cpu.uc.mem_map(base,size)
        cpu.uc.mem_write(T.SETTINGS, self.changed.get(T.SETTINGS_DEFAULT, T.SETTINGS_BYTES))
        cpu.uc.mem_write(HEAP-1, b'\xa5'*(T.SNAPSHOT_STORAGE_BYTES+2))
        cpu.uc.mem_write(HEAP, bytes(T.SNAPSHOT_STORAGE_BYTES))
        cpu.uc.mem_write(T.SNAPSHOT_POINTER, (HEAP & 0xFFFFF).to_bytes(3, 'little'))
        cpu.uc.mem_write(T.ADV_RAM, b'\1'+bytes(187))
        cpu.stub(0x3089E, HEAP-4)
        return cpu

    def test_fixed_dev_120_rounds_native_equivalence_first_match_and_fifth_hop(self):
        rng = random.Random(5)
        sent, missed = [0]*6, [0]*6
        with self.cpu() as patched, self.cpu(False) as original:
            patched.uc.mem_write(STATE, b'\1')
            patched.uc.mem_write(T.MOTION_STATE,bytes((patched.byte(T.MOTION_STATE)|T.RADIO_OUTCOMES_ACTIVE_MASK,)))
            for k in range(120):
                miss = (k>>1)&1 if k<8 else k&1
                hops = bytes(rng.randrange(256) for _ in range(5)) if k%5 else bytes((11,41,62,79,11))
                freq = hops[rng.randrange(5)] if rng.random()<.8 else rng.randrange(256)
                observed = []
                for cpu in (original, patched):
                    rate=1+(k&1)
                    cpu.uc.mem_write(T.RADIO_STATE+2,b'\1')
                    cpu.uc.mem_write(T.RADIO_STATE+0x186,b'\6')
                    cpu.uc.mem_write(T.RADIO_STATE+1,b'\1')
                    cpu.uc.mem_write(0x2000E8BE,b'\x5a')
                    cpu.uc.mem_write(T.MOTION_STATE,bytes((cpu.byte(T.MOTION_STATE)|T.RADIO_OUTCOMES_ACTIVE_MASK,)))
                    cpu.uc.mem_write(0x2000EA4F,bytes((rate,)))
                    cpu.put32(0x200064F8, T.RADIO_TIMER)
                    cpu.uc.mem_write(T.CHAN_HOPS, hops)
                    cpu.put32(T.CHAN_FREQUENCY, freq)
                    if miss:
                        cpu.uc.mem_write(T.RADIO_STATE+0x186,b'\6')
                        cpu.run(T.RADIO_SLOT_DECISION,count=100000)
                    else:
                        cpu.put32(0x5008A21C,1)
                        cpu.put32(0x5008AE0C,1)
                        cpu.put32(0x5008AE10,0x5A)
                        cpu.run(T.RADIO_DECISION,count=100000)
                    observed.append((bytes(cpu.uc.mem_read(T.RADIO_STATE,0x190)),
                        bytes(cpu.uc.mem_read(0x50082000,0x600)),
                        bytes(cpu.uc.mem_read(0x5008A000,0xF00)),
                        bytes(cpu.uc.mem_read(0x200064E8,16)),cpu.reg('sp'),
                        [cpu.reg(f'r{i}') for i in range(4,12)]))
                self.assertEqual(observed[0], observed[1], k)
                index = hops.index(freq) if freq in hops else 5
                sent[index] = (sent[index]+1)&65535
                missed[index] = (missed[index]+miss)&65535
                self.assertEqual(list(struct.unpack('<12H', patched.uc.mem_read(STATE+4,24))), sent+missed)
                self.assertEqual(bytes(patched.uc.mem_read(STATE+28,5)), hops)
            self.assertGreater(sent[4], 0)
            self.assertGreater(sent[5], 0)
            self.assertEqual(patched.byte(HEAP-1), 0xA5)
            self.assertEqual(patched.byte(HEAP+T.SNAPSHOT_STORAGE_BYTES), 0xA5)

    def test_atomic_protocol_reset_wrap_and_allocation_failure(self):
        with self.cpu() as cpu:
            native = bytes(cpu.uc.mem_read(T.SETTINGS,T.SETTINGS_BYTES))
            for mask in (0,1):
                cpu.uc.reg_write(UC_ARM_REG_PRIMASK,mask)
                for action in (1,2,0):
                    raw = request(cpu,P.SET,(0,P.CHANNELS,action),target=T)
                    self.assertEqual(raw[0],0xA0)
                    decoded = P.decode_channels(raw[1])
                    self.assertEqual(decoded['unknown_bucket'],5)
                    self.assertEqual(len(decoded['sent']),6)
                    self.assertEqual(len(decoded['hops']),5)
                    self.assertEqual(decoded['enabled'],action!=0)
                    self.assertEqual(cpu.uc.reg_read(UC_ARM_REG_PRIMASK),mask)
                self.assertEqual(bytes(cpu.uc.mem_read(T.SETTINGS,T.SETTINGS_BYTES)),native)
            for command,payload in ((P.GET,(1,13)),(P.GET,(0,13,0)),(P.SET,(0,13)),
                                    (P.SET,(1,13,1)),(P.SET,(0,13,3)),(P.SET,(0,13,1,0))):
                self.assertEqual(request(cpu,command,payload,target=T)[0],0xA2)
            cpu.uc.mem_write(STATE,b'\1')
            cpu.uc.mem_write(STATE+4,b'\xff'*24)
            cpu.uc.mem_write(T.CHAN_HOPS,b'\x0b\x29\x3e\x4f\x61')
            cpu.put32(T.CHAN_FREQUENCY,97)
            cpu.run(self.builder.symbols['channels_count'],0,0,1)
            self.assertEqual(bytes(cpu.uc.mem_read(STATE+12,2)),b'\0\0')
            self.assertEqual(bytes(cpu.uc.mem_read(STATE+24,2)),b'\0\0')
            cpu.uc.mem_write(STATE,b'\0')
            before = bytes(cpu.uc.mem_read(STATE,T.CHAN_BYTES))
            cpu.run(self.builder.symbols['channels_count'],0,0,1)
            self.assertEqual(bytes(cpu.uc.mem_read(STATE,T.CHAN_BYTES)),before)
            cpu.uc.mem_write(T.SNAPSHOT_POINTER,bytes(3))
            cpu.stub(0x3089E,0)
            self.assertEqual(request(cpu,P.SET,(0,13,1),target=T)[0],0xA2)
            self.assertEqual(P.decode_channels(request(cpu,P.GET,(0,13),target=T)[1])['sent'],[0]*6)

    def test_radio_outcome_gate_tracks_independent_stats_and_channels(self):
        with self.cpu() as cpu:
            self.assertEqual(cpu.byte(T.MOTION_STATE)&T.RADIO_OUTCOMES_ACTIVE_MASK,0)
            self.assertEqual(request(cpu,P.SET,(0,13,1),target=T)[0],0xA0)
            self.assertEqual(cpu.byte(T.MOTION_STATE)&T.RADIO_OUTCOMES_ACTIVE_MASK,
                             T.RADIO_OUTCOMES_ACTIVE_MASK)
            self.assertEqual(request(cpu,P.SET,(0,4,1),target=T)[0],0xA0)
            self.assertEqual(request(cpu,P.SET,(0,13,0),target=T)[0],0xA0)
            self.assertEqual(cpu.byte(T.MOTION_STATE)&T.RADIO_OUTCOMES_ACTIVE_MASK,
                             T.RADIO_OUTCOMES_ACTIVE_MASK)
            self.assertEqual(request(cpu,P.SET,(0,4,0),target=T)[0],0xA0)
            self.assertEqual(cpu.byte(T.MOTION_STATE)&T.RADIO_OUTCOMES_ACTIVE_MASK,0)

    def test_outcome_settings_preserve_pointer_motion_bits_and_interrupt_mask(self):
        for mask,state in ((0,0),(1,0x10),(0,0x20),(1,0x70)):
            with self.cpu() as cpu:
                pointer=bytes(cpu.uc.mem_read(T.SNAPSHOT_POINTER,3))
                original=(pointer[2]&15)|state
                cpu.uc.mem_write(T.MOTION_STATE,bytes((original,)))
                cpu.uc.reg_write(UC_ARM_REG_PRIMASK,mask)
                for op,action,active in ((4,1,True),(13,1,True),(4,0,True),
                                         (13,2,True),(13,0,False)):
                    self.assertEqual(request(cpu,P.SET,(0,op,action),target=T)[0],0xA0)
                    self.assertEqual(cpu.byte(T.MOTION_STATE),original|(0x80 if active else 0))
                    self.assertEqual(bytes(cpu.uc.mem_read(T.SNAPSHOT_POINTER,2)),pointer[:2])
                    self.assertEqual(cpu.uc.reg_read(UC_ARM_REG_PRIMASK),mask)
                for op in (4,13):
                    before=bytes(cpu.uc.mem_read(T.SNAPSHOT_POINTER,192))
                    self.assertEqual(request(cpu,P.SET,(0,op,3),target=T)[0],0xA2)
                    self.assertEqual(bytes(cpu.uc.mem_read(T.SNAPSHOT_POINTER,192)),before)

    def test_continuous_native_tx_receive_reject_timeout_and_fast_send(self):
        # Same fixed-dev lifecycle matrix as Thorn, using MAYA native entry
        # points; outcomes are never injected by calling the count helper.
        for stats,chan,rate in ((s,c,r) for s,c in ((0,0),(1,0),(0,1),(1,1)) for r in (1,2)):
            for fast,crc,address,success,timeout in ((0,1,0x5A,1,0),
                    (0,0,0x5A,0,1),(0,1,0xA5,0,1),(1,1,0x5A,0,0)):
                with self.subTest(stats=stats,chan=chan,rate=rate,fast=fast,crc=crc,address=address), self.cpu() as cpu:
                    self.assertEqual(request(cpu,P.SET,(0,4,stats),target=T)[0],0xA0)
                    self.assertEqual(request(cpu,P.SET,(0,13,chan),target=T)[0],0xA0)
                    cpu.uc.mem_write(T.RADIO_STATE+1,b'\1\1')
                    cpu.uc.mem_write(T.RADIO_STATE+0x186,b'\4')
                    cpu.uc.mem_write(T.RADIO_ACK_FLAG,bytes((fast,)))
                    cpu.uc.mem_write(0x2000E8BE,b'\x5a')
                    cpu.uc.mem_write(0x2000EA4F,bytes((rate,)))
                    cpu.uc.mem_write(T.CHAN_HOPS,bytes((11,41,62,79,97)))
                    cpu.put32(T.CHAN_FREQUENCY,97)
                    cpu.put32(0x200064F8,T.RADIO_TIMER)
                    writes=[]
                    if not stats and not chan:
                        def observe(uc,access,address,size,value,user):
                            if (T.ADV_RAM<=address<T.ADV_RAM+T.ADV_BYTES or
                                    STATE<=address<STATE+T.CHAN_BYTES):
                                writes.append((address,size,value))
                        cpu.add_hook(UC_HOOK_MEM_WRITE,observe)
                    cpu.put32(0x5008A21C,1)
                    cpu.run(T.RADIO_DECISION,count=100000)
                    self.assertEqual(cpu.byte(T.RADIO_STATE+0x186),8 if fast else 6)
                    self.assertEqual(cpu.u32(T.ADV_RAM+A.OFF['tx_attempts']),0)
                    if not fast:
                        cpu.put32(0x5008A21C,1)
                        cpu.put32(0x5008AE0C,crc)
                        cpu.put32(0x5008AE10,address)
                        cpu.run(T.RADIO_DECISION,count=100000)
                        self.assertEqual(cpu.byte(T.RADIO_STATE+0x186),8 if success else 6)
                    # Real timer IRQ dispatches the native slot-end callback.
                    cpu.put32(T.RADIO_EVENT,1)
                    cpu.run(T.RADIO_IRQ,count=100000)
                    self.assertEqual(cpu.u32(T.ADV_RAM+A.OFF['tx_attempts']),stats*(success+timeout))
                    self.assertEqual(cpu.u32(T.ADV_RAM+A.OFF['acked']),stats*success)
                    self.assertEqual(cpu.u32(T.ADV_RAM+A.OFF['no_ack']),stats*timeout)
                    self.assertEqual(int.from_bytes(cpu.uc.mem_read(STATE+12,2),'little'),chan*(success+timeout))
                    self.assertEqual(int.from_bytes(cpu.uc.mem_read(STATE+24,2),'little'),chan*timeout)
                    self.assertEqual(writes,[])

    def test_enabling_stats_before_first_allocation_preserves_runtime_flag(self):
        with self.cpu() as cpu:
            cpu.uc.mem_write(T.SNAPSHOT_POINTER,bytes(3))
            self.assertEqual(request(cpu,P.SET,(0,4,1),target=T)[0],0xA0)
            self.assertEqual(request(cpu,P.SET,(0,13,1),target=T)[0],0xA0)
            self.assertEqual(cpu.byte(T.MOTION_STATE),((HEAP>>16)&15)|0x80)
            self.assertTrue(P.decode_channels(request(cpu,P.GET,(0,13),target=T)[1])['enabled'])
            self.assertEqual(request(cpu,P.SET,(0,4,0),target=T)[0],0xA0)
            self.assertEqual(cpu.byte(T.MOTION_STATE)&0x80,0x80)
            self.assertEqual(request(cpu,P.SET,(0,13,0),target=T)[0],0xA0)
            self.assertEqual(cpu.byte(T.MOTION_STATE),((HEAP>>16)&15))

    def test_chan_independent_of_stats_and_counts_only_window_outcomes(self):
        for enabled in (0,1):
            for outcome in ('state4','receive','timeout','bad_address'):
                with self.cpu() as cpu:
                    cpu.uc.mem_write(STATE,bytes((enabled,)))
                    cpu.uc.mem_write(T.ADV_RAM+1,b'\0')
                    cpu.uc.mem_write(T.MOTION_STATE,bytes((
                        cpu.byte(T.MOTION_STATE)|(T.RADIO_OUTCOMES_ACTIVE_MASK if enabled else 0),)))
                    cpu.put32(0x200064F8,T.RADIO_TIMER)
                    cpu.uc.mem_write(T.CHAN_HOPS,bytes((11,41,62,79,97)))
                    cpu.put32(T.CHAN_FREQUENCY,97)
                    cpu.uc.mem_write(T.RADIO_STATE+2,b'\1')
                    cpu.uc.mem_write(T.RADIO_STATE+1,b'\1')
                    cpu.uc.mem_write(T.RADIO_STATE+0x186,b'\6' if outcome!='state4' else b'\4')
                    cpu.uc.mem_write(0x2000E8BE,b'\x5a')
                    cpu.uc.mem_write(0x2000EA4F,b'\1')
                    if outcome=='timeout':
                        cpu.run(T.RADIO_SLOT_DECISION,count=100000)
                    else:
                        cpu.put32(0x5008A21C,1)
                        cpu.put32(0x5008AE0C,1)
                        cpu.put32(0x5008AE10,0xA5 if outcome=='bad_address' else 0x5A)
                        cpu.run(T.RADIO_DECISION,count=100000)
                    self.assertEqual(cpu.u32(T.ADV_RAM+A.OFF['tx_attempts']),0)
                    self.assertEqual(int.from_bytes(cpu.uc.mem_read(STATE+12,2),'little'),
                                     int(enabled and outcome in ('receive','timeout')),
                                     (enabled,outcome))
                    self.assertEqual(int.from_bytes(cpu.uc.mem_read(STATE+24,2),'little'),
                                     int(enabled and outcome=='timeout'))

    def test_host_uses_real_maya_thumb_handler_and_legacy_decode(self):
        with self.cpu() as cpu:
            class Device:
                def set_report(self,packet):
                    cpu.uc.mem_write(T.PACKET,packet)
                    cpu.uc.mem_write(T.PACKET,b'\xa0')
                    cpu.run(T.GROUP1)
                    result=bytearray(cpu.uc.mem_read(T.PACKET,64))
                    if result[0]==0xA0: result[0]=0xA1
                    self.reply=bytes(result)
                def get_report(self): return b'\0'+self.reply
            mouse=cfg.Mouse(cfg.Link(Device(),delay=0),0,1)
            self.assertFalse(mouse.channels()['enabled'])
            self.assertEqual(mouse.channels()['outcome_semantics'],P.RADIO_OUTCOME_SEMANTICS)
            self.assertTrue(mouse.channels('on')['enabled'])
            self.assertEqual(mouse.channels('reset')['sent'],[0]*6)
            self.assertFalse(mouse.channels('off')['enabled'])
            legacy=bytes((0,13,1,0))+struct.pack('<10H',*range(10))+bytes((11,41,62,79))
            self.assertEqual(P.decode_channels(legacy)['unknown_bucket'],4)
            self.assertEqual(P.decode_channels(legacy)['sent'],list(range(5)))
            raw=bytearray(request(cpu,P.GET,(0,13),target=T)[1])
            for index in (2,3,4,5,35):
                bad=raw.copy();bad[index]=255
                with self.assertRaises(ValueError):P.decode_channels(bad)


if __name__=='__main__':
    unittest.main()
