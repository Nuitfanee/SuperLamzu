"""Reuse fixed-dev CHAN's 120-round actual Thumb/model/ABI comparison."""
import random,struct
from . import target as T,protocol as P,advanced as A
from .checks import fresh
from .optical_checks import initialize,HEAP
from .verify import request

STATE=HEAP+T.CHAN_OFFSET


def verify_native_outcomes(b):
    """Execute native TX, RX validation and expiry paths, not injected ACK flags."""
    n=0
    for stats,chan in ((0,0),(1,0),(0,1),(1,1)):
        for state,event,crc,address,fast,connected,expected in (
            (4,1,1,1,0,1,0),  # ordinary TX completion starts reception
            (4,1,1,1,1,1,0),  # fast-button TX expects no receiver response
            (6,1,1,1,0,1,1),  # valid addressed response
            (6,1,1,1,0,0,0),  # startup/disconnected is not a connected outcome
            (6,1,0,1,0,1,0),  # bad CRC
            (6,1,1,2,0,1,0),  # another receiver address
            (6,0,1,1,0,1,0),  # no END event
            (8,1,1,1,0,1,0),  # idle
        ):
            with fresh(b) as a:
                initialize(a);a.uc.mem_write(STATE,bytes((chan,)))
                a.uc.mem_write(T.ADV_RAM+1,bytes((stats,)))
                a.uc.mem_write(T.RADIO_STATE+1,bytes((connected,1)))
                a.uc.mem_write(T.RADIO_STATE+0x186,bytes((state,)))
                a.uc.mem_write(T.CHAN_FAST_TX_FLAG,bytes((fast,)))
                a.uc.mem_write(0x2300D559,b'\1');a.uc.mem_write(T.CHAN_FLAG,b'\1')
                a.uc.mem_write(T.CHAN_HOPS,bytes((11,41,62,79)))
                a.put32(T.CHAN_FREQUENCY,41);a.put32(0x5302C21C,event)
                a.put32(0x5302CE0C,crc);a.put32(0x5302CE10,address)
                a.ends.add(0x230025D8)
                a.run(T.CHAN_IRQ,count=100000)
                assert a.u32(T.ADV_RAM+A.OFF['tx_attempts'])==stats*expected
                assert a.u32(T.ADV_RAM+A.OFF['acked'])==stats*expected
                assert a.u32(T.ADV_RAM+A.OFF['no_ack'])==0
                assert a.uc.mem_read(STATE+6,2)==struct.pack('<H',chan*expected)
                assert a.uc.mem_read(STATE+16,2)==b'\0\0'
                n+=1
        for state,connected,active,expected in ((6,1,1,1),(4,1,1,0),(8,1,1,0),
                                               (6,0,1,0),(6,1,0,0)):
            with fresh(b) as a:
                initialize(a);a.uc.mem_write(STATE,bytes((chan,)))
                a.uc.mem_write(T.ADV_RAM+1,bytes((stats,)))
                a.uc.mem_write(T.RADIO_STATE+1,bytes((connected,active)))
                a.uc.mem_write(T.RADIO_STATE+0x186,bytes((state,)))
                a.uc.mem_write(T.CHAN_HOPS,bytes((11,41,62,79)));a.put32(T.CHAN_FREQUENCY,41)
                a.ends.update((0x23003294,0x23003328,0x230036B2))
                a.run(T.CHAN_SLOT_END,count=100000)
                assert a.u32(T.ADV_RAM+A.OFF['tx_attempts'])==stats*expected
                assert a.u32(T.ADV_RAM+A.OFF['acked'])==0
                assert a.u32(T.ADV_RAM+A.OFF['no_ack'])==stats*expected
                assert a.uc.mem_read(STATE+6,2)==struct.pack('<H',chan*expected)
                assert a.uc.mem_read(STATE+16,2)==struct.pack('<H',chan*expected)
                n+=1
        # Follow a TX through its actual RX/fast transition and the deadline.
        # A rejected frame must leave the window pending; a valid response or
        # a fast-button send must not then be counted again as a timeout.
        for fast,crc,address,success,timeout in ((0,1,1,1,0),(0,0,1,0,1),
                                                (0,1,2,0,1),(1,1,1,0,0)):
            with fresh(b) as a:
                initialize(a);a.uc.mem_write(STATE,bytes((chan,)))
                a.uc.mem_write(T.ADV_RAM+1,bytes((stats,)))
                a.uc.mem_write(T.RADIO_STATE+1,b'\1\1')
                a.uc.mem_write(T.RADIO_STATE+0x186,b'\4')
                a.uc.mem_write(T.CHAN_FAST_TX_FLAG,bytes((fast,)))
                a.uc.mem_write(0x2300D559,b'\1');a.uc.mem_write(T.CHAN_FLAG,b'\1')
                a.uc.mem_write(T.CHAN_HOPS,bytes((11,41,62,79)))
                a.put32(T.CHAN_FREQUENCY,41);a.put32(0x5302C21C,1)
                a.ends.update((0x230025D8,0x23003294,0x23003328,0x230036B2))
                a.run(T.CHAN_IRQ,count=100000)
                assert a.byte(T.RADIO_STATE+0x186)==(8 if fast else 6)
                assert a.u32(T.ADV_RAM+A.OFF['tx_attempts'])==0
                if not fast:
                    a.put32(0x5302C21C,1);a.put32(0x5302CE0C,crc);a.put32(0x5302CE10,address)
                    a.run(T.CHAN_IRQ,count=100000)
                    assert a.byte(T.RADIO_STATE+0x186)==(8 if success else 6)
                a.run(T.CHAN_SLOT_END,count=100000)
                assert a.u32(T.ADV_RAM+A.OFF['tx_attempts'])==stats*(success+timeout)
                assert a.u32(T.ADV_RAM+A.OFF['acked'])==stats*success
                assert a.u32(T.ADV_RAM+A.OFF['no_ack'])==stats*timeout
                assert a.uc.mem_read(STATE+6,2)==struct.pack('<H',chan*(success+timeout))
                assert a.uc.mem_read(STATE+16,2)==struct.pack('<H',chan*timeout)
                n+=1
    return n


def verify(b):
    from unicorn.arm_const import UC_ARM_REG_PRIMASK
    n=0;rng=random.Random(5);sent=[0]*5;missed=[0]*5
    with fresh(b) as patched,fresh(b) as original:
        initialize(patched);initialize(original)
        for site,raw in T.CHAN_PREIMAGES.items():original.uc.mem_write(site,raw)
        patched.uc.mem_write(STATE,b'\1'+bytes(27))
        for a in (patched,original):
            a.ends.update(site+10 for site in T.CHAN_PREIMAGES)
        for k in range(120):
            miss=(k>>1)&1 if k<8 else k&1
            site=T.CHAN_MISS_SITE if miss else T.CHAN_ACK_SITE
            hops=bytes(rng.randrange(256) for _ in range(4)) if k%5 else bytes((11,41,62,11))
            freq=hops[rng.randrange(4)] if rng.random()<.8 else rng.randrange(256)
            regs=[rng.getrandbits(32) for _ in range(12)]
            regs[1]=0x23020520;regs[2]=0x23020500;regs[4]=0x23020000
            flag=rng.randrange(4);observed=[]
            for a in (original,patched):
                for i,value in enumerate(regs):a.setreg(f'r{i}',value)
                a.uc.mem_write(0x23020500,b'\x73');a.uc.mem_write(T.CHAN_FLAG,bytes((flag,)))
                a.uc.mem_write(0x23020001,b'\1');a.uc.mem_write(0x23020186,b'\6')
                a.uc.mem_write(0x23020520,b'\x91')
                a.uc.mem_write(T.CHAN_HOPS,hops);a.put32(T.CHAN_FREQUENCY,freq)
                a.run(site)
                observed.append(([a.reg(f'r{i}') for i in range(12)],
                    bytes(a.uc.mem_read(0x23020000,0x600)),a.reg('sp'),a.reg('apsr')&0xF8000000))
            assert observed[0]==observed[1],(k,site,observed)
            index=hops.index(freq) if freq in hops else 4
            sent[index]=(sent[index]+1)&65535;missed[index]=(missed[index]+miss)&65535
            assert list(struct.unpack('<10H',patched.uc.mem_read(STATE+4,20)))==sent+missed
            assert bytes(patched.uc.mem_read(STATE+24,4))==hops
            n+=1
        # Wrap and default-off behavior, without altering any other heap owner.
        patched.uc.mem_write(STATE+4,bytes.fromhex('ffffffff')*5)
        patched.uc.mem_write(T.CHAN_HOPS,b'\x0b\x29\x3e\x0b');patched.put32(T.CHAN_FREQUENCY,11)
        patched.setreg('r4',0x23020000);patched.setreg('r2',0x23020500)
        patched.run(T.CHAN_MISS_SITE)
        assert patched.uc.mem_read(STATE+4,2)==b'\0\0' and patched.uc.mem_read(STATE+14,2)==b'\0\0'
        n+=1
        patched.uc.mem_write(STATE,b'\0');before=bytes(patched.uc.mem_read(STATE,28))
        patched.setreg('r4',0x23020000);patched.setreg('r1',0x23020520);patched.run(T.CHAN_ACK_SITE)
        assert bytes(patched.uc.mem_read(STATE,28))==before
        assert patched.byte(HEAP-1)==patched.byte(HEAP+T.SNAPSHOT_STORAGE_BYTES)==0xa5
        n+=1
    with fresh(b) as a:
        initialize(a);a.stub(0x0E07FAD4,HEAP-4)
        native=bytes(a.uc.mem_read(T.SETTINGS,704))
        for mask in (0,1):
            a.uc.reg_write(UC_ARM_REG_PRIMASK,mask)
            assert request(a,P.GET,(0,13))[1][:4]==bytes((0,13,0,0))
            assert request(a,P.SET,(0,13,1))[1][:4]==bytes((0,13,1,0))
            a.uc.mem_write(STATE+4,b'\x22'*24)
            assert request(a,P.SET,(0,13,2))[1][:28]==bytes((0,13,1,0))+bytes(24)
            assert request(a,P.SET,(0,13,0))[1][:4]==bytes((0,13,0,0))
            assert a.uc.reg_read(UC_ARM_REG_PRIMASK)==mask
            n+=4
        for command,payload in ((P.GET,(1,13)),(P.GET,(0,13,0)),(P.SET,(0,13)),
                                (P.SET,(1,13,1)),(P.SET,(0,13,3)),(P.SET,(0,13,1,0))):
            assert request(a,command,payload)[0]==0xa2
            n+=1
        assert bytes(a.uc.mem_read(T.SETTINGS,704))==native
        a.uc.mem_write(T.SNAPSHOT_POINTER,bytes(3));a.stub(0x0E07FAD4,0)
        assert request(a,P.SET,(0,13,1))[0]==0xa2
        assert request(a,P.GET,(0,13))[1][:28]==bytes((0,13))+bytes(26)
        n+=1
    return n+verify_native_outcomes(b)
