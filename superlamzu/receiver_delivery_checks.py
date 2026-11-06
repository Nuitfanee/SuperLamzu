"""THORN radio reports through the native FIFO consumer and USB queues."""
from collections import deque
import struct

from . import receiver as R
from .common import assemble
from .emulation import Arm, MemoryLayout
from .verify import patched_image


LAYOUT = MemoryLayout(
    ram_regions=((0x23000000,0x40000),),stack=0x23030000,stop=0x2303F000,
    copies=((R.CODE_SOURCE,R.CODE_RAM,R.CODE_BYTES),
            (R.DATA_SOURCE,R.DATA_RAM,R.DATA_BYTES)))


class _Parked(Exception):
    pass


class Delivery:
    """Kernel FIFO/heap and the endpoint are the explicit service boundaries."""
    def __init__(self, builder):
        self.cpu=Arm(patched_image(builder),layout=LAYOUT)
        self.pending=deque()
        self.owned=set()
        self.input=b''
        self.allocate=True
        self.next_node=0x23023000
        self.endpoint_ok=True
        self.inflight=None
        self.attempts=[]
        self.delivered=[]
        self.freed=[]
        self.consumer_context=None
        a=self.cpu
        # Unicorn lacks these ARMv8 acquire/release forms. Execute their
        # ordinary load/exclusive equivalents in this single-core fixture.
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
        cs=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_MCLASS)
        for lo,hi in ((0x0E0C4D9C,0x0E0C4DE4),(R.REPORT_THREAD,0x0E0C5052),
                      (R.USB_START,0x0E0C51D2),(0x0E0BD996,0x0E0BD9A6)):
            for ins in cs.disasm(a.image.get(lo,hi-lo),R.runtime(lo)):
                op={'lda.w':'ldr.w','ldaex':'ldrex','stlex':'strex'}.get(ins.mnemonic)
                if op:
                    replacement=assemble([op+' '+ins.op_str],ins.address)
                    assert len(replacement)==ins.size
                    a.uc.mem_write(ins.address,replacement)
        for index in range(5):
            a.run(R.USB_QUEUE_INIT,index)
        a.uc.mem_write(0x23007924,b'\1')
        a.stub(R.runtime(R.RX_QUEUE_GET),effect=self._input)
        a.stub(R.runtime(R.NATIVE_ALLOC),effect=self._allocate)
        a.stub(R.runtime(R.FIFO_PUT),effect=self._put)
        a.stub(R.runtime(R.FIFO_GET),effect=self._get)
        a.stub(R.runtime(R.REPORT_FREE),effect=self._free)
        a.stub(R.runtime(R.REPORT_WAKE))
        a.stub(R.runtime(R.USB_SUBMIT),effect=self._endpoint)

    def __enter__(self):
        return self

    def __exit__(self,*args):
        self.consumer_context=None
        self.cpu.close()

    def _input(self,a):
        destination=a.u32(a.reg('r0'))
        a.uc.mem_write(destination,self.input)
        return 1

    def _allocate(self,a):
        assert a.reg('r0')==24
        if not self.allocate:
            return 0
        node=self.next_node
        self.next_node+=32
        self.owned.add(node)
        a.uc.mem_write(node,b'\xA5'*24)
        return node

    def _put(self,a):
        assert a.reg('r0')==R.REPORT_FIFO
        node=a.reg('r1')
        assert node in self.owned
        assert a.byte(node+4)==8 and a.byte(node+5)==2
        self.pending.append(node)

    def _get(self,a):
        assert a.reg('r0')==R.REPORT_FIFO
        if not self.pending:
            raise _Parked
        return self.pending.popleft()

    def _free(self,a):
        node=a.reg('r0')
        assert node in self.owned
        self.owned.remove(node)
        self.freed.append(node)

    def _endpoint(self,a):
        assert a.reg('r1')==8
        payload=bytes(a.uc.mem_read(a.reg('r2'),8))
        self.attempts.append(payload)
        if not self.endpoint_ok:
            return -11
        assert self.inflight is None
        self.inflight=payload
        return 0

    def frame(self,x,y,*,absolute=True,active=True,short=False):
        header=10 if absolute else 2
        self.input=(bytes((2,header,3)) if short else
                    struct.pack('<BBBHH',7,header,3,x&65535,y&65535))
        self.cpu.uc.mem_write(0x23007924,bytes((int(active),)))
        return self.cpu.run(R.runtime(R.RECEIVE_DISPATCH))

    def consume(self):
        a=self.cpu
        caller=a.uc.context_save()
        if self.consumer_context is None:
            # Context saves registers; the parked thread also needs its own stack.
            a.setreg('sp',a.layout.stack-0x8000)
            a.setreg('lr',a.stop|1)
            entry=R.runtime(R.REPORT_THREAD)
        else:
            a.uc.context_restore(self.consumer_context)
            entry=a.reg('pc')
        try:
            a.uc.emu_start(entry|1,a.stop,count=100000)
        except _Parked:
            self.consumer_context=a.uc.context_save()
            return
        finally:
            a.uc.context_restore(caller)
        raise AssertionError('native FIFO consumer did not park')

    def complete(self):
        assert self.inflight is not None
        self.delivered.append(self.inflight)
        self.inflight=None
        self.cpu.run(R.runtime(R.USB_COMPLETED),count=100000)

    def finish(self):
        while self.inflight is not None:
            self.complete()

    def baseline(self):
        a=self.cpu
        return bool(a.byte(R.ABS_VALID)),int.from_bytes(a.uc.mem_read(R.ABS_X,2),'little'),int.from_bytes(a.uc.mem_read(R.ABS_Y,2),'little')


def verify(builder):
    scenarios=0
    native_types=0
    for kind in (3,6):
        for length in (8,16):
            outcomes=[]
            for entry in (R.runtime(R.USB_REPORT),builder.symbols['abs_usb_report']):
                with Delivery(builder) as d:
                    source=0x23020000
                    d.cpu.uc.mem_write(source,bytes(range(32)))
                    ret=d.cpu.run(entry,kind,source,length)
                    outcomes.append((ret,bytes(d.cpu.uc.mem_read(R.USB_QUEUE_BASE,5*640)),
                                     d.baseline()))
            assert outcomes[0]==outcomes[1],(kind,length)
            native_types+=1
    # Radio parsing publishes totals, and FIFO backlog does not advance the
    # baseline. A full native USB ring rejects the excess; the next cumulative
    # point catches those rejected deltas after endpoint completion drains it.
    for initial in (0,65530):
        with Delivery(builder) as d:
            for n in range(31):
                assert d.frame(initial+n,200-n)==1
            assert len(d.pending)==31 and d.baseline()==(False,0,0)
            d.consume()
            assert not d.pending and not d.owned and len(d.freed)==31
            assert d.baseline()==(True,(initial+24)&65535,176)
            d.finish()
            assert len(d.delivered)==25
            assert d.frame(initial+31,169)==1
            d.consume()
            d.finish()
            delta=[struct.unpack_from('<hh',p,2) for p in d.delivered]
            assert sum(x for x,y in delta)==31 and sum(y for x,y in delta)==-31
            scenarios+=1
    with Delivery(builder) as d:
        d.frame(100,200)
        d.consume()
        d.finish()
        d.allocate=False
        d.frame(110,190)
        assert not d.pending and d.baseline()==(True,100,200)
        d.allocate=True
        d.frame(115,185,active=False)
        assert not d.pending and d.baseline()==(True,100,200)
        d.frame(120,180)
        d.consume()
        d.finish()
        assert struct.unpack_from('<hh',d.delivered[-1],2)==(20,-20)
        scenarios+=1
    with Delivery(builder) as d:
        d.endpoint_ok=False
        d.frame(100,200)
        d.frame(110,190)
        d.consume()
        queue=R.USB_QUEUE_BASE+2*640
        assert not d.delivered and d.cpu.byte(queue+3)==0
        assert d.cpu.u32(R.USB_BUSY)==0 and d.baseline()==(True,110,190)
        # Re-enter the existing native endpoint submission with the retained
        # head. Failed submission has neither popped nor altered its payload.
        old=d.attempts[-1]
        d.endpoint_ok=True
        assert d.cpu.run(R.runtime(R.USB_START),R.USB_BUFFER,8)==0
        assert d.attempts[-1]==old
        d.finish()
        assert len(d.delivered)==2
        assert struct.unpack_from('<hh',d.delivered[-1],2)==(10,-10)
        scenarios+=1
    for mask in (0,0x20,0x80):
        with Delivery(builder) as d:
            d.cpu.setreg('basepri',mask)
            for n in range(25):
                d.frame(n,-n)
            d.consume()
            assert d.baseline()==(True,24,65512)
            d.frame(5,-6,absolute=False)
            d.consume()
            assert d.baseline()==(True,24,65512)
            d.finish()
            d.frame(32,-32)
            d.consume()
            d.finish()
            assert struct.unpack_from('<hh',d.delivered[-1],2)==(8,-8)
            d.frame(0,0,short=True)
            d.consume()
            d.finish()
            assert d.baseline()==(True,32,65504)
            d.frame(5,-6,absolute=False)
            d.consume()
            d.finish()
            assert not d.baseline()[0]
            assert struct.unpack_from('<hh',d.delivered[-1],2)==(5,-6)
            d.frame(33,-33)
            d.consume()
            d.finish()
            assert struct.unpack_from('<hh',d.delivered[-1],2)==(0,0)
            assert d.cpu.reg('basepri')==mask
            scenarios+=1
    return dict(result='PASS',scenarios=scenarios,native_types=native_types,
                boundary='native dispatcher/report/parked FIFO consumer resumes on its own stack/USB queue/endpoint retry; kernel heap/FIFO scheduling and endpoint response are explicit services')
