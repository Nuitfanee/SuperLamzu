"""SUPER capability rejection and exact removal of telemetry-only hooks."""
from . import target as T, protocol as P
from .profiles import TELEMETRY_FLAGS
from .verify import patched_image,request


def verify_super(b):
    from .checks import fresh
    image=patched_image(b)
    assert b.extension['flags'] & TELEMETRY_FLAGS == 0
    forbidden=('channels_', 'advanced_tick', 'advanced_spi_done', 'advanced_burst',
               'advanced_reinit', 'advanced_radio_count')
    assert not any(name.startswith(forbidden) for name in b.symbols)
    spans=[(0x0E0897AC,8),(0x0E07E716,4),(0x0E07EA32,4)]
    spans += [(T.flash_source(site),10) for site in (T.CHAN_ACK_SITE,T.CHAN_MISS_SITE,0x230024DC,0x230024E8)]
    for address,size in spans:
        assert image.get(address,size)==b.image.get(address,size),hex(address)
    n=0
    with fresh(b) as a:
        a.run(b.symbols['advanced_queue_init'],0)
        caps=P.decode_capabilities(request(a,P.GET,(0,P.CAPS))[1])
        assert caps['flags']==b.extension['flags'] and caps['stats_bytes']==0
        for op in (P.STATS,P.CHANNELS):
            for cmd,body in [(P.GET,(0,op)),(P.GET,(0,op,0))]+[(P.SET,(0,op,k)) for k in (0,1,2)]:
                before=bytes(a.uc.mem_read(T.ADV_RAM,188))
                assert request(a,cmd,body)[0]==0xA2
                assert bytes(a.uc.mem_read(T.ADV_RAM,188))==before
                n+=1
        # Even a stale/nonzero former switch byte cannot re-enable counters.
        a.uc.mem_write(T.ADV_RAM+1,b'\1')
        a.uc.mem_write(0x23025000,b'\1'+bytes(7))
        a.stub(T.MOTION_NATIVE,0x12345678)
        a.run(b.symbols['advanced_motion'],0x23025000)
        assert bytes(a.uc.mem_read(T.ADV_RAM+16,168))==bytes(168)
        n+=1
    return dict(result='PASS',cases=n,native_telemetry_spans=len(spans),
                stats_bytes=0,telemetry_hooks='not installed',hardware='not run')
