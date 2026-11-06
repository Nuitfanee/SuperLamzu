"""Execute stock optical sampling and debounce after optical-direct retirement."""
from . import target as T, protocol as P
from .checks import fresh
from .optical import stock_evidence
from .settings import encode_record, decode_record
from .verify import request

HEAP = 0x23024004


def initialize(a):
    """Shared native-heap and optical-input fixture for existing checks."""
    a.uc.mem_write(HEAP - 4, b'\xa5' * (T.SNAPSHOT_STORAGE_BYTES + 8))
    a.uc.mem_write(HEAP, bytes(T.SNAPSHOT_STORAGE_BYTES))
    a.uc.mem_write(T.SNAPSHOT_POINTER,
                   bytes((HEAP & 255, (HEAP >> 8) & 255, (HEAP >> 16) & 15)))
    a.put32(0x2300A4AC, 1)
    a.put32(0x2300A4B0, 2)
    a.put32(T.CLICK_NATIVE_QUEUE + 12, 8)
    a.put32(T.CLICK_NATIVE_QUEUE + 0x20, 0)
    a.put32(0x2300A4D8, 0x2300672F)
    a.put32(0x2300A4D4, 0x23005B58)
    a.put32(0x23005B58, 0x5F934000)
    for i, (pointer, descriptor, cache) in enumerate(zip(
            T.CLICK_DESCRIPTOR_PTRS, T.CLICK_DESCRIPTORS, T.CLICK_CACHES)):
        a.put32(pointer, descriptor)
        a.uc.mem_write(descriptor + 6, bytes((0x82 + i,)))
        a.uc.mem_write(cache, b'\1')
        a.uc.mem_write(T.CLICK_NATIVE_STATE + 12 * (i + 2),
                       b'\1' + bytes(8) + b'\1\0\0')
        a.uc.mem_write(T.CLICK_BINDINGS + 16 * (i + 2) + 2,
                       bytes((1, 0, i + 1, 0, 0, 0, 0)))
    a.stub(0x23005688, effect=lambda c: c.u32(c.reg('r0')))

    def atomic(c):
        old = c.u32(c.reg('r0'))
        c.put32(c.reg('r0'), c.reg('r1'))
        return old

    a.stub(0x23005678, effect=atomic)
    for address in (0x23005808, 0x23005658, 0x23005818, 0x230056B8):
        a.stub(address)
    a.stub(0x230057F0, 1)
    a.stub(0x23002CCC, 8)
    a.stub(T.CLICK_FAST)
    events = []

    def dispatch(c):
        events.append((c.reg('r2'), c.reg('r1'), c.reg('r0'),
                       bytes(c.uc.mem_read(c.reg('r3'), 5))))
        return 0

    a.stub(T.CLICK_DISPATCH, effect=dispatch)
    a.levels = [1, 1]
    a.stub(0x23005630, effect=lambda c: a.levels[0 if c.reg('r1') == 3 else 1])
    a.put32(T.CLICK_TIMER + 0x548, 800)
    return events


def sample(a, left, right, valid=True):
    a.levels = [left, right]
    a.put32(0x2300A4AC, int(valid))
    a.run(0x23001A34)


def drain(a):
    a.run(0x23001E88, 0, count=100000)


def stock_timelines(b):
    """Compare native sampling, EGU and real debounce timers to stock."""
    from .verify import arm, patched_image
    fixtures = [
        ((0, 2, 20, 20), False, 2, ((0, 0), (5000, 1))),
        ((0, 2, 20, 20), False, 2, ((0, 0), (30000, 1))),
        ((0, 2, 20, 20), False, 2, ((0, 0), (30000, 1), (35000, 0))),
        ((0, 2, 20, 20), False, 2, ((0, 0), (5000, 1), (10000, 0), (15000, 1))),
        ((0, 2, 0, 0), False, 2, ((0, 0), (5000, 1), (10000, 0), (15000, 1))),
        ((5, 2, 20, 20), False, 2, ((0, 0),)),
        ((5, 2, 20, 20), True, 2, ((0, 0), (5000, 1))),
        ((0, 2, 20, 20), False, 3, ((0, 0), (5000, 1))),
        ((0, 2, 20, 20), False, 2, ((0, 0),)),
    ]
    for timings, speed, key, inputs in fixtures:
        outputs = []
        for image in (b.image, patched_image(b)):
            with arm(image) as a:
                a.uc.mem_map(0x53000000, 0x100000)
                a.uc.mem_map(0x5F900000, 0x100000)
                initialize(a)
                a.uc.mem_write(0x2300CC50, bytes(timings))
                a.uc.mem_write(T.SETTINGS + 0x17, bytes((speed, speed)))
                now, pending, events = [0], {}, []

                def timer(c):
                    pending[c.reg('r0') & 127] = now[0] + (
                        (31250 * c.reg('r1') + 999) // 1000) * 32
                    return 0

                a.stub(0x23001118, effect=timer)
                a.stub(T.CLICK_DISPATCH, effect=lambda c: events.append(
                    (now[0], c.reg('r2'), c.reg('r1'))) or 0)

                def advance(until):
                    for _ in range(1000):
                        if not pending:
                            break
                        k = min(pending, key=pending.get)
                        if pending[k] > until:
                            break
                        now[0] = pending.pop(k)
                        a.run(T.CLICK_TIMERS[k - 2])
                    else:
                        raise AssertionError('native timer did not converge')
                    now[0] = until

                for time, level in inputs:
                    advance(time)
                    sample(a, level if key == 2 else 1, level if key == 3 else 1)
                    a.run(0x23001E88, key - 2)
                advance(100000)
                outputs.append((events, bytes(a.uc.mem_read(T.CLICK_NATIVE_STATE + 24, 24))))
        assert outputs[0] == outputs[1], (timings, speed, key, outputs)
        assert outputs[0][0], (timings, key)
    return len(fixtures)


def retired_mode_check(b):
    """Old saved direct bits cannot change stock sampling or debounce."""
    cases = 0
    for bit in (0, 1):
        with fresh(b) as a:
            initialize(a)
            record = encode_record(fps=0, lock=1, lead=80, tracking=1,
                                   motion_path=1, abs_motion=1, optical_click=bit)
            a.uc.mem_write(T.ADV_STORAGE, record)
            a.uc.mem_write(T.SENSOR_READY, b'\0')
            a.run(b.advanced['settings']['load'])
            assert a.byte(T.ADV_RAM + 2) == 1
            assert a.byte(T.SMOOTHING_STATE) & 128
            assert a.byte(T.MOTION_STATE) & (16 | 64) == 16 | 64
            assert bytes(a.uc.mem_read(T.ADV_STORAGE, 16)) == record
            for cmd, body in ((P.GET, (0, P.OPTICAL_CLICK)),
                              (P.SET, (0, P.OPTICAL_CLICK, 0)),
                              (P.SET, (0, P.OPTICAL_CLICK, 1))):
                before = bytes(a.uc.mem_read(T.CLICK_NATIVE_STATE, 96))
                assert request(a, cmd, body)[0] == 0xA2
                assert bytes(a.uc.mem_read(T.CLICK_NATIVE_STATE, 96)) == before
                cases += 1
            sample(a, 1, 1)
            assert a.u32(T.CLICK_TIMER + 0x548) == 800

            def store(c):
                assert c.reg('r0') == T.ADV_STORAGE_OFFSET
                assert c.reg('r2') == 16
                c.uc.mem_write(T.ADV_STORAGE, bytes(c.uc.mem_read(c.reg('r1'), 16)))
                return 0

            a.stub(T.STORAGE_WRITE, effect=store)
            assert request(a, P.SET, (0, P.SAVE_ADVANCED, 1))[0] == 0xA0
            saved = decode_record(bytes(a.uc.mem_read(T.ADV_STORAGE, 16)))
            assert saved['optical_click'] == 0
            assert saved['lock'] == saved['tracking'] == saved['motion_path'] == saved['abs_motion'] == 1
            cases += 2
    return cases


def verify(b):
    stock_evidence(b)
    return len(T.CLICK_PREIMAGES) + stock_timelines(b) + retired_mode_check(b)
