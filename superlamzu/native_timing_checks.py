"""Checks for the emitted THORN configuration and real timer callsites."""

import itertools
import struct

from . import native_clock as N, native_plock as P, protocol as W, target as T
from .checks import fresh
from .native_plock_checks import Timeline, run_checks, native_radio_check
from .verify import patched_image, request


def configuration_check(builder):
    from unicorn.arm_const import UC_ARM_REG_PRIMASK
    heap = 0x23024004
    cases = 0
    image = patched_image(builder)
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS)
    for site in T.REPORT_TIMER_PERIOD_CALLS:
        ins = next(decoder.disasm(image.get(site, 4), site))
        assert ins.mnemonic == 'bl' and int(ins.op_str[1:], 0) == builder.native_plock['rate']
        cases += 1
    with fresh(builder) as cpu:
        cpu.stub(0x0E07FAD4, heap - 4)
        assert cpu.run(builder.symbols['advanced_snapshot_storage']) == heap
        cpu.uc.mem_write(heap + N.OFFSET, bytes(N.BYTES))
        cpu.uc.mem_write(heap + N.OFFSET + N.PHASE,
                         bytes((N.HELD, N.INITIALIZED | N.WANTED)))
        cpu.uc.mem_write(T.TRANSPORT_STATE, b'\1')
        cpu.uc.mem_write(T.NATIVE_CLOCK_READY, b'\1')
        cpu.uc.mem_write(T.REPORT_DIVIDER, b'\1')
        tm = Timeline(cpu, T.REPORT_TIMER)
        for period, leads in ((250, (0, 1, 116, 117, 118, 124, 125, 499)),
                              (500, (0, 241, 242, 243, 249, 250, 499)),
                              (1000, (0, 491, 492, 493, 499))):
            for lead in leads:
                cpu.uc.mem_write(T.TICKS_PER_MS, bytes((1000 // period,)))
                for pending, mask in itertools.product((0, 1), (0, 1)):
                    cpu.uc.mem_write(heap + P.CONTROL_OFFSET, bytes(8))
                    cpu.put32(T.REPORT_TIMER + 0x200, 1)
                    cpu.put32(T.REPORT_TIMER + 0x540, period)
                    cpu.put32(T.REPORT_TIMER + 0x140, pending)
                    cpu.uc.reg_write(UC_ARM_REG_PRIMASK, mask)
                    payload = (0, W.LOCK, 1, lead & 255, lead >> 8)
                    assert request(cpu, W.SET, payload)[0] == 0xA0
                    split = (lead or 80) <= period // 2 - 8
                    assert cpu.u32(T.REPORT_TIMER + 0x200) == (2 if split else 1)
                    assert cpu.u32(T.REPORT_TIMER + 0x540) == (
                        period - (lead or 80) if split else period)
                    assert cpu.u32(T.REPORT_TIMER + 0x140) == pending
                    assert cpu.uc.reg_read(UC_ARM_REG_PRIMASK) == mask
                    before = (list(tm.tasks), bytes(cpu.uc.mem_read(heap + 308, 8)))
                    assert request(cpu, W.SET, payload)[0] == 0xA0
                    assert before == (tm.tasks, bytes(cpu.uc.mem_read(heap + 308, 8)))
                    assert request(cpu, W.SET, (0, W.LOCK, 0, lead & 255, lead >> 8))[0] == 0xA0
                    assert cpu.u32(T.REPORT_TIMER + 0x200) == 1
                    assert cpu.u32(T.REPORT_TIMER + 0x540) == period
                    assert cpu.u32(T.REPORT_TIMER + 0x140) == pending
                    cases += 1
        # Only configuration changes the layout; loss of radio activity does not.
        cpu.uc.mem_write(T.TICKS_PER_MS, b'\4')
        for transport, divider, held, expected in ((1, 1, True, 2), (0, 1, True, 1),
                                                  (1, 2, True, 1), (1, 1, False, 1)):
            cpu.uc.mem_write(T.TRANSPORT_STATE, bytes((transport,)))
            cpu.uc.mem_write(T.REPORT_DIVIDER, bytes((divider,)))
            cpu.uc.mem_write(heap + N.OFFSET + N.PHASE,
                             bytes((N.HELD if held else N.PENDING,
                                    N.INITIALIZED | N.WANTED)))
            cpu.put32(heap + N.OFFSET + 8, 0 if held else 1)
            assert request(cpu, W.SET, (0, W.LOCK, 1, 80, 0))[0] == 0xA0
            assert cpu.u32(T.REPORT_TIMER + 0x200) == expected
            cases += 1
        cpu.uc.mem_write(heap + N.OFFSET + N.PHASE,
                         bytes((N.HELD, N.INITIALIZED | N.WANTED)))
        cpu.uc.mem_write(T.REPORT_DIVIDER, b'\1')
        cpu.uc.mem_write(T.TRANSPORT_STATE, b'\1')
        for ready, mask, period in itertools.product((0, 1), (0, 1), (0, 125, 250, 500, 1000)):
            cpu.uc.mem_write(T.NATIVE_CLOCK_READY, bytes((ready,)))
            cpu.uc.reg_write(UC_ARM_REG_PRIMASK, mask)
            for reg in range(4, 12):
                cpu.setreg(f'r{reg}', 0xD00D0000 + reg)
            tm.tasks.clear()
            before = bytes(cpu.uc.mem_read(T.REPORT_TIMER, 0x600))
            site = next(iter(T.REPORT_TIMER_PERIOD_CALLS))
            cpu.ends.add(site + 4)
            assert cpu.run(site, period) == period
            cpu.ends.clear()
            assert cpu.uc.reg_read(UC_ARM_REG_PRIMASK) == mask
            assert all(cpu.reg(f'r{reg}') == 0xD00D0000 + reg for reg in range(4, 12))
            if period == 0:
                assert before == bytes(cpu.uc.mem_read(T.REPORT_TIMER, 0x600))
            else:
                assert cpu.byte(T.TICKS_PER_MS) == 1000 // period
                if ready:
                    assert cpu.u32(T.REPORT_TIMER + 0x540) == (115 if period == 125 else period - 80)
                    assert cpu.u32(T.REPORT_TIMER + 0x200) == (1 if period == 125 else 2)
                    assert tm.tasks[-1] == 0
                else:
                    assert 0 not in tm.tasks
            cases += 1
    return cases


def verify(builder):
    result = run_checks(builder, builder.native_plock)
    result['native_radio'] = native_radio_check(builder, builder.native_plock)
    result['configuration'] = configuration_check(builder)
    from .native_sample_checks import verify as samples
    result['samples'] = samples(builder)
    return result
