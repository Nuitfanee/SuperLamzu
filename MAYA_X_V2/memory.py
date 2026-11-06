"""Guard the actual MAYA queue tail; never infer ownership from RAM mapping."""
import struct

from . import target as T


def evidence(image):
    references = tuple(a for a in range(image.base, image.end-3)
                       if image.u32(a) == T.QUEUE_BASE)
    if references != T.QUEUE_BASE_REFERENCES:
        raise ValueError('MAYA queue base reference inventory changed')
    aliases = [(a, image.u32(a)) for a in range(image.base, image.end-3)
               if T.SNAPSHOT_POINTER <= image.u32(a) < T.RADIO_QUEUE2+T.QUEUE_STRIDE]
    if aliases:
        raise ValueError(f'MAYA queue tail has absolute aliases: {aliases}')
    for address, original in T.QUEUE_PREIMAGES.items():
        if image.get(T.flash_source(address), len(original)) != original:
            raise ValueError(f'MAYA queue accessor changed at {address:#x}')
    for address, expected in T.QUEUE_FUNCTION_POINTERS.items():
        if image.u32(address) != expected:
            raise ValueError(f'MAYA queue function pointer changed at {address:#x}')
    descriptor = struct.unpack('<III', image.get(T.MPU_DESCRIPTOR, 12))
    if descriptor != (T.RAM_RUN, T.RAM_LEN, 0x10006):
        raise ValueError('MAYA code MPU descriptor changed')
    if T.SMOOTHING_STATE+1 != T.RADIO_QUEUE2+T.QUEUE_STRIDE:
        raise ValueError('MAYA extension overlaps queue3')
    return dict(queue2=T.RADIO_QUEUE2, header_bytes=T.QUEUE_HEADER,
                stride=T.QUEUE_STRIDE, capacity=8, record_bytes=12,
                live_end=T.SNAPSHOT_POINTER, pointer=T.SNAPSHOT_POINTER,
                pointer_bytes=3, stats=T.ADV_RAM, stats_bytes=188,
                smoothing=T.SMOOTHING_STATE, queue3=T.SMOOTHING_STATE+1,
                readonly_code_region=dict(base=descriptor[0], bytes=descriptor[1],
                                          attributes=descriptor[2]),
                pointer_references=list(references), absolute_tail_aliases=aliases,
                evidence='IDA native-queue, mapped accessors and caller fragmentation; Thumb boundary checks')
