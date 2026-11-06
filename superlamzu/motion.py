"""Wireless decode-to-callback path with native queue/thread fallback.

Adapt dev _path_dec at Thorn's message-post call. A blocked done thread is
linked in the queue wait list; a dequeued/not-yet-completed callback is absent
until the thread blocks again. Together with count this handles transitions
without an extra pending-message counter or a resized queue.
"""
from . import target as T, protocol as P
from .advanced import addr, call, tail

DIRECT, OWNER = 0x10, 0x20


def owned_call(destination):
    # Mask only ownership updates, not the callback's native work scheduling.
    # Restore exactly the caller's OWNER bit, preserving concurrent other tags.
    return (['push {r4,r5,r6,lr}'] + addr('r4', T.MOTION_STATE)
        + ['.hword 0xf3ef,0x8c10', 'cpsid i', 'ldrb r5,[r4]',
           f'orr r1,r5,#{OWNER}', 'strb r1,[r4]', '.hword 0xf38c,0x8810']
        + call(destination)
        + ['.hword 0xf3ef,0x8c10', 'cpsid i', 'ldrb r1,[r4]',
           'lsrs r5,r5,#5', 'bfi r1,r5,#5,#1',
           'strb r1,[r4]', '.hword 0xf38c,0x8810', 'pop {r4,r5,r6,pc}'])


def install(b):
    for site, original in ((T.MOTION_POST_SITE, T.MOTION_POST_PREIMAGE),
                           (T.REPORT_SITE, T.REPORT_PREIMAGE),
                           (T.MOTION_TAIL_SITE, T.MOTION_TAIL_PREIMAGE)):
        if b.image.get(site, len(original)) != original:
            raise ValueError(f'motion hook preimage changed at {site:#x}')
    post = b.code('motion_post', ['push {r0-r6,lr}', '.hword 0xf3ef,0x8610', 'cpsid i']
        + addr('r4', T.MOTION_STATE)
        + ['ldrb r5,[r4]', f'and r5,r5,#{DIRECT | OWNER}',
           f'cmp r5,#{DIRECT}', 'bne fallback']
        + addr('r5', T.TRANSPORT_STATE) + ['ldrb r5,[r5]', 'cmp r5,#1', 'bne fallback']
        + addr('r5', T.MOTION_DONE_QUEUE)
        + ['ldr r2,[r5,#32]', 'cmp r2,#0', 'bne fallback',
           'ldr r2,[r5]', 'cmp r2,#0', 'beq fallback', 'cmp r2,r5', 'beq fallback']
        + addr('r2', T.MOTION_CALLBACK)
        + ['ldr r3,[r2]', 'cmp r3,#0', 'beq fallback',
           'ldrb r5,[r4]', f'orr r5,r5,#{OWNER}', 'strb r5,[r4]', '.hword 0xf386,0x8810']
        + addr('r0', T.MOTION_SAMPLE) + ['blx r3',
           'cpsid i', 'ldrb r5,[r4]', f'bic r5,r5,#{OWNER}',
           'strb r5,[r4]', '.hword 0xf386,0x8810',
           'movs r0,#0', 'add sp,#16', 'pop {r4,r5,r6,pc}',
           'fallback:', '.hword 0xf386,0x8810', 'pop {r0-r6,lr}'] + tail(T.MOTION_POST))
    # The callback's common exit has finished XY, ABS, wheel and enqueue/clear
    # work. Its lift semaphore can switch out the done thread; retaining OWNER
    # through that switch would suppress every timer retry until it resumes.
    # Consume the final shared-sample byte first, then release OWNER in a short
    # masked update. Reproduce CMP flags for the original conditional epilogue.
    release = b.code('motion_tail_release', ['ldrb r3,[r5,#1]']
        + addr('r1', T.MOTION_STATE)
        + ['.hword 0xf3ef,0x8c10', 'cpsid i', 'ldrb r2,[r1]',
           f'bic r2,r2,#{OWNER}', 'strb r2,[r1]', '.hword 0xf38c,0x8810',
           'cmp r3,#0'] + tail(T.MOTION_TAIL_SITE+4))
    # Native timer and callback share accumulated motion/scroll. Defer this
    # timer invocation while the callback owns those values; a decoder which
    # interrupts the timer falls back to the existing done thread.
    report = b.code('motion_report', addr('r1', T.MOTION_STATE)
        + ['ldrb r1,[r1]', f'tst r1,#{OWNER}', 'bne busy']
        + owned_call(T.REPORT_NATIVE) + ['busy:', 'bx lr'])
    b.bl(T.MOTION_POST_SITE, post, 'wireless direct callback with native queue fallback')
    b.bl(T.REPORT_SITE, report, 'serialize native timer and motion report ownership')
    b.branch(T.MOTION_TAIL_SITE, release, 'release motion ownership before native lift scheduling')
    return dict(post=post, report=report, state=T.MOTION_STATE,
                release=release, release_site=T.MOTION_TAIL_SITE,
                state_mask=DIRECT | OWNER, default='thread', wired='thread',
                queue_capacity=8, snapshot_bytes=P.SENSOR_SNAPSHOT_BYTES)
