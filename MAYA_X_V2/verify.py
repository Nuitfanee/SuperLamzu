"""Replay existing target tests, then attest the exact paired sparse images."""
import io
import sys
import unittest

from superlamzu.verify import patched_image

from . import target as T,receiver as R
from .full import flags,build_pair


def structure(mouse,receiver):
    from .memory import evidence
    from .optical import stock
    from .persistence import evidence as storage_evidence
    from superlamzu.common import assemble
    from .receiver_facts import QUEUE_PREIMAGES
    images=[patched_image(b) for b in (mouse,receiver)]
    for builder,image in zip((mouse,receiver),images):
        if set(image.mem)!=set(builder.image.mem) or image.entry!=builder.image.entry:
            raise ValueError('MAYA FULL changed sparse addresses or entry')
        if image.get(builder.target.BASE,8)!=builder.image.get(builder.target.BASE,8):
            raise ValueError('MAYA FULL changed stack/reset vectors')
        if any(a not in builder.image.mem for a in builder.changes):
            raise ValueError('MAYA FULL writes an undefined HEX gap')
    if mouse.extension['flags']!=flags(getattr(mouse,'profile','FULL')):
        raise ValueError('incomplete firmware variant capabilities')
    from superlamzu import protocol as P
    if mouse.extension['flags'] & P.F_OPTICAL_CLICK:
        raise ValueError('retired optical-direct capability advertised')
    if any(v['name'].startswith(('optical_','maya_optical_','settings_click_')) for v in mouse.allocations):
        raise ValueError('retired optical-direct code remains in candidate')
    optical=stock(mouse)
    if images[0].get(T.MPU_DESCRIPTOR,12)!=mouse.image.get(T.MPU_DESCRIPTOR,12):
        raise ValueError('MAYA MPU configuration changed')
    expected=assemble(R.tail(receiver.absolute['init'])+['nop'],R.QUEUE_INIT)
    if images[1].get(R.QUEUE_INIT,len(expected))!=expected:
        raise ValueError('receiver ABS lifecycle veneer missing')
    for key in ('main','finish','init','commit'):
        if not R.QUEUE_BASE>receiver.absolute[key]>=0x20000CE0:
            raise ValueError('receiver code outside reclaimed native writer region')
    aliases=[(a,receiver.image.u32(a)) for a in range(receiver.image.base,receiver.image.end-3)
             if (R.ABS_VALID<=receiver.image.u32(a)<R.ABS_X+2
                 or R.ABS_Y<=receiver.image.u32(a)<R.ABS_Y+2)]
    if aliases:raise ValueError(f'new receiver ABS tail aliases: {aliases}')
    allowed=((R.flash_source(0x20002EBC),R.flash_source(0x20002FB4)),
             (R.flash_source(0x200030E8),R.flash_source(0x20003154)),
             (R.QUEUE_INIT,R.QUEUE_INIT+12),
             (R.flash_source(R.REPORT_POINTER),R.flash_source(R.REPORT_POINTER)+4),
             (R.flash_source(R.USB_QUEUE_PUT_POINTER),R.flash_source(R.USB_QUEUE_PUT_POINTER)+4))
    if any(not any(lo<=a<hi for lo,hi in allowed) for a in receiver.changes):
        raise ValueError('receiver edit outside verified queue/callback owners')
    # SOF driver, USB tables, LED handlers and radio IRQ remain byte-exact.
    for source,_,size in R.COPIES:
        if source==0x154C8 and images[1].get(source,size)!=receiver.image.get(source,size):
            raise ValueError('native receiver SOF driver changed')
    return dict(mouse=dict(changed_bytes=len(mouse.changes),
                    remaining_code_bytes=sum(z-a for a,z in mouse.pools),
                    allocated_pool_bytes=sum(a['bytes'] for a in mouse.allocations),
                    largest_contiguous_code_bytes=max(z-a for a,z in mouse.pools),
                    allocations=len(mouse.allocations),defined_bytes=len(images[0].mem),gap_bytes=8,
                    queue=evidence(mouse.image),storage=storage_evidence(mouse.image),optical=optical),
                receiver=dict(changed_bytes=len(receiver.changes),
                    remaining_code_bytes=sum(z-a for a,z in receiver.pools),
                    allocated_pool_bytes=sum(a['bytes'] for a in receiver.allocations),
                    largest_contiguous_code_bytes=max(z-a for a,z in receiver.pools),
                    allocations=len(receiver.allocations),defined_bytes=len(images[1].mem),gap_bytes=9,
                    absolute_tail_aliases=aliases,queue_preimage_guards=len(QUEUE_PREIMAGES),
                    native_sof='PUBLISH_SOF -> cross-domain DPPI -> TIMER20 SUBSCRIBE_CLEAR'))


def verify(mouse,receiver):
    """Use existing unittest/Thumb checks; never import tests into firmware code."""
    # This is the verification entry, not firmware generation. Keep all
    # feature fixtures in their existing tests rather than duplicating them.
    if sys.flags.optimize:
        raise RuntimeError('MAYA verification requires assertions; do not use -O/PYTHONOPTIMIZE')
    profile=getattr(mouse,'profile','FULL')
    suite=unittest.defaultTestLoader.discover(str(T.ROOT/'tests'),top_level_dir=str(T.ROOT.parent))
    excluded=[]
    if profile=='SUPER':
        def selected(items):
            for item in items:
                if isinstance(item,unittest.TestSuite):
                    yield from selected(item)
                elif item.__class__.__module__ in (
                        'MAYA_X_V2.tests.test_full',
                        'MAYA_X_V2.tests.test_channels',
                        'MAYA_X_V2.tests.test_stats'):
                    excluded.append(item.id())
                else:
                    yield item
        suite=unittest.TestSuite(selected(suite))
    stream=io.StringIO()
    result=unittest.TextTestRunner(stream=stream,verbosity=2).run(suite)
    T.ROOT.joinpath('build').mkdir(exist_ok=True)
    logfile='full-verification.log' if profile=='FULL' else 'super-verification.log'
    (T.ROOT/'build'/logfile).write_text(stream.getvalue(),encoding='utf-8')
    if not result.wasSuccessful():
        raise AssertionError(f'MAYA {profile} verification failed; see MAYA_X_V2/build/{logfile}')
    # Tests reconstruct their own complete candidate; confirm they attested
    # these exact edits, not merely the same capability flags.
    expected=build_pair(getattr(mouse,'profile','FULL'))
    for actual,checked in zip((mouse,receiver),expected):
        if actual.changes!=checked.changes or actual.image.mem!=checked.image.mem:
            raise ValueError('candidate differs from the verified builder output')
    return dict(result='PASS',tests=result.testsRun,failures=len(result.failures),errors=len(result.errors),
                skipped=len(result.skipped),excluded_other_profile=excluded,
                hardware='not run',structure=structure(mouse,receiver))
