"""Stock optical-button invariants; no replacement algorithm or firmware hooks."""
from . import protocol as P, target as T


def stock_evidence(builder, *, target=T):
    """Reject any patch at the retired optical-direct hook sites."""
    spans = []
    for site, original in target.CLICK_PREIMAGES.items():
        address = target.flash_source(site)
        if builder.image.get(address, len(original)) != original:
            raise ValueError(f'stock optical preimage changed at {site:#x}')
        patched = bytes(builder.changes.get(address + i, byte)
                        for i, byte in enumerate(original))
        if patched != original:
            raise ValueError(f'stock optical path was patched at {site:#x}')
        spans.append(dict(address=site, flash_source=address, bytes=len(original)))
    if builder.extension['flags'] & P.F_OPTICAL_CLICK:
        raise ValueError('retired optical-direct capability is advertised')
    if any(name.startswith(('optical_', 'settings_click_')) for name in builder.symbols):
        raise ValueError('retired optical-direct code is still allocated')
    return dict(mode='stock', native=True, exposed=False, native_spans=spans)
