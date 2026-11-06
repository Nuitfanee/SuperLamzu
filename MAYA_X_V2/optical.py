"""Native optical sampling and debounce evidence; no click patch installation."""
from . import target as T


def stock(builder):
    for address, original in T.CLICK_PREIMAGES.items():
        source=T.flash_source(address)
        actual=bytes(builder.changes.get(source+i,builder.image.get(source+i,1)[0])
                     for i in range(len(original)))
        if actual != original:
            raise ValueError(f'MAYA native optical path changed at {address:#x}')
    return dict(mode='stock',native=True,exposed=False,hooks=False,
                algorithm='native debounce and Speed Click',
                sampling='native timer CC0=20, CC1=40, CC2=800; DPPI IR chain preserved',
                consumer='native GPIOTE IRQ and button-event thread',
                preimage_guards=len(T.CLICK_PREIMAGES))
