"""Thorn V2 Receiver B target identity and bounded offline FULL adapter.

The two user-supplied images are separate CPUAPP and CPURAD targets.
SOF/ABS reuse native executable allocations and proven queue padding,
never a Flash tail or link-table slot.
"""
from dataclasses import dataclass
from pathlib import Path

from . import target as T
from .hexfile import Image

VID, APP_PID, BL_PID = 0x37B0, 0x002E, 0x0033
BL_VERSION = 'b1.00.00.01'
VERSION = "0.0.1.16"
RADIO_HOOKS = {
    "motion_copy": (0x0E0C5254, bytes.fromhex("bdf81330adf80a30bdf81530adf80c30")),
    "sof_isr": (0x0E0B80F6, bytes.fromhex("05232269")),
    "sof_callback": (0x0E0C5E78, bytes.fromhex("03640b78284cdbb22370d0f84035dbb20b70")),
}
RECEIVE_DISPATCH, USB_ISR, SOF_CALLBACK = 0x0E0C51DC, 0x0E0B805C, 0x0E0C5E60
RECEIVE_REPORT, RECEIVE_REPORT_SITE = 0x0E0C4D04, 0x0E0C527E
RECEIVE_REPORT_PREIMAGE = bytes.fromhex('fff741fd')
REPORT_FIFO_SITE, REPORT_FIFO_PREIMAGE = 0x0E0C4D44, bytes.fromhex('01f062ff')
REPORT_CONSUMER_SITE, REPORT_CONSUMER_PREIMAGE = 0x0E0C4F28, bytes.fromhex('fff762ff')
USB_REPORT = 0x0E0C4DF0
# REPORT clears node[6:24] and copies its eight-byte motion payload. The
# consumer reads only node[6:14] for type2, so byte14 carries its ABS marker.
REPORT_ABS_TAG = 14
REPORT_THREAD, REPORT_FIFO, FIFO_GET = 0x0E0C4EF0, 0x230040C4, 0x0E0C6C4C
USB_QUEUE_BASE, USB_QUEUE_INIT = 0x23005618, 0x0E0B285C
USB_QUEUE_READ, USB_QUEUE_POP = 0x0E0C510C, 0x0E0C5154
USB_START, USB_COMPLETED, USB_SUBMIT = 0x0E0C5190, 0x0E0C4D9C, 0x0E0C6C1C
USB_BUSY, USB_BUFFER = 0x23006574, 0x23005610
REPORT_FREE, REPORT_WAKE = 0x0E0C6CAC, 0x0E0C6C84
CODE_SOURCE, CODE_RAM, CODE_BYTES = 0x0E0C4D04, 0x230007A0, 0x1FC0
DATA_SOURCE, DATA_RAM, DATA_BYTES = 0x0E0C6CC4, 0x23002760, 0x1B20
SOF_TIMER, SOF_STATE, SOF_COUNT = 0x5F9A3000, 0x23007B88, 0x23007882
SOF_BLOCK_END = 0x0E0C5F30
# Three native queue send adapters share the same 25-record ring mechanics.
# The third callable entry is +4 past the preceding adapter's queue literal;
# IDA's linear function at 6AB0 is not itself a callable entry.
QUEUE_BASE, QUEUE_STRIDE, QUEUE_COUNT = 0x23006808, 640, 7
QUEUE_HEADER, QUEUE_RECORD, QUEUE_CAPACITY = 12, 25, 25
QUEUE_RAW, QUEUE_PREFIX, QUEUE_OBJECT = 0x0E0C69CC, 0x0E0C6A2C, 0x0E0C6AB4
QUEUE_BLOCK_END, QUEUE_MEMCPY = 0x0E0C6B28, 0x0E0C6CA4
QUEUE_ORIGINAL = bytes.fromhex(
    '2de9f0410646104631b31ab34ff4207808fb06f7114ce35de519ebb9192095f802c007f10c0310fb0c30204400f054f9'
    'ab782a790133dbb29a4298bf0023ea78ab709a4204bf0123e3550023012008fb06446370bde8f0810020fbe708680023'
    '2de9f843074699b192b1eff31188602080f31288bff36f8f4ff4207909fb07f5184c605d661930b188f31188bff36f8f'
    '0020bde8f883192096f802e005f10d0300fb0e5c10fb0e30a44420448cf80c2000f012f9b37832790133dbb29a4298bf'
    '0023f278b3709a4204bf01236355002309fb0744637088f31188bff36f8f0120d7e700bf086800232de9f0410c460746'
    '11461a4623466cb361b35ab34ff4207808fb00f5144c605d661918bb4ff0190cb07893f800e00cfb00530cfb00500d30'
    '2344204483f80ce000f0d6f8b37832790133dbb29a4298bf0023f278b3709a4204bf012363550023012008fb07446370'
    'bde8f0810020fbe708680023')
# Each queue occupies 12 + 25*25 = 637 of its 640 bytes. Use only the
# three-byte tails of queues 0/1: valid, aligned X and aligned Y.
ABS_STATE = QUEUE_BASE + QUEUE_HEADER + QUEUE_RECORD * QUEUE_CAPACITY - 1
ABS_VALID, ABS_X, ABS_Y = ABS_STATE + 1, ABS_STATE + 2, ABS_STATE + QUEUE_STRIDE + 2
ABS_JUMP_LIMIT = 0x4000
RX_QUEUE_GET, NATIVE_ALLOC, FIFO_PUT = 0x0E0C5C5C, 0x0E0C6C5C, 0x0E0C6C0C
IPC_PUT = FIFO_PUT  # Compatibility name; the owner is a native local FIFO.
RUNTIME_COPY = (0x0E0BCFE0, bytes.fromhex('0848094a08b5121a084905f0e7fe0848084a0949121a05f0e1febde8084006f099bb'))
SOF_VENEER = (0x0E0C38A8, bytes.fromhex('5ff800f0fd180023'))
SOF_ORIGINAL = bytes.fromhex(
    '10b52b4b1b78002b3dd02a4a1378032b0bd101232848294903640b78284cdbb22370'
    'd0f84035dbb20b7026490b7853b32548038801339bb2402b038023d91378012bd8b2'
    '04d11c4bd860022313701ae01378022b17d10120174b1864d3f840457a2c11d9d3f8'
    '40457f2c0dd8fa24d860c3f84c450824c3f800420323137000230b70124b187010bd'
    '40f2e530d3f8404584420ad940f2ea30d3f84045844204d801204ff47a74d860e2e7'
    '0123cee700bf8f7b00238c7b002300309a5f8b7b00238a7b00238e7b0023827800238d7b0023')


def runtime(address):
    return CODE_RAM + address - CODE_SOURCE if CODE_SOURCE <= address < CODE_SOURCE+CODE_BYTES else address


def flash_source(address):
    return CODE_SOURCE + address - CODE_RAM if CODE_RAM <= address < CODE_RAM+CODE_BYTES else address


@dataclass(frozen=True)
class ReceiverCore:
    name: str
    source: Path
    base: int
    span: int
    defined_bytes: int
    initial_sp: int
    reset: int

    def inspect(self):
        image = Image(self.source)
        actual = (image.base, len(image.data), len(image.mem),
                  image.u32(image.base), image.u32(image.base + 4))
        expected = (self.base, self.span, self.defined_bytes, self.initial_sp, self.reset)
        if actual != expected:
            raise ValueError(f"{self.name}: receiver image span/vectors changed: {actual}")
        return dict(core=self.name, source=str(self.source), version=VERSION,
                    base=self.base, end=self.base+self.span,
                    span_bytes=self.span, defined_bytes=self.defined_bytes,
                    gap_bytes=self.span-self.defined_bytes,
                    initial_sp=self.initial_sp, reset_vector=self.reset,
                    patch_status="sof-abs-full" if self.name=='cpurad' else "unchanged-native",
                    flash_available=False,
                    write_entry_point="flasher/SuperLAMZU THORN V2-0.1.0-windows-x64.exe",
                    verified_bootloader=BL_VERSION)


CORES = (
    ReceiverCore("cpuapp", T.ROOT / "firmware" / "LAMZU_Thorn_Dongle_capuapp_code_V2_v0.0.1.16_20260730.hex",
                 0x0E03A800, 42532, 42508, 0x2F01C5A8, 0x0E03CAA5),
    ReceiverCore("cpurad", T.ROOT / "firmware" / "LAMZU_Thorn_Dongle_capurad_code_V2_v0.0.1.16_20260730.hex",
                 0x0E0B1000, 96244, 96222, 0x23012240, 0x0E0B5961),
)


def inventory():
    radio = Image(CORES[1].source)
    for name, (address, original) in RADIO_HOOKS.items():
        if radio.get(address, len(original)) != original:
            raise ValueError(f"receiver {name}: original hook bytes changed")
    return dict(target="Thorn V2 Receiver B", vid=VID, app_pid=APP_PID,
                version=VERSION, display="three RGB LEDs; no screen",
                cores=[core.inspect() for core in CORES],
                hooks={name: dict(address=address, original=original.hex())
                       for name, (address, original) in RADIO_HOOKS.items()},
                hardware_operations=dict(backup=True,install_from_stock=True,update_from_verified_full=True,
                                         restore_saved_bytes=True,erase=False),
                pending=["paired mouse ABS enable and hardware acceptance",
                         "SOF timing acceptance"])


def _sof_callback_lines():
    # Same native acquisition states, volatile read order and 16-bit counter.
    # Only steady state uses the ISR's CC1/CC2 instead of shared CC0.
    return [
        'push {r4,lr}', f'ldr r2,={SOF_STATE:#x}', 'ldrb r3,[r2,#7]', 'cmp r3,#0', 'beq out',
        'ldrb r3,[r2,#4]', 'cmp r3,#3', 'bne acquire', f'ldr r0,={SOF_TIMER:#x}',
        'ldr r3,[r0,#0x548]', 'strb r3,[r2,#2]', 'ldr r3,[r0,#0x544]', 'strb r3,[r2,#3]',
        'acquire:', 'ldrb r3,[r2,#6]', 'cbz r3,out', f'ldr r0,={SOF_COUNT:#x}',
        'ldrh r3,[r0]', 'adds r3,#1', 'uxth r3,r3', 'strh r3,[r0]', 'cmp r3,#64', 'bls out',
        'ldrb r3,[r2,#4]', 'cmp r3,#1', 'uxtb r0,r3', 'bne second', f'ldr r3,={SOF_TIMER:#x}',
        'str r0,[r3,#12]', 'movs r3,#2', 'b state', 'second:', 'ldrb r3,[r2,#4]',
        'cmp r3,#2', 'bne out', 'movs r0,#1', f'ldr r3,={SOF_TIMER:#x}', 'str r0,[r3,#0x40]',
        'ldr r4,[r3,#0x540]', 'cmp r4,#122', 'bls slow', 'ldr r4,[r3,#0x540]', 'cmp r4,#127',
        'bhi slow', 'movs r4,#250', 'b commit', 'slow:', 'movw r0,#997', 'ldr r4,[r3,#0x540]',
        'cmp r4,r0', 'bls retry', 'movw r0,#1002', 'ldr r4,[r3,#0x540]', 'cmp r4,r0', 'bhi retry',
        'movs r0,#1', 'movw r4,#1000', 'commit:', 'str r0,[r3,#12]', 'str r4,[r3,#0x54C]',
        'movs r4,#8', 'str r4,[r3,#0x200]', 'movs r3,#3', 'strb r3,[r2,#4]',
        'movs r3,#0', 'strb r3,[r2,#6]', 'strb r0,[r2,#5]', 'out:', 'pop {r4,pc}',
        'retry:', 'movs r3,#1', 'state:', 'strb r3,[r2,#4]', 'b out', '.ltorg']


def _sof_isr_lines():
    # dev sof_lines, calibrated to target timer. IRQ clobbers only ip plus
    # the original displaced r2/r3 results. Capture channels 1/2 are not CC0.
    return [f'movw ip,#{SOF_TIMER&65535}', f'movt ip,#{SOF_TIMER>>16}',
            'ldr r3,[ip,#0x544]', 'str r3,[ip,#0x548]', 'movs r3,#1',
            'str r3,[ip,#0x44]', 'movs r3,#5', 'ldr r2,[r4,#0x10]', 'bx lr']


def build(core='cpurad'):
    from .common import Builder, assemble
    if core not in ('cpuapp', 'cpurad'):
        raise ValueError('receiver core must be cpuapp or cpurad')
    target = next(c for c in CORES if c.name == core)
    target.inspect()
    # Reuse the formal sparse writer, allocation checks and manifest, with an
    # explicit receiver identity rather than weakening the mouse constructor.
    class ReceiverBuilder(Builder):
        def __init__(self):
            self.source, self.image = target.source.resolve(), Image(target.source)
            self.changes, self.reasons, self.symbols = {}, {}, {}
            self.pools, self.allocations = [], []
        def edit(self, address, data, reason):
            return super().edit(flash_source(address), data, reason)
        def write(self, destination):
            if Path(destination).resolve() in {c.source.resolve() for c in CORES}:
                raise ValueError('refusing to overwrite original receiver firmware')
            return super().write(destination)
        def manifest(self, profile='FULL'):
            result = super().manifest(profile)
            result.update(target='LAMZU Thorn V2 Receiver B 0.0.1.16', core=core,
                          base=hex(target.base), span=target.span,
                          scope=dict(sof_irq=core=='cpurad', abs=core=='cpurad', relative_preserved=True,
                                     cpuapp_unchanged=True, new_ram_bytes=0,
                                     queue_padding_bytes=5 if core=='cpurad' else 0,
                                     hardware='not run', flash_available=False))
            return result
    b = ReceiverBuilder()
    if core == 'cpuapp':
        return b
    if b.image.get(SOF_CALLBACK,len(SOF_ORIGINAL)) != SOF_ORIGINAL:
        raise ValueError('receiver SOF callback allocation preimage changed')
    for address, original in (RUNTIME_COPY, SOF_VENEER):
        if b.image.get(address, len(original)) != original:
            raise ValueError(f'receiver runtime mapping preimage changed at {address:#x}')
    site, original = RADIO_HOOKS['sof_isr']
    if b.image.get(site, len(original)) != original:
        raise ValueError('receiver SOF IRQ preimage changed')
    callback = assemble(_sof_callback_lines(), runtime(SOF_CALLBACK))
    irq_address = (SOF_CALLBACK+len(callback)+3)&~3
    # The callback is copied to RAM by native startup. Its recycled tail also
    # has a Flash alias within the native code image; the USB IRQ calls that
    # Flash alias with a same-domain BL. The helper has no PC-relative data.
    irq = assemble(_sof_isr_lines(), irq_address)
    if irq_address + len(irq) > SOF_BLOCK_END:
        raise ValueError('receiver SOF adapter exceeds its native executable block')
    b.edit(SOF_CALLBACK, callback, 'SOF callback; retain native acquisition and use IRQ captures')
    b.edit(irq_address, irq, 'SOF IRQ capture helper in recycled native callback allocation')
    b.edit(site, assemble(f'bl #{irq_address:#x}',site), 'capture SOF before deferred callback')
    b.symbols.update(sof_callback=runtime(SOF_CALLBACK), sof_irq=irq_address)
    b.allocations.extend([dict(name='sof_callback', address=hex(SOF_CALLBACK), runtime=hex(runtime(SOF_CALLBACK)),bytes=len(callback)),
                          dict(name='sof_irq',address=hex(irq_address),bytes=len(irq))])
    from .receiver_abs import install
    install(b)
    return b
