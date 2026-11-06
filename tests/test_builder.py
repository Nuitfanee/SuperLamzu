import tempfile
import unittest
from pathlib import Path

from superlamzu import target as T
from superlamzu.common import Builder, Image


class BuilderTests(unittest.TestCase):
    def test_sparse_records_and_line_endings(self):
        from superlamzu.patch import build
        b=build('SUPER')
        before=T.STOCK.read_bytes().splitlines(keepends=True)
        with tempfile.TemporaryDirectory() as tmp:
            p=b.write(Path(tmp)/'SUPER.hex')
            after=p.read_bytes().splitlines(keepends=True)
            self.assertEqual(len(before),len(after))
            self.assertEqual(set(Image(p).mem),set(b.image.mem))
            for old,new in zip(before,after):
                self.assertEqual(old[len(old.rstrip(b'\r\n')):],new[len(new.rstrip(b'\r\n')):])
                if old!=new:
                    r=bytes.fromhex(new[1:].decode())
                    self.assertEqual(r[3],0)
                    self.assertEqual(old[:9],new[:9])
                    self.assertEqual(sum(r)&255,0)

    def test_reject_non_target_and_original_destination(self):
        b=Builder()
        with self.assertRaises(ValueError):b.write(T.STOCK)
        with tempfile.TemporaryDirectory() as tmp:
            source=Path(tmp)/'changed.hex'
            address=T.FLASH_RECIPES[0]+2
            b.edit(address,bytes([b.image.mem[address]^1]),'test')
            b.write(source)
            with self.assertRaises(ValueError):Builder(source)

    def test_reject_gap_conflict_and_far_branch(self):
        b=Builder()
        gap=next(a for a in range(b.image.base,b.image.end) if a not in b.image.mem)
        with self.assertRaises(ValueError):b.edit(gap,b'\x00','unowned')
        a=T.FLASH_RECIPES[0]+2
        b.edit(a,b'\xff','first')
        with self.assertRaises(ValueError):b.edit(a,b'\xfe','second')
        with self.assertRaises(ValueError):b.branch(0x230012D8,0x0E085000,'out of range')

    def test_code_assembled_at_selected_fragment(self):
        b=Builder()
        a=T.FLASH_RECIPES[0]+16
        z=T.FLASH_RECIPES[1]+16
        b.add_pool(a,a+2)
        b.add_pool(z,z+32)
        where=b.code('test',iter(['bl #0x0E06CE70','bx lr']))
        self.assertEqual(where,z)
        from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB
        data=b.output_image()[where-b.image.base:where-b.image.base+4]
        ins=next(Cs(CS_ARCH_ARM,CS_MODE_THUMB).disasm(data,where))
        self.assertEqual(int(ins.op_str[1:],0),T.WR)

    def test_shared_address_literals_preserve_flags_and_alignment(self):
        from superlamzu.common import assemble
        from superlamzu.emulation import Arm
        from superlamzu.verify import patched_image
        source = ['movs r2,#0', 'cmp r2,#1']
        for reg in ('r0', 'r1', 'r12'):
            source += [f'movw {reg},#56063', f'movt {reg},#8960']
        source += ['mrs r3,apsr', 'bx lr']
        for padding in (0, 2):
            b = Builder()
            start = T.FLASH_RECIPES[0] + 16 + padding
            b.add_pool(start, start + 128)
            entry = b.code('literal_contract', source)
            raw = assemble(source, entry)
            self.assertLess(b.allocations[-1]['bytes'], len(raw))
            original = Builder()
            original.edit(entry, raw, 'uncompressed comparison')
            states = []
            for candidate in (original, b):
                with Arm(patched_image(candidate)) as cpu:
                    cpu.run(entry)
                    states.append(tuple(cpu.reg(reg) for reg in ('r0','r1','r2','r3','r12')))
            self.assertEqual(states[0], states[1])
            self.assertEqual(states[1][:3], (0x2300DAFF, 0x2300DAFF, 0))

    def test_reject_keystone_forward_relaxation_absolute_call_drift(self):
        from superlamzu.common import assemble
        lines=['beq later', 'bl #0x0E06CE70']+['nop']*130+['later:', 'bx lr']
        with self.assertRaisesRegex(ValueError, 'absolute branch targets'):
            assemble(lines,0x0E085000)
        lines[0]='beq.w later'
        self.assertTrue(assemble(lines,0x0E085000))


if __name__=='__main__':unittest.main()
