"""MAYA target facts, sparse protections and shared Thumb fixture integration."""
import tempfile
import unittest
from pathlib import Path

from MAYA_X_V2 import target as T
from MAYA_X_V2.sensor import LAYOUT, run, stock
from superlamzu.common import Builder
from superlamzu.emulation import Arm
from superlamzu.hexfile import Image


class TargetTests(unittest.TestCase):
    def test_paired_stock_inventory(self):
        report = T.inventory()
        self.assertEqual(report['mouse']['gap_bytes'], 8)
        self.assertEqual(report['receiver']['gap_bytes'], 9)
        self.assertEqual(report['mouse']['span_bytes'], 169004)
        self.assertEqual(report['receiver']['span_bytes'], 97160)
        self.assertEqual(len(report['recipe_entries']), 9)
        self.assertEqual(report['native_configuration']['profile_stride'], 233)
        self.assertEqual(report['native_configuration']['handler'], 0x1F650)
        self.assertFalse(report['mouse']['flash_available'])

    def test_all_runtime_copies_round_trip(self):
        for source, runtime, size in T.COPIES:
            for offset in (0, size//2, size-1):
                self.assertEqual(T.flash_source(runtime+offset), source+offset)
                self.assertEqual(T.runtime(source+offset), runtime+offset)
        self.assertEqual(T.flash_source(T.NATIVE_WR), 0x15730)
        self.assertEqual(T.flash_source(T.NATIVE_RD), 0x156BC)
        self.assertEqual(T.flash_source(T.RECIPE_DISPATCH), T.DISPATCH_SOURCE)

    def test_thorn_constructor_rejects_maya(self):
        with self.assertRaises(ValueError):
            Builder(T.STOCK)

    def test_runtime_patch_uses_maya_source_not_thorn(self):
        builder = stock()
        address = T.NATIVE_WR
        source = T.flash_source(address)
        builder.edit(address, bytes([builder.image.mem[source] ^ 1]), 'fixture')
        self.assertEqual(set(builder.changes), {source})
        from superlamzu import target as thorn
        for original in (*T.PROTECTED_SOURCES, thorn.STOCK):
            with self.subTest(original=original.name), self.assertRaises(ValueError):
                builder.write(original)
        with tempfile.TemporaryDirectory() as tmp:
            output = builder.write(Path(tmp)/'fixture.hex')
            changed = Image(output)
            self.assertEqual(set(changed.mem), set(builder.image.mem))
            self.assertEqual(changed.entry, builder.image.entry)
            with self.assertRaises(ValueError):
                Builder(output, target=T)

    def test_shared_executor_loads_both_ram_code_regions(self):
        image = Image(T.STOCK)
        with Arm(image, layout=LAYOUT) as cpu:
            for source, runtime, size in T.COPIES:
                self.assertEqual(bytes(cpu.uc.mem_read(runtime, 16)), image.get(source, 16))
            cpu.stub(T.NATIVE_WR, 1)
            self.assertEqual(cpu.run(T.WR), 1)
            self.assertEqual(cpu.reg('sp'), T.SP)

    def test_stock_recipe_runs_real_thumb(self):
        log = run(Image(T.STOCK), T.FLASH_RECIPES[0])
        self.assertTrue(len(log) > 100)
        self.assertTrue(any(e['op']=='write' and (e['page'],e['reg'],e['value'])==(5,0x44,4)
                            for e in log))

    def test_inspection_remains_offline_and_lightweight(self):
        import subprocess
        import sys
        program = """
import contextlib,io,sys
from MAYA_X_V2.__main__ import main
with contextlib.redirect_stdout(io.StringIO()):
    assert main(['inspect'])==0
assert not {'hid','unicorn','capstone','keystone'} & sys.modules.keys()
"""
        result=subprocess.run([sys.executable,'-B','-c',program],cwd=T.WORKSPACE,
                              capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)


if __name__ == '__main__':
    unittest.main()
