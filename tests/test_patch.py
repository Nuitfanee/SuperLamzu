import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from superlamzu import patch as firmware_patch
from superlamzu.patch import build
from superlamzu.verify import verify


class TargetBuildTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.full = build('SUPER')

    def test_super_verification(self):
        self.assertEqual(verify(self.full)["result"], "PASS")

    def test_shared_recipes_reconstruct_all_ordered_events(self):
        from superlamzu import target as T
        registers,bases,variants=firmware_patch.recipe_layout(self.full.image)
        self.assertEqual(len(registers),136)
        self.assertEqual(len(bases),2)
        self.assertEqual([i+1 for i,v in enumerate(variants) if v[2]],[6])
        for entry,(family,overrides,early) in zip(T.FLASH_RECIPES,variants):
            with self.subTest(entry=hex(entry)):
                pairs=list(zip(registers,bases[family]))
                self.assertEqual(overrides[-1],255)
                indices=[]
                for i in range(0,len(overrides)-1,3):
                    index,reg,value=overrides[i:i+3]
                    indices.append(index)
                    pairs[index]=(reg,value)
                self.assertEqual(indices,sorted(set(indices)))
                if early:
                    pairs.remove((0xC0,0))
                    pairs.insert(0,(0xC0,0))
                expected=bytearray(firmware_patch.recipe_events(self.full.image,entry))
                page=0
                for i in range(0,len(expected),2):
                    reg,value=expected[i:i+2]
                    if reg==127:page=value
                    elif page==5 and reg==68:expected[i+1]|=64
                self.assertEqual(bytes(x for pair in pairs for x in pair),expected)

    def test_recipe_manifest_and_remaining_space(self):
        self.assertEqual(self.full.recipes,dict(register_count=136,value_families=2,
                                              entries=7,early_cached_read=[6]))
        # Features use original recipe bodies plus only the 20 accumulation
        # bytes fully replaced by the guarded ABS tail branch.
        from superlamzu import target as T
        regions=[(a+4,a+n) for a,n in zip(T.FLASH_RECIPES,T.RECIPE_SIZES)]
        regions.append((T.ABS_ACC_SITE+4,T.ABS_ACC_SITE+len(T.ABS_ACC_PREIMAGE)))
        self.assertEqual(self.full.image.get(T.ABS_ACC_SITE,len(T.ABS_ACC_PREIMAGE)),T.ABS_ACC_PREIMAGE)
        intervals=[(int(x['address'],16),int(x['address'],16)+x['bytes'])
                   for x in self.full.allocations]
        intervals.extend((a,z) for a,z in self.full.pools if z>a)
        for a,z in intervals:
            self.assertTrue(any(lo<=a<z<=hi for lo,hi in regions),(hex(a),hex(z)))
        ordered=sorted(intervals)
        self.assertTrue(all(z<=c for (a,z),(c,d) in zip(ordered,ordered[1:])))

    def test_abs_reclaimed_bytes_and_native_pop_reject_changed_preimages(self):
        import copy
        from superlamzu import target as T
        from superlamzu.mouse_abs import install
        for site in (T.ABS_ACC_SITE+4,T.ABS_ACC_SITE+23,T.ABS_FRAME_POP_SITE):
            builder=copy.copy(self.full);builder.image=copy.deepcopy(self.full.image)
            builder.image.mem[T.flash_source(site)]^=1
            builder.image.__dict__.pop('data',None)
            with self.subTest(site=hex(site)),self.assertRaisesRegex(ValueError,'preimage changed'):
                install(builder)
        builder=copy.copy(self.full);builder.image=copy.deepcopy(self.full.image)
        for i,value in enumerate((T.ABS_ACC_SITE+5).to_bytes(4,'little')):
            builder.image.mem[T.BASE+0x100+i]=value
        builder.image.__dict__.pop('data',None)
        with self.assertRaisesRegex(ValueError,'external interior recipe reference'):
            install(builder)

    def test_removed_builds_rejected_by_api(self):
        for profile in ("B", "EQUIV", "BDB"):
            with self.subTest(profile=profile):
                with self.assertRaisesRegex(ValueError, "choose FULL or SUPER"):
                    build(profile)
                with self.assertRaisesRegex(ValueError, "choose FULL or SUPER"):
                    verify(self.full, profile)

    def test_removed_builds_rejected_by_cli_before_building(self):
        for profile in ("B", "EQUIV", "BDB"):
            with self.subTest(profile=profile), \
                    patch.object(firmware_patch, "build") as builder, \
                    contextlib.redirect_stderr(io.StringIO()), \
                    self.assertRaises(SystemExit) as exc:
                firmware_patch.main([profile])
            self.assertEqual(exc.exception.code, 2)
            builder.assert_not_called()

    def test_output_cannot_be_overwritten_by_its_own_json_manifest(self):
        for name in ('firmware.json', 'firmware', 'firmware.bin'):
            with self.subTest(output=name), patch.object(firmware_patch, 'build') as builder, \
                    contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                firmware_patch.main(['--output', name])
            self.assertEqual(error.exception.code, 2)
            builder.assert_not_called()

    def test_original_destination_rejected_before_expensive_build(self):
        from superlamzu import target as T
        with patch.object(firmware_patch, 'build') as builder, \
                contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            firmware_patch.main(['-o', str(T.STOCK)])
        self.assertEqual(error.exception.code, 2)
        builder.assert_not_called()

    def test_cli_default_contract_and_explicit_super(self):
        for args, profile in (([], 'SUPER'), (["SUPER"], 'SUPER')):
            with self.subTest(args=args), tempfile.TemporaryDirectory() as tmp:
                output = Path(tmp) / f"{profile}.hex"
                with patch.object(firmware_patch, "build", return_value=self.full) as builder, \
                        contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(firmware_patch.main([*args, "--skip-check", "-o", str(output)]), 0)
                builder.assert_called_once_with(profile, self.full.source)
                self.assertTrue(output.exists())
                manifest = json.loads(output.with_suffix(".json").read_text())
                self.assertEqual(manifest["profile"], profile)
                self.assertTrue(manifest["scope"]["native_debounce_profiles"])
                self.assertEqual(manifest["verification"], "not run")


if __name__=='__main__':unittest.main()
