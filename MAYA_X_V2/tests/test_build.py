"""Sparse export and artifact rejection without hardware or duplicate suites."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from MAYA_X_V2 import target as T
from MAYA_X_V2.build import verify_exports
from MAYA_X_V2.full import build_pair,filenames
from superlamzu.hexfile import Image


class BuildTests(unittest.TestCase):
    def test_exact_pair_export_preserves_records_and_changed_artifact_is_rejected(self):
        mouse,receiver=build_pair('SUPER')
        mouse_filename,receiver_filename=filenames('SUPER')
        with tempfile.TemporaryDirectory() as tmp:
            folder=Path(tmp)
            for builder,name in zip((mouse,receiver),(mouse_filename,receiver_filename)):
                path=builder.write(folder/name);actual=Image(path)
                self.assertEqual(set(actual.mem),set(builder.image.mem))
                self.assertEqual(actual.entry,builder.image.entry)
                # Preserve the source record order, types, lengths and line
                # endings, not merely the flattened byte span.
                original=builder.source.read_bytes().splitlines(keepends=True)
                written=path.read_bytes().splitlines(keepends=True)
                self.assertEqual(len(original),len(written))
                for before,after in zip(original,written):
                    self.assertEqual(before[:9],after[:9])
                    self.assertEqual(before[-2:],after[-2:])
            with patch('MAYA_X_V2.verify.verify',return_value={'result':'fixture'}) as check:
                self.assertEqual(verify_exports(folder,profile='SUPER'),{'result':'fixture'})
                self.assertEqual(check.call_count,1)
                # A valid but stock receiver file is not the paired SUPER.
                (folder/receiver_filename).write_bytes(receiver.source.read_bytes())
                with self.assertRaisesRegex(ValueError,'differs from reproducible'):
                    verify_exports(folder,profile='SUPER')
                self.assertEqual(check.call_count,1)

    def test_optimized_verification_fails_before_running_checks(self):
        import subprocess,sys
        program="from MAYA_X_V2.full import build_pair; from MAYA_X_V2.verify import verify; verify(*build_pair('SUPER'))"
        result=subprocess.run([sys.executable,'-O','-c',program],cwd=T.WORKSPACE,capture_output=True,text=True)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('requires assertions',result.stderr)


if __name__=='__main__':unittest.main()
