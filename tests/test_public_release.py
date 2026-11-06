"""Public package boundaries and documentation links."""
import contextlib
import io
from pathlib import Path
import re
import unittest
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]


class PublicReleaseTests(unittest.TestCase):
    def test_public_sources_do_not_ship_private_material(self):
        for name in ("references", "analysis", "AGENTS.md"):
            self.assertFalse((ROOT / name).exists(), name)
        self.assertEqual(len(list((ROOT / "firmware").rglob("*.hex"))), 5)
        self.assertEqual(len(list((ROOT / "flasher").glob("*.exe"))), 3)
        self.assertFalse((ROOT / "flasher" / "old").exists())

    def test_only_standalone_flasher_is_shipped(self):
        for path in ("superlamzu/device_flash.py", "superlamzu/receiver_flash.py",
                     "superlamzu/flash_protocol.py", "MAYA_X_V2/flash_protocol.py",
                     "tools/Restore-App.ps1"):
            self.assertFalse((ROOT / path).exists(), path)

    def test_configuration_is_cli_only(self):
        for path in ("superlamzu/panel.py", "superlamzu/panel_web",
                     "Start-SuperLamzu.ps1", "SuperLamzu.cmd"):
            self.assertFalse((ROOT / path).exists(), path)
        from superlamzu.__main__ import main
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            self.assertEqual(main([]), 0)
            self.assertIn("cfg", output.getvalue())
            self.assertEqual(main(["panel"]), 2)

    def test_flasher_does_not_embed_local_user_paths(self):
        for path in (ROOT / "flasher").glob("*.exe"):
            data = path.read_bytes()
            for encoding in ("ascii", "utf-16-le"):
                text = data.decode(encoding, errors="ignore")
                self.assertIsNone(re.search(r"(?i)[a-z]:[\\/]+Users[\\/]", text), path.name)

    def test_public_document_links_resolve(self):
        documents = [*sorted(ROOT.glob("README*.md")), ROOT / "NOTICE.md",
                     *sorted((ROOT / "docs").glob("*.md"))]
        for document in documents:
            text = document.read_text(encoding="utf-8")
            self.assertNotRegex(text, r"(?i)[a-z]:[\\/]+Users[\\/]")
            for destination in re.findall(r"\]\(([^)]+)\)", text):
                parsed = urlsplit(destination)
                if parsed.scheme or parsed.netloc:
                    continue
                target = (document.parent / unquote(parsed.path)).resolve()
                self.assertTrue(target.is_relative_to(ROOT), destination)
                self.assertTrue(target.exists(), f"{document.name}: {destination}")


if __name__ == "__main__":
    unittest.main()
