"""The public entry point offers CLI configuration without opening hardware."""
import contextlib
import io
import unittest
from unittest.mock import patch

from superlamzu import cfg
from superlamzu.__main__ import main


class CliTests(unittest.TestCase):
    def test_no_arguments_explain_configuration_without_enumeration(self):
        out = io.StringIO()
        with patch.object(cfg.hid, 'find_nodes', side_effect=AssertionError('no hardware')), \
                contextlib.redirect_stdout(out):
            self.assertEqual(main([]), 0)
        self.assertIn('python -m superlamzu cfg list', out.getvalue())
        self.assertIn('python -m superlamzu cfg show', out.getvalue())
        self.assertNotIn('panel', out.getvalue())

    def test_removed_panel_command_is_rejected(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(['panel']), 2)
