"""Dev test_cfg_schema_and_presets adapted to LAMZU wire/units/saving.

FakeDevice is the existing HID boundary; no new simulator or hardware access.
"""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from superlamzu import cfg, config_registry as R, protocol as P
from test_host import FakeDevice


def preset(**settings):
    return dict(superlamzu_preset=1, schema_version=1,
                target="Thorn V2 / 00.00.01.16", settings=settings)


class RegistryTest(unittest.TestCase):
    def setUp(self):
        self.guard = patch.object(cfg.hid, "find_nodes", side_effect=AssertionError("real HID forbidden"))
        self.guard.start()
        self.sleep = patch.object(cfg.native.time, "sleep")
        self.sleep.start()
        self.dev = FakeDevice(P.F_DB | P.F_FPS | P.F_LOCK | P.F_FPS_CUSTOM)
        self.dev.regs[(1, 1, 0x88)] = 0x13
        self.dev.regs[(1, 1, 0x80)] = 64
        self.mouse = cfg.Mouse(cfg.Link(self.dev, 0), profile=1)

    def tearDown(self):
        self.sleep.stop()
        self.guard.stop()

    def run_cli(self, args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            code = cfg.main(args)
        return code, out.getvalue()

    def writes(self):
        return [r for r in self.dev.log if r[5] < 0x80]

    def test_schema_offline_stable_unique_and_target_limits(self):
        self.assertEqual(R.schema(), R.schema())
        rows = {r['name']: r for r in R.registry()}
        self.assertEqual(len(rows), len(R.registry()))
        self.assertEqual(rows['debounce']['max'], 255)
        self.assertEqual(rows['lock-lead']['max'], 499)
        self.assertEqual(rows['lod']['values'], ['0.7', '1', '1.3', '1.5', '1.7'])
        self.assertNotIn('click-mode', rows)
        self.assertNotIn('click', rows)
        for args in (['schema', '--json'], ['options'], ['options', 'debounce'], ['preset', 'list']):
            self.assertEqual(self.run_cli(args)[0], 0)
        self.assertEqual(json.loads(self.run_cli(['schema', '--json'])[1]), R.schema())

    def test_retired_optical_preset_is_skipped_without_calling_legacy_api(self):
        with patch.object(self.mouse, 'optical_click') as legacy:
            result = R.do_apply(self.mouse, preset(click='optical-direct'))
        self.assertEqual(result['results'], [dict(name='click', status='unknown-skipped')])
        legacy.assert_not_called()
        self.assertEqual(self.writes(), [])

    def test_dump_roundtrip_dry_run_unchanged_only_skip_unknown(self):
        original = R.make_preset(self.mouse)
        self.assertEqual(original['settings']['lod'], '1.3')
        self.assertEqual(original['settings']['dpi'], [[800, 800], [1600, 1600]])
        self.assertEqual(original['settings']['debounce'], dict(zip(P.DB_NAMES, P.DB_FACTORY)))
        unchanged = R.do_apply(self.mouse, original)
        self.assertTrue(unchanged['complete'])
        self.assertTrue(all(r['status'] == 'unchanged' for r in unchanged['results']))
        self.assertEqual(self.writes(), [])
        document = preset(**{'angle-snap': False, 'speed-click': [False, True], 'future-setting': 1})
        self.assertTrue(R.do_apply(self.mouse, document, dry_run=True)['complete'])
        self.assertEqual(self.writes(), [])
        result = R.do_apply(self.mouse, document, skip=['speed-click'])
        self.assertEqual(result['results'][0]['status'], 'unknown-skipped')
        self.assertFalse(R.read_typed(self.mouse, 'angle-snap'))
        self.assertEqual(R.read_typed(self.mouse, 'speed-click'), [False, False])
        result = R.do_apply(self.mouse, original, only=['angle-snap'])
        self.assertTrue(result['complete'])
        self.assertTrue(R.read_typed(self.mouse, 'angle-snap'))

    def test_every_debounce_byte_and_strict_types(self):
        for value in range(256):
            item = dict.fromkeys(P.DB_NAMES, value)
            self.assertEqual(R.validate_typed('debounce', item), item)
        for name, value in [('debounce', dict.fromkeys(P.DB_NAMES, '2.3')),
                            ('lock-lead', 500), ('lock-lead', True), ('polling', True),
                            ('lod', '2'), ('dpi', [[40001, 1]]), ('fps', 255),
                            ('speed-click', [1, 0]), ('fps', dict(unit=1, slow=1, fast=2))]:
            with self.subTest(name=name, value=value), self.assertRaises(cfg.CfgError):
                R.validate_typed(name, value)

    def test_invalid_late_value_is_rejected_before_any_write(self):
        with self.assertRaises(cfg.CfgError):
            R.do_apply(self.mouse, preset(**{'angle-snap': False, 'polling': 3}))
        self.assertEqual(self.writes(), [])

    def test_capability_skip_and_fps_count_preflight(self):
        result = R.do_apply(self.mouse, preset(path='direct', tracking=True))
        self.assertTrue(all(r['status'] == 'unsupported-skipped' for r in result['results']))
        with self.assertRaises(cfg.CfgError):
            R.do_apply(self.mouse, preset(fps=5))
        self.assertEqual(self.writes(), [])

    def test_communication_failure_not_hidden_as_unsupported(self):
        with patch.object(self.mouse, 'capabilities', side_effect=cfg.CfgError('timeout')):
            with self.assertRaisesRegex(cfg.CfgError, 'timeout'):
                R.dump_settings(self.mouse)
        with patch.object(self.mouse, 'angle_tune', side_effect=cfg.CfgError('timeout')):
            with self.assertRaises(cfg.CfgError):
                R.do_apply(self.mouse, preset(**{'angle-snap': False, 'angle-tune': 4}))
        self.assertEqual(self.writes(), [])

    def test_independent_readback_failure_stops_following_writes(self):
        with patch.object(self.mouse, 'set_flag'):
            result = R.do_apply(self.mouse, preset(**{'angle-snap': False, 'lock': True}))
        self.assertFalse(result['complete'])
        self.assertEqual(result['results'][-1]['status'], 'failed')
        self.assertFalse(self.mouse.lock_status()['enabled'])

    def test_stage_dependency_shrink_and_expand(self):
        self.dev.active_stages[1] = 2
        result = R.do_apply(self.mouse, preset(**{'dpi': [[2301, 2302]], 'dpi-active': 1}))
        self.assertTrue(result['complete'])
        writes = self.writes()
        self.assertEqual([r[5] for r in writes], [2, 1])
        self.dev.log.clear()
        result = R.do_apply(self.mouse, preset(**{'dpi': [[800, 800], [1600, 1600]], 'dpi-active': 2}))
        self.assertTrue(result['complete'])
        self.assertEqual([r[5] for r in self.writes()], [1, 2])
        with self.assertRaises(cfg.CfgError):
            R.do_apply(self.mouse, preset(dpi=[[800, 800]]))

    def test_custom_fps_readback_is_request_not_applied_claim(self):
        recipe = dict(unit=60, slow=1, fast=1)
        result = R.do_apply(self.mouse, preset(fps=recipe))
        self.assertTrue(result['complete'])
        self.assertTrue(self.mouse.fps_status()['pending'])
        self.assertEqual(R.read_typed(self.mouse, 'fps'), recipe)

    def test_local_preset_lifecycle_and_cli_device_routes(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict('os.environ', {'SUPERLAMZU_PRESETS': tmp}):
            with patch.object(cfg, 'open_device', return_value=(self.dev, None)):
                self.assertEqual(self.run_cli(['preset', 'save', 'mine'])[0], 0)
                self.assertEqual(self.run_cli(['dump', '--json'])[0], 0)
                self.assertEqual(self.run_cli(['apply', 'mine', '--dry-run'])[0], 0)
                self.assertEqual(self.run_cli(['preset', 'load', 'mine', '--dry-run'])[0], 0)
            self.assertEqual(json.loads(self.run_cli(['preset', 'list'])[1]), ['mine'])
            self.assertEqual(self.run_cli(['preset', 'show', 'mine'])[0], 0)
            self.assertEqual(self.run_cli(['preset', 'delete', 'mine'])[0], 0)
            self.assertFalse((Path(tmp) / 'mine.json').exists())
            self.assertNotEqual(self.run_cli(['preset', 'show', 'mine'])[0], 0)
            for bad in ['..', 'a b', '../escape']:
                if bad == '../escape':
                    continue  # explicit paths are supported intentionally
                with self.assertRaises(cfg.CfgError): R.preset_path(bad, must_exist=False)

    def test_save_before_polling_and_no_dry_run_save(self):
        fake = Mock()
        fake.capabilities.return_value = dict(flags=P.F_ADV_SAVED, preset_count=0)
        fake.polling.side_effect = [4000, 1000]
        result = R.do_apply(fake, preset(polling=1000), save=True)
        self.assertTrue(result['saved'])
        names = [x[0] for x in fake.mock_calls]
        self.assertLess(names.index('save_advanced'), names.index('set_polling'))
        fake.reset_mock()
        fake.polling.side_effect = None
        fake.polling.return_value = 4000
        R.do_apply(fake, preset(polling=1000), save=True, dry_run=True)
        fake.save_advanced.assert_not_called()
