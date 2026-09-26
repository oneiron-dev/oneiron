"""Offline contracts and opt-in Mac PowerPoint integration."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('deck_oracle', ROOT / 'deck_oracle.py')
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)


class OfflineContracts(unittest.TestCase):
    def test_dialogs_fail_closed(self):
        self.assertEqual(oracle.dialog_class(['Repair Presentation'], 'candidate'), 'repaired')
        self.assertEqual(oracle.dialog_class(['PowerPoint found a problem with content in candidate.pptx'],
                                             'candidate'), 'repaired')
        self.assertEqual(oracle.dialog_class(['Grant File Access'], 'candidate'), 'unsupported')
        self.assertEqual(oracle.dialog_class(['unexpected prompt'], 'candidate'), 'unsupported')
        self.assertIsNone(oracle.dialog_class(['candidate'], 'candidate'))

    def test_damage_and_hashes(self):
        clean = ROOT / 'fixtures/clean.pptx'
        with zipfile.ZipFile(clean) as z:
            self.assertIn('ppt/slides/slide1.xml', z.namelist())
        with zipfile.ZipFile(ROOT / 'fixtures/repair.pptx') as z:
            self.assertNotIn('ppt/slides/slide1.xml', z.namelist())
        with zipfile.ZipFile(ROOT / 'fixtures/damaged.pptx') as z:
            self.assertIn(b'BAD', z.read('ppt/presentation.xml'))
        with self.assertRaises(zipfile.BadZipFile):
            zipfile.ZipFile(ROOT / 'fixtures/failed.pptx')
        self.assertEqual(len(oracle.digest(clean)), 64)

    def test_pptarena_pin_and_classification(self):
        manifest = json.loads((ROOT / 'pptarena.json').read_text())
        self.assertEqual(len(manifest['cases']), 100)
        self.assertEqual(len({c['id'] for c in manifest['cases']}), 100)
        self.assertTrue(all(len(c[k]['sha256']) == 64 for c in manifest['cases']
                            for k in ('original', 'ground_truth')))
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / 'clean').mkdir()
            (Path(tmp) / 'clean/receipt.json').write_text('{"status":"clean"}')
            (Path(tmp) / 'damaged-candidate').mkdir()
            (Path(tmp) / 'damaged-candidate/receipt.json').write_text('{"status":"clean"}')
            report = oracle.classify_manifest(ROOT / 'fixtures.json', Path(tmp))
            self.assertEqual(report['counts']['fail'], 1)
            self.assertEqual(report['counts']['pass'], 1)
            self.assertEqual(report['counts']['inconclusive'], 3)

    def test_linux_skips_with_receipt(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(oracle.sys, 'platform', 'linux'):
            output = Path(tmp) / 'run'
            result = oracle.oracle(ROOT / 'fixtures/clean.pptx', output)
            self.assertEqual(result['status'], 'unsupported')
            self.assertIn('macOS-only', result['detail'])
            self.assertEqual(json.loads((output / 'receipt.json').read_text())['status'], 'unsupported')

    def test_review_seed_v1_packet(self):
        seed_spec = importlib.util.spec_from_file_location('review_seed_check', ROOT / 'review_seed_check.py')
        module = importlib.util.module_from_spec(seed_spec)
        seed_spec.loader.exec_module(module)
        seed = json.loads((ROOT / 'review_seed.json').read_text())
        answer = json.loads((ROOT / 'review_example.json').read_text())
        self.assertEqual(module.validate(seed, answer)['answers'][0]['unit_id'], 'slide:1')
        answer['glossary_version'] = 2
        with self.assertRaisesRegex(ValueError, 'stale'):
            module.validate(seed, answer)

    def test_timeout_is_not_clean(self):
        proc = mock.Mock()
        proc.poll.return_value = None
        proc.communicate.return_value = ('', '')
        with mock.patch.object(oracle.subprocess, 'Popen', return_value=proc), \
             mock.patch.object(oracle, 'app_pid', return_value=None), \
             mock.patch.object(oracle.time, 'monotonic', return_value=10):
            status, _ = oracle.run_script(ROOT / 'fixtures/clean.pptx', 'open', None, 'cua', 9)
        self.assertEqual(status, 'timed_out')
        proc.terminate.assert_called_once()
    def test_untitled_repair_dialog_text_is_observed(self):
        with mock.patch.object(oracle, 'command', return_value=(
                'PowerPoint found a problem with content in candidate.pptx.\n'
                'PowerPoint can attempt to repair the presentation.')):
            lines = oracle.windows('system-events', 123)
        self.assertEqual(oracle.dialog_class(lines, 'candidate'), 'repaired')

    def test_owned_repair_is_cancelled_before_custody_close(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = {'staged': None}
            def scripted(source, action, target, observer, deadline):
                state['staged'] = source
                return 'repaired', 'repair alert'
            with mock.patch.object(oracle.sys, 'platform', 'darwin'), \
                 mock.patch.object(oracle, 'APP', ROOT / 'fixtures/clean.pptx'), \
                 mock.patch.object(oracle, 'STAGING', root / 'sandbox'), \
                 mock.patch.object(oracle, 'observer_status', return_value=None), \
                 mock.patch.object(oracle, 'env_pin', return_value={'test': True}), \
                 mock.patch.object(oracle, 'app_pid', return_value=123), \
                 mock.patch.object(oracle, 'presentations', return_value=[]), \
                 mock.patch.object(oracle, 'launch_hidden'), \
                 mock.patch.object(oracle, 'hide_powerpoint'), \
                 mock.patch.object(oracle, 'run_script', side_effect=scripted), \
                 mock.patch.object(oracle, 'cancel_owned_repair') as cancel, \
                 mock.patch.object(oracle, 'close_owned', return_value=None) as close:
                result = oracle.oracle(ROOT / 'fixtures/repair.pptx', root / 'result')
            self.assertEqual(result['status'], 'repaired')
            cancel.assert_called_once_with(state['staged'])
            close.assert_called_once()
            self.assertFalse(list((root / 'sandbox').iterdir()))

    def test_invalid_package_repair_alert_still_fails(self):
        self.assertFalse(oracle.invalid_presentation_package(ROOT / 'fixtures/clean.pptx'))
        self.assertFalse(oracle.invalid_presentation_package(ROOT / 'fixtures/repair.pptx'))
        self.assertTrue(oracle.invalid_presentation_package(ROOT / 'fixtures/failed.pptx'))
        self.assertTrue(oracle.invalid_presentation_package(ROOT / 'fixtures/damaged.pptx'))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with mock.patch.object(oracle.sys, 'platform', 'darwin'), \
                 mock.patch.object(oracle, 'APP', ROOT / 'fixtures/clean.pptx'), \
                 mock.patch.object(oracle, 'STAGING', root / 'sandbox'), \
                 mock.patch.object(oracle, 'observer_status', return_value=None), \
                 mock.patch.object(oracle, 'env_pin', return_value={'test': True}), \
                 mock.patch.object(oracle, 'app_pid', return_value=123), \
                 mock.patch.object(oracle, 'presentations', return_value=[]), \
                 mock.patch.object(oracle, 'launch_hidden'), \
                 mock.patch.object(oracle, 'hide_powerpoint'), \
                 mock.patch.object(oracle, 'run_script', return_value=('repaired', 'repair alert')), \
                 mock.patch.object(oracle, 'cancel_owned_repair') as cancel, \
                 mock.patch.object(oracle, 'close_owned', return_value=None):
                result = oracle.oracle(ROOT / 'fixtures/failed.pptx', root / 'result')
            self.assertEqual(result['status'], 'failed')
            self.assertIn('repair alert on invalid package', result['detail'])
            cancel.assert_called_once()

    def test_empty_inventory_is_not_missing_value(self):
        with mock.patch.object(oracle, 'command', return_value='') as command:
            self.assertEqual(oracle.presentations(), [])
        self.assertIn('custody', command.call_args.args[0])

    def test_saved_unrelated_presentation_blocks_custody(self):
        # A real saved deck can be open without a repair dialog or suspect window.
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(oracle.sys, 'platform', 'darwin'), \
             mock.patch.object(oracle, 'APP', ROOT / 'fixtures/clean.pptx'), \
             mock.patch.object(oracle, 'observer_status', return_value=None), \
             mock.patch.object(oracle, 'app_pid', return_value=5432), \
             mock.patch.object(oracle, 'presentations', return_value=['Quarterly Report.pptx']), \
             mock.patch.object(oracle, 'launch_hidden') as launch, \
             mock.patch.object(oracle, 'close_owned') as close:
            result = oracle.oracle(ROOT / 'fixtures/clean.pptx', Path(tmp) / 'run')
        self.assertEqual(result['status'], 'unsupported')
        self.assertIn('Quarterly Report.pptx', result['detail'])
        launch.assert_not_called()
        close.assert_not_called()
        self.assertIn('unrelated', oracle.custody(['Quarterly Report.pptx'], {'candidate.pptx'}))

    def test_staging_pdf_raster_saveback_and_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = {'name': None}
            def inventory():
                return [state['name']] if state['name'] else []
            def scripted(source, action, target, observer, deadline):
                self.assertEqual(source.parent.parent, root / 'sandbox')
                self.assertIn(f'-{os.getpid()}-', source.parent.name)
                state['name'] = source.name
                if target:
                    self.assertEqual(target.parent, source.parent)
                    if action == 'pdf':
                        target.write_bytes(b'%PDF-1.4 test')
                    else:
                        target.write_bytes((ROOT / 'fixtures/clean.pptx').read_bytes())
                return None, 'ok'
            def raster(args, timeout=8):
                self.assertEqual(args[0], 'swift')
                self.assertEqual(Path(args[2]).parent, Path(args[3]))
                Path(args[3], 'page-0001.png').write_bytes(b'\x89PNG\r\n\x1a\nfixture')
                return 'pages=1'
            with mock.patch.object(oracle.sys, 'platform', 'darwin'), \
                 mock.patch.object(oracle, 'APP', ROOT / 'fixtures/clean.pptx'), \
                 mock.patch.object(oracle, 'STAGING', root / 'sandbox'), \
                 mock.patch.object(oracle, 'observer_status', return_value=None), \
                 mock.patch.object(oracle, 'env_pin', return_value={'test': True}), \
                 mock.patch.object(oracle, 'app_pid', return_value=123), \
                 mock.patch.object(oracle, 'presentations', side_effect=inventory), \
                 mock.patch.object(oracle, 'launch_hidden'), \
                 mock.patch.object(oracle, 'hide_powerpoint'), \
                 mock.patch.object(oracle, 'run_script', side_effect=scripted), \
                 mock.patch.object(oracle, 'command', side_effect=raster), \
                 mock.patch.object(oracle, 'close_owned', return_value=None):
                result = oracle.oracle(ROOT / 'fixtures/clean.pptx', root / 'results')
            self.assertEqual(result['status'], 'clean', result['detail'])
            self.assertEqual(set(result['outputs']), {'render.pdf', 'reference.pptx', 'page-0001.png'})
            self.assertFalse(list((root / 'sandbox').iterdir()))
            self.assertEqual((root / 'results/render.pdf').read_bytes(), b'%PDF-1.4 test')

    def test_quit_requires_empty_document_inventory(self):
        with mock.patch.object(oracle, 'app_pid', return_value=5432), \
             mock.patch.object(oracle, 'presentations', return_value=['Quarterly Report.pptx']), \
             mock.patch.object(oracle, 'command') as command:
            with self.assertRaisesRegex(RuntimeError, 'refusing to quit'):
                oracle.quit_if_empty()
            command.assert_not_called()


@unittest.skipUnless(sys.platform == 'darwin' and oracle.APP.exists() and
                     os.environ.get('ONEIRON_DECK_ORACLE') == '1',
                     'Mac PowerPoint integration requires macOS, PowerPoint, and ONEIRON_DECK_ORACLE=1')
class MacIntegration(unittest.TestCase):
    def test_clean_and_damaged_candidate(self):
        reason = oracle.observer_status('system-events')
        if reason:
            self.skipTest(reason)
        with tempfile.TemporaryDirectory(prefix='deck-oracle-') as tmp:
            root = Path(tmp)
            clean = oracle.oracle(ROOT / 'fixtures/clean.pptx', root / 'clean')
            self.assertEqual(clean['status'], 'clean', clean['detail'])
            self.assertIn('page-0001.png', clean['outputs'])
            bad = oracle.oracle(ROOT / 'fixtures/damaged.pptx', root / 'damaged')
            self.assertNotEqual(bad['status'], 'clean', bad['detail'])
        oracle.quit_if_empty()


if __name__ == '__main__':
    unittest.main()
