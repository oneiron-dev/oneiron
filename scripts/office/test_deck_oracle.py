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
APPROVED_ENV = json.loads((ROOT / 'environment.json').read_text())['environment']
spec = importlib.util.spec_from_file_location('deck_oracle', ROOT / 'deck_oracle.py')
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)


class OfflineContracts(unittest.TestCase):

    def test_changed_source_during_environment_preflight_is_refused_before_open(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / 'candidate.pptx'
            source.write_bytes((ROOT / 'fixtures/clean.pptx').read_bytes())
            replacement = root / 'replacement.pptx'
            with zipfile.ZipFile(source) as original, zipfile.ZipFile(replacement, 'w') as changed:
                for member in original.infolist():
                    body = original.read(member.filename)
                    if member.filename == 'ppt/slides/slide1.xml':
                        body = body.replace(b'<a:t>', b'<a:t>CHANGED: ')
                    changed.writestr(member, body)
            original_hash = oracle.digest(source)
            def rewrite_during_preflight(_observer):
                source.write_bytes(replacement.read_bytes())
                return APPROVED_ENV.copy()
            with mock.patch.object(oracle.sys, 'platform', 'darwin'), \
                 mock.patch.object(oracle, 'APP', ROOT / 'fixtures/clean.pptx'), \
                 mock.patch.object(oracle, 'STAGING', root / 'sandbox'), \
                 mock.patch.object(oracle, 'observer_status', return_value=None), \
                 mock.patch.object(oracle, 'app_pid', return_value=None), \
                 mock.patch.object(oracle, 'env_pin', side_effect=rewrite_during_preflight), \
                 mock.patch.object(oracle, 'launch_hidden') as launch:
                receipt = oracle.oracle(source, root / 'results/clean')
            self.assertEqual(receipt['input']['sha256'], original_hash)
            self.assertNotEqual(receipt['staged_input_sha256'], original_hash)
            self.assertEqual(receipt['status'], 'unsupported', receipt)
            launch.assert_not_called()
            self.assertFalse(list((root / 'sandbox').iterdir()))
            report = oracle.classify_manifest(ROOT / 'fixtures.json', root / 'results')
            clean = next(row for row in report['cases'] if row['id'] == 'clean')
            self.assertEqual(clean['verdict'], 'fail', clean)

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
                 mock.patch.object(oracle, 'env_pin', return_value=APPROVED_ENV.copy()), \
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
