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
    def test_dialogs_fail_closed(self):
        self.assertEqual(oracle.dialog_class(['DIALOG:Repair Presentation'], 'candidate'), 'repaired')
        self.assertEqual(oracle.dialog_class(['DIALOG:PowerPoint found a problem with content in candidate.pptx'],
                                             'candidate'), 'repaired')
        self.assertEqual(oracle.dialog_class(['DIALOG:Grant File Access'], 'candidate'), 'unsupported')
        self.assertEqual(oracle.dialog_class(['DIALOG:unexpected prompt'], 'candidate'), 'unsupported')
        self.assertIsNone(oracle.dialog_class(['WINDOW:candidate'], 'candidate'))

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
            (Path(tmp) / 'clean/receipt.json').write_text(json.dumps({'status': 'clean',
                'input': {'sha256': oracle.digest(ROOT / 'fixtures/clean.pptx')},
                'staged_input_sha256': oracle.digest(ROOT / 'fixtures/clean.pptx'),
                'environment': APPROVED_ENV}))
            (Path(tmp) / 'damaged-candidate').mkdir()
            (Path(tmp) / 'damaged-candidate/receipt.json').write_text(json.dumps({'status': 'clean',
                'input': {'sha256': oracle.digest(ROOT / 'fixtures/damaged.pptx')},
                'staged_input_sha256': oracle.digest(ROOT / 'fixtures/damaged.pptx'),
                'environment': APPROVED_ENV}))
            report = oracle.classify_manifest(ROOT / 'fixtures.json', Path(tmp))
            self.assertEqual(report['counts']['fail'], 1)
            self.assertEqual(report['counts']['pass'], 1)
            self.assertEqual(report['counts']['inconclusive'], 3)

    def test_pinned_case_requires_input_hash_binding(self):
        corpus = json.loads((ROOT / 'pptarena.json').read_text())['cases'][:2]
        with tempfile.TemporaryDirectory() as tmp:
            results = Path(tmp)
            for case in corpus:
                folder = results / case['id']
                folder.mkdir()
                (folder / 'receipt.json').write_text(json.dumps({
                    'status': 'clean', 'input': {'sha256': oracle.digest(ROOT / 'fixtures/clean.pptx')},
                    'environment': APPROVED_ENV}))
            manifest = results / 'manifest.json'
            manifest.write_text(json.dumps({'cases': corpus}))
            report = oracle.classify_manifest(manifest, results)
            self.assertEqual(report['counts'].get('pass', 0), 0)
            first = corpus[0]
            (results / first['id'] / 'receipt.json').write_text(json.dumps({
                'status': 'clean', 'input': {'sha256': first['original']['sha256']},
                'staged_input_sha256': first['original']['sha256'],
                'environment': APPROVED_ENV}))
            self.assertEqual(oracle.classify_manifest(manifest, results)['counts']['pass'], 1)
            (results / first['id'] / 'receipt.json').write_text(json.dumps({
                'status': 'clean', 'input': {'sha256': first['original']['sha256']},
                'environment': {**APPROVED_ENV, 'pdfkit': 'unapproved'}}))
            self.assertEqual(oracle.classify_manifest(manifest, results)['counts'].get('pass', 0), 0)
            (results / first['id'] / 'receipt.json').write_text(json.dumps({
                'status': 'clean', 'input': {'sha256': first['original']['sha256']},
                'staged_input_sha256': first['original']['sha256'],
                'environment': APPROVED_ENV}))
            second = corpus[1]
            (results / second['id'] / 'receipt.json').write_text(json.dumps({
                'status': 'clean', 'input': {'sha256': first['original']['sha256']},
                'staged_input_sha256': first['original']['sha256'],
                'environment': APPROVED_ENV}))
            self.assertEqual(oracle.classify_manifest(manifest, results)['counts'],
                             {'pass': 1, 'fail': 1})
            (results / first['id'] / 'receipt.json').write_text(json.dumps({
                'status': 'clean', 'input': {'sha256': first['ground_truth']['sha256']},
                'staged_input_sha256': first['ground_truth']['sha256'],
                'environment': APPROVED_ENV}))
            self.assertEqual(oracle.classify_manifest(manifest, results)['counts']['pass'], 1)
            (results / first['id'] / 'receipt.json').write_text(json.dumps({'status': 'clean'}))
            self.assertEqual(oracle.classify_manifest(manifest, results)['counts'].get('pass', 0), 0)

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

    def test_repair_package_check_uses_staged_snapshot_not_mutable_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / 'candidate.pptx'
            source.write_bytes((ROOT / 'fixtures/repair.pptx').read_bytes())
            def source_changes_after_open(staged, action, target, observer, deadline):
                self.assertTrue(staged.exists())
                source.write_bytes((ROOT / 'fixtures/failed.pptx').read_bytes())
                return 'repaired', 'PowerPoint offered repair'
            with mock.patch.object(oracle.sys, 'platform', 'darwin'), \
                 mock.patch.object(oracle, 'APP', ROOT / 'fixtures/clean.pptx'), \
                 mock.patch.object(oracle, 'STAGING', root / 'sandbox'), \
                 mock.patch.object(oracle, 'observer_status', return_value=None), \
                 mock.patch.object(oracle, 'app_pid', return_value=123), \
                 mock.patch.object(oracle, 'presentations', return_value=[]), \
                 mock.patch.object(oracle, 'env_pin', return_value=APPROVED_ENV.copy()), \
                 mock.patch.object(oracle, 'launch_hidden'), \
                 mock.patch.object(oracle, 'hide_powerpoint'), \
                 mock.patch.object(oracle, 'run_script', side_effect=source_changes_after_open), \
                 mock.patch.object(oracle, 'cancel_owned_repair'), \
                 mock.patch.object(oracle, 'close_owned', return_value=None):
                receipt = oracle.oracle(source, root / 'result')
            self.assertTrue(oracle.invalid_presentation_package(source))
            self.assertEqual(receipt['status'], 'repaired', receipt)
            self.assertEqual(receipt['input']['sha256'], receipt['staged_input_sha256'])

    def test_classifier_rejects_missing_or_conflicting_staged_hash(self):
        receipt = json.loads((ROOT / 'results/mac-mini-008/clean/receipt.json').read_text())
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            folder = root / 'clean'
            folder.mkdir()
            for staged_hash in (None, '0' * 64):
                with self.subTest(staged_hash=staged_hash):
                    attempt = dict(receipt)
                    if staged_hash is None:
                        attempt.pop('staged_input_sha256')
                    else:
                        attempt['staged_input_sha256'] = staged_hash
                    (folder / 'receipt.json').write_text(json.dumps(attempt))
                    report = oracle.classify_manifest(ROOT / 'fixtures.json', root)
                    clean = next(row for row in report['cases'] if row['id'] == 'clean')
                    self.assertEqual(clean['verdict'], 'fail', clean)
                    self.assertIn('binding_error', clean)

    def test_incomplete_classification_cli_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = oracle.subprocess.run([sys.executable, str(ROOT / 'deck_oracle.py'), 'classify',
                                          str(ROOT / 'fixtures.json'), tmp],
                                         capture_output=True, text=True, check=False)
        self.assertEqual(json.loads(proc.stdout)['counts'], {'inconclusive': 5})
        self.assertNotEqual(proc.returncode, 0)

    def test_completed_script_past_deadline_is_timed_out(self):
        proc = mock.Mock()
        proc.poll.return_value = 0
        proc.returncode = 0
        proc.communicate.return_value = ('ok', '')
        with mock.patch.object(oracle.subprocess, 'Popen', return_value=proc), \
             mock.patch.object(oracle, 'app_pid', return_value=None), \
             mock.patch.object(oracle.time, 'monotonic', return_value=10):
            status, _ = oracle.run_script(ROOT / 'fixtures/clean.pptx', 'saveback',
                                          Path('/unused/reference.pptx'), 'system-events', 9)
        self.assertEqual(status, 'timed_out')

    def test_postprocessing_overrun_is_timed_out(self):
        clock = [10]
        original_digest = oracle.digest
        def costly_digest(path):
            value = original_digest(path)
            if path.name == 'reference.pptx':
                clock[0] += 100
            return value
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = {'name': None}
            def inventory():
                return [state['name']] if state['name'] else []
            def scripted(source, action, target, observer, deadline):
                state['name'] = source.name
                if target:
                    target.write_bytes(b'%PDF-1.4 fixture' if action == 'pdf'
                                       else (ROOT / 'fixtures/clean.pptx').read_bytes())
                return None, 'ok'
            def raster(args, timeout=8):
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
                 mock.patch.object(oracle, 'close_owned', return_value=None), \
                 mock.patch.object(oracle.time, 'monotonic', side_effect=lambda: clock[0]), \
                 mock.patch.object(oracle, 'digest', side_effect=costly_digest):
                result = oracle.oracle(ROOT / 'fixtures/clean.pptx', root / 'result', timeout=1)
        self.assertEqual(result['status'], 'timed_out', result)

    def test_expired_budget_does_not_start_raster(self):
        clock = [10]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = {'name': None}
            def inventory():
                return [state['name']] if state['name'] else []
            def scripted(source, action, target, observer, deadline):
                state['name'] = source.name
                if target:
                    target.write_bytes(b'%PDF-1.4 fixture')
                    clock[0] += 100
                return None, 'ok'
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
                 mock.patch.object(oracle, 'command') as swift, \
                 mock.patch.object(oracle, 'close_owned', return_value=None), \
                 mock.patch.object(oracle.time, 'monotonic', side_effect=lambda: clock[0]):
                result = oracle.oracle(ROOT / 'fixtures/clean.pptx', root / 'result', timeout=1)
        self.assertEqual(result['status'], 'timed_out')
        swift.assert_not_called()

    def test_unapproved_environment_blocks_open(self):
        unapproved = {**APPROVED_ENV, 'powerpoint': '99.0-unapproved'}
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(oracle.sys, 'platform', 'darwin'), \
             mock.patch.object(oracle, 'APP', ROOT / 'fixtures/clean.pptx'), \
             mock.patch.object(oracle, 'observer_status', return_value=None), \
             mock.patch.object(oracle, 'app_pid', return_value=None), \
             mock.patch.object(oracle, 'env_pin', return_value=unapproved), \
             mock.patch.object(oracle, 'launch_hidden') as launch:
            result = oracle.oracle(ROOT / 'fixtures/clean.pptx', Path(tmp) / 'result')
        self.assertEqual(result['status'], 'unsupported', result)
        self.assertIn('powerpoint', result['detail'])
        launch.assert_not_called()
        self.assertIn('font_inventory_sha256', oracle.environment_mismatch(
            {key: value for key, value in APPROVED_ENV.items() if key != 'font_inventory_sha256'}))

    def test_ordinary_deck_titles_are_not_dialogs(self):
        for stem in ('Disaster Recovery-123-abcd', 'Repair Plan', 'Permission Review'):
            with self.subTest(stem=stem):
                self.assertIsNone(oracle.dialog_class(['WINDOW:' + stem + '.pptx'], stem))
                # PowerPoint can label its ordinary document window AXDialog.
                self.assertIsNone(oracle.dialog_class(['DIALOG:' + stem + '.pptx'], stem))
        self.assertEqual(oracle.dialog_class(['DIALOG:PowerPoint found a problem with content'],
                                             'Disaster Recovery'), 'repaired')
        with mock.patch.object(oracle, 'command', return_value=(
                'WINDOW:Repair Plan.pptx\x1eDIALOG:PowerPoint found a problem with content')):
            observed = oracle.windows('system-events', 123)
        self.assertEqual(observed, ['WINDOW:Repair Plan.pptx',
                                    'DIALOG:PowerPoint found a problem with content'])

    def test_unsupported_modal_warns_after_closing_documents(self):
        with mock.patch.object(oracle, 'app_pid', return_value=123), \
             mock.patch.object(oracle, 'presentations', return_value=[]), \
             mock.patch.object(oracle, 'hide_powerpoint'), \
             mock.patch.object(oracle, 'windows', return_value=['DIALOG:Grant File Access']):
            warning = oracle.close_owned({'candidate.pptx'})
        self.assertIsNotNone(warning)
        self.assertIn('dialog', warning.lower())
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(oracle.sys, 'platform', 'darwin'), \
             mock.patch.object(oracle, 'APP', ROOT / 'fixtures/clean.pptx'), \
             mock.patch.object(oracle, 'STAGING', Path(tmp) / 'sandbox'), \
             mock.patch.object(oracle, 'observer_status', return_value=None), \
             mock.patch.object(oracle, 'env_pin', return_value=APPROVED_ENV.copy()), \
             mock.patch.object(oracle, 'app_pid', return_value=123), \
             mock.patch.object(oracle, 'presentations', return_value=[]), \
             mock.patch.object(oracle, 'launch_hidden'), \
             mock.patch.object(oracle, 'hide_powerpoint'), \
             mock.patch.object(oracle, 'run_script', return_value=('unsupported', 'Grant File Access')), \
             mock.patch.object(oracle, 'windows', return_value=['DIALOG:Grant File Access']):
            result = oracle.oracle(ROOT / 'fixtures/clean.pptx', Path(tmp) / 'result')
        self.assertEqual(result['status'], 'unsupported')
        self.assertIn('dialog', result['cleanup_warning'].lower())

    def test_matrix_stops_after_unsupported_oracle(self):
        runner_spec = importlib.util.spec_from_file_location('run_fixture_matrix', ROOT / 'run_fixture_matrix.py')
        runner = importlib.util.module_from_spec(runner_spec)
        with mock.patch.dict(sys.modules, {'deck_oracle': oracle}):
            runner_spec.loader.exec_module(runner)
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(runner.sys, 'platform', 'darwin'), \
             mock.patch.object(runner, 'APP', ROOT / 'fixtures/clean.pptx'), \
             mock.patch.object(runner, 'app_pid', return_value=123), \
             mock.patch.object(runner, 'oracle', return_value={
                 'status': 'unsupported', 'detail': 'Grant File Access'}) as run_case, \
             mock.patch.object(runner.sys, 'argv', ['run_fixture_matrix.py', str(Path(tmp) / 'run')]):
            self.assertEqual(runner.main(), 1)
        run_case.assert_called_once()

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
             mock.patch.object(oracle.time, 'monotonic', side_effect=[8, 10]):
            status, _ = oracle.run_script(ROOT / 'fixtures/clean.pptx', 'open', None, 'cua', 9)
        self.assertEqual(status, 'timed_out')
        proc.terminate.assert_called_once()
    def test_untitled_repair_dialog_text_is_observed(self):
        with mock.patch.object(oracle, 'command', return_value=(
                'DIALOG:PowerPoint found a problem with content in candidate.pptx.\x1e'
                'DIALOG:PowerPoint can attempt to repair the presentation.')):
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
                 mock.patch.object(oracle, 'env_pin', return_value=APPROVED_ENV.copy()), \
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
                 mock.patch.object(oracle, 'env_pin', return_value=APPROVED_ENV.copy()), \
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
