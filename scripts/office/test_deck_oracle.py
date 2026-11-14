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
                return valid_env()
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
                 mock.patch.object(oracle, 'env_pin', return_value=valid_env()), \
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


ENVIRONMENT = json.loads((ROOT / 'environment.json').read_text())


def valid_env() -> dict:
    """The approved renderer pin with this run's role-held font approval."""
    env = APPROVED_ENV.copy()
    env['font_account'] = 'isolated-console'
    env['font_role'] = 'isolated'
    env['font_inventory_sha256'] = ENVIRONMENT['approved_font_inventories']['isolated']
    return env


def fit_unit(slide=1, index=1, name='Title 1', kind='text', block='a-title', shape_id=2,
             planned=None):
    return {'slide': slide, 'part': f'ppt/slides/slide{slide}.xml', 'shape_index': index,
            'shape_id': shape_id, 'name': name, 'block': block, 'kind': kind,
            'planned_emu': planned if planned is not None else [457200, 274638, 8229600, 1143000]}


def ok_line(slide=1, index=1, name='Title 1', left=457200, top=274638, width=8229600,
            height=1143000, text=1, ml=91440, mt=45720, mr=91440, mb=45720,
            bw=3000000, bh=500000, table=0, rows=0):
    return '\t'.join(['OK', str(slide), str(index), name, str(left), str(top), str(width),
                       str(height), str(text), str(ml), str(mt), str(mr), str(mb), str(bw),
                       str(bh), str(table), str(rows)])


class FitContracts(unittest.TestCase):
    """The fit probe's rows: SPEC section 4, one test per rule. No PowerPoint."""

    def test_fit_rows_no_row_is_inconclusive(self):
        unit = fit_unit()
        (row,) = oracle.fit_rows([unit], '')
        self.assertEqual(row['verdict'], 'inconclusive')
        self.assertEqual(row['detail'], 'PowerPoint returned no row')
        self.assertIsNone(row['frame_emu'])
        self.assertIsNone(row['inner_emu'])
        self.assertIsNone(row['bound_emu'])
        (row,) = oracle.fit_rows([unit], ok_line(index=2, name='TextBox 2'))
        self.assertEqual((row['verdict'], row['detail']), ('inconclusive', 'PowerPoint returned no row'))

    def test_fit_rows_err_row_is_inconclusive(self):
        (row,) = oracle.fit_rows([fit_unit()], 'ERR\t1\t1\tno such shape')
        self.assertEqual(row['verdict'], 'inconclusive')
        self.assertEqual(row['detail'], 'no such shape')
        self.assertIsNone(row['frame_emu'])

    def test_fit_rows_name_mismatch_is_inconclusive(self):
        (row,) = oracle.fit_rows([fit_unit()], ok_line(name='TextBox 9'))
        self.assertEqual(row['verdict'], 'inconclusive')
        self.assertEqual(row['detail'], "PowerPoint names shape 1 of slide 1 'TextBox 9', "
                                        "the candidate 'Title 1'")
        self.assertIsNone(row['frame_emu'])

    def test_fit_rows_chart_is_inconclusive_with_frame(self):
        unit = fit_unit(name='Chart 1', kind='chart', block='b-revenue')
        (row,) = oracle.fit_rows([unit], ok_line(name='Chart 1', text=0, bw=0, bh=0))
        self.assertEqual(row['verdict'], 'inconclusive')
        self.assertEqual(row['detail'], "PowerPoint's AppleScript dictionary exposes no chart text layout")
        self.assertEqual(row['frame_emu'], [457200, 274638, 8229600, 1143000])
        self.assertIsNone(row['inner_emu'])
        self.assertIsNone(row['bound_emu'])

    def test_fit_rows_frame_mismatch_is_inconclusive(self):
        unit = fit_unit()
        (row,) = oracle.fit_rows([unit], ok_line(left=457200 + oracle.FIT_SLACK_EMU + 1))
        self.assertEqual(row['verdict'], 'inconclusive')
        self.assertEqual(row['detail'], "PowerPoint's frame differs from the planned frame")
        self.assertEqual(row['frame_emu'], [457200 + oracle.FIT_SLACK_EMU + 1, 274638, 8229600, 1143000])

    def test_fit_rows_table_height_may_grow(self):
        unit = fit_unit(name='Table 1', kind='table', block='d-table')
        (row,) = oracle.fit_rows(
            [unit], ok_line(name='Table 1', height=1500000, text=0, bw=0, bh=0, table=1, rows=900000))
        self.assertEqual(row['verdict'], 'fits', row)
        self.assertEqual(row['frame_emu'], [457200, 274638, 8229600, 1500000])
        self.assertEqual(row['inner_emu'], [8229600, 1143000])
        self.assertEqual(row['bound_emu'], [8229600, 900000])

    def test_fit_rows_text_without_bounds_is_inconclusive(self):
        unit = fit_unit()
        (row,) = oracle.fit_rows([unit], ok_line(bw=0, bh=0))
        self.assertEqual((row['verdict'], row['detail']),
                         ('inconclusive', 'PowerPoint laid out no text'))
        (row,) = oracle.fit_rows([unit], ok_line(text=0, bw=0, bh=0))
        self.assertEqual((row['verdict'], row['detail']),
                         ('inconclusive', 'PowerPoint laid out no text'))

    def test_fit_rows_text_fits_at_tolerance(self):
        unit = fit_unit()
        inner_w, inner_h = 8229600 - 91440 - 91440, 1143000 - 45720 - 45720
        (row,) = oracle.fit_rows(
            [unit], ok_line(bw=inner_w + oracle.FIT_EPS_EMU, bh=inner_h + oracle.FIT_EPS_EMU))
        self.assertEqual(row['verdict'], 'fits', row)
        self.assertEqual(row['detail'], '')
        self.assertEqual(row['inner_emu'], [inner_w, inner_h])
        self.assertEqual(row['bound_emu'], [inner_w + oracle.FIT_EPS_EMU, inner_h + oracle.FIT_EPS_EMU])

    def test_fit_rows_text_overflows_by_height(self):
        unit = fit_unit()
        inner_h = 1143000 - 45720 - 45720
        (row,) = oracle.fit_rows([unit], ok_line(bw=100, bh=inner_h + oracle.FIT_EPS_EMU + 12700))
        self.assertEqual(row['verdict'], 'overflows', row)
        self.assertEqual(row['detail'], 'text overflows vertically by 1.05 pt')

    def test_fit_rows_text_overflows_by_width(self):
        unit = fit_unit()
        inner_w = 8229600 - 91440 - 91440
        (row,) = oracle.fit_rows([unit], ok_line(bw=inner_w + 2 * 12700, bh=100))
        self.assertEqual(row['verdict'], 'overflows', row)
        self.assertEqual(row['detail'], 'text overflows horizontally by 2.00 pt')

    def test_fit_rows_table_fits(self):
        unit = fit_unit(name='Table 1', kind='table', block='d-table')
        (row,) = oracle.fit_rows(
            [unit], ok_line(name='Table 1', text=0, bw=0, bh=0, table=1, rows=1143000))
        self.assertEqual(row['verdict'], 'fits', row)
        self.assertEqual(row['inner_emu'], [8229600, 1143000])
        self.assertEqual(row['bound_emu'], [8229600, 1143000])

    def test_fit_rows_table_overflows(self):
        unit = fit_unit(name='Table 1', kind='table', block='d-table')
        (row,) = oracle.fit_rows(
            [unit], ok_line(name='Table 1', text=0, bw=0, bh=0, table=1,
                            rows=1143000 + oracle.FIT_EPS_EMU + 1))
        self.assertEqual(row['verdict'], 'overflows', row)
        self.assertEqual(row['detail'], 'PowerPoint grew the rows past the frame')

    def test_oracle_measures_fit_between_open_and_pdf(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state, seen = {'name': None}, {}
            def inventory():
                return [state['name']] if state['name'] else []
            def scripted(source, action, target, observer, deadline, *ignored, script=None, argv=None):
                seen.setdefault('order', []).append(action)
                state['name'] = source.name
                if action == 'open':
                    return None, f'{source.name}:2'
                if action == 'fit':
                    seen['script'], seen['argv'] = script, argv
                    return None, '\n'.join([ok_line(), ok_line(index=2, name='TextBox 2')])
                if target:
                    if action == 'pdf':
                        target.write_bytes(b'%PDF-1.4 test')
                    else:
                        target.write_bytes((ROOT / 'fixtures/clean.pptx').read_bytes())
                return None, 'ok'
            def raster(args, timeout=8):
                Path(args[3], 'page-0001.png').write_bytes(b'\x89PNG\r\n\x1a\nfixture')
                return 'pages=1'
            units = [fit_unit(), fit_unit(index=2, name='TextBox 2', block='h-one')]
            binding = {'case_set': 'deck-create-v1', 'case': 'board-review',
                       'case_manifest_sha256': 'a' * 64, 'source': 'b' * 40}
            with mock.patch.object(oracle.sys, 'platform', 'darwin'), \
                 mock.patch.object(oracle, 'APP', ROOT / 'fixtures/clean.pptx'), \
                 mock.patch.object(oracle, 'STAGING', root / 'sandbox'), \
                 mock.patch.object(oracle, 'observer_status', return_value=None), \
                 mock.patch.object(oracle, 'env_pin', return_value=valid_env()), \
                 mock.patch.object(oracle, 'app_pid', return_value=123), \
                 mock.patch.object(oracle, 'presentations', side_effect=inventory), \
                 mock.patch.object(oracle, 'launch_hidden'), \
                 mock.patch.object(oracle, 'hide_powerpoint'), \
                 mock.patch.object(oracle, 'run_script', side_effect=scripted), \
                 mock.patch.object(oracle, 'command', side_effect=raster), \
                 mock.patch.object(oracle, 'close_owned', return_value=None):
                result = oracle.oracle(ROOT / 'fixtures/clean.pptx', root / 'results',
                                       fit=units, binding=binding)
            self.assertEqual(result['status'], 'clean', result['detail'])
            self.assertEqual(seen['order'], ['open', 'fit', 'pdf', 'saveback'])
            self.assertEqual(seen['script'], oracle.FIT_SCRIPT)
            self.assertEqual(seen['argv'], [state['name'], '1:1', '1:2'])
            self.assertEqual(result['binding'], binding)
            self.assertEqual([row['verdict'] for row in result['fit']], ['fits', 'fits'])
            self.assertEqual(result['fit_script_sha256'], oracle.digest(oracle.FIT_SCRIPT))
            stored = json.loads((root / 'results/receipt.json').read_text())
            self.assertEqual(stored['fit'], result['fit'])

    def test_failed_fit_step_leaves_every_row_inconclusive(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = {'name': None}
            def inventory():
                return [state['name']] if state['name'] else []
            def scripted(source, action, target, observer, deadline, *ignored, script=None, argv=None):
                state['name'] = source.name
                if action == 'open':
                    return None, f'{source.name}:1'
                if action == 'fit':
                    return 'timed_out', 'fit exceeded deadline'
                raise AssertionError(f'the pass ends at fit, not {action}')
            units = [fit_unit(), fit_unit(index=2, name='TextBox 2', block='h-one')]
            with mock.patch.object(oracle.sys, 'platform', 'darwin'), \
                 mock.patch.object(oracle, 'APP', ROOT / 'fixtures/clean.pptx'), \
                 mock.patch.object(oracle, 'STAGING', root / 'sandbox'), \
                 mock.patch.object(oracle, 'observer_status', return_value=None), \
                 mock.patch.object(oracle, 'env_pin', return_value=valid_env()), \
                 mock.patch.object(oracle, 'app_pid', return_value=123), \
                 mock.patch.object(oracle, 'presentations', side_effect=inventory), \
                 mock.patch.object(oracle, 'launch_hidden'), \
                 mock.patch.object(oracle, 'hide_powerpoint'), \
                 mock.patch.object(oracle, 'run_script', side_effect=scripted), \
                 mock.patch.object(oracle, 'close_owned', return_value=None):
                result = oracle.oracle(ROOT / 'fixtures/clean.pptx', root / 'results', fit=units)
            self.assertEqual(result['status'], 'timed_out', result)
            self.assertEqual(result['detail'], 'fit: fit exceeded deadline')
            self.assertEqual([row['verdict'] for row in result['fit']],
                             ['inconclusive', 'inconclusive'])
            self.assertTrue(all(row['detail'] == 'fit exceeded deadline' for row in result['fit']))


if __name__ == '__main__':
    unittest.main()
