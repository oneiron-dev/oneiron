"""Offline: which account may run the deck gate's Office half, and whose font
approval applies. No PowerPoint; runs on any host:

    python3 -I -m unittest discover -s scripts/office -p 'test_deck_gate_accounts.py' -v
"""
import argparse
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
spec = importlib.util.spec_from_file_location('deck_gate', ROOT / 'deck_gate.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
oracle = gate.oracle_mod
ENVIRONMENT = json.loads((ROOT / 'environment.json').read_text())
CASES = json.loads((ROOT / 'pptx-live-v1.json').read_text())
STOP = 'observer stopped here, after the account check'


class TrackedConfigNamesNoOwnerAccount(unittest.TestCase):
    """The tracked configuration keys accounts by role; no owner account name."""

    def test_case_manifest_office_has_no_owner_account_list(self):
        office = CASES['office']
        self.assertNotIn('owner_accounts', office)
        self.assertEqual(set(office), {'timeout_seconds', 'observer', 'scripts'})

    def test_environment_keys_font_approvals_by_role(self):
        self.assertEqual(ENVIRONMENT['version'], 3)
        self.assertEqual(set(ENVIRONMENT['approved_font_inventories']), {'owner', 'isolated'})
        self.assertEqual(ENVIRONMENT['isolated_accounts'], ['decktest'])
        self.assertIsNone(oracle.environment_problem(ENVIRONMENT))


class OwnerFile(unittest.TestCase):
    """Points the owner-account file at a temporary path; absent unless a test writes it."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.owner_file = self.tmp / 'office-owner-account'
        patcher = mock.patch.object(oracle, 'OWNER_ACCOUNT_FILE', self.owner_file)
        patcher.start()
        self.addCleanup(patcher.stop)


class IsolatedAccountFlag(unittest.TestCase):
    """`--isolated-account` runs only in an account environment.json allowlists.
    The run manifest here still carries an old `owner_accounts` list: the gate
    must not consult it."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.owner_file = self.tmp / 'office-owner-account'
        patcher = mock.patch.object(oracle, 'OWNER_ACCOUNT_FILE', self.owner_file, create=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def office(self, account: str, isolated: bool) -> tuple[int, str, mock.Mock]:
        manifest = {'office': {'timeout_seconds': 90, 'observer': 'system-events', 'scripts': [],
                               'owner_accounts': ['owner-account']}}
        args = argparse.Namespace(run=self.tmp, results=None, isolated_account=isolated,
                                  observer=None, timeout=None)
        stderr = io.StringIO()
        with mock.patch.object(gate, 'load_run', return_value=manifest), \
             mock.patch.object(gate, 'verify', return_value=[]), \
             mock.patch.object(gate.sys, 'platform', 'darwin'), \
             mock.patch.object(oracle, 'APP', ROOT), \
             mock.patch('getpass.getuser', return_value=account), \
             mock.patch.object(oracle, 'font_account', return_value=account), \
             mock.patch.object(oracle, 'observer_status', return_value=STOP) as observer, \
             contextlib.redirect_stderr(stderr):
            code = gate.cmd_office(args)
        return code, stderr.getvalue(), observer

    def test_refused_in_an_account_outside_the_allowlist(self):
        code, err, observer = self.office('someone', isolated=True)
        self.assertEqual(code, 2)
        self.assertIn('someone is not an isolated test account', err)
        observer.assert_not_called()

    def test_refused_in_the_owner_account(self):
        self.owner_file.write_text('owner-account\n')
        code, err, observer = self.office('owner-account', isolated=True)
        self.assertEqual(code, 2)
        self.assertIn('owner-account is', err)
        observer.assert_not_called()

    def test_allowed_in_the_allowlisted_test_account(self):
        code, err, observer = self.office('decktest', isolated=True)
        self.assertEqual(code, 2)
        self.assertNotIn('isolated test account', err)
        self.assertIn(STOP, err)
        observer.assert_called_once()

    def test_without_the_flag_no_account_check_runs_here(self):
        code, err, observer = self.office('someone', isolated=False)
        self.assertEqual(code, 2)
        self.assertIn(STOP, err)
        observer.assert_called_once()


class RoleKeyedFontApproval(OwnerFile):
    """Font approvals are judged and written by role, never by account name."""

    def observed(self, role, digest) -> dict:
        return dict(ENVIRONMENT['environment'], font_account='someone', font_role=role,
                    font_inventory_sha256=digest)

    def test_account_role(self):
        self.assertEqual(oracle.account_role('decktest', ['decktest']), 'isolated')
        self.assertIsNone(oracle.account_role('someone', ['decktest']), 'no owner file: no owner role')
        self.owner_file.write_text('')
        self.assertIsNone(oracle.account_role('someone', ['decktest']), 'an empty owner file names nobody')
        self.owner_file.write_text('someone\n')
        self.assertEqual(oracle.account_role('someone', ['decktest']), 'owner')
        self.assertIsNone(oracle.account_role('other', ['decktest']))

    def test_receipt_is_judged_against_its_recorded_role(self):
        approved = ENVIRONMENT['approved_font_inventories']
        self.assertNotEqual(approved['owner'], approved['isolated'])
        self.assertIsNone(oracle.environment_mismatch(self.observed('owner', approved['owner'])))
        self.assertIsNone(oracle.environment_mismatch(self.observed('isolated', approved['isolated'])))
        self.assertIn('unapproved font inventory for the isolated role',
                      oracle.environment_mismatch(self.observed('isolated', approved['owner'])))
        self.assertIn("account 'someone' holds no role",
                      oracle.environment_mismatch(self.observed(None, approved['owner'])))

    def test_version_2_environment_is_refused(self):
        old = dict(ENVIRONMENT, version=2)
        self.assertIn('unsupported', oracle.environment_problem(old))

    def approve(self, account: str) -> tuple[int, dict, str]:
        target = self.tmp / 'environment.json'
        shutil.copyfile(ROOT / 'environment.json', target)
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(oracle, 'font_inventory', return_value=(account, 'f' * 64, ())), \
             contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = oracle.fonts(target)
        return code, json.loads(target.read_text()), err.getvalue()

    def test_approve_writes_the_role_key(self):
        self.owner_file.write_text('someone\n')
        code, config, _ = self.approve('someone')
        self.assertEqual(code, 0)
        self.assertEqual(config['approved_font_inventories'],
                         {'owner': 'f' * 64, 'isolated': ENVIRONMENT['approved_font_inventories']['isolated']})

    def test_approve_refuses_an_account_without_a_role(self):
        code, config, err = self.approve('someone')
        self.assertEqual(code, 2)
        self.assertIn('account someone holds no role', err)
        self.assertEqual(config, ENVIRONMENT)


if __name__ == '__main__':
    unittest.main()
