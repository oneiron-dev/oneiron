"""The verb table: one JSON file per verb under scripts/sdk/verbs/, named by its verb (untangle slice 4.2).

A verb PR adds or edits its own file and no shared one. The table is read in verb-name order."""
import json
from pathlib import Path

VERBS_DIR = Path(__file__).resolve().with_name('verbs')
# ARCH-0082 #act-table: every row states the act class of the act it makes (`act_class`), by the ruled names
# (VERB-SURFACE-DESIGN 3.1, VS-CHECKIN-NAMES = A), in the order of `crate::check_in::ActClass::ALL`.
ACT_CLASSES = (
    'reversible_work', 'spawn', 'spend_over_cap', 'outbound_send', 'room_add', 'member_add', 'member_remove',
    'legal_send', 'sign', 'billing', 'delete', 'vault_delete', 'erase', 'ownership_transfer', 'key_recovery',
    'security_control_disable', 'mass_secret_export', 'world_widen', 'grant_widen', 'grant_widen_own',
)
# `read` marks a read: check-in is never asked for one, and only a Read row states it. `unstated` marks a row
# whose effect has no proven undo class, so it holds on silence. No default fills a missing class (ARCH-0082:212).
ACT_CLASS_VALUES = ACT_CLASSES + ('read', 'unstated')


def check_act_class(row):
    'Fails unless the row states one act class, and `read` only on a Read row.'
    value = row.get('act_class')
    if not isinstance(value, str) or value not in ACT_CLASS_VALUES:
        raise ValueError(f"{row['name']}: `act_class` is one of {', '.join(ACT_CLASS_VALUES)}; no default fills a missing one")
    if value == 'read' and row.get('scope') != 'Read':
        raise ValueError(f"{row['name']}: `act_class` is `read` on a Read row only")


def load_verbs(directory=VERBS_DIR):
    'Every verb row, in verb-name order; a file is named by the verb it holds.'
    rows = []
    for path in sorted(directory.glob('*.json')):
        row = json.loads(path.read_text())
        if path.name != f"{row['name']}.json":
            raise ValueError(f"{path.name}: a verb file is named by its verb, {row['name']}.json")
        check_act_class(row)
        rows.append(row)
    return rows
