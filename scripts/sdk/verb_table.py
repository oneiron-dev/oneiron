"""The verb table: one JSON file per verb under scripts/sdk/verbs/, named by its verb (untangle slice 4.2).

A verb PR adds or edits its own file and no shared one. The table is read in verb-name order."""
import json
from pathlib import Path

VERBS_DIR = Path(__file__).resolve().with_name('verbs')


def load_verbs(directory=VERBS_DIR):
    'Every verb row, in verb-name order; a file is named by the verb it holds.'
    rows = []
    for path in sorted(directory.glob('*.json')):
        row = json.loads(path.read_text())
        if path.name != f"{row['name']}.json":
            raise ValueError(f"{path.name}: a verb file is named by its verb, {row['name']}.json")
        rows.append(row)
    return rows
