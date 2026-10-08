"""Saved text survives an SDK process restart (prune e2e row 4).

Process A opens a vault, witnesses one invented line, recalls it and exits.
Process B, a new process, opens the same vault and must recall that line under
the reference process A saw.
"""

import json
import subprocess
import sys
import textwrap

from oneiron import Oneiron

TEXT = "The spare oar for the Velmonte skiff is tied under the third pier plank."
QUERY = "Velmonte skiff"

WRITER = """
import json, sys
from oneiron import Oneiron
vault, text, query = sys.argv[1:]
memory = Oneiron.open(vault)
memory.witness(
    {
        "conversation_ref": "55555555555555555555555555555555",
        "messages": [{"author": "user", "message_type": "dialogue", "content": text, "order": 0}],
    }
)
items = memory.recall(query)["items"]
print(json.dumps([item["short_id"] for item in items if text in item["value_text"]]))
"""


def test_text_witnessed_by_one_process_is_recalled_by_the_next(tmp_path) -> None:
    vault = str(tmp_path / "vault")
    writer = subprocess.run(
        [sys.executable, "-c", textwrap.dedent(WRITER), vault, TEXT, QUERY],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    assert writer.returncode == 0, writer.stderr
    before = json.loads(writer.stdout.strip().splitlines()[-1])
    assert len(before) == 1, writer.stdout

    items = Oneiron.open(vault).recall(QUERY)["items"]
    after = [item["short_id"] for item in items if TEXT in item["value_text"]]
    assert after == before, items
