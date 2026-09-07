"""Keep both wire CI triggers sensitive to all core crate dependencies."""

from fnmatch import fnmatchcase
from pathlib import Path

import pytest


WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/wire-quickstart.yml"


def trigger_paths(event):
    # This workflow uses explicit, equally indented event and path blocks.
    # Parse that narrow shape without adding a YAML dependency to the wire job.
    lines = WORKFLOW.read_text().splitlines()
    start = lines.index(f"  {event}:") + 1
    paths = []
    for line in lines[start:]:
        if line and not line.startswith("    "):
            break
        if line.startswith('      - "'):
            paths.append(line.strip()[3:-1])
    assert paths, f"missing {event} path filter"
    return paths


@pytest.mark.parametrize("event", ["pull_request", "push"])
def test_wire_filters_cover_the_whole_core_crate(event):
    paths = trigger_paths(event)
    assert "crates/oneiron/**" in paths
    for changed in [
        "crates/oneiron/Cargo.toml",
        "crates/oneiron/src/gate/evaluate.rs",
        "crates/oneiron/src/store/admission.rs",
        "crates/oneiron/src/batch/apply.rs",
        "crates/oneiron/src/memory/witness.rs",
        "Cargo.toml",
        "Cargo.lock",
        "scripts/tests/test_wire_workflow.py",
    ]:
        assert any(fnmatchcase(changed, pattern) for pattern in paths), changed
