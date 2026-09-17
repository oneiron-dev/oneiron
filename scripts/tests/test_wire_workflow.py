"""Keep wire CI path coverage and the fixture's locked build contracts intact."""

from fnmatch import fnmatchcase
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

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


@pytest.mark.parametrize("failed_build", [0, 1, 2], ids=["metadata-stop", "server-fails", "provisioner-fails"])
def test_wire_fixture_builds_locked_separate_graphs_and_stops_on_failure(tmp_path, failed_build):
    repo = tmp_path / "checkout with spaces"
    scripts = repo / "scripts"
    scripts.mkdir(parents=True)
    helper = scripts / "wire-test-server.sh"
    shutil.copy2(WORKFLOW.parents[2] / "scripts/wire-test-server.sh", helper)
    tools = tmp_path / "tools"
    tools.mkdir()
    log = tmp_path / "cargo.jsonl"
    cargo = tools / "cargo"
    cargo.write_text(
        f"#!{sys.executable}\n"
        "import json, os, pathlib, sys\n"
        "log = pathlib.Path(os.environ['WIRE_TEST_LOG'])\n"
        "with log.open('a') as stream:\n"
        "    stream.write(json.dumps({'argv': sys.argv[1:], 'cwd': os.getcwd()}) + '\\n')\n"
        "if sys.argv[1] == 'build':\n"
        "    failed = len(log.read_text().splitlines()) == int(os.environ['WIRE_TEST_FAIL_BUILD'])\n"
        "    sys.exit(17 if failed else 0)\n"
        "if sys.argv[1] == 'metadata':\n"
        "    print(json.dumps({'target_directory': os.environ['CARGO_TARGET_DIR']}))\n"
        "    sys.exit(23)  # Stop before any provisioner or server can start.\n"
        "sys.exit(99)\n"
    )
    cargo.chmod(0o755)
    work = tmp_path / "work"
    work.mkdir()
    result = subprocess.run(
        ["/bin/bash", str(helper)], cwd=tmp_path,
        env=os.environ | {
            "PATH": f"{tools}{os.pathsep}{os.environ['PATH']}",
            "TMPDIR": str(work),
            "CARGO_TARGET_DIR": str(tmp_path / "no-built-binaries"),
            "ONEIRON_WIRE_PORT": "43210",  # No socket allocation in this fixture.
            "ONEIRON_WIRE_EXEC": "",
            "WIRE_TEST_LOG": str(log),
            "WIRE_TEST_FAIL_BUILD": str(failed_build),
        },
        text=True, capture_output=True, timeout=10, check=False,
    )
    assert result.returncode == (17 if failed_build else 23), result.stdout + result.stderr
    builds = [
        ["build", "--locked", "--quiet", "-p", "oneiron-server", "--bin", "oneiron-server"],
        ["build", "--locked", "--quiet", "-p", "oneiron-remote", "--example", "provision-fixture-actor"],
    ]
    expected = builds[:failed_build] if failed_build else [
        *builds, ["metadata", "--format-version", "1", "--no-deps"],
    ]
    records = [json.loads(line) for line in log.read_text().splitlines()]
    assert [record["argv"] for record in records] == expected
    assert all(Path(record["cwd"]) == repo.resolve() for record in records)
    assert not list(work.iterdir())  # The EXIT trap still removes its scratch vault.
