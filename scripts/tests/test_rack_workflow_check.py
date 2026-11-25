"""scripts/rack/workflow_check.py: the audit's check contract and the drain readback (pass 34 row K1).

Every run is the entry as a subprocess against a stand-in box
(rack_fixture.Box): stub programs on PATH, a fake /proc, a config file.
"""

from __future__ import annotations

import json
import re
import stat

import pytest

from rack_fixture import HOST, Box

SECRET_SHAPES = re.compile(
    r"SHA256:[A-Za-z0-9+/]{20,}|AAAA[A-Za-z0-9+/]{20,}|\b(?:\d{1,3}\.){3}\d{1,3}\b|AbCdEf0123456789"
)


@pytest.fixture
def box(tmp_path):
    return Box(tmp_path)


def test_a_drained_box_answers_exactly_the_pass_line(box):
    done = box.run(HOST, "after", "old-channels-drained")
    assert done.returncode == 0, done.stderr
    assert done.stdout == f"PASS {HOST} after old-channels-drained\n"
    assert done.stderr == ""


LIVE = {
    "sshfs mounts": lambda box: box.output("findmnt", "sshfs", "/srv/engine/vibe-build\n"),
    "tool units": lambda box: box.output(
        "systemctl", "units", "fleet-cache-prune.timer loaded active waiting Prune the cache\n"
    ),
    "tool processes": lambda box: box.process(4242, ["/usr/local/bin/gpu", "run", "--host", "sel"]),
    "ssh transports": lambda box: box.output("ss", "dport", "0 0 192.0.2.10:50000 192.0.2.89:22\n"),
    "ssh control sockets": lambda box: box.socket("cm-sel"),
    "ssh forwards": lambda box: box.process(4243, ["ssh", "-N", "-L", "8317:127.0.0.1:8317", "sel"]),
    "transfers": lambda box: box.process(4244, ["rsync", "-a", "tree/", "sel:tree/"]),
}


@pytest.mark.parametrize("kind", sorted(LIVE))
def test_each_live_old_channel_alone_fails_the_drain_readback(box, kind):
    LIVE[kind](box)
    done = box.run(HOST, "after", "old-channels-drained")
    assert done.returncode == 1
    assert done.stdout == ""
    assert done.stderr.startswith(f"FAIL {HOST} after old-channels-drained: live: 1 {kind}")


def test_a_source_that_cannot_be_read_is_no_proof_of_a_drain(box):
    box.output("systemctl", "units", "", rc=1)
    done = box.run(HOST, "after", "old-channels-drained")
    assert done.returncode == 1
    assert "1 sources not read" in done.stderr


def test_a_kept_mount_an_inactive_unit_and_a_peer_outside_the_rack_do_not_count(box):
    box.config["drain"]["ignore_mounts"] = ["/srv/kept"]
    box.output("findmnt", "sshfs", "/srv/kept\n")
    box.output("systemctl", "units", "fleet-old.service loaded inactive dead Old\n")
    box.output("ss", "dport", "0 0 198.51.100.10:50000 198.51.100.89:22\n")
    done = box.run(HOST, "after", "old-channels-drained")
    assert done.returncode == 0, done.stderr


def test_with_no_rack_addresses_every_ssh_transport_counts(box):
    box.config["drain"]["rack_addresses"] = []
    box.output("ss", "dport", "0 0 [::ffff:198.51.100.10]:50000 [::ffff:198.51.100.89]:22\n")
    done = box.run(HOST, "after", "old-channels-drained")
    assert done.returncode == 1
    assert "1 ssh transports" in done.stderr


def test_other_rsync_looks_only_at_transfers(box):
    box.output("findmnt", "sshfs", "/srv/engine/vibe-build\n")
    assert box.run(HOST, "after", "other-rsync").returncode == 0
    box.process(4250, ["scp", "a", "sel:b"])
    done = box.run(HOST, "after", "other-rsync")
    assert done.returncode == 1
    assert "1 transfers" in done.stderr


def test_a_check_whose_rows_are_not_merged_waits_and_never_passes(box):
    done = box.run(HOST, "staged", "sol-lock")
    assert done.returncode == 3
    assert done.stdout == ""
    assert done.stderr.startswith(f"WAITS {HOST} staged sol-lock: needs Q5 #10467")


@pytest.mark.parametrize(
    "words",
    [
        (HOST, "during", "old-channels-drained"),
        (HOST, "after", "no-such-check"),
        ("no-such-host", "after", "old-channels-drained"),
        (HOST, "after"),
    ],
)
def test_an_unknown_host_phase_or_check_exits_2_with_no_pass(box, words):
    done = box.run(*words)
    assert done.returncode == 2
    assert done.stdout == ""


def test_one_box_never_answers_for_another(box):
    box.config["hosts"]["elsewhere"] = {"box_names": ["no-box-has-this-name"]}
    done = box.run("elsewhere", "after", "old-channels-drained")
    assert done.returncode == 2
    assert "this box is not elsewhere" in done.stderr
    assert done.stdout == ""


@pytest.mark.parametrize(
    ("argv", "forward"),
    [
        (["ssh", "-N", "-L", "8317:127.0.0.1:8317", "sel"], True),
        (["ssh", "-fNR", "9000:localhost:22", "sel"], True),
        (["ssh", "-oLocalForward=8080 127.0.0.1:80", "sel"], True),
        (["ssh", "-o", "RemoteForward 9000 localhost:22", "sel"], True),
        (["autossh", "-M", "0", "-N", "-D", "1080", "sel"], True),
        (["ssh", "-oUserKnownHostsFile=/dev/null", "-i", "/k/Wkey", "sel", "ls", "-L"], False),
        (["ssh", "-x", "-a", "-oClearAllForwardings=yes", "-2", "sel", "-s", "sftp"], False),
        (["sshfs", "-o", "reconnect", "sel:/srv", "/mnt"], False),
    ],
)
def test_an_ssh_forward_is_read_as_ssh_reads_its_options(argv, forward):
    from rack.readback.drain import is_forward

    assert is_forward(argv) is forward


def test_a_wrongly_typed_config_value_exits_2(box):
    box.config["command_timeout_secs"] = "15"
    done = box.run(HOST, "after", "old-channels-drained")
    assert done.returncode == 2
    assert "command_timeout_secs" in done.stderr


def test_a_second_run_of_a_passing_check_passes_again(box):
    env = {"ONEIRON_RACK_RUN_ID": "second-run"}
    assert box.run(HOST, "after", "old-channels-drained", env=env).returncode == 0
    assert box.run(HOST, "after", "old-channels-drained", env=env).returncode == 0


def test_evidence_is_private_and_redacted(box):
    box.process(4260, ["/usr/local/bin/gpu", "run", "--to", "192.0.2.77", "--token", "AbCdEf0123456789AbCdEf0123456789XyZ1"])
    done = box.run(HOST, "before", "old-channels-drained", env={"ONEIRON_RACK_RUN_ID": "r1"})
    assert done.returncode == 1
    (record,) = box.evidence_files()
    assert stat.S_IMODE(record.stat().st_mode) == 0o600
    assert stat.S_IMODE(record.parent.stat().st_mode) == 0o700
    text = record.read_text()
    assert "192.0.2.77" not in text and "AbCdEf0123456789" not in text
    assert "<address>" in text and "<token>" in text
    facts = json.loads(text)
    assert facts["outcome"] == "fail" and facts["check"] == "old-channels-drained"


def test_evidence_on_a_shared_filesystem_is_refused_and_nothing_passes(box):
    box.output("findmnt", "fstype", "fuse.sshfs\n")
    done = box.run(HOST, "after", "old-channels-drained")
    assert done.returncode == 2
    assert done.stdout == ""
    assert "shared filesystem" in done.stderr


def test_list_names_every_check_with_its_state(box):
    done = box.run("--list")
    assert done.returncode == 0
    rows = {line.split("\t")[0]: line.split("\t")[1] for line in done.stdout.splitlines()}
    assert rows["old-channels-drained"] == "built"
    for name in ("sol-lock", "inbox-append", "kind-6-logs", "kind-1-gpu-arms"):
        assert rows[name] == "waits"
    for name in (
        "identity-scope",
        "pivot-audit",
        "mesh-probe",
        "fleet-exec",
        "forward-policy",
        "other-rsync",
        "kind-3-machine-switch",
        "kind-5-drain-guard",
    ):
        assert rows[name] == "built"


def test_forward_policy_refuses_a_loopback_gateway_and_a_live_forward(box):
    box.config["canary"] = {"model_list_url": "http://127.0.0.1:8317/v1/models"}
    done = box.run(HOST, "after", "forward-policy")
    assert done.returncode == 1
    assert "loopback" in done.stderr
    box.config["canary"] = {"model_list_url": "http://198.51.100.1:8317/v1/models"}
    box.process(4270, ["ssh", "-fNR", "9000:localhost:22", "sel"])
    done = box.run(HOST, "after", "forward-policy")
    assert done.returncode == 1
    assert "1 ssh forwards" in done.stderr


def test_no_printed_line_carries_a_key_fingerprint_token_or_address(box):
    box.process(4280, ["rsync", "192.0.2.77:/x", "AbCdEf0123456789AbCdEf0123456789XyZ1"])
    box.output("ss", "dport", "0 0 192.0.2.10:50000 192.0.2.89:22\n")
    for check in ("old-channels-drained", "other-rsync", "identity-scope", "forward-policy", "sol-lock"):
        done = box.run(HOST, "before", check)
        assert not SECRET_SHAPES.search(done.stdout + done.stderr), (check, done.stderr)
