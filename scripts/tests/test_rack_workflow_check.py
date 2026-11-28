"""scripts/rack/workflow_check.py: the audit's check contract and the drain readback (pass 34 row K1).

Every run is the entry as a subprocess against a stand-in box
(rack_fixture.Box): stub programs on PATH, a fake /proc, a config file.
"""

from __future__ import annotations

import http.server
import json
import os
import re
import stat
import subprocess
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from rack_fixture import ENTRY, HOST, Box

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
        # ssh reads options after the destination too, up to the remote command or `--`.
        (["ssh", "sel", "-L", "8080:127.0.0.1:80"], True),
        (["ssh", "sel", "--", "-L", "8080:127.0.0.1:80"], False),
        (["ssh", "--", "sel", "-L", "8080:127.0.0.1:80"], False),
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


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:8317/v1/models",
        "http://127.1:8317/v1/models",
        "http://0.0.0.0:8317/v1/models",
        "http://[::ffff:127.0.0.1]:8317/v1/models",
        "http://gateway.localhost:8317/v1/models",
    ],
)
def test_forward_policy_refuses_a_gateway_url_that_connects_to_this_box(box, url):
    box.config["canary"] = {"model_list_url": url}
    done = box.run(HOST, "after", "forward-policy")
    assert done.returncode == 1
    assert "loopback or local address" in done.stderr


def test_forward_policy_refuses_a_live_forward(box):
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


def test_the_entry_is_an_executable_that_runs_isolated():
    assert os.access(ENTRY, os.X_OK)
    assert ENTRY.read_text().splitlines()[0] == "#!/usr/bin/env -S python3 -I"
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C", "PYTHONPATH": "/nonexistent-injected"}
    done = subprocess.run([str(ENTRY), "--list"], capture_output=True, text=True, env=env, timeout=60)
    assert done.returncode == 0, done.stderr
    assert "old-channels-drained\tbuilt" in done.stdout


def gateway_box(box, config: str) -> Box:
    """An ssh process with no forward on its command line, and a user ssh configuration."""
    (box.home / ".ssh/config").write_text(config)
    box.config["canary"] = {"model_list_url": "http://198.51.100.1:8317/v1/models"}
    return box


@pytest.mark.parametrize(
    "config",
    [
        "Host gateway\n  LocalForward 8317 127.0.0.1:8317\n",
        "Host *\n    RemoteForward=9000 localhost:22\n",
        "Include ~/.ssh/conf.d/*.conf\n",
    ],
)
def test_a_forward_in_the_ssh_configuration_fails_the_drain_and_forward_policy(box, config):
    gateway_box(box, config)
    (box.home / ".ssh/conf.d").mkdir()
    (box.home / ".ssh/conf.d/gateway.conf").write_text("Host gateway\n  DynamicForward 1080\n")
    box.process(4300, ["ssh", "-N", "gateway"])
    done = box.run(HOST, "after", "old-channels-drained")
    assert done.returncode == 1
    assert done.stderr.startswith(f"FAIL {HOST} after old-channels-drained: live: 1 ssh forwards")
    done = box.run(HOST, "after", "forward-policy")
    assert done.returncode == 1
    assert "1 ssh forwards" in done.stderr


def test_a_forward_in_a_file_the_system_configuration_includes_counts(box):
    box.ssh_system_config.parent.mkdir()
    (box.ssh_system_config.parent / "ssh_config.d").mkdir()
    box.ssh_system_config.write_text("Include ssh_config.d/*.conf\n")
    (box.ssh_system_config.parent / "ssh_config.d/20-gateway.conf").write_text("LocalForward 8317 127.0.0.1:8317\n")
    box.process(4301, ["ssh", "-N", "gateway"])
    done = box.run(HOST, "after", "old-channels-drained")
    assert done.returncode == 1
    assert "1 ssh forwards" in done.stderr


@pytest.mark.parametrize(
    "argv",
    [
        # sshfs's own ssh clears every forwarding on its command line.
        ["ssh", "-x", "-a", "-oClearAllForwardings=yes", "-2", "gateway", "-s", "sftp"],
        # A -F file replaces both the user and the system configuration.
        ["ssh", "-F", "@CLEAN@", "-N", "gateway"],
        ["ssh", "-F", "none", "-N", "gateway"],
    ],
)
def test_a_configured_forward_the_process_does_not_read_does_not_count(box, argv):
    gateway_box(box, "Host gateway\n  LocalForward 8317 127.0.0.1:8317\n")
    clean = box.tmp / "clean_config"
    clean.write_text("Host gateway\n  User owen\n")
    box.process(4302, [str(clean) if word == "@CLEAN@" else word for word in argv])
    done = box.run(HOST, "after", "old-channels-drained")
    assert done.returncode == 0, done.stderr


@pytest.mark.parametrize(
    "sockets",
    [{"listen_tcp": (7001,)}, {"listen_unix": (7002,)}],
    ids=["a local or dynamic forward", "a control master"],
)
def test_an_ssh_process_holding_a_listening_socket_is_a_forward(box, sockets):
    box.process(4310, ["ssh", "-N", "gateway"], connected=(7003,), **sockets)
    done = box.run(HOST, "after", "old-channels-drained")
    assert done.returncode == 1
    assert "1 ssh forwards" in done.stderr


def test_an_ssh_process_with_only_a_connected_socket_is_no_forward(box):
    box.process(4311, ["ssh", "gateway", "uptime"], connected=(7004,))
    done = box.run(HOST, "after", "old-channels-drained")
    assert done.returncode == 0, done.stderr


def test_an_ssh_process_whose_sockets_cannot_be_read_is_no_proof(box):
    box.config["canary"] = {"model_list_url": "http://198.51.100.1:8317/v1/models"}
    box.process(4312, ["ssh", "-N", "gateway"], fds_readable=False)
    done = box.run(HOST, "after", "old-channels-drained")
    assert done.returncode == 1
    assert "1 sources not read" in done.stderr
    done = box.run(HOST, "after", "forward-policy")
    assert done.returncode == 1
    assert "not read: ssh process sockets" in done.stderr


def test_an_ssh_configuration_that_cannot_be_read_is_no_proof(box):
    (box.home / ".ssh/config").mkdir()
    box.process(4313, ["ssh", "-N", "gateway"])
    done = box.run(HOST, "after", "old-channels-drained")
    assert done.returncode == 1
    assert "1 sources not read" in done.stderr


def test_the_units_are_read_with_the_user_bus_and_only_it(box):
    bus = {"DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus", "SSH_AUTH_SOCK": "/tmp/agent.sock"}
    done = box.run(HOST, "after", "old-channels-drained", env=bus)
    assert done.returncode == 0, done.stderr
    seen = box.env_of("systemctl", "units")
    assert {"XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"} <= seen
    assert "SSH_AUTH_SOCK" not in seen
    assert not {"XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "SSH_AUTH_SOCK"} & box.env_of("ss", "dport")


def test_without_the_user_bus_the_units_are_not_read_and_the_drain_fails(box):
    box.session_env = {}
    done = box.run(HOST, "after", "old-channels-drained")
    assert done.returncode == 1
    assert "1 sources not read" in done.stderr


@pytest.mark.parametrize(
    "include",
    [
        'Include "~/.ssh/conf d/*.conf"',
        "Include '~/.ssh/conf d/gateway.conf'",
        "Include ~/.ssh/conf\\ d/gateway.conf",
    ],
)
def test_a_quoted_include_path_with_a_space_is_the_file_ssh_reads(box, include):
    # A RemoteForward has no listener on this side and need not be on the command line.
    gateway_box(box, include + "\n")
    (box.home / ".ssh/conf d").mkdir()
    (box.home / ".ssh/conf d/gateway.conf").write_text("Host gateway\n  RemoteForward 9000 localhost:22\n")
    box.process(4310, ["ssh", "-N", "gateway"])
    for check in ("old-channels-drained", "forward-policy"):
        done = box.run(HOST, "after", check)
        assert done.returncode == 1, check
        assert "1 ssh forwards" in done.stderr, check


@pytest.mark.parametrize(
    ("user_config", "system_config"),
    [
        ('Include "~/.ssh/conf d/gateway.conf\n', ""),
        ("Include\n", ""),
        ("", "Include ~/.ssh/conf.d/gateway.conf\n"),
    ],
)
def test_an_ssh_configuration_ssh_would_refuse_is_no_proof(box, user_config, system_config):
    gateway_box(box, user_config)
    box.ssh_system_config.parent.mkdir()
    box.ssh_system_config.write_text(system_config)
    box.process(4320, ["ssh", "-N", "gateway"])
    done = box.run(HOST, "after", "forward-policy")
    assert done.returncode == 1
    assert "not read: ssh configuration" in done.stderr


def test_ssh_configuration_lines_are_split_as_openssh_splits_them():
    from rack.readback.drain import config_line

    assert config_line('Include "a b" c # d') == ("include", ["a b", "c"])
    assert config_line("  RemoteForward=9000 localhost:22") == ("remoteforward", ["9000", "localhost:22"])
    assert config_line('"RemoteForward" 9000 x:22') == ("remoteforward", ["9000", "x:22"])
    assert config_line("Include 'it''s' a\\ b") == ("include", ["its", "a b"])
    assert config_line("# a comment") == ("", [])
    assert config_line("   ") == ("", [])
    with pytest.raises(ValueError):
        config_line('Include "open')
    with pytest.raises(ValueError):
        config_line("Include")


def test_an_include_directory_that_cannot_be_listed_is_no_proof(tmp_path, monkeypatch):
    from rack.readback import drain

    (tmp_path / "conf.d").mkdir()
    listdir = os.listdir

    def denied(path):
        if str(path) == str(tmp_path / "conf.d"):
            raise PermissionError(13, "Permission denied")
        return listdir(path)

    monkeypatch.setattr(drain.os, "listdir", denied)
    with pytest.raises(drain.SshConfigUnread):
        drain.strict_glob(f"{tmp_path}/conf.d/*.conf")


def test_a_proc_mount_that_hides_other_users_processes_is_no_proof(box):
    box.proc_mount("rw,nosuid,hidepid=invisible,gid=4242424")
    done = box.run(HOST, "after", "old-channels-drained")
    if os.geteuid() == 0:
        # root reads every process through hidepid.
        assert done.returncode == 0, done.stderr
    else:
        assert done.returncode == 1
        assert "1 sources not read" in done.stderr


def test_a_hidepid_mount_whose_group_this_run_is_in_shows_every_process(box):
    box.proc_mount(f"rw,hidepid=2,gid={os.getegid()}")
    done = box.run(HOST, "after", "old-channels-drained")
    assert done.returncode == 0, done.stderr


def test_a_process_table_with_no_proc_mount_at_it_is_no_proof(box):
    box.proc_mount("rw", at=box.tmp / "elsewhere")
    done = box.run(HOST, "after", "old-channels-drained")
    assert done.returncode == 1
    assert "1 sources not read" in done.stderr


def test_a_process_entry_that_cannot_be_read_is_no_proof_and_one_that_ended_is_none(box):
    # An entry whose cmdline is gone ended while the table was read.
    (box.proc / "4400").mkdir()
    done = box.run(HOST, "after", "old-channels-drained")
    assert done.returncode == 0, done.stderr
    unreadable = box.proc / "4401"
    unreadable.mkdir()
    (unreadable / "cmdline").mkdir()
    (unreadable / "status").write_text("Name:\tssh\nPPid:\t1\n")
    done = box.run(HOST, "after", "old-channels-drained")
    assert done.returncode == 1
    assert "1 sources not read" in done.stderr


def serve(status: int, location: str = ""):
    """A model gateway stand-in on 127.0.0.1 answering every GET with `status`; it records (path, Host)."""
    seen: list[tuple[str, str]] = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append((self.path, self.headers.get("Host", "")))
            self.send_response(status)
            if location:
                self.send_header("Location", location)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, seen


def gateway_context():
    return SimpleNamespace(config=SimpleNamespace(command_timeout_secs=5), evidence=SimpleNamespace(add=lambda *a: None))


def test_forward_policy_follows_no_redirect_and_connects_only_to_the_judged_address():
    from rack.addresses import Target
    from rack.checks import gateway_outcome

    after, after_seen = serve(200)
    first, first_seen = serve(302, f"http://127.0.0.1:{after.server_port}/v1/models")
    try:
        # The name never resolves: the request reaches the gateway only through the judged address.
        target = Target("http", "gateway.invalid", first.server_port, ("127.0.0.1",), False, False, "/v1/models")
        outcome = gateway_outcome(gateway_context(), target)
        assert not outcome.passed
        assert "redirect (302)" in outcome.reason
        assert first_seen == [("/v1/models", f"gateway.invalid:{first.server_port}")]
        assert after_seen == []
    finally:
        first.shutdown()
        after.shutdown()


def test_forward_policy_takes_a_401_over_the_judged_address_as_the_route_working():
    from rack.addresses import Target
    from rack.checks import gateway_outcome

    gateway, seen = serve(401)
    try:
        target = Target("http", "gateway.invalid", gateway.server_port, ("127.0.0.1",), False, False, "/v1/models?x=1")
        assert gateway_outcome(gateway_context(), target).passed
        assert seen == [("/v1/models?x=1", f"gateway.invalid:{gateway.server_port}")]
    finally:
        gateway.shutdown()


def test_a_run_directory_that_is_a_link_is_refused_and_nothing_is_written_through_it(box):
    elsewhere = box.tmp / "elsewhere-private"
    elsewhere.mkdir(mode=0o700)
    box.evidence.mkdir(mode=0o700)
    (box.evidence / "r1").symlink_to(elsewhere)
    done = box.run(HOST, "after", "old-channels-drained", env={"ONEIRON_RACK_RUN_ID": "r1"})
    assert done.returncode == 2
    assert done.stdout == ""
    assert "the run directory is a link" in done.stderr
    assert list(elsewhere.iterdir()) == []


def test_a_run_directory_on_another_filesystem_than_the_evidence_root_is_refused(tmp_path, monkeypatch):
    from rack import evidence

    devices = {}

    def device(fd):
        # The first directory asked about (the run directory) is on another device.
        return devices.setdefault(fd, len(devices) + 1)

    monkeypatch.setattr(evidence, "_device", device)
    monkeypatch.setattr(evidence, "filesystem_type", lambda path: "ext4")
    record = evidence.Evidence(tmp_path / "evidence", "r1", HOST, "after", "old-channels-drained")
    with pytest.raises(evidence.EvidenceError, match="another filesystem"):
        record.write("pass", "")
    assert list((tmp_path / "evidence" / "r1").iterdir()) == []


def test_the_example_configuration_names_every_key_and_only_those():
    from rack import rack_config
    from rack.rack_config import DEFAULTS

    example = json.loads(Path(rack_config.__file__).with_name("rack.example.json").read_text())

    def keys(value, defaults, where=""):
        assert set(value) == set(defaults), where
        for key, default in defaults.items():
            if isinstance(default, dict) and default:
                keys(value[key], default, f"{where}.{key}")

    keys({k: v for k, v in example.items() if k != "hosts"}, {k: v for k, v in DEFAULTS.items() if k != "hosts"})
