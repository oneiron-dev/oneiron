"""scripts/rack: the key readback (pass 34 15.1 gate C, row K1 part c) at one box.

The stand-in box's sshd journal, live sessions, authorized_keys and the
rack's client key list are fixtures. The rack's keys are kel's; the owner's
device is mac, whose key stays (section 13).
"""

from __future__ import annotations

import shutil
import stat
from pathlib import Path

import pytest

from rack_fixture import HOST, Box, key_blob, sshd_settings

from rack.readback.keys import (
    Account,
    authorized_keys_paths,
    expand_authorized_keys_file,
    fingerprint,
    parse_authorized_keys,
)

# A throwaway key made for this test with ssh-keygen (private half deleted);
# `ssh-keygen -lf` printed the fingerprint below.
KNOWN_KEY = "AAAAC3NzaC1lZDI1NTE5AAAAIMV0qjj7l2sgpmyerCo1hbitK4ODKCldGr20QXfIqMmJ"
KNOWN_FINGERPRINT = "SHA256:hAg9nZAR3zrheu6oD0JmTcOBNYhMI3T9dJvSwqbFOvY"


def test_a_fingerprint_is_the_one_ssh_keygen_prints():
    assert fingerprint(KNOWN_KEY) == KNOWN_FINGERPRINT


def test_options_with_quoted_commas_and_spaces_are_read_around():
    line = f'restrict,command="echo a, b",from="192.0.2.0/24" ssh-ed25519 {KNOWN_KEY} kel-fleet-mesh'
    (key,) = parse_authorized_keys(f"# a comment\n\n{line}\n")
    assert key.fingerprint == KNOWN_FINGERPRINT
    assert key.comment == "kel-fleet-mesh"
    assert key.restricted


class Rack:
    """kel's key (a rack machine) and mac's key (the owner's device) on the stand-in box."""

    def __init__(self, box: Box):
        self.box = box
        self.kel = key_blob()
        self.mac = key_blob()
        self.kel_fp = fingerprint(self.kel)
        self.mac_fp = fingerprint(self.mac)
        (box.rack_keys / "kel.keys").write_text(f"{self.kel_fp} kel\n")
        (box.rack_keys / "mac.keys").write_text(f"{self.mac_fp} mac\n")
        self.authorize(self.kel, self.mac)
        self.journal: list[str] = []
        self.sessions: list[str] = []

    def authorize(self, *blobs: str) -> None:
        lines = [f"ssh-ed25519 {blob} key-{n}\n" for n, blob in enumerate(blobs)]
        (self.box.home / ".ssh/authorized_keys").write_text("".join(lines))

    def accept(self, when: int, fp: str, addr: str, port: int) -> None:
        self.journal.append(
            f"{when}.000000 box sshd-session[{port}]: Accepted publickey for owen from {addr} port {port} ssh2: ED25519 {fp}\n"
        )

    def live(self, peer: str) -> None:
        self.sessions.append(f"0 0 192.0.2.5:22 {peer}\n")

    def run(self, phase: str = "before", check: str = "identity-scope"):
        self.box.output("journalctl", "journal", "".join(self.journal))
        self.box.output("ss", "sport", "".join(self.sessions))
        return self.box.run(HOST, phase, check)


@pytest.fixture
def rack(tmp_path):
    return Rack(Box(tmp_path))


def test_the_owners_logins_and_live_session_pass(rack):
    rack.accept(1500, rack.mac_fp, "192.0.2.30", 600)
    rack.live("192.0.2.30:600")
    done = rack.run()
    assert done.returncode == 0, done.stderr
    assert done.stdout == f"PASS {HOST} before identity-scope\n"


def test_pivot_audit_reads_the_same_keys(rack):
    rack.accept(1500, rack.kel_fp, "192.0.2.40", 700)
    done = rack.run(check="pivot-audit")
    assert done.returncode == 1
    assert "1 rack key logins since the freeze" in done.stderr


def test_a_rack_key_login_after_the_freeze_fails(rack):
    rack.accept(1500, rack.kel_fp, "192.0.2.40", 700)
    done = rack.run()
    assert done.returncode == 1
    assert done.stdout == ""
    assert "1 rack key logins since the freeze" in done.stderr


def test_a_rack_key_login_before_the_freeze_with_no_live_session_passes(rack):
    rack.accept(500, rack.kel_fp, "192.0.2.40", 700)
    assert rack.run().returncode == 0


def test_a_session_opened_on_a_rack_key_before_the_freeze_and_still_live_fails(rack):
    rack.accept(500, rack.kel_fp, "192.0.2.40", 700)
    rack.live("192.0.2.40:700")
    done = rack.run()
    assert done.returncode == 1
    assert "1 live sessions on a rack key" in done.stderr


def test_a_dual_stack_peer_matches_its_v4_accept(rack):
    rack.accept(1500, rack.mac_fp, "192.0.2.30", 600)
    rack.live("[::ffff:192.0.2.30]:600")
    assert rack.run().returncode == 0


def test_a_live_session_with_no_accept_record_is_no_proof(rack):
    rack.live("192.0.2.50:800")
    done = rack.run()
    assert done.returncode == 1
    assert "1 live sessions with no accept record" in done.stderr


def test_after_the_removal_a_rack_key_still_listed_fails_and_none_passes(rack):
    done = rack.run(phase="after")
    assert done.returncode == 1
    assert "1 rack keys still authorized" in done.stderr
    rack.authorize(rack.mac)
    assert rack.run(phase="after").returncode == 0


def test_an_authorized_keys_file_that_cannot_be_read_is_no_proof(rack):
    unreadable = rack.box.tmp / "a-directory"
    unreadable.mkdir()
    rack.box.config["keys"]["authorized_keys_files"].append(str(unreadable))
    done = rack.run()
    assert done.returncode == 1
    assert "1 authorized_keys files not read" in done.stderr


def test_an_unreadable_journal_no_freeze_time_or_no_rack_list_is_no_proof(rack):
    rack.box.output("journalctl", "journal", "", rc=1)
    done = rack.box.run(HOST, "before", "identity-scope")
    assert done.returncode == 1 and "sshd journal" in done.stderr
    (rack.box.out / "journalctl.journal.rc").unlink()
    rack.box.config["keys"]["freeze_unix"] = 0
    done = rack.run()
    assert done.returncode == 1 and "no freeze time" in done.stderr
    rack.box.config["keys"]["freeze_unix"] = 1000
    for listed in rack.box.rack_keys.glob("*.keys"):
        listed.unlink()
    done = rack.run()
    assert done.returncode == 1 and "no rack client key list" in done.stderr


def test_the_owners_own_device_is_never_a_rack_key(rack):
    rack.accept(1500, rack.mac_fp, "192.0.2.30", 600)
    rack.box.config["keys"]["owner_devices"] = []
    done = rack.run()
    assert done.returncode == 1
    assert "1 rack key logins since the freeze" in done.stderr


def test_the_export_writes_this_boxs_fingerprints_privately_and_prints_nothing_on_stdout(rack):
    (rack.box.home / ".ssh/id_ed25519.pub").write_text(f"ssh-ed25519 {KNOWN_KEY} owen@box\n")
    (rack.box.home / ".ssh/id_ed25519").write_text("not read: a private key file is never opened\n")
    done = rack.box.run("--export-client-keys", HOST)
    assert done.returncode == 0, done.stderr
    assert done.stdout == ""
    exported = rack.box.evidence / "client-keys" / f"{HOST}.keys"
    assert exported.read_text() == f"{KNOWN_FINGERPRINT} {HOST}\n"
    assert stat.S_IMODE(exported.stat().st_mode) == 0o600


def test_a_journal_read_that_starts_after_the_freeze_is_no_proof(rack):
    # A rack-key login at 1500 lies between the freeze (1000) and the read's start (2000): never read.
    rack.box.config["keys"]["journal_since_unix"] = 2000
    done = rack.run()
    assert done.returncode == 1
    assert "journal_since_unix is later than the freeze" in done.stderr


def test_a_journal_with_no_record_from_before_the_freeze_is_no_proof(rack):
    rack.box.output("journalctl", "coverage", "")
    done = rack.run()
    assert done.returncode == 1
    assert "no record from before the freeze" in done.stderr
    rack.box.output("journalctl", "coverage", "", rc=1)
    done = rack.run()
    assert done.returncode == 1
    assert "journal coverage" in done.stderr


def test_a_privileged_run_reads_only_absolute_authorized_keys_paths():
    default = ["~/.ssh/authorized_keys", "/root/.ssh/authorized_keys"]
    paths, problems = authorized_keys_paths(default, privileged=True)
    assert [str(p) for p in paths] == ["/root/.ssh/authorized_keys"]
    assert len(problems) == 1 and "absolute path" in problems[0]
    named = ["/home/owen/.ssh/authorized_keys", "/root/.ssh/authorized_keys"]
    paths, problems = authorized_keys_paths(named, privileged=True)
    assert [str(p) for p in paths] == named and problems == []
    paths, problems = authorized_keys_paths(default, privileged=False)
    assert len(paths) == 2 and problems == []
    paths, problems = authorized_keys_paths(["owen/authorized_keys"], privileged=False)
    assert paths == [] and "relative path" in problems[0]


def test_a_rack_key_in_a_login_accounts_file_fails_after_with_no_further_file_named(rack):
    # owen's file is found through the password database; keys.authorized_keys_files names nothing.
    assert rack.box.config["keys"]["authorized_keys_files"] == []
    done = rack.run(phase="after")
    assert done.returncode == 1
    assert "1 rack keys still authorized" in done.stderr


def test_a_rack_key_in_roots_file_fails_after(rack):
    rack.authorize(rack.mac)
    (rack.box.root_home / ".ssh").mkdir(parents=True)
    (rack.box.root_home / ".ssh/authorized_keys").write_text(f"ssh-ed25519 {rack.kel} kel-to-root\n")
    done = rack.run(phase="after")
    assert done.returncode == 1
    assert "1 rack keys still authorized" in done.stderr


def test_the_authorized_keys_file_patterns_are_expanded_as_sshd_expands_them(rack):
    rack.authorize(rack.mac)
    keys_dir = rack.box.tmp / "etc-ssh-keys"
    keys_dir.mkdir()
    (keys_dir / "owen-1000").write_text(f"ssh-ed25519 {rack.kel} kel\n")
    rack.box.config["keys"]["authorized_keys_file_patterns"] = [".ssh/authorized_keys", f"{keys_dir}/%u-%U"]
    done = rack.run(phase="after")
    assert done.returncode == 1
    assert "1 rack keys still authorized" in done.stderr


def test_no_login_account_or_one_the_password_database_does_not_know_is_no_proof(rack):
    rack.box.config["keys"]["login_accounts"] = []
    done = rack.run()
    assert done.returncode == 1
    assert "no rack login accounts" in done.stderr
    rack.box.config["keys"]["login_accounts"] = ["owen", "yuki"]
    rack.box.output("getent", "passwd-yuki", "", rc=2)
    done = rack.run()
    assert done.returncode == 1
    assert "does not know" in done.stderr


def test_an_authorized_keys_file_pattern_is_expanded_with_sshds_tokens():
    account = Account("owen", 1000, Path("/home/owen"))
    assert expand_authorized_keys_file(".ssh/authorized_keys", account) == Path("/home/owen/.ssh/authorized_keys")
    assert expand_authorized_keys_file("%h/.ssh/keys", account) == Path("/home/owen/.ssh/keys")
    assert expand_authorized_keys_file("/etc/ssh/keys/%u.%U.%%", account) == Path("/etc/ssh/keys/owen.1000.%")
    assert expand_authorized_keys_file("none", account) is None
    with pytest.raises(ValueError):
        expand_authorized_keys_file("/etc/ssh/keys/%z", account)


def test_an_sshd_listener_outside_the_configured_units_is_no_proof(rack):
    # A second sshd logs to rack-ssh.service: accepts read from sshd.service alone would miss its logins.
    rack.box.process(
        610,
        ["/usr/sbin/sshd", "-D", "-f", "/etc/ssh/sshd_config_rack"],
        name="sshd",
        cgroup="0::/system.slice/rack-ssh.service\n",
    )
    done = rack.run()
    assert done.returncode == 1
    assert "rack-ssh.service, outside keys.sshd_units" in done.stderr
    rack.box.config["keys"]["sshd_units"] = ["sshd.service", "rack-ssh.service"]
    assert rack.run().returncode == 0


def test_with_no_sshd_listener_found_the_journal_source_is_no_proof(rack):
    shutil.rmtree(rack.box.proc / "600")
    done = rack.run()
    assert done.returncode == 1
    assert "no sshd listener found" in done.stderr


def test_an_sshd_listener_whose_cgroup_cannot_be_read_is_no_proof(rack):
    cgroup = rack.box.proc / "600" / "cgroup"
    cgroup.unlink()
    cgroup.mkdir()
    done = rack.run()
    assert done.returncode == 1
    assert "cgroup not read" in done.stderr


def test_sshds_per_connection_processes_are_not_listeners(rack):
    scope = "0::/user.slice/user-1000.slice/session-4.scope\n"
    rack.box.process(620, ["sshd: owen [priv]"], ppid=600, name="sshd", cgroup=scope)
    rack.box.process(621, ["sshd-session: owen@pts/0"], ppid=620, name="sshd-session", cgroup=scope)
    done = rack.run()
    assert done.returncode == 0, done.stderr


def test_the_coverage_probe_reads_the_sshd_units_the_accepts_are_read_from(rack):
    rack.box.config["keys"]["sshd_units"] = ["sshd.service", "sshd@*.service"]
    done = rack.run()
    assert done.returncode == 0, done.stderr
    units = ["-u", "sshd.service", "-u", "sshd@*.service"]
    probe = rack.box.argv_of("journalctl", "coverage")
    assert probe[-len(units) :] == units and "--until" in probe and "--system" not in probe
    assert rack.box.argv_of("journalctl", "journal")[-len(units) :] == units


def test_sshd_is_asked_about_root_and_every_login_account_from_every_rack_connection(rack):
    rack.box.config["keys"]["rack_connections"] = ["addr=192.0.2.40,host=kel", "addr=192.0.2.41,lport=22"]
    done = rack.run()
    assert done.returncode == 0, done.stderr
    assert (rack.box.out / "sshd.calls").read_text().splitlines() == [
        "-T -C user=root,addr=192.0.2.40,host=kel",
        "-T -C user=root,addr=192.0.2.41,lport=22",
        "-T -C user=owen,addr=192.0.2.40,host=kel",
        "-T -C user=owen,addr=192.0.2.41,lport=22",
    ]


def test_an_sshd_that_logs_below_info_for_a_rack_login_is_no_proof(rack):
    # A Match block quiets sshd for owen: a rack key's accept would leave no journal record.
    rack.box.output("sshd", "T-owen", sshd_settings(loglevel="ERROR"))
    done = rack.run()
    assert done.returncode == 1
    assert "LogLevel ERROR" in done.stderr and "user=owen,addr=192.0.2.40,host=kel" in done.stderr
    rack.box.output("sshd", "T-owen", sshd_settings(loglevel="VERBOSE"))
    assert rack.run().returncode == 0


def test_an_authorized_keys_file_sshd_reads_outside_the_patterns_is_no_proof(rack):
    # kel's key sits in a file only sshd's Match block names: the readback never opens it.
    rack.authorize(rack.mac)
    rack.box.output("sshd", "T-owen", sshd_settings(authorizedkeysfile=".ssh/authorized_keys /etc/ssh/rack-keys/%u"))
    done = rack.run(phase="after")
    assert done.returncode == 1
    assert "AuthorizedKeysFile /etc/ssh/rack-keys/%u, not in keys.authorized_keys_file_patterns" in done.stderr
    rack.box.output("sshd", "T-owen", sshd_settings(authorizedkeysfile=".ssh/authorized_keys"))
    assert rack.run(phase="after").returncode == 0
    rack.box.output("sshd", "T-owen", sshd_settings(authorizedkeysfile="none"))
    assert rack.run(phase="after").returncode == 0


def test_keys_from_an_authorized_keys_command_or_a_user_certificate_authority_are_no_proof(rack):
    rack.authorize(rack.mac)
    rack.box.output("sshd", "T-root", sshd_settings(authorizedkeyscommand="/usr/local/bin/rack-keys %u"))
    done = rack.run(phase="after")
    assert done.returncode == 1
    assert "AuthorizedKeysCommand" in done.stderr and "user=root," in done.stderr
    rack.box.output("sshd", "T-root", sshd_settings(trustedusercakeys="/etc/ssh/user_ca.pub"))
    done = rack.run(phase="after")
    assert done.returncode == 1
    assert "TrustedUserCAKeys" in done.stderr


@pytest.mark.parametrize(
    "connections",
    [
        [],
        ["host=kel"],
        ["addr=192.0.2.40,user=root"],
        ["addr=192.0.2.40,lport=ssh"],
        ["addr=192.0.2.40,addr=192.0.2.41"],
        ["addr=192.0.2.40 host=kel"],
        ["addr=192.0.2.40,"],
    ],
)
def test_no_rack_connection_or_one_sshds_test_cannot_take_is_no_proof(rack, connections):
    rack.box.config["keys"]["rack_connections"] = connections
    done = rack.run()
    assert done.returncode == 1
    assert "keys.rack_connections" in done.stderr
    assert not (rack.box.out / "sshd.calls").exists()


def test_a_login_account_name_that_would_add_a_connection_field_is_never_handed_to_sshd(rack):
    rack.box.config["keys"]["login_accounts"] = ["owen", "owen,addr=192.0.2.9"]
    rack.box.account("owen,addr=192.0.2.9", 1001, rack.box.home)
    done = rack.run()
    assert done.returncode == 1
    assert "connection test cannot carry" in done.stderr
    assert not any("192.0.2.9" in call for call in (rack.box.out / "sshd.calls").read_text().splitlines())


def test_sshd_is_asked_with_each_listeners_own_config_file_and_options(rack):
    # A second listener in its own unit, and a third whose argv sshd rewrote into its listener title.
    rack.box.config["keys"]["sshd_units"] = ["sshd.service", "rack-ssh.service"]
    rack.box.process(
        610,
        ["/usr/sbin/sshd", "-D", "-f", "/etc/ssh/sshd_config_rack", "-oLogLevel=VERBOSE"],
        name="sshd",
        cgroup="0::/system.slice/rack-ssh.service\n",
    )
    rack.box.process(
        611,
        ["sshd: /usr/sbin/sshd -De -f/etc/ssh/sshd_config_two [listener] 0 of 10-100 startups"],
        name="sshd",
        cgroup="0::/system.slice/rack-ssh.service\n",
    )
    done = rack.run()
    assert done.returncode == 0, done.stderr
    calls = (rack.box.out / "sshd.calls").read_text().splitlines()
    assert "-T -C user=owen,addr=192.0.2.40,host=kel" in calls
    assert "-T -f /etc/ssh/sshd_config_rack -o LogLevel=VERBOSE -C user=owen,addr=192.0.2.40,host=kel" in calls
    assert "-T -f /etc/ssh/sshd_config_two -C user=root,addr=192.0.2.40,host=kel" in calls
    assert len(calls) == 6
    # Only the rack listener's own configuration quiets sshd: that listener's logins are no proof.
    rack.box.output("sshd", "T-sshd_config_rack", sshd_settings(loglevel="QUIET"))
    done = rack.run()
    assert done.returncode == 1
    assert "LogLevel QUIET" in done.stderr and "with -f /etc/ssh/sshd_config_rack -o LogLevel=VERBOSE" in done.stderr


@pytest.mark.parametrize(
    "title",
    [
        ["sshd: /usr/sbin/sshd -D -o LogLevel QUIET [listener] 0 of 10-100 startups"],
        ["sshd: /usr/sbin/sshd -D -f /etc/ssh/sshd_config_rack"],
        ["/usr/sbin/sshd", "-D", "-Z"],
        ["/usr/sbin/sshd", "-D", "-f"],
    ],
)
def test_a_listener_command_line_not_read_as_sshd_reads_it_is_no_proof(rack, title):
    rack.box.config["keys"]["sshd_units"] = ["sshd.service", "rack-ssh.service"]
    rack.box.process(610, title, name="sshd", cgroup="0::/system.slice/rack-ssh.service\n")
    done = rack.run()
    assert done.returncode == 1
    assert "its -f and -o are unknown" in done.stderr


def test_an_sshd_that_does_not_print_its_settings_is_no_proof(rack):
    # A run that is not root: sshd loads no host key and exits before it prints.
    rack.box.output("sshd", "T-owen", "", rc=255)
    done = rack.run()
    assert done.returncode == 1
    assert "sshd effective configuration" in done.stderr
    (rack.box.out / "sshd.T-owen.rc").unlink()
    rack.box.output("sshd", "T-owen", "port 22\nloglevel INFO\n")
    done = rack.run()
    assert done.returncode == 1
    assert "sshd -T printed no authorizedkeysfile, authorizedkeyscommand, trustedusercakeys" in done.stderr
