"""scripts/rack: the key readback (pass 34 15.1 gate C, row K1 part c) at one box.

The stand-in box's sshd journal, live sessions, authorized_keys and the
rack's client key list are fixtures. The rack's keys are kel's; the owner's
device is mac, whose key stays (section 13).
"""

from __future__ import annotations

import stat

import pytest

from rack_fixture import HOST, Box, key_blob

from rack.readback.keys import authorized_keys_paths, fingerprint, parse_authorized_keys

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
