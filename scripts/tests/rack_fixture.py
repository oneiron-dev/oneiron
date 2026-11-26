"""A stand-in box for the rack harness tests (scripts/rack): stub programs, a fake /proc, a config.

Each read-only program the harness calls (findmnt, ss, systemctl, journalctl,
getent, sshd, oneiron) is a small shell stub first on PATH. It prints the file
`out/<program>.<key>` and exits with `out/<program>.<key>.rc` when that file
exists, where the key is picked from its arguments; it writes the names of
its environment to `out/<program>.<key>.env` and its arguments, one a line,
to `out/<program>.<key>.argv`. The harness passes only PATH,
HOME and LC_ALL to a child (and to `systemctl --user` the user's bus
variables, without which the stub fails as systemctl does), so the stubs
carry their fixture paths inside them. Each run has the login session's
XDG_RUNTIME_DIR (`Box.session_env`).
"""

from __future__ import annotations

import base64
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ENTRY = ROOT / "scripts/rack/workflow_check.py"
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))
HOST = "testhost"
# The key readback's freeze: two hours from now, so a listener of the fake /proc (it starts one
# hour from now) started after every file a test writes and before the freeze. Tests name times
# relative to it.
FREEZE = int(time.time()) + 7200

_STUBS = {
    "findmnt": """case " $* " in
  *" -T "*) key=fstype ;;
  *) key=sshfs ;;
esac""",
    "ss": """case "$*" in
  *dport*) key=dport ;;
  *) key=sport ;;
esac""",
    "systemctl": """key=units
[ -n "${XDG_RUNTIME_DIR:-}${DBUS_SESSION_BUS_ADDRESS:-}" ] || { echo "Failed to connect to bus" >&2; exit 1; }""",
    "journalctl": """case " $* " in
  *" --until "*) key=coverage ;;
  *) key=journal ;;
esac""",
    "getent": 'key="$1-$2"',
}

# A stand-in sshd. `sshd -T [-f <dir>/<file>] ... -C user=<name>,...` prints on stdout the most specific
# of out/sshd.T-<file>-<name>, T-<file>, T-<name> and T that exists; `sshd -T -dd ...` prints on stderr
# the same pick of out/sshd.files*, the configuration files sshd says it read. Each exits with the
# pick's .rc file. Every call's arguments are appended, one call a line, to out/sshd.calls. When
# out/sshd.edit-on-settings names a path, each settings call (`-C`) dates that entry (not what it
# links to) a day ahead: a change to the configuration while the readback probes it.
_SSHD_STUB = """import pathlib, sys
out = pathlib.Path(@OUT@)
args = sys.argv[1:]
with open(out / "sshd.calls", "a") as log:
    log.write(" ".join(args) + "\\n")
cfg = spec = ""
for prev, arg in zip(args, args[1:]):
    if prev == "-f":
        cfg = pathlib.Path(arg).name
    if prev == "-C":
        spec = arg
user = spec[len("user="):].split(",", 1)[0] if spec.startswith("user=") else ""
kind = "files" if "-dd" in args else "T"
edit = out / "sshd.edit-on-settings"
if kind == "T" and edit.exists():
    import os, time
    ahead = time.time() + 86400
    os.utime(edit.read_text().strip(), (ahead, ahead), follow_symlinks=False)
key = kind
for k in (kind + "-" + user, kind + "-" + cfg, kind + "-" + cfg + "-" + user):
    if (out / ("sshd." + k)).exists():
        key = k
picked = out / ("sshd." + key)
text = picked.read_text() if picked.exists() else ""
(sys.stderr if kind == "files" else sys.stdout).write(text)
rc = out / ("sshd." + key + ".rc")
sys.exit(int(rc.read_text()) if rc.exists() else 0)
"""


def sshd_settings(**changed: str) -> str:
    """`sshd -T` output for one login: sshd's defaults, with `changed` keywords replaced."""
    settings = {
        "loglevel": "INFO",
        "authorizedkeysfile": ".ssh/authorized_keys .ssh/authorized_keys2",
        "authorizedkeyscommand": "none",
        "authorizedkeyscommanduser": "none",
        "trustedusercakeys": "none",
        **changed,
    }
    return "port 22\n" + "".join(f"{name} {value}\n" for name, value in settings.items()) + "pubkeyauthentication yes\n"


def sshd_files(etc: Path, *extra: str) -> str:
    """`sshd -T -dd` stderr naming the files read: etc/sshd_config, its Include and etc/sshd_config.d/*.conf."""
    lines = [
        "debug1: sshd version OpenSSH_10.6, OpenSSL 3.6.5",
        f"debug2: load_server_config: filename {etc}/sshd_config",
        f"debug2: load_server_config: done config len = 29",
        f"debug2: {etc}/sshd_config line 1: new include {etc}/sshd_config.d/*.conf",
    ]
    lines += [f"debug2: load_server_config: filename {path}" for path in sorted((etc / "sshd_config.d").glob("*.conf"))]
    return "\n".join([*lines, *extra]) + "\n"


TCP_HEADER = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"
UNIX_HEADER = "Num       RefCount Protocol Flags    Type St Inode Path"


_ONEIRON_STUB = """import json, os, pathlib, subprocess, sys
out = pathlib.Path(@OUT@)
argv = sys.argv[1:]
verb = argv[argv.index("call") + 1]
body = json.loads(sys.stdin.read() or "null")
if (out / "oneiron.runs_curl").exists():
    # As `oneiron api` does: the host's curl from PATH, -q first.
    base_url = argv[argv.index("--base-url") + 1]
    curl = subprocess.run(["curl", "-q", "--silent", "--url", base_url + "/api/verbs/" + verb])
    if curl.returncode != 0:
        sys.exit(curl.returncode)
with open(out / "oneiron.calls.jsonl", "a") as log:
    log.write(json.dumps({"verb": verb, "argv": argv, "body": body, "env": sorted(os.environ)}) + "\\n")
listed = out / ("oneiron." + verb + ".json")
if not listed.exists():
    sys.stdout.write(json.dumps({"error": {"code": "NOT_FOUND", "message": "no fixture"}}))
    sys.exit(22)
answers = json.loads(listed.read_text())
counter = out / ("oneiron." + verb + ".n")
n = int(counter.read_text()) if counter.exists() else 0
counter.write_text(str(n + 1))
answer = answers[min(n, len(answers) - 1)]
if answer.get("hang"):
    # An issuer that takes the request and never answers: a body staged in TMPDIR and a
    # curl stand-in in this process group, both left for the caller's deadline to end.
    import subprocess, time
    (pathlib.Path(os.environ["TMPDIR"]) / "oneiron-api-test.body").write_text(json.dumps(body))
    helper = subprocess.Popen(["sleep", "60"])
    (out / "oneiron.hang.json").write_text(json.dumps({"tmpdir": os.environ["TMPDIR"], "helper": helper.pid}))
    time.sleep(60)
sys.stdout.write(json.dumps(answer["body"]))
sys.exit(answer.get("rc", 0))
"""


def this_box() -> str:
    return socket.gethostname().split(".", 1)[0]


def key_blob() -> str:
    """A fresh ed25519-shaped public key body (random; only its hash matters)."""
    raw = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + os.urandom(32)
    return base64.b64encode(raw).decode()


class Box:
    def __init__(self, tmp: Path):
        self.tmp = tmp
        self.bin = tmp / "bin"
        self.out = tmp / "out"
        self.proc = tmp / "proc"
        self.home = tmp / "home"
        self.evidence = tmp / "evidence"
        self.rack_keys = tmp / "rack-keys"
        # Unix socket paths are short: keep this one out of the deep tmp path.
        self.sockets = Path(tempfile.mkdtemp(prefix="rk"))
        for directory in (self.bin, self.out, self.proc, self.home / ".ssh", self.rack_keys):
            directory.mkdir(parents=True, exist_ok=True)
        for program, pick in _STUBS.items():
            self.stub(program, pick)
        sshd = self.bin / "sshd"
        sshd.write_text(f"#!{sys.executable}\n" + _SSHD_STUB.replace("@OUT@", repr(str(self.out))))
        sshd.chmod(0o755)
        # sshd as the readback reads it, for every login from every rack connection.
        self.output("sshd", "T", sshd_settings())
        # The configuration files sshd reads: sshd_config, which Includes sshd_config.d/*.conf.
        self.sshd_etc = tmp / "etc-sshd"
        (self.sshd_etc / "sshd_config.d").mkdir(parents=True)
        (self.sshd_etc / "sshd_config").write_text("Include sshd_config.d/*.conf\n")
        (self.sshd_etc / "sshd_config.d" / "10-rack.conf").write_text("LogLevel INFO\n")
        self.output("sshd", "files", sshd_files(self.sshd_etc))
        self.output("findmnt", "fstype", "ext4\n")
        # The sshd journal reaches back before the fixtures' freeze.
        self.output("journalctl", "coverage", f"{FREEZE - 500}.000000 box sshd[600]: Server listening on :: port 22.\n")
        # The fake /proc is a proc mount that hides no process; every process in it started an hour
        # from now (boot time plus a starttime of 0), after any file a test writes.
        self.proc_mount("rw")
        self.booted(3600)
        # sshd's listener, in the unit its journal is read from.
        self.process(600, ["sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups"], name="sshd", cgroup="0::/system.slice/sshd.service\n")
        # The password database: root, and owen, the rack's login account here.
        self.root_home = tmp / "roothome"
        self.account("root", 0, self.root_home)
        self.account("owen", 1000, self.home)
        self.ssh_system_config = tmp / "etc-ssh" / "ssh_config"
        # The login session's variables every run gets (an ssh login sets XDG_RUNTIME_DIR).
        self.session_env: dict[str, str] = {"XDG_RUNTIME_DIR": str(tmp / "run")}
        self.config: dict = {
            "hosts": {HOST: {"box_names": [this_box()]}},
            "evidence_dir": str(self.evidence),
            "proc_root": str(self.proc),
            "drain": {
                "tool_process_patterns": ["/usr/local/bin/gpu", "okc_then_render.sh"],
                "tool_unit_patterns": ["fleet-*"],
                "control_socket_globs": [f"{self.sockets}/cm-*"],
                "rack_addresses": ["192.0.2.0/24"],
                "ssh_system_config": str(self.ssh_system_config),
            },
            "keys": {
                "login_accounts": ["owen"],
                "authorized_keys_files": [],
                "client_key_globs": [str(self.home / ".ssh/*.pub")],
                "rack_client_keys_dir": str(self.rack_keys),
                "owner_devices": ["mac"],
                "rack_connections": ["addr=192.0.2.40,host=kel"],
                "freeze_unix": FREEZE,
            },
        }

    def stub(self, program: str, pick: str) -> None:
        path = self.bin / program
        path.write_text(
            "#!/bin/sh\n"
            f"{pick}\n"
            f'out="{self.out}/{program}.$key"\n'
            '[ -f "$out" ] && cat "$out"\n'
            'env | sed "s/=.*//" > "$out.env"\n'
            'printf "%s\\n" "$@" > "$out.argv"\n'
            'rc=0; [ -f "$out.rc" ] && rc=$(cat "$out.rc")\n'
            "exit $rc\n"
        )
        path.chmod(0o755)

    def oneiron(self, answers: dict[str, list[dict]], runs_curl: bool = False) -> None:
        """A stand-in `oneiron`: each verb answers its list in turn (the last repeats).

        An answer is {"body": <JSON printed on stdout>, "rc": <exit, default 0>}.
        Every call is logged to out/oneiron.calls.jsonl with its argv, body and
        the names of the environment variables it was given. With `runs_curl`
        it first runs `curl -q --silent --url <base url>/...` from its PATH, as
        `oneiron api` does (see `curl`).
        """
        for verb, listed in answers.items():
            (self.out / f"oneiron.{verb}.json").write_text(json.dumps(listed))
            (self.out / f"oneiron.{verb}.n").unlink(missing_ok=True)
        marker = self.out / "oneiron.runs_curl"
        if runs_curl:
            marker.write_text("")
        else:
            marker.unlink(missing_ok=True)
        path = self.bin / "oneiron"
        path.write_text(f"#!{sys.executable}\n" + _ONEIRON_STUB.replace("@OUT@", repr(str(self.out))))
        path.chmod(0o755)

    def curl(self) -> None:
        """A stand-in host `curl` that answers 0 and logs each argv, a JSON list a line, to out/curl.argv.jsonl."""
        path = self.bin / "curl"
        path.write_text(
            f"#!{sys.executable}\n"
            "import json, sys\n"
            f"with open({str(self.out / 'curl.argv.jsonl')!r}, 'a') as log:\n"
            "    log.write(json.dumps(sys.argv[1:]) + '\\n')\n"
        )
        path.chmod(0o755)

    def curl_calls(self) -> list[list[str]]:
        log = self.out / "curl.argv.jsonl"
        return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []

    def proc_mount(self, super_options: str, at: Path | None = None) -> None:
        """The fake /proc's own mount table line: a proc mount at `at` (the fake /proc) with these options."""
        (self.proc / "self").mkdir(exist_ok=True)
        point = os.path.realpath(at or self.proc).replace(" ", "\\040")
        (self.proc / "self" / "mountinfo").write_text(
            f"22 1 0:5 / / rw,relatime shared:1 - ext4 /dev/root rw\n"
            f"25 22 0:21 / {point} rw,nosuid,nodev,noexec,relatime shared:12 - proc proc {super_options}\n"
        )

    def booted(self, from_now_secs: int) -> None:
        """The fake /proc/stat's boot time, `from_now_secs` from now: each process starts then."""
        (self.proc / "stat").write_text(f"cpu  0 0 0 0\nbtime {int(time.time()) + from_now_secs}\nprocesses 1\n")

    def account(self, name: str, uid: int, home: Path) -> None:
        """A password database entry `getent passwd <name>` prints."""
        self.output("getent", f"passwd-{name}", f"{name}:x:{uid}:{uid}::{home}:/bin/sh\n")

    def argv_of(self, program: str, key: str) -> list[str]:
        """The arguments the stub `program` was last started with under `key`."""
        return (self.out / f"{program}.{key}.argv").read_text().splitlines()

    def calls(self) -> list[dict]:
        log = self.out / "oneiron.calls.jsonl"
        if not log.exists():
            return []
        return [json.loads(line) for line in log.read_text().splitlines()]

    def output(self, program: str, key: str, text: str, rc: int = 0) -> None:
        (self.out / f"{program}.{key}").write_text(text)
        if rc:
            (self.out / f"{program}.{key}.rc").write_text(str(rc))

    def process(
        self,
        pid: int,
        argv: list[str],
        ppid: int = 1,
        listen_tcp: tuple[int, ...] = (),
        listen_unix: tuple[int, ...] = (),
        connected: tuple[int, ...] = (),
        fds_readable: bool = True,
        name: str = "",
        cgroup: str = "0::/user.slice/user-1000.slice/session-1.scope\n",
    ) -> None:
        """A process in the fake /proc: its argv, parent, open sockets (by inode) and its network tables.

        `listen_tcp` and `listen_unix` are listening sockets it holds, `connected` other sockets.
        With `fds_readable` false its fd directory cannot be listed, as another user's is to a non-root run.
        `name` is its status Name (default: its program's file name), `cgroup` its /proc/<pid>/cgroup.
        """
        entry = self.proc / str(pid)
        entry.mkdir()
        (entry / "cmdline").write_bytes(b"\0".join(a.encode() for a in argv) + b"\0")
        (entry / "status").write_text(f"Name:\t{name or Path(argv[0]).name}\nPPid:\t{ppid}\n")
        # /proc/<pid>/stat: starttime (field 22) is 0 ticks after boot.
        (entry / "stat").write_text(f"{pid} ({name or Path(argv[0]).name}) S {ppid} " + "0 " * 17 + "0 0 0\n")
        (entry / "cgroup").write_text(cgroup)
        net = entry / "net"
        net.mkdir()
        tcp = [TCP_HEADER]
        tcp += [
            f"   {n}: 0100007F:206D 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 {inode} 1 0 100 0 0 10 0"
            for n, inode in enumerate(listen_tcp)
        ]
        tcp += [
            f"   {n + 50}: 0100007F:C350 0100007F:0016 01 00000000:00000000 00:00000000 00000000  1000        0 {inode} 1 0 20 4 30 10 -1"
            for n, inode in enumerate(connected)
        ]
        (net / "tcp").write_text("\n".join(tcp) + "\n")
        (net / "tcp6").write_text(TCP_HEADER + "\n")
        unix = [UNIX_HEADER] + [f"0000000000000000: 00000002 00000000 00010000 0001 01 {inode} {self.sockets}/cm-{inode}" for inode in listen_unix]
        (net / "unix").write_text("\n".join(unix) + "\n")
        if not fds_readable:
            (entry / "fd").write_text("not a directory: listing it fails\n")
            return
        (entry / "fd").mkdir()
        for n, inode in enumerate((*listen_tcp, *listen_unix, *connected)):
            os.symlink(f"socket:[{inode}]", entry / "fd" / str(n + 3))
        os.symlink("/dev/null", entry / "fd" / "0")

    def socket(self, name: str) -> None:
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(self.sockets / name))
        listener.close()

    def run(self, *words: str, env: dict | None = None) -> subprocess.CompletedProcess:
        config = self.tmp / "rack.json"
        config.write_text(json.dumps(self.config))
        full_env = {
            "PATH": f"{self.bin}:{os.environ.get('PATH', '/usr/bin:/bin')}",
            "HOME": str(self.home),
            "LC_ALL": "C",
            **self.session_env,
        }
        if env:
            full_env.update(env)
        return subprocess.run(
            [sys.executable, "-I", str(ENTRY), "--config", str(config), *words],
            capture_output=True,
            text=True,
            env=full_env,
            timeout=120,
        )

    def evidence_files(self) -> list[Path]:
        return sorted(self.evidence.glob("*/*.json"))

    def env_of(self, program: str, key: str) -> set[str]:
        """The environment names the stub `program` was last started with under `key`."""
        return set((self.out / f"{program}.{key}.env").read_text().split())
