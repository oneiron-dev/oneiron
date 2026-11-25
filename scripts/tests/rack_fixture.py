"""A stand-in box for the rack harness tests (scripts/rack): stub programs, a fake /proc, a config.

Each read-only program the harness calls (findmnt, ss, systemctl, journalctl,
oneiron) is a small shell stub first on PATH. It prints the file
`out/<program>.<key>` and exits with `out/<program>.<key>.rc` when that file
exists, where the key is picked from its arguments. The harness passes only
PATH, HOME and LC_ALL to a child, so the stubs carry their fixture paths
inside them.
"""

from __future__ import annotations

import base64
import json
import os
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ENTRY = ROOT / "scripts/rack/workflow_check.py"
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))
HOST = "testhost"

_STUBS = {
    "findmnt": """case " $* " in
  *" -T "*) key=fstype ;;
  *) key=sshfs ;;
esac""",
    "ss": """case "$*" in
  *dport*) key=dport ;;
  *) key=sport ;;
esac""",
    "systemctl": "key=units",
    "journalctl": "key=journal",
}


_ONEIRON_STUB = """import json, os, pathlib, sys
out = pathlib.Path(@OUT@)
argv = sys.argv[1:]
verb = argv[argv.index("call") + 1]
body = json.loads(sys.stdin.read() or "null")
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
        self.output("findmnt", "fstype", "ext4\n")
        self.config: dict = {
            "hosts": {HOST: {"box_names": [this_box()]}},
            "evidence_dir": str(self.evidence),
            "drain": {
                "proc_root": str(self.proc),
                "tool_process_patterns": ["/usr/local/bin/gpu", "okc_then_render.sh"],
                "tool_unit_patterns": ["fleet-*"],
                "control_socket_globs": [f"{self.sockets}/cm-*"],
                "rack_addresses": ["192.0.2.0/24"],
            },
            "keys": {
                "authorized_keys_files": [str(self.home / ".ssh/authorized_keys")],
                "client_key_globs": [str(self.home / ".ssh/*.pub")],
                "rack_client_keys_dir": str(self.rack_keys),
                "owner_devices": ["mac"],
                "freeze_unix": 1000,
            },
        }

    def stub(self, program: str, pick: str) -> None:
        path = self.bin / program
        path.write_text(
            "#!/bin/sh\n"
            f"{pick}\n"
            f'out="{self.out}/{program}.$key"\n'
            '[ -f "$out" ] && cat "$out"\n'
            'rc=0; [ -f "$out.rc" ] && rc=$(cat "$out.rc")\n'
            "exit $rc\n"
        )
        path.chmod(0o755)

    def oneiron(self, answers: dict[str, list[dict]]) -> None:
        """A stand-in `oneiron`: each verb answers its list in turn (the last repeats).

        An answer is {"body": <JSON printed on stdout>, "rc": <exit, default 0>}.
        Every call is logged to out/oneiron.calls.jsonl with its argv, body and
        the names of the environment variables it was given.
        """
        for verb, listed in answers.items():
            (self.out / f"oneiron.{verb}.json").write_text(json.dumps(listed))
            (self.out / f"oneiron.{verb}.n").unlink(missing_ok=True)
        path = self.bin / "oneiron"
        path.write_text(f"#!{sys.executable}\n" + _ONEIRON_STUB.replace("@OUT@", repr(str(self.out))))
        path.chmod(0o755)

    def calls(self) -> list[dict]:
        log = self.out / "oneiron.calls.jsonl"
        if not log.exists():
            return []
        return [json.loads(line) for line in log.read_text().splitlines()]

    def output(self, program: str, key: str, text: str, rc: int = 0) -> None:
        (self.out / f"{program}.{key}").write_text(text)
        if rc:
            (self.out / f"{program}.{key}.rc").write_text(str(rc))

    def process(self, pid: int, argv: list[str], ppid: int = 1) -> None:
        entry = self.proc / str(pid)
        entry.mkdir()
        (entry / "cmdline").write_bytes(b"\0".join(a.encode() for a in argv) + b"\0")
        (entry / "status").write_text(f"Name:\t{Path(argv[0]).name}\nPPid:\t{ppid}\n")

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
