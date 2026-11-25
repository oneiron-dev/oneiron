"""The rack harness's inputs: one JSON file the Orchestrator writes.

Every value a check reads comes from this file, with the defaults below.
No host, unit name, address or time bound is a constant inside a check
(policy as settings). A value of the wrong type is a ConfigError, which the
entry answers with exit 2 and never with a PASS.
"""

from __future__ import annotations

import copy
import json
import os
import re
from pathlib import Path
from typing import Any

PHASES = ("before", "staged", "after")

# An Oneiron entity id (a machine, a project, a check-in): 32 lower hex.
ENTITY_ID = re.compile(r"^[0-9a-f]{32}$")

DEFAULTS: dict[str, Any] = {
    # host -> {"box_names": [...], "issuer": {...}}; a host's issuer keys
    # override the rack-wide "issuer" below.
    "hosts": {},
    "issuer": {
        "base_url": "",
        "secret_env": "ONEIRON_SECRET",
        "binding_key_env": "ONEIRON_BINDING_KEY",
        # A loopback issuer URL is refused unless the box itself serves the
        # issuer: on any other box it would be a forward to somewhere else.
        "loopback_allowed": False,
    },
    "oneiron_bin": "oneiron",
    "command_timeout_secs": 15,
    # The box's process table (the drain and the key readbacks read it).
    "proc_root": "/proc",
    # Empty: $XDG_STATE_HOME/oneiron-rack, else ~/.local/state/oneiron-rack.
    "evidence_dir": "",
    "canary": {
        # Machine ids (32 hex) the machine canaries must find answering.
        "target_machines": [],
        # The machine (32 hex) fleet-exec orders its probe on, and the offer it charges.
        "exec_machine": "",
        "offer": "",
        "probe": {
            "template": "probe",
            "commit": "",
            "contract_path": "",
            "contract_sha256": "",
            "entry": "",
            "args": [],
            "cpu_threads": 1,
            "memory_mib": 512,
            "disk_mib": 64,
            "maximum_secs": 300,
            # A project id (32 hex) lets a compute.pin standing grant cover the pin.
            "project": "",
            # The owner's answered check-in for this pin, once it asked.
            "check_in_ref": "",
        },
        "order_deadline_secs": 900,
        "poll_secs": 5,
        "model_list_url": "",
    },
    "drain": {
        "tool_process_patterns": [],
        "tool_unit_patterns": [],
        "ignore_mounts": [],
        "rack_addresses": [],
        "control_socket_globs": ["~/.ssh/cm-*", "~/.ssh/sockets/*"],
        "transfer_programs": ["rsync", "scp", "sftp"],
        # The system ssh client configuration (an ssh process without -F reads it after ~/.ssh/config).
        "ssh_system_config": "/etc/ssh/ssh_config",
    },
    "keys": {
        # The accounts the rack logs in to this box as (root's files are always read too).
        "login_accounts": [],
        # sshd's AuthorizedKeysFile: %h the account's home, %u its name, %U its uid, %% a
        # percent sign; a relative entry is under the home. sshd's default is below.
        "authorized_keys_file_patterns": [".ssh/authorized_keys", ".ssh/authorized_keys2"],
        # Further files to read (absolute; a privileged run refuses a `~` entry).
        "authorized_keys_files": [],
        "client_key_globs": ["~/.ssh/*.pub"],
        "rack_client_keys_dir": "",
        "owner_devices": [],
        "sshd_units": ["sshd.service"],
        # Each rack machine's connection as this box's sshd sees it: `addr=<address>`, then
        # host=, laddr=, lport= or rdomain= when sshd_config matches on them. The readback
        # asks `sshd -T -C user=<account>,<connection>` for root and every login account.
        "rack_connections": [],
        "sshd_program": "sshd",
        # AuthorizedKeysCommand lines (exactly as `sshd -T` prints them) whose answer the readback
        # reads by running the command itself, as root, for each account (%u %U %h %% only);
        # sshd taking keys from any other command is no proof. The default is Arch's userdb drop-in.
        "authorized_keys_commands": ["/usr/bin/userdbctl ssh-authorized-keys %u"],
        "freeze_unix": 0,
        "journal_since_unix": 0,
    },
}


class ConfigError(Exception):
    """The configuration cannot be used; the entry exits 2."""


def _merge(base: dict[str, Any], over: dict[str, Any], path: str) -> dict[str, Any]:
    out = copy.deepcopy(base)
    for key, value in over.items():
        where = f"{path}.{key}" if path else key
        if key not in base:
            raise ConfigError(f"unknown key {where}")
        if isinstance(base[key], dict) and base[key] and not isinstance(value, dict):
            raise ConfigError(f"{where} must be an object")
        if isinstance(base[key], dict) and base[key]:
            out[key] = _merge(base[key], value, where)
        elif isinstance(base[key], bool):
            if not isinstance(value, bool):
                raise ConfigError(f"{where} must be true or false")
            out[key] = value
        elif isinstance(base[key], int):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ConfigError(f"{where} must be a whole number of at least 0")
            out[key] = value
        elif isinstance(base[key], str):
            if not isinstance(value, str):
                raise ConfigError(f"{where} must be a string")
            out[key] = value
        elif isinstance(base[key], list):
            if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
                raise ConfigError(f"{where} must be a list of strings")
            out[key] = value
        else:
            out[key] = value
    return out


class RackConfig:
    """The merged configuration, with typed reads."""

    def __init__(self, raw: dict[str, Any]):
        self.raw = raw

    @classmethod
    def load(cls, path: Path | None) -> RackConfig:
        over: dict[str, Any] = {}
        if path is not None:
            try:
                over = json.loads(Path(path).read_text(encoding="utf-8"))
            except OSError as error:
                raise ConfigError(f"config not read: {error.strerror}") from None
            except json.JSONDecodeError as error:
                raise ConfigError(f"config is not JSON: line {error.lineno}") from None
            if not isinstance(over, dict):
                raise ConfigError("config must be a JSON object")
        merged = _merge(DEFAULTS, over, "")
        if not isinstance(merged["hosts"], dict):
            raise ConfigError("hosts must be an object")
        for host, row in merged["hosts"].items():
            if not isinstance(row, dict):
                raise ConfigError(f"hosts.{host} must be an object")
            for key in row:
                if key not in ("box_names", "issuer"):
                    raise ConfigError(f"unknown key hosts.{host}.{key}")
            names = row.get("box_names", [host])
            if not isinstance(names, list) or not all(isinstance(n, str) and n for n in names):
                raise ConfigError(f"hosts.{host}.box_names must be a list of names")
            issuer = row.get("issuer", {})
            if not isinstance(issuer, dict):
                raise ConfigError(f"hosts.{host}.issuer must be an object")
            row["box_names"] = names
            row["issuer"] = _merge(merged["issuer"], issuer, f"hosts.{host}.issuer")
        canary = merged["canary"]
        ids = [("canary.target_machines", m) for m in canary["target_machines"]]
        ids += [("canary.exec_machine", canary["exec_machine"])]
        ids += [("canary.probe.project", canary["probe"]["project"])]
        ids += [("canary.probe.check_in_ref", canary["probe"]["check_in_ref"])]
        for where, value in ids:
            if value and not ENTITY_ID.match(value):
                raise ConfigError(f"{where} must be a 32-hex id")
        return cls(merged)

    def section(self, name: str) -> dict[str, Any]:
        return self.raw[name]

    def hosts(self) -> list[str]:
        return sorted(self.raw["hosts"])

    def box_names(self, host: str) -> list[str]:
        return self.raw["hosts"][host]["box_names"]

    def issuer(self, host: str) -> dict[str, Any]:
        return self.raw["hosts"][host]["issuer"]

    @property
    def oneiron_bin(self) -> str:
        return self.raw["oneiron_bin"]

    @property
    def command_timeout_secs(self) -> int:
        return max(1, self.raw["command_timeout_secs"])

    @property
    def proc_root(self) -> Path:
        return expand(self.raw["proc_root"])

    def evidence_root(self) -> Path:
        named = self.raw["evidence_dir"]
        if named:
            return expand(named)
        state = os.environ.get("XDG_STATE_HOME")
        base = Path(state) if state else Path.home() / ".local" / "state"
        return base / "oneiron-rack"


def expand(path: str) -> Path:
    """A configured path with a leading ~ taken as the running user's home."""
    return Path(os.path.expanduser(path))
