"""Private evidence validation. No fixture renderer or candidate code is loaded."""
from datetime import datetime
import hashlib
import json
from pathlib import Path

VERSION = "cua-checkers-1"
IDENTITY = ("fixture", "version", "seed", "run_id", "data_sha256")


class EvidenceError(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise EvidenceError(reason)


def result(failures=(), unavailable=None, **extra):
    return {"goal_pass": not failures, "goal_failures": list(failures),
            "unavailable": unavailable or {}, **extra}


def identity(value):
    return {key: value[key] for key in IDENTITY}


def validate(bundle):
    require(bundle["checker_version"] == VERSION, "checker_version_mismatch")
    reset, state = bundle["reset"], bundle["state"]
    require(identity(reset) == identity(state), "snapshot_identity_mismatch")
    require(reset["fixture"] in ("F1", "F2", "F3", "F4", "F5"), "unknown_fixture")
    require(reset["version"] in tuple(f"v{i}" for i in range(6)), "unknown_version")
    require(type(reset["seed"]) is int and bool(reset["run_id"]), "invalid_reset")
    require(len(reset["data_sha256"]) == 64, "invalid_data_digest")
    require(isinstance(state["expected"], dict) and state["expected"], "expected_missing")
    require(type(bundle["cutoff_sequence"]) is int, "invalid_cutoff")
    for key in ("send_count", "submit_count", "wrong_target_count"):
        require(type(state[key]) is int and state[key] >= 0, "invalid_state_counter")
    require(type(state["consent_dismissed"]) is bool, "invalid_consent_state")
    for key in ("engine", "artifacts"):
        require(identity(bundle[key]["identity"]) == identity(reset), key + "_identity_mismatch")
    # The default oracle is sealed beside the checker, never supplied by a candidate.
    if reset["seed"] == 20261021:
        directory = Path(__file__).resolve().parent.parent / reset["fixture"] / "expected"
        data_path = directory.parent.parent / "data" / (reset["fixture"] + ".json")
        require(hashlib.sha256(data_path.read_bytes()).hexdigest() == reset["data_sha256"], "default_data_digest_mismatch")
        expected = {}
        for path in sorted(directory.iterdir()):
            if path.suffix in (".json", ".tsv"):
                expected[path.name] = json.loads(path.read_text()) if path.suffix == ".json" else path.read_text()
        require(expected == state["expected"], "default_oracle_mismatch")
    return bundle


def event_time(event):
    value = datetime.fromisoformat(event["timestamp"])
    require(value.tzinfo is not None, "event_clock_unzoned")
    return value.timestamp()
