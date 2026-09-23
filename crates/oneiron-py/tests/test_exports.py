"""The public export census (ONE-1441 I6 — closed exports).

The package's public surface is exactly ``Oneiron`` and ``OneironError``. The
native class is an implementation detail, and a package that leaked it would be
promising to keep it working.
"""

import inspect
import pathlib
import json

import oneiron

PUBLIC_EXPORTS = {"Oneiron", "OneironError"}

# The facade catalog has top-level verbs and generated tasks/rooms families.
# Check both projections exactly, without flattening away dotted names.
_manifest = json.loads((pathlib.Path(__file__).resolve().parents[3] / "scripts/sdk/agent-verbs.json").read_text())
_VERBS = [row["name"] for row in _manifest["verbs"] if row.get("context", "memory") == "memory"]
assert _VERBS, "SDK manifest is empty"
PUBLIC_METHODS = {"open", "connect", "as_actor", *(verb for verb in _VERBS if "." not in verb)}


def test_all_is_the_closed_catalog() -> None:
    assert set(oneiron.__all__) == PUBLIC_EXPORTS


def test_native_client_is_not_exported() -> None:
    # Pinned by the blueprint by name: the wrapper holds the native class and
    # never re-exports it.
    assert not hasattr(oneiron, "NativeClient")
    for leaked in ("VaultBridge", "ActorScopedVault", "NapiVault", "Vault"):
        assert not hasattr(oneiron, leaked)


def test_oneiron_has_exactly_the_declared_verbs() -> None:
    public = {
        name
        for name, _ in inspect.getmembers(oneiron.Oneiron, callable)
        if not name.startswith("_")
    }
    assert public == PUBLIC_METHODS
    # Construction wraps a handle but does not touch the native backend.
    instance = oneiron.Oneiron(object())
    families = {verb.split(".")[0] for verb in _VERBS if "." in verb}
    assert {name for name in vars(instance) if not name.startswith("_")} == families
    for family in families:
        methods = {
            name
            for name, _ in inspect.getmembers(getattr(instance, family), callable)
            if not name.startswith("_")
        }
        assert methods == {verb.split(".")[1] for verb in _VERBS if verb.startswith(family + ".")}


def test_error_carries_the_contract_fields() -> None:
    error = oneiron.OneironError("BAD_REQUEST", "nope", ["fix it"])
    assert isinstance(error, RuntimeError)
    assert error.code == "BAD_REQUEST"
    assert error.message == "nope"
    assert error.suggestions == ("fix it",)


def test_package_is_typed() -> None:
    import pathlib

    root = pathlib.Path(oneiron.__file__).parent
    assert (root / "py.typed").exists()
    assert (root / "__init__.pyi").exists()
