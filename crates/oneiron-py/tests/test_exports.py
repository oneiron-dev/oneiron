"""The public export census (ONE-1441 I6 — closed exports).

The package's public surface is exactly ``Oneiron`` and ``OneironError``. The
native class is an implementation detail, and a package that leaked it would be
promising to keep it working.
"""

import inspect
import pathlib
import re

import oneiron

PUBLIC_EXPORTS = {"Oneiron", "OneironError"}

# The four calls of the canonical quickstart, plus the two constructors and the
# actor rebind. Compared as a SET so an accidental extra public method is a
# failing test rather than a silent surface expansion.
_catalog_source = (pathlib.Path(__file__).resolve().parents[2] / "oneiron-remote/src/lib.rs").read_text()
_catalog_match = re.search(r"pub const FACADE_VERB_CATALOG[^=]*=\s*\[([^\]]+)\]", _catalog_source)
assert _catalog_match is not None, "Rust facade catalog is missing"
_VERBS = re.findall(r'"([a-z_]+)"', _catalog_match[1])
assert _VERBS, "Rust facade catalog is empty"
PUBLIC_METHODS = {"open", "connect", "as_actor", *_VERBS}


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
