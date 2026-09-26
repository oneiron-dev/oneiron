"""Guard the one-way document-engine dependency (ARCH-0075 §2)."""

from pathlib import Path
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]


def manifest(crate):
    with (ROOT / "crates" / crate / "Cargo.toml").open("rb") as f:
        return tomllib.load(f)


def dependencies(data, workspace_dependencies):
    """Only actual Cargo dependency tables, including target/dev/build edges."""
    result = set()
    for table in (data, *data.get("target", {}).values()):
        for kind in ("dependencies", "dev-dependencies", "build-dependencies"):
            for key, spec in table.get(kind, {}).items():
                if isinstance(spec, dict):
                    if spec.get("workspace"):
                        inherited = workspace_dependencies.get(key, {})
                        if isinstance(inherited, dict):
                            result.add(spec.get("package", inherited.get("package", key)))
                            continue
                    result.add(spec.get("package", key))
                else:
                    result.add(key)
    return result


class DoceditDirectionTest(unittest.TestCase):
    def test_engine_consumes_docedit_and_docedit_cannot_reach_engine(self):
        with (ROOT / "Cargo.toml").open("rb") as f:
            root_data = tomllib.load(f)
        workspace = root_data["workspace"]
        workspace_dependencies = root_data.get("workspace", {}).get("dependencies", {})
        self.assertIn("oneiron-docedit", dependencies(manifest("oneiron"), workspace_dependencies))
        excluded = {
            path.resolve()
            for pattern in workspace.get("exclude", [])
            for path in ROOT.glob(pattern)
        }
        members = {}
        for pattern in workspace["members"]:
            for directory in ROOT.glob(pattern):
                if directory.resolve() in excluded:
                    continue
                cargo_toml = directory / "Cargo.toml"
                if cargo_toml.is_file():
                    data = tomllib.loads(cargo_toml.read_text())
                    members[data["package"]["name"]] = data
        self.assertIn("oneiron-macos", members)
        self.assertIn("oneiron-docedit", members)
        visited = set()
        pending = ["oneiron-docedit"]
        while pending:
            name = pending.pop()
            self.assertNotEqual(name, "oneiron", "docedit depends on the engine")
            if name in visited:
                continue
            visited.add(name)
            pending.extend(dependencies(members[name], workspace_dependencies) & members.keys())

    def test_renamed_workspace_dependency_is_resolved(self):
        self.assertIn(
            "oneiron",
            dependencies(
                {"dependencies": {"engine-alias": {"workspace": True}}},
                {"engine-alias": {"package": "oneiron", "path": "crates/oneiron"}},
            ),
        )


if __name__ == "__main__":
    unittest.main()
