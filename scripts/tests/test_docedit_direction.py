"""ARCH-0075 dependency-direction fitness check (no compilation)."""
import pathlib
import tomllib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]


class DocumentOrganDirection(unittest.TestCase):
    def test_organ_cannot_reach_engine(self):
        workspace = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]
        inherited = workspace.get("dependencies", {})
        graph = {}
        pending_paths = list((ROOT / "crates").glob("*/Cargo.toml"))
        loaded_paths = set()
        while pending_paths:
            path = pending_paths.pop().resolve()
            if path in loaded_paths:
                continue
            loaded_paths.add(path)
            manifest = tomllib.loads(path.read_text())
            package = manifest.get("package")
            if not package:
                continue
            deps = set()
            tables = [manifest]
            tables.extend(manifest.get("target", {}).values())
            for table in tables:
                for kind in ("dependencies", "build-dependencies", "dev-dependencies"):
                    for alias, spec in table.get(kind, {}).items():
                        base = path.parent
                        if isinstance(spec, dict) and spec.get("workspace"):
                            spec = inherited[alias]
                            base = ROOT
                        deps.add(spec.get("package", alias) if isinstance(spec, dict) else alias)
                        if isinstance(spec, dict) and "path" in spec:
                            pending_paths.append(base / spec["path"] / "Cargo.toml")
            graph[package["name"]] = deps
        self.assertIn("oneiron-docedit", graph["oneiron"])
        seen = set()
        pending = ["oneiron-docedit"]
        while pending:
            name = pending.pop()
            if name in seen:
                continue
            seen.add(name)
            self.assertNotEqual(name, "oneiron", "document organ must not depend on storage")
            pending.extend(graph.get(name, ()))


if __name__ == "__main__":
    unittest.main()
