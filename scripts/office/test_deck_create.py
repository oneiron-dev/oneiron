"""Offline contracts for the deck-create-v1 Office half. No PowerPoint; runs
on any host:

    python3 -I scripts/office/test_deck_create.py
"""
import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent


def load(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


template_mod = load("make_deck_create_template")
gate = load("deck_create_gate")

CASE_ID = re.compile(r"^[a-z]+(-[a-z]+)*$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def fake_run(root: Path) -> Path:
    """A small run directory shaped as the engine half writes it."""
    run = root / "run"
    (run / "candidates").mkdir(parents=True)
    (run / "office").mkdir()
    case_manifest = b'{"case_set": "deck-create-v1"}'
    (run / "case-manifest.json").write_bytes(case_manifest)
    candidate = (ROOT / "fixtures/clean.pptx").read_bytes()
    (run / "candidates/board-review.pptx").write_bytes(candidate)
    script = b"# the pinned script\n"
    (run / "office/deck_create_gate.py").write_bytes(script)

    def pin(data: bytes) -> dict:
        return {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}

    manifest = {
        "schema": gate.RUN_SCHEMA,
        "case_set": gate.CASE_SET,
        "source": "c" * 40,
        "case_manifest": {"path": "case-manifest.json", **pin(case_manifest)},
        "template": {"path": "scripts/office/fixtures/deck-create-template.pptx",
                     "sha256": "0" * 64, "bytes": 1},
        "office": {"scripts": [{"path": "office/deck_create_gate.py", **pin(script)}],
                   "timeout_seconds": 120, "observer": "system-events"},
        "candidates": [{
            "id": "board-review", "file": "candidates/board-review.pptx",
            "sha256": hashlib.sha256(candidate).hexdigest(), "blake3": "1" * 64,
            "bytes": len(candidate), "slides": 7,
            "units": [
                {"slide": 1, "part": "ppt/slides/slide1.xml", "shape_index": 1,
                 "shape_id": 2, "name": "Title 1", "block": "a-title", "kind": "text",
                 "planned_emu": [457200, 274638, 8229600, 1143000]},
                {"slide": 1, "part": "ppt/slides/slide1.xml", "shape_index": 2,
                 "shape_id": 3, "name": "Table 2", "block": "d-table", "kind": "table",
                 "planned_emu": [457200, 1500000, 8229600, 2000000]},
            ]}],
        "refused": [],
    }
    (run / "manifest.json").write_text(json.dumps(manifest))
    return run


class TemplateContracts(unittest.TestCase):

    def test_template_generator_reproduces_the_committed_template(self):
        clean = (ROOT / "fixtures/clean.pptx").read_bytes()
        committed = (ROOT / "fixtures/deck-create-template.pptx").read_bytes()
        self.assertEqual(template_mod.template_bytes(clean), committed)
        import zipfile
        with zipfile.ZipFile(ROOT / "fixtures/deck-create-template.pptx") as archive:
            for info in archive.infolist():
                self.assertFalse(info.filename.startswith("ppt/slides/"), info.filename)
                self.assertEqual(info.compress_type, zipfile.ZIP_STORED, info.filename)
                self.assertEqual(info.date_time, (1980, 1, 1, 0, 0, 0), info.filename)
                self.assertEqual(info.external_attr, 0o644 << 16, info.filename)


class ManifestContracts(unittest.TestCase):

    def test_manifest_names_existing_briefs_and_scripts(self):
        manifest = json.loads((ROOT / "deck-create-v1.json").read_text())
        self.assertEqual(manifest["case_set"], "deck-create-v1")
        ids = [case["id"] for case in manifest["cases"]]
        self.assertEqual(len(ids), len(set(ids)), "case ids repeat")
        for case in manifest["cases"]:
            self.assertRegex(case["id"], CASE_ID)
            brief = json.loads((ROOT.parent.parent / case["brief"]).read_text())
            for page in brief["pages"]:
                for block in page["blocks"]:
                    self.assertNotEqual(block["kind"], "asset", (case["id"], block["id"]))
                    for pin in block.get("evidence", []):
                        quote = pin["quote"].encode("utf-8")
                        self.assertLessEqual(len(quote), 64, (case["id"], block["id"]))
                        self.assertRegex(pin["quote_hash"], HEX64, (case["id"], block["id"]))
        for name in manifest["office"]["scripts"]:
            self.assertTrue((ROOT / name).is_file(), name)


class GateContracts(unittest.TestCase):

    def test_verify_accepts_a_run_and_flags_a_tampered_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = fake_run(Path(tmp))
            manifest = gate.load_run(run)
            self.assertEqual(gate.verify(run, manifest), [])
            (run / "candidates/board-review.pptx").write_bytes(b"tampered")
            problems = gate.verify(run, manifest)
            self.assertTrue(problems, "a tampered candidate passes verify")
            self.assertTrue(any("board-review" in problem for problem in problems), problems)
            manifest["candidates"][0]["units"][0]["kind"] = "picture"
            kinds = gate.verify(run, manifest)
            self.assertTrue(any("kind" in problem for problem in kinds), kinds)

    def test_office_refuses_off_mac(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run = fake_run(root)
            args = argparse.Namespace(run=run, results=None, observer=None, timeout=None)
            lock = root / "w7-oracle" / "lock"
            stderr = io.StringIO()
            with mock.patch.object(gate.sys, "platform", "linux"), \
                 mock.patch.object(gate.deck_session, "LOCK", lock), \
                 contextlib.redirect_stderr(stderr):
                code = gate.cmd_office(args)
            self.assertEqual(code, 2)
            self.assertIn("Mac mini", stderr.getvalue())
            self.assertFalse(lock.exists(), "no lock is taken on refusal")


if __name__ == "__main__":
    unittest.main()
