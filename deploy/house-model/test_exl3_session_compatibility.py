"""Session snapshots and the speed parts that change the target's arithmetic
(`KV_ARITHMETIC_PARTS`): a snapshot exported with FP16 prefill or the fused
projections on is refused `snapshot_incompatible` by a worker with them off,
and a worker with both off keeps the compatibility it had before the parts
existed. The fuse_projections switch owns exllamav3's fusion variables, so an
inherited one cannot fuse projections the compatibility does not name. CPU only, with the stand-ins of `test_exl3_reply_limits` and
stand-ins for the exllamav3 modules the session layer imports; no model is
loaded. Run from this folder:
`python3 -m unittest test_exl3_session_compatibility`."""
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

import test_exl3_reply_limits  # noqa: F401  (stands in for the GPU modules the server imports)

import cache_usage
import exl3_server


def stand_in_session_modules():
    """Stand-ins for the exllamav3 and torch modules the session layer
    imports, when exllamav3 is not installed: every name asked of a stand-in
    module is a class, and the page is 256 tokens. An installed module is
    left as it is."""
    try:
        import exllamav3.modules.gated_delta_net  # noqa: F401
        return
    except ImportError:
        pass
    for name in ("torch", "exllamav3", "exllamav3.constants", "exllamav3.modules",
                 "exllamav3.modules.gated_delta_net", "exllamav3.modules.sliding_attn",
                 "exllamav3.generator", "exllamav3.generator.pagetable"):
        module = sys.modules.get(name)
        if module is None:
            module = sys.modules[name] = types.ModuleType(name)
        if getattr(module, "__file__", None) is None:
            module.__getattr__ = lambda attr: type(attr, (), {})
    sys.modules["exllamav3.constants"].PAGE_SIZE = 256


stand_in_session_modules()
from exl3_session import layer  # noqa: E402


class Generator:
    cache = object()


def compatibility(kv_arithmetic=()):
    """A worker's snapshot compatibility, with its speed parts that change
    the KV arithmetic, over a stand-in cache every worker here shares."""
    with tempfile.TemporaryDirectory() as target:
        (Path(target) / "tokenizer.json").write_text("{}", encoding="utf-8")
        identity = cache_usage.BackendIdentity(
            target, "template", cache_settings={}, server_settings={}, model_digest="model",
            launch=("launch-manifest", "runtime"), kv_arithmetic=kv_arithmetic)
    with mock.patch.object(layer.snapshot, "hostable", return_value=True), \
            mock.patch.object(layer.snapshot, "kv_layout", return_value={"layout": "quant-8-8"}), \
            mock.patch.object(layer.state, "portable_kind", return_value="gdn+swa"), \
            mock.patch.object(layer, "attention_digest", return_value="attention"):
        return layer.compatibility(identity, Generator())


def import_refusal(test, exported, importing):
    """The refusal of an import, on a worker whose compatibility is
    `importing`, of a snapshot taken under `exported`."""
    worker = object.__new__(layer.SessionLayer)
    worker.compatibility = importing
    header = dict.fromkeys(layer.HEADER_FIELDS)
    header["compatibility"] = exported
    with mock.patch.object(layer.snapshot, "decode_snapshot", return_value=(header, {})):
        with test.assertRaises(layer.Refused) as caught:
            worker.decode_import(b"", {"frontier_tokens": 1})
    return caught.exception


INCOMPATIBLE_MESSAGE = "the snapshot was taken on another model, build or layout"


class SnapshotCompatibility(unittest.TestCase):
    def test_the_server_names_only_the_parts_that_change_the_kv(self):
        every = dict.fromkeys(exl3_server.SPEED_PART_DEFAULTS, True)
        self.assertEqual(exl3_server.kv_arithmetic(every), ["fp16_prefill", "fuse_projections"])
        self.assertEqual(exl3_server.kv_arithmetic(dict(every, fuse_projections=False)), ["fp16_prefill"])
        self.assertEqual(exl3_server.kv_arithmetic(dict(every, fp16_prefill=False, fuse_projections=False)), [])
        self.assertEqual(exl3_server.kv_arithmetic(dict.fromkeys(exl3_server.SPEED_PART_DEFAULTS, False)), [])

    def test_a_worker_with_no_such_part_keeps_its_compatibility(self):
        compat = compatibility()
        self.assertEqual(set(compat), set(layer.IDENTITY_FIELDS) | {"kv", "state", "attention"})
        self.assertEqual(compatibility([]), compat)

    def test_fp16_prefill_binds_the_snapshot(self):
        self.assertEqual(compatibility(["fp16_prefill"])["kv_arithmetic"], ["fp16_prefill"])
        self.assertNotEqual(compatibility(["fp16_prefill"]), compatibility())
        self.assertNotEqual(compatibility(["fp16_prefill"]), compatibility(["fuse_projections"]))
        self.assertEqual(compatibility(["fuse_projections", "fp16_prefill"]),
                         compatibility(["fp16_prefill", "fuse_projections"]))

    def test_an_fp16_prefill_snapshot_is_refused_by_a_worker_without_it(self):
        # The review's case: exported with --fp16-prefill, imported with --no-fp16-prefill.
        refusal = import_refusal(self, compatibility(["fp16_prefill"]), compatibility())
        self.assertEqual(refusal.code, layer.SNAPSHOT_INCOMPATIBLE)
        self.assertEqual(str(refusal), INCOMPATIBLE_MESSAGE)
        refusal = import_refusal(self, compatibility(), compatibility(["fuse_projections"]))
        self.assertEqual(str(refusal), INCOMPATIBLE_MESSAGE)

    def test_a_matching_snapshot_passes_the_compatibility_check(self):
        # The same parts on both workers: the import goes on to its checkpoint check.
        refusal = import_refusal(self, compatibility(["fp16_prefill"]), compatibility(["fp16_prefill"]))
        self.assertNotEqual(str(refusal), INCOMPATIBLE_MESSAGE)


class ProjectionFusionSwitch(unittest.TestCase):
    INHERITED = {"EXL3_MGEMM_K_THRESHOLD": "0", "EXL3_MGEMM_N_THRESHOLD": "4096"}

    def test_off_clears_an_inherited_fusion_override(self):
        # The review's case: an EnvironmentFile sets EXL3_MGEMM_K_THRESHOLD=0 and the launcher passes
        # --no-fuse-projections; no Config built after this may see the override.
        with mock.patch.dict(os.environ, self.INHERITED):
            self.assertEqual(exl3_server.set_projection_fusion(False), self.INHERITED)
            for name in exl3_server.PROJECTION_FUSION_ENV:
                self.assertNotIn(name, os.environ)

    def test_on_fuses_every_pair_whatever_was_inherited(self):
        with mock.patch.dict(os.environ, self.INHERITED):
            self.assertEqual(exl3_server.set_projection_fusion(True), self.INHERITED)
            self.assertEqual(os.environ.get("EXL3_MGEMM_K_THRESHOLD"), "0")
            self.assertNotIn("EXL3_MGEMM_N_THRESHOLD", os.environ)

    def test_off_with_nothing_inherited_changes_nothing(self):
        with mock.patch.dict(os.environ, {}):
            for name in exl3_server.PROJECTION_FUSION_ENV:
                os.environ.pop(name, None)
            before = dict(os.environ)
            self.assertEqual(exl3_server.set_projection_fusion(False), {})
            self.assertEqual(dict(os.environ), before)


if __name__ == "__main__":
    unittest.main()
