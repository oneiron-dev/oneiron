"""Session snapshots and the speed parts that change the target's arithmetic
(`KV_ARITHMETIC_PARTS`): a snapshot exported with FP16 prefill or the fused
projections on is refused `snapshot_incompatible` by a worker with them off,
and a worker with both off keeps the compatibility it had before the parts
existed. The fuse_projections switch owns exllamav3's fusion variables, so an
inherited one cannot fuse projections the compatibility does not name. Every
other inherited exllamav3 variable (EXL3_*) is named in the server's settings
and its snapshots' compatibility. CPU only, with the stand-ins of `test_exl3_reply_limits` and
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


def execution_mode(server_settings):
    """The execution digest of one plain request on a server with `server_settings`."""
    with tempfile.TemporaryDirectory() as target:
        (Path(target) / "tokenizer.json").write_text("{}", encoding="utf-8")
        identity = cache_usage.BackendIdentity(
            target, "template", cache_settings={}, server_settings=server_settings, model_digest="model",
            launch=("launch-manifest", "runtime"))
    return identity.execution_mode({}, False)


class InheritedExllamav3Environment(unittest.TestCase):
    # The FIX row's case (HOUSE-EXL3-ENV-IDENTITY): the host's EnvironmentFile turns exllamav3's int8 GEMV and
    # its fused sampler off, which changes the target's kernels; the server must not answer, cache or export
    # under the stock identity.
    INHERITED = {"EXL3_INT8_GEMV": "0", "EXL3_FUSED_SAMPLER": "0"}
    LOOKUP_ONLY = dict(dict.fromkeys(exl3_server.SPEED_PART_DEFAULTS, False), prompt_lookup=True)

    def test_every_inherited_exllamav3_variable_but_the_fusion_pair_is_collected(self):
        environ = dict(self.INHERITED, EXL3_MGEMM_K_THRESHOLD="0", EXL3_MGEMM_N_THRESHOLD="4096",
                       PATH="/usr/bin", EXLLAMAV3_TUNE_CACHE="/var/cache/tune.bin")
        collected = exl3_server.exllamav3_environment(environ)
        self.assertEqual(list(collected.items()), [("EXL3_FUSED_SAMPLER", "0"), ("EXL3_INT8_GEMV", "0")])
        with mock.patch.dict(os.environ, self.INHERITED):
            self.assertEqual(exl3_server.exllamav3_environment()["EXL3_INT8_GEMV"], "0")

    def test_the_digest_names_each_variable_and_its_value(self):
        digest = exl3_server.environment_digest
        self.assertIsNone(digest({}))
        self.assertEqual(digest(self.INHERITED), digest(dict(reversed(self.INHERITED.items()))))
        self.assertNotEqual(digest({"EXL3_INT8_GEMV": "0"}), digest({"EXL3_INT8_GEMV": "1"}))
        self.assertNotEqual(digest({"EXL3_INT8_GEMV": "0"}), digest({"EXL3_GEMV": "0"}))
        # A value with a line break never reads as a second variable.
        self.assertNotEqual(digest({"EXL3_GEMV": "0\nEXL3_INT8_GEMV=0"}),
                            digest({"EXL3_GEMV": "0", "EXL3_INT8_GEMV": "0"}))

    def test_a_server_with_none_keeps_its_identity(self):
        off = dict.fromkeys(exl3_server.SPEED_PART_DEFAULTS, False)
        self.assertEqual(exl3_server.arithmetic_identity(off), ({}, []))
        self.assertEqual(exl3_server.arithmetic_identity(off, None, exl3_server.environment_digest({})), ({}, []))
        ext = "e" * 64
        self.assertEqual(exl3_server.arithmetic_identity(dict(self.LOOKUP_ONLY, fp16_prefill=True), ext),
                         ({"speed_parts": ["fp16_prefill", "prompt_lookup"], "exllamav3_ext": ext},
                          ["fp16_prefill", f"exllamav3_ext={ext}"]))

    def test_an_inherited_variable_changes_the_execution_mode(self):
        env = exl3_server.environment_digest(self.INHERITED)
        named, _ = exl3_server.arithmetic_identity(self.LOOKUP_ONLY, None, env)
        stock, _ = exl3_server.arithmetic_identity(self.LOOKUP_ONLY)
        self.assertEqual(named, dict(stock, exllamav3_env=env))
        self.assertNotEqual(execution_mode(named), execution_mode(stock))
        other, _ = exl3_server.arithmetic_identity(
            self.LOOKUP_ONLY, None, exl3_server.environment_digest(dict(self.INHERITED, EXL3_INT8_GEMV="1")))
        self.assertNotEqual(execution_mode(named), execution_mode(other))

    def test_a_snapshot_is_refused_across_inherited_variables(self):
        env = exl3_server.environment_digest(self.INHERITED)
        _, arithmetic = exl3_server.arithmetic_identity(self.LOOKUP_ONLY, None, env)
        _, stock = exl3_server.arithmetic_identity(self.LOOKUP_ONLY)
        self.assertEqual(arithmetic, [f"exllamav3_env={env}"])
        for exported, importing in ((arithmetic, stock), (stock, arithmetic)):
            refusal = import_refusal(self, compatibility(exported), compatibility(importing))
            self.assertEqual(refusal.code, layer.SNAPSHOT_INCOMPATIBLE)
            self.assertEqual(str(refusal), INCOMPATIBLE_MESSAGE)
        # The same variables on both workers: the import goes on to its checkpoint check.
        refusal = import_refusal(self, compatibility(arithmetic), compatibility(arithmetic))
        self.assertNotEqual(str(refusal), INCOMPATIBLE_MESSAGE)


class IdentityBuilt(Exception):
    """Raised by the stand-in BackendIdentity, with the arguments `load` built it from."""

    def __init__(self, kwargs):
        super().__init__("identity built")
        self.kwargs = kwargs


class LoadNamesInheritedVariables(unittest.TestCase):
    """`load` itself, from its arguments to the identity it builds, with stand-ins for every model and cache it
    touches (no draft, every speed part at its default, the installed extension); the stand-in identity stops it."""

    def identity_kwargs(self, environ):
        def build(*args, **kwargs):
            raise IdentityBuilt(kwargs)

        with tempfile.TemporaryDirectory() as target:
            (Path(target) / "chat_template.jinja").write_text("template", encoding="utf-8")
            args = types.SimpleNamespace(
                context=4096, draft_tokens=1, max_in_flight=1, draft_ring_pages=None, draft_dir=None,
                cache_tokens=None, target_dir=target, weights_manifest=None, launch_manifest=None,
                recurrent_cache_gib=1, no_sessions=True, model_id="house", exllamav3_ext_dir=None)
            stand_ins = {name: mock.MagicMock() for name in
                         ("Config", "Model", "Tokenizer", "Cache", "Generator", "Environment", "exl3_executor",
                          "exl3_stats", "check_placement", "warm_schema_tokenizer", "weights_digest",
                          "launch_identity")}
            inherited = {name: value for name, value in os.environ.items()
                         if not name.startswith("EXL3_")}
            with mock.patch.multiple(exl3_server, **stand_ins), \
                    mock.patch.object(exl3_server, "rebuilt_extension_digest", return_value=None), \
                    mock.patch.object(cache_usage, "BackendIdentity", side_effect=build), \
                    mock.patch.dict(os.environ, dict(inherited, **environ), clear=True), \
                    mock.patch("builtins.print"):
                with self.assertRaises(IdentityBuilt) as built:
                    exl3_server.load(args)
        return built.exception.kwargs

    def test_a_server_without_exllamav3_variables_builds_the_stock_identity(self):
        kwargs = self.identity_kwargs({})
        self.assertEqual(kwargs["server_settings"],
                         {"context": 4096, "draft": False, "draft_tokens": 0, "max_in_flight": 1})
        self.assertEqual(kwargs["kv_arithmetic"], [])

    def test_an_inherited_variable_is_named_in_the_settings_and_the_compatibility(self):
        # The fuse_projections switch (off by default) clears the inherited fusion variable, so it is not named.
        kwargs = self.identity_kwargs({"EXL3_INT8_GEMV": "0", "EXL3_MGEMM_K_THRESHOLD": "6"})
        self.assertIn("exllamav3_env", kwargs["server_settings"])
        env = exl3_server.environment_digest({"EXL3_INT8_GEMV": "0"})
        self.assertEqual(kwargs["server_settings"]["exllamav3_env"], env)
        self.assertEqual(kwargs["kv_arithmetic"], [f"exllamav3_env={env}"])


if __name__ == "__main__":
    unittest.main()
