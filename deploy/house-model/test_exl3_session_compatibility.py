"""Session snapshots and the speed parts that change the target's arithmetic
(`KV_ARITHMETIC_PARTS`): a snapshot exported with FP16 prefill or the fused
projections on is refused `snapshot_incompatible` by a worker with them off,
and a worker with both off keeps the compatibility it had before the parts
existed. The fuse_projections switch owns exllamav3's fusion variables, so an
inherited one cannot fuse projections the compatibility does not name. Every
other inherited exllamav3 variable (EXL3_*) is named in the server's settings
and its snapshots' compatibility, by a keyed digest. CPU only, with the stand-ins of `test_exl3_reply_limits` and
stand-ins for the exllamav3 modules the session layer imports; no model is
loaded. Run from this folder:
`python3 -m unittest test_exl3_session_compatibility`."""
import hashlib
import hmac
import json
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
    # The key file the workers that exchange snapshots share.
    KEY = b"k" * 32

    def digest(self, variables, key=KEY):
        return exl3_server.environment_digest(variables, key)

    def test_every_inherited_exllamav3_variable_but_the_fusion_pair_is_collected(self):
        environ = dict(self.INHERITED, EXL3_MGEMM_K_THRESHOLD="0", EXL3_MGEMM_N_THRESHOLD="4096",
                       PATH="/usr/bin", EXLLAMAV3_TUNE_CACHE="/var/cache/tune.bin")
        collected = exl3_server.exllamav3_environment(environ)
        self.assertEqual(list(collected.items()), [("EXL3_FUSED_SAMPLER", "0"), ("EXL3_INT8_GEMV", "0")])
        with mock.patch.dict(os.environ, self.INHERITED):
            self.assertEqual(exl3_server.exllamav3_environment()["EXL3_INT8_GEMV"], "0")

    def test_the_digest_names_each_variable_and_its_value(self):
        digest = self.digest
        self.assertIsNone(digest({}))
        self.assertEqual(digest(self.INHERITED), digest(dict(reversed(self.INHERITED.items()))))
        self.assertNotEqual(digest({"EXL3_INT8_GEMV": "0"}), digest({"EXL3_INT8_GEMV": "1"}))
        self.assertNotEqual(digest({"EXL3_INT8_GEMV": "0"}), digest({"EXL3_GEMV": "0"}))
        # A value with a line break never reads as a second variable.
        self.assertNotEqual(digest({"EXL3_GEMV": "0\nEXL3_INT8_GEMV=0"}),
                            digest({"EXL3_GEMV": "0", "EXL3_INT8_GEMV": "0"}))

    def test_the_digest_is_keyed(self):
        # Review round 2's case: a six-digit pin under the prefix. A plain SHA-256 of the canonical JSON is found
        # by hashing the million candidates; the digest is an HMAC under a key no log reader holds.
        pin = {"EXL3_DEPLOY_PIN": "042731"}
        canonical = b'{"EXL3_DEPLOY_PIN":"042731"}'
        self.assertEqual(self.digest(pin), hmac.new(self.KEY, canonical, hashlib.sha256).hexdigest())
        self.assertNotEqual(self.digest(pin), hashlib.sha256(canonical).hexdigest())
        self.assertNotEqual(self.digest(pin), self.digest(pin, b"o" * 32))

    def test_the_key_is_the_key_file_or_the_process_own(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "exl3-env.key"
            path.write_bytes(self.KEY)
            self.assertEqual(exl3_server.environment_key(str(path)), self.KEY)
            path.write_bytes(self.KEY[1:])
            with self.assertRaisesRegex(ValueError, "holds 31 bytes; the key needs at least 32"):
                exl3_server.environment_key(str(path))
        own = exl3_server.environment_key()
        self.assertEqual(len(own), 32)
        self.assertNotEqual(own, exl3_server.environment_key())

    def test_a_value_that_is_not_utf8_is_digested(self):
        # `EXL3_UNUSED=$'\xff'` in a UTF-8 locale: os.environ decodes the byte to the lone surrogate U+DCFF.
        digest = self.digest
        undecodable = digest({"EXL3_UNUSED": "\udcff"})
        self.assertRegex(undecodable, "^[0-9a-f]{64}$")
        self.assertNotEqual(undecodable, digest({"EXL3_UNUSED": "ÿ"}))
        self.assertNotEqual(undecodable, digest({"EXL3_UNUSED": "\\udcff"}))
        self.assertRegex(digest({"EXL3_\udcff": "0"}), "^[0-9a-f]{64}$")

    def test_a_server_with_none_keeps_its_identity(self):
        off = dict.fromkeys(exl3_server.SPEED_PART_DEFAULTS, False)
        self.assertEqual(exl3_server.arithmetic_identity(off), ({}, []))
        self.assertEqual(exl3_server.arithmetic_identity(off, None, self.digest({})), ({}, []))
        ext = "e" * 64
        self.assertEqual(exl3_server.arithmetic_identity(dict(self.LOOKUP_ONLY, fp16_prefill=True), ext),
                         ({"speed_parts": ["fp16_prefill", "prompt_lookup"], "exllamav3_ext": ext},
                          ["fp16_prefill", f"exllamav3_ext={ext}"]))

    def test_an_inherited_variable_changes_the_execution_mode(self):
        env = self.digest(self.INHERITED)
        named, _ = exl3_server.arithmetic_identity(self.LOOKUP_ONLY, None, env)
        stock, _ = exl3_server.arithmetic_identity(self.LOOKUP_ONLY)
        self.assertEqual(named, dict(stock, exllamav3_env=env))
        self.assertNotEqual(execution_mode(named), execution_mode(stock))
        other, _ = exl3_server.arithmetic_identity(
            self.LOOKUP_ONLY, None, self.digest(dict(self.INHERITED, EXL3_INT8_GEMV="1")))
        self.assertNotEqual(execution_mode(named), execution_mode(other))

    def test_a_snapshot_is_refused_across_inherited_variables(self):
        env = self.digest(self.INHERITED)
        _, arithmetic = exl3_server.arithmetic_identity(self.LOOKUP_ONLY, None, env)
        _, stock = exl3_server.arithmetic_identity(self.LOOKUP_ONLY)
        self.assertEqual(arithmetic, [f"exllamav3_env={env}"])
        # Two processes with the same variables but keys of their own (no shared key file) refuse each other too.
        _, own_key = exl3_server.arithmetic_identity(
            self.LOOKUP_ONLY, None, self.digest(self.INHERITED, exl3_server.environment_key()))
        for exported, importing in ((arithmetic, stock), (stock, arithmetic), (own_key, arithmetic)):
            refusal = import_refusal(self, compatibility(exported), compatibility(importing))
            self.assertEqual(refusal.code, layer.SNAPSHOT_INCOMPATIBLE)
            self.assertEqual(str(refusal), INCOMPATIBLE_MESSAGE)
        # The same variables and the same key file on both workers: the import goes on to its checkpoint check.
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

    KEY = InheritedExllamav3Environment.KEY

    def identity_kwargs(self, environ, key_file=None):
        def build(*args, **kwargs):
            raise IdentityBuilt(kwargs)

        with tempfile.TemporaryDirectory() as target:
            (Path(target) / "chat_template.jinja").write_text("template", encoding="utf-8")
            args = types.SimpleNamespace(
                context=4096, draft_tokens=1, max_in_flight=1, draft_ring_pages=None, draft_dir=None,
                cache_tokens=None, target_dir=target, weights_manifest=None, launch_manifest=None,
                recurrent_cache_gib=1, no_sessions=True, model_id="house", exllamav3_ext_dir=None,
                exllamav3_env_key_file=key_file)
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
                    mock.patch("builtins.print") as printed:
                with self.assertRaises(IdentityBuilt) as built:
                    exl3_server.load(args)
        # The lines `load` printed, for the log checks.
        self.printed_lines = [str(call.args[0]) for call in printed.call_args_list if call.args]
        return built.exception.kwargs

    def key_file(self):
        """The path of a key file holding KEY, removed after the test."""
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        path = Path(folder.name) / "exl3-env.key"
        path.write_bytes(self.KEY)
        return str(path)

    def printed_line(self, prefix):
        lines = [line for line in self.printed_lines if line.startswith(prefix + " ")]
        self.assertEqual(len(lines), 1, self.printed_lines)
        return lines[0]

    def test_a_server_without_exllamav3_variables_builds_the_stock_identity(self):
        for key_file in (None, self.key_file()):
            kwargs = self.identity_kwargs({}, key_file)
            self.assertEqual(kwargs["server_settings"],
                             {"context": 4096, "draft": False, "draft_tokens": 0, "max_in_flight": 1})
            self.assertEqual(kwargs["kv_arithmetic"], [])
            self.assertEqual([line for line in self.printed_lines if line.startswith("EXL3_ENV")], [])

    def test_an_inherited_variable_is_named_in_the_settings_and_the_compatibility(self):
        # The fuse_projections switch (off by default) clears the inherited fusion variable, so it is not named.
        key_file = self.key_file()
        kwargs = self.identity_kwargs({"EXL3_INT8_GEMV": "0", "EXL3_MGEMM_K_THRESHOLD": "6"}, key_file)
        env = exl3_server.environment_digest({"EXL3_INT8_GEMV": "0"}, self.KEY)
        self.assertEqual(kwargs["server_settings"]["exllamav3_env"], env)
        self.assertEqual(kwargs["kv_arithmetic"], [f"exllamav3_env={env}"])
        self.assertEqual(self.printed_line("EXL3_ENV"), f"EXL3_ENV EXL3_INT8_GEMV hmac_sha256={env} key={key_file}")

    def test_workers_agree_through_a_shared_key_file_only(self):
        environ = {"EXL3_INT8_GEMV": "0"}
        key_file = self.key_file()
        shared = [self.identity_kwargs(environ, key_file)["server_settings"]["exllamav3_env"] for _ in range(2)]
        self.assertEqual(shared[0], shared[1])
        own = [self.identity_kwargs(environ)["server_settings"]["exllamav3_env"] for _ in range(2)]
        self.assertNotEqual(own[0], own[1])
        self.assertNotIn(shared[0], own)
        self.assertEqual(self.printed_line("EXL3_ENV"), f"EXL3_ENV EXL3_INT8_GEMV hmac_sha256={own[1]} key=process")

    def test_the_log_and_the_identity_carry_no_plain_hash_of_a_value(self):
        # The review's cases: a private token, and a six-digit pin whose plain SHA-256 a journal reader finds by
        # hashing the million candidates, under the prefix in the unit's EnvironmentFile.
        for secret, environ in (("token-value-7f3a", {"EXL3_DEPLOY_TOKEN": "token-value-7f3a", "EXL3_INT8_GEMV": "0"}),
                                ("042731", {"EXL3_DEPLOY_PIN": "042731"})):
            kwargs = self.identity_kwargs(environ)
            env = kwargs["server_settings"]["exllamav3_env"]
            canonical = json.dumps(environ, sort_keys=True, separators=(",", ":")).encode("ascii")
            plain = hashlib.sha256(canonical).hexdigest()
            for text in self.printed_lines + kwargs["kv_arithmetic"]:
                self.assertNotIn(plain, text)
            self.assertNotEqual(env, plain)
            for line in self.printed_lines:
                self.assertNotIn(secret, line.replace(env, ""))
            self.assertEqual(self.printed_line("EXL3_ENV"),
                             f"EXL3_ENV {' '.join(sorted(environ))} hmac_sha256={env} key=process")

    def test_a_server_starts_with_a_value_that_is_not_utf8(self):
        # `EXL3_UNUSED=$'\xff'` (and the same byte in an inherited fusion variable) in a UTF-8 locale: load builds
        # its identity, and its log lines are ASCII, so they print under any stdout encoding.
        key_file = self.key_file()
        kwargs = self.identity_kwargs({"EXL3_UNUSED": "\udcff", "EXL3_MGEMM_K_THRESHOLD": "\udcff"}, key_file)
        env = exl3_server.environment_digest({"EXL3_UNUSED": "\udcff"}, self.KEY)
        self.assertEqual(kwargs["server_settings"]["exllamav3_env"], env)
        self.assertEqual(kwargs["kv_arithmetic"], [f"exllamav3_env={env}"])
        self.assertEqual(self.printed_line("EXL3_ENV"), f"EXL3_ENV EXL3_UNUSED hmac_sha256={env} key={key_file}")
        self.assertEqual(self.printed_line("FUSION_ENV_REPLACED"), "FUSION_ENV_REPLACED EXL3_MGEMM_K_THRESHOLD=\\udcff")
        for prefix in ("EXL3_ENV", "FUSION_ENV_REPLACED"):
            self.printed_line(prefix).encode("ascii")


if __name__ == "__main__":
    unittest.main()
