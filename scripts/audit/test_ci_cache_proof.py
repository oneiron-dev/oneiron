"""Fail closed unless a fresh artifact target gains real GHA cache hits and time."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from ci_cache_proof import measure, validate


def stats(hits=0, misses=0, writes=0, location="ghac, name: proof-key, prefix: /sccache/"):
    return {"stats": {"cache_hits": {"counts": {"Rust": hits}},
                      "cache_misses": {"counts": {"Rust": misses}}, "cache_writes": writes},
            "cache_location": location}


class CacheProofTests(unittest.TestCase):
    def receipts(self):
        common = {"run_id": "123", "revision": "deadbeef", "namespace": "proof-123-linux-x64-lock",
                  "target": "/runner/_temp/proof-123/target", "command": ["cargo", "check"],
                  "version": "sccache 0.15.0", "runner": "arch", "os": "Linux", "arch": "X64"}
        first = dict(common, baseline_seconds=120.0, populate_seconds=130.0,
                     populate_stats=stats(misses=15, writes=15))
        repeat = dict(common, repeat_seconds=70.0, repeat_stats=stats(hits=15))
        return first, repeat

    def test_distinct_job_with_shared_backend_and_fresh_target_can_pass(self):
        validate(*self.receipts())

    def test_no_hits_or_no_speedup_fails_even_with_clean_target(self):
        for field, value in (("repeat_stats", stats()), ("repeat_seconds", 120.0)):
            first, repeat = self.receipts()
            repeat[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate(first, repeat)

    def test_both_jobs_build_at_same_fresh_run_owned_target(self):
        with tempfile.TemporaryDirectory() as temp:
            env = dict(os.environ, GITHUB_RUN_ID="123", GITHUB_SHA="deadbeef",
                       GITHUB_SERVER_URL="https://github.com", GITHUB_REPOSITORY="oneiron-dev/oneiron",
                       RUNNER_TEMP=temp, RUNNER_NAME="arch", RUNNER_OS="Linux", RUNNER_ARCH="X64",
                       SCCACHE_GHA_ENABLED="on", SCCACHE_GHA_VERSION="proof-123-linux-x64-lock",
                       ACTIONS_RESULTS_URL="https://cache.invalid", ACTIONS_RUNTIME_TOKEN="fixture")
            first = Path(temp) / "populate.json"
            second = Path(temp) / "repeat.json"
            built = []

            def fake_build(target, build_env):
                self.assertFalse(target.exists(), "the prior job left Cargo artifacts behind")
                target.mkdir()
                built.append((str(target), build_env.get("RUSTC_WRAPPER")))
                return (120.0, 130.0, 70.0)[len(built) - 1]

            def fake_output(argv, **kwargs):
                if argv == ["sccache", "--version"]:
                    return "sccache 0.15.0"
                return json.dumps(stats(misses=15, writes=15) if len(built) == 2 else stats(hits=15))

            with patch.dict(os.environ, env, clear=True), patch("ci_cache_proof.run_build", side_effect=fake_build), \
                 patch("ci_cache_proof.subprocess.check_output", side_effect=fake_output), \
                 patch("ci_cache_proof.subprocess.run"):
                measure("populate", first, None)
                measure("repeat", second, first)
            self.assertEqual([wrapper for _, wrapper in built], [None, "sccache", "sccache"])
            self.assertEqual(len({target for target, _ in built}), 1)
            self.assertFalse(Path(built[0][0]).exists())
            self.assertEqual(json.loads(second.read_text())["repeat_seconds"], 70.0)

    def test_wrong_backend_no_population_or_stale_receipt_fails(self):
        for field, value in (("namespace", "another-key"), ("revision", "other-head"),
                             ("target", "/other/target"), ("version", "sccache 0.14.0"),
                             ("populate_stats", stats())):
            first, repeat = self.receipts()
            first[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate(first, repeat)
        first, repeat = self.receipts()
        repeat["repeat_stats"] = stats(hits=15, location="disk")
        with self.assertRaises(ValueError):
            validate(first, repeat)


if __name__ == "__main__":
    unittest.main()
