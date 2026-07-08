#!/usr/bin/env python3
"""S1 test-split recut (TS S1 + D9.5 row 3) + S2 deferred test-splits.
Reuses PR-0's proven gen_tests (mod-tests move rows + test-body impl-delta)."""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gen  # PR-0 generator (functions only; __main__ guarded)

_top = gen._top
_srv = gen._srv

# --- S1 (recut) ---
# tests-w1: the 10 codec-adjacent MINUS companion + psych_profile (deferred to S2)
W1 = [_top(s) for s in [
    "claim", "authority", "persona_snapshot", "channel_identity",
    "counterparty_contact", "federation", "outbound_grant", "access_grant",
]]

# tests-w2: remaining oneiron top-level, MINUS types (D9.5 #3 drop) + export
# (deferred to S2 after B1), PLUS the trio + vault (new S1 rows, TS S1)
W2 = [_top(s) for s in [
    "store", "serialize", "gate", "pipeline", "context_pack", "lens",
    "dreamer_runner", "policy_model", "repo_mutation", "code_revision", "bm25",
    "ppr", "receipt", "hnsw", "job_queue", "code_run", "code_symbol", "graph_fs",
    "channel_identity_provider", "dreamer_tournament", "engine_executor", "codebase",
    "maintain", "sweep", "inbox", "llm", "provenance", "genui", "deletion",
    "code_sandbox", "off_record", "blob_artifact", "delivery_window", "critic",
    "channel_identity_lifecycle", "skill", "run_tree", "ingest", "extraction_eval",
    "identity_reputation", "artifact_hosting", "thread_lens", "recovery",
    "surface_event", "embed", "settings", "fusion",
    # NEW S1 rows: the ex-LEAVE-ALONE trio + vault
    "batch", "outbound", "anchored_annotation", "vault",
]]

# tests-w3 / tests-w4 unchanged from PR-0
W3 = gen.W3
W4 = gen.W4

# --- S2 deferred test-splits (after U for companion/psych_profile; after B1 for export) ---
S2_UNMOUNT = [_top(s) for s in ["companion", "psych_profile"]]
# export: after B1 it lives at src/batch/export.rs -> batch/export/tests.rs
S2_EXPORT = [("crates/oneiron/src/batch/export.rs",
              "crates/oneiron/src/batch/export/tests.rs")]

STAGES = [
    ("tests-w1", W1, "crates/oneiron"),
    ("tests-w2", W2, "crates/oneiron"),
    ("tests-w3", W3, "crates/oneiron"),
    ("tests-w4", W4, "crates/oneiron-server"),
    ("tests-s2-unmount", S2_UNMOUNT, "crates/oneiron"),
]

if __name__ == "__main__":
    for sid, rows, crate in STAGES:
        gen.gen_tests(sid, rows, crate)
    if gen.STOPS:
        print(f"\n{len(gen.STOPS)} STOP(s)", file=sys.stderr)
        sys.exit(1)
    print("OK — S1/S2 test-splits generated with no STOPs")
    print("NOTE: tests-s2-export (batch/export.rs -> batch/export/tests.rs) is cut at "
          "B1 package time (src path exists only post-B1).")
