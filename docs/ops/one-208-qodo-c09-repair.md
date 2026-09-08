# ONE-208: captured Qodo C09 material repair

## Scope and status

- Captured candidate: PR #881, head `c09a07f4b70961423950a45d962a1d53c26ba1b1`.
- Inputs: `QODO-C09-FINDINGS.md` and `PR881-INLINE.json` under
  `<harness-report-dir>/factory-wave6-launch-20260906/v11/mass-coverage/front-dispatch/ONE-208/`
  (the dispatch harness's report directory on the worker host; not part of this repo).
- Changes are limited to the three captured findings, their source-contract adaptations,
  and focused regressions. Existing quality tests and source are retained.
- File-only repair in the isolated ONE-208 workspace. No ONE-207 workspace was accessed
  or changed. No Git commands or mutations, Cargo commands, builds, tests, formatter,
  network calls, delegation, or fallback review were run.
- **Implementation is patched, not execution-verified. No PASS is claimed.**
- **Codex GitHub review remains unresolved because its quota is exhausted.** This
  repair and the written regressions do not replace that external review.

## Findings addressed

1. **Failed deep reads losing accrued usage.** The engine returns a usage-bearing
   `RetrievalError`. The deep executor adds successful decomposition/rerank usage to
   any failing call's reported usage, with saturating `u64` arithmetic. Local failures
   after a successful backend call (including narrowing and malformed rerank output)
   retain the accumulator. Both API paths record success OR error usage before
   propagating errors. Memory reason records retrieval usage before evidence projection,
   and composition usage before mapping a composition error. Its finalizer encloses all
   post-retrieval fallible work. Only zero-use abandoned/failed admissions are aborted;
   recorded positive usage is settled, including in Drop cleanup.
2. **Settlement failures being reduced to warnings.** `DeepAdmission::settle` returns
   `Result<(), ApiError>`. `finish` settles before returning successful results or spent
   errors, and propagates settlement failure as the existing HTTP 503
   `DEEP_RETRIEVAL_UNAVAILABLE`. Raw search and memory reason both use it. A failed
   settlement cannot expose a successful result. Drop retries settlement for recorded
   spend, rather than erasing it with an abort. It cannot report an error itself; normal
   returns use the explicit fallible finalizer.
3. **Unescaped controls in quoted YAML/TOON evidence.** The shared quoted writer keeps
   the existing quote, backslash, newline, carriage-return and tab escapes, and adds
   `\uNNNN` for other controls. It also escapes YAML line separators and the two
   BMP noncharacters forbidden literally in YAML. All three quoted fields are covered.
   YAML regressions use `serde_yaml_ng`; the TOON regression checks the unchanged
   tabular header and parses its always-quoted row using JSON-compatible scalar escapes.
   It is not a full independent TOON-decoder conformance test.

Quality fields, confidence adjustment, channel diagnostics, scope/admission checks,
backend work caps, ranking, engine score values, citation validation, and existing
composition fallback behavior are unchanged. No new wire field or error code is added.
`BudgetGuard`, `BudgetLease`, and successful `BackendSpend<T>` are unchanged.

## Exact Rust API change to relay to ONE-207

The cohesive minimum is explicit failure-side usage, not a general lease-meter redesign.
`oneiron::retrieval_depth` now exports:

```rust
pub type RetrievalResult<T> = std::result::Result<T, RetrievalError>;

pub struct RetrievalError {
    pub error: oneiron::Error,
    pub tokens_used: u64,
}
```

These return types change; parameters stay identical:

| Method | Previous return | New return |
| --- | --- | --- |
| `DeepSearchBackend::decompose` | `oneiron::Result<BackendSpend<Vec<String>>>` | `RetrievalResult<BackendSpend<Vec<String>>>` |
| `DeepSearchBackend::rerank` | `oneiron::Result<BackendSpend<Vec<f32>>>` | `RetrievalResult<BackendSpend<Vec<f32>>>` |
| `ScopedRead::search_with_effort` | `oneiron::Result<DepthSearchResult>` | `RetrievalResult<DepthSearchResult>` |
| Server-local `MemoryReasonBackend::compose` | `oneiron::Result<BackendSpend<MemoryReasonComposition>>` | `RetrievalResult<BackendSpend<MemoryReasonComposition>>` |

Backend implementations must report **only the failed call's actual usage**:

```rust
Err(RetrievalError {
    error,
    tokens_used: actual_tokens_for_this_failed_call,
})
```

`From<oneiron::Error>` exists only as a zero-use conversion. A plain error with `?`
therefore means that failing call consumed zero tokens. A backend that already spent
must construct the explicit error instead. Do not report a reservation, a request cap,
previous calls' totals, or estimate unknown spend as zero. Successful answers continue
using unchanged `BackendSpend<T>`. Providers remain responsible for reporting their
actual usage; this change does not infer usage a provider never reports.

The engine's error contains **whole-search usage**, including earlier successful calls.
Hosts must settle that total before mapping/returning `failure.error`. They then add
composition's per-call success/error usage once. The host owns final settlement of the
shared lease; backend methods must not independently finalize it. There is deliberately
no lossy conversion from `RetrievalError` back to `oneiron::Error`.

This is a source-breaking Rust error-type change requiring ONE-207 relay. No changes
have been made in ONE-207. Existing in-tree backend fixtures and success tests were
adapted without deleting their quality/ranking assertions.

## Focused regressions written (not run)

### `crates/oneiron/src/retrieval_depth/tests/spend_tests.rs`

- `deep_malformed_rerank_retains_decompose_and_rerank_spend`
- `deep_spent_backend_errors_retain_prior_calls`
- `deep_error_spend_saturates_without_wrapping`
- `deep_narrowing_error_after_decompose_retains_spend`

### `crates/oneiron-server/src/api/tests/depth_spend.rs`

- `deep_api_malformed_rerank_and_spent_errors_settle_before_return`
- `deep_reason_composition_errors_settle_retrieval_and_error_spend`
- `deep_api_aborted_lease_fails_closed_for_success_and_search_error`
- `deep_api_zero_usage_errors_abort_instead_of_settling`

### `crates/oneiron-server/src/api/memory_reason/deep_admission/tests.rs`

- `deep_admission_later_evidence_error_settles_prior_usage_once`
- `deep_admission_missing_lease_blocks_completed_and_spent_error_results`
- `deep_admission_aborted_lease_blocks_even_zero_usage_success`
- `deep_admission_drop_settles_spend_and_only_aborts_zero_usage`

### `crates/oneiron-server/src/api/memory_reason/render.rs`

- `quoted_controls_roundtrip_without_literal_controls`
- `yaml_evidence_controls_roundtrip_all_quoted_fields`
- `toon_evidence_controls_roundtrip_quoted_row`

The late-evidence regression exercises the admission finalizer with a projection error;
it is not an end-to-end injected storage failure in the HTTP handler. Engine narrowing
has a real post-decomposition corrupt-short-id fixture. HTTP tests cover raw text search
and memory reason. Raw vector search shares the patched `run_depth_search` finalizer.
Missing-lease tests use a deliberately mismatched guard/lease fixture without widening
production admission. Aborted-lease HTTP tests cover both a usable backend result and
an original retrieval error, to pin settlement-error precedence.

The existing `retrieval_quality_depth_deep_still_refuses_missing_lease_before_channels`
regression now also asserts zero error usage. Existing quality, ranking, admission,
additive/idempotent settlement, and composition-fallback assertions remain present.

## Changed paths

- `crates/oneiron/src/retrieval_depth.rs`
- `crates/oneiron-server/src/api/memory_reason.rs`
- `crates/oneiron-server/src/api/memory_reason/deep_admission.rs`
- `crates/oneiron-server/src/api/memory_reason/render.rs`
- `crates/oneiron-server/src/api/search.rs`
- `crates/oneiron/src/retrieval_depth/accumulation.rs`
- `crates/oneiron-server/Cargo.toml`
- `crates/oneiron-server/src/api/tests/depth_quality.rs`
- `crates/oneiron-server/src/api/tests.rs`
- `crates/oneiron/src/retrieval_depth/tests.rs`
- `Cargo.lock`
- `crates/oneiron/src/retrieval_depth/spend.rs`
- `crates/oneiron/src/retrieval_depth/tests/spend_tests.rs`
- `crates/oneiron-server/src/api/tests/depth_spend.rs`
- `crates/oneiron-server/src/api/memory_reason/deep_admission/tests.rs`
- `docs/ops/one-208-qodo-c09-repair.md`

The manifest/lockfile change adds only a direct test dependency on already-locked
`serde_yaml_ng` 0.10.0. No package version or checksum changes. All validation gates
remain unrun by instruction and must be run by the authorized validation owner.
