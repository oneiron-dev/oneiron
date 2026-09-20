# W7-C08 review recovery ledger

Refreshed PR #933 REST issue comments, reviews, inline comments and GraphQL threads before fixes. Published head `0c458e0a63562eeecf75db0e90732f186a8a2c8e`; local review head `ff5e713c`. Snapshot: 10 issue comments, 3 reviews, 28 inline comments, 28 threads. No newer bodies or inline IDs since the consolidation packet. Every nested thread page is complete. Raw receipts: `/home/lexi/w7-build/tickets/W7-C08/fix-review-receipts/`; original packet: `/home/lexi/w7-build/recovery/pr933-review-consolidation-20260919/`. Internal root verdicts supplied in this fix-review session supersede incomplete child previews. Codex supplied a completed substantive review, not a quota failure or pending review.

- F01: Fallback responses bypass JSON schema. Inline IDs: 4052784002. Disposition below.
- F02: Missing own-server LLM routes. Inline IDs: 4052784004, 4052796170. Disposition below.
- F03: Done published before durable sink succeeds. Inline IDs: 4052784005, 4052796175. Disposition below.
- F04: Provider export redaction misses camelCase credentials and private keys. Inline IDs: 4052784009, 4052796173. Disposition below.
- F05: Driver featureless test unresolved imports. Inline IDs: 4052784000. Disposition below.
- F06: Gemini helper public surface. Inline IDs: 4052784001. Disposition below.
- F07: Gemini success status rejected by stream. Inline IDs: 4052784008. Disposition below.
- F08: Shadow verdict converts legacy Hold/Unavailable to Allow. Inline IDs: 4052796169, 4052800041. Disposition below.
- F09: Malformed before-tags accepted. Inline IDs: 4052796174. Disposition below.
- F10: Owner voice refs accept self-declared provenance. Inline IDs: 4052796181. Disposition below.
- F11: Consent withdrawal leaves owner source clips. Inline IDs: 4052796185. Disposition below.
- F12: Anthropic raw usage delta overwrites earlier fields. Inline IDs: 4052800019. Disposition below.
- F13: Gemini metadata-only thoughtSignature aborts stream. Inline IDs: 4052800022. Disposition below.
- F14: Remote blocking stream read ignores cancellation. Inline IDs: 4052800025. Disposition below.
- F15: Remote stream inherits 120s total response timeout. Inline IDs: 4052800030. Disposition below.
- F16: Provider wire serialization lives in core. Inline IDs: 4052800031. Disposition below.
- F17: BYOA user_login flag bypasses hosted credential restriction. Inline IDs: 4052800032. Disposition below.
- F18: Named provider runners in core. Inline IDs: 4052800034. Disposition below.
- F19: Provider wire ingest lives in core. Inline IDs: 4052800036. Disposition below.
- F20: Empty Anthropic system record accepted. Inline IDs: 4052800038. Disposition below.
- F21: Malformed text blocks imported as JSON text. Inline IDs: 4052800039. Disposition below.
- F22: Conflicting equal-time model scores overwrite nondeterministically. Inline IDs: 4052800042. Disposition below.
- F23: Scraper config accepts downstream-overlong identifiers. Inline IDs: 4052800044. Disposition below.
- F24: Soniox string error codes gain JSON quotes. Inline IDs: 4052800048. Disposition below.

Internal Opus blockers map to F08, F03, F04, F02, F01, F09, F13. Grok duplicates F08, F04, F13. Opus nonblocking findings map to F12, F24, F23, F20/F21. O01 rejected: Acceptance 24 requires exactly three bad responses, not four. O02 rejected as blocking: extraction acceptance is covered and conflict fallback uses the same declared seam; missing separate conflict coverage is informational. F05 rejected by root: test-local imports exist; voice-only glob is correctly gated.

## Final applicability assessment

### F01

Fixed: deterministic fatal fallback must satisfy the requested JSON schema before persistence; invalid fallback remains terminal, settles prior spend, and is not memoized.

### F02

Fixed: /v1/llm/generate and /v1/llm/stream now have server counterparts with owner authentication, explicit backend injection, and server-side budget admission. Real HTTP integration drives the shipped RemoteLlmClient against the server router.

### F03

Fixed: the durable sink must succeed before Done enters subscriber queues or history. A rejected terminal can be retried; no false Done is observable.

### F04

Fixed: normalize credential key case and separators, cover private/SSH keys, and reject PEM private-key values before truncation as well as at serialization.

### F05

Dismissed: the new driver test already imports its dependencies inside the function. The separate voice-only glob correctly uses cfg(all(unix, feature = "voice")). No unresolved featureless imports reproduced; internal root rejected this finding.

### F06

Fixed: Gemini accumulator and wire helpers now use private re-exports and pub(super) definitions, not a public helper API.

### F07

Fixed: stream Status frames in 200..300 continue decoding; non-success status classification is unchanged.

### F08

Fixed: legacy Hold (including all host reasons) and Unavailable survive both verdict modes. Calibrated verdict floor behavior remains shadow/enforce-specific.

### F09

Fixed: validate before and after retrieval tags before surprise calculation and any paid call.

### F10

Dismissed as a caller-boundary allegation: store_owner_voice_refs is a trusted in-process Vault owner-capture door, not a wire or guest API. No server/NAPI/Python mapping exposes it. Origin rejects vendor identity but is not an authentication token. As with record_voice_consent and enrollment, the embedding host authenticates its owner before calling; an untrusted host with a Vault already has full write authority. No authenticated remote enrollment contract is added by this ticket.

### F11

Fixed: owner-indexed reference packs are deleted inside the same transaction as biometric withdrawal/retention. Withdrawal leaves neither readable nor cloneable source packs and is reflected in already_absent.

### F12

Fixed: Anthropic raw usage merges delta keys rather than replacing the message-start raw object; typed totals stay guarded.

### F13

Fixed: thoughtSignature-only Gemini metadata is a no-op; unsupported content with a signature is still refused.

### F14

Fixed: a cancellable asynchronous response reader runs in the transport-owned worker. Dropping the stream interrupts an active network read and closes the connection.

### F15

Fixed: the streaming client has connect and idle-read deadlines but no whole-response timeout. Non-streaming calls retain the existing total timeout.

### F16

Dismissed: contract step 20 explicitly requires these provider read formats in PackFormat and the serializer. They are upstream wire protocols shared by arbitrary engine consumers, not downstream product/persona conveniences.

### F17

Dismissed as a caller-boundary allegation: DispatchByoa is an in-process host request, with user_login explicitly host-stamped; no server, NAPI or Python ingress accepts that field from a guest. The trusted host also injects the credential executor and egress authority. Dispatch and execution both enforce the host-stamped placement. A future untrusted request mapping must derive it from custody, not deserialize it as authority.

### F18

Dismissed: steps 12–13 explicitly require DreamerProviderAdapter and the three named CLI runners. They are upstream provider integrations, not downstream consumer products, and retain argv-only/handle-only sandbox execution.

### F19

Dismissed: step 19 explicitly requires registered provider IngestSources. These upstream wire protocols normalize at Imported/Proposed trust and do not introduce a downstream product into the engine.

### F20

Fixed: trimmed-empty Anthropic system text is refused with EmptyText.

### F21

Fixed: malformed text/thinking and unknown block shapes are refused instead of importing arbitrary JSON. Explicit supported tool blocks retain typed-field validation.

### F22

Fixed: same-time conflicting existing model/benchmark observations are rejected atomically; identical same-time replay stays idempotent.

### F23

Fixed: source IDs and benchmark identifiers over 128 bytes are rejected during scraper config validation before fetch.

### F24

Fixed: Soniox string error codes are extracted as strings; numeric/non-string codes retain JSON fallback.

## New Codex findings on `ff98e02b`

The latest complete refresh has 12 top-level comments, 4 reviews, and 34 inline comments/threads. Codex review 5255585686 completed (not quota-blocked). Original 24 groups remain above; these six additions are assessed and fixed separately. Qodo marks its six valid original items resolved and repeats F05, whose function-local imports still refute it. Cursor reported usage exhaustion; CodeRabbit auto-review is disabled. The C03 cross-ticket clarification is not C08 validation.

- **F25**, inline **4053051176**: Fix. Add bearer/auth/API token and passphrase aliases to pre-truncation redaction.
- **F26**, inline **4053051180**: Fix. Compare every benchmark in one snapshot against the pre-snapshot source watermark; newer multi-benchmark updates and equal-time conflict rollback are tested.
- **F27**, inline **4053051182**: Fix. Require matching declared block types; untyped text is restricted to Gemini parts.
- **F28**, inline **4053051185**: Fix. Derive server budget locality from the vault model catalog, never from the client envelope; ContinueOnLocal cannot turn a third-party call into free local spend.
- **F29**, inline **4053051189**: Fix. Refuse empty reasoning and malformed structured fallback messages before memoization.
- **F30**, inline **4053051191**: Fix. Started calls without terminal usage conservatively charge their own reservation; terminal usage still settles exactly once. Cancellation and stream-error paths are tested.

Server-production Clippy initially refused a large Response error variant; the admission helper now boxes that internal error rather than suppressing the lint. Final-source regressions passed: 56 featureless core tests and 3 real/controlled server route tests. Production server Clippy passed after boxing the error. The detailed command evidence follows.


## Completed repair validation

All six touched crates were tested on the MacBook through the normal factory wrapper, with at most 3 Cargo jobs and 3 test threads, and `.w7/real-tmp.toml`:

```text
cargo test --no-fail-fast -p oneiron -p oneiron-remote -p oneiron-server -p oneiron-llm-gemini -p oneiron-llm-anthropic -p oneiron-llm-own-server --config .w7/real-tmp.toml -- --test-threads=3
```

That completed command recorded **8,746 passes, 21 ignored, and one failing socket-closure assertion**. The cancellation implementation closed the macOS connection with `ConnectionReset` rather than EOF. The fixture was corrected to accept either closed-socket result, but not a timeout or live connection. Its entire target was rerun:

```text
cargo test -p oneiron-llm-own-server --test remote_transport --config .w7/real-tmp.toml -- --test-threads=3
```

**4 passed, exit 0**, including active-read cancellation. The other completed target passes are reused, not rerun:
- Core: **7,061** library tests; **473** main integration tests; **184** sync tests; other integration/compile-fail/doctest targets passed.
- Server: **749** library tests and **91** main integration tests; managed, privacy, and WebSocket tests passed. Both real own-server route tests passed.
- Anthropic **10**, Gemini **3**, own-server **1**, remote SDK **7** unit tests passed, plus all remote SDK integration targets.
- `cargo test -p oneiron --lib --no-default-features --config .w7/real-tmp.toml -- --test-threads=3`: **6,558 passed, 0 failed, 4 ignored**, exit 0.
- `cargo clippy -p oneiron-llm-gemini --all-targets -- -D warnings`: **exit 0**. This covers the private production import correction; its unit-test expansion did not change.
- Server-production Clippy initially failed only on the new admission helper's large `Response` error variant. The helper now boxes that internal response; repeat Clippy passed (exit 0).

Additional completed Codex findings were fixed after the broad runs. The exact final-core command was:

```text
cargo nextest run -p oneiron --no-default-features --lib -E 'test(llm::registry::tests) | test(llm::step::tests) | test(ingest::tests::provider_) | test(serialize::tests::provider_)' --test-threads 3
```

It passed **56 tests**, exit 0. `cargo test -p oneiron-server --lib api::llm::tests --config .w7/real-tmp.toml -- --test-threads=3` passed **3 tests**, exit 0. These cover real authenticated remote routes, catalog-derived locality under exhausted ContinueOnLocal, and both cancellation/error reservation settlement.

`cargo clippy -p oneiron-server --all-features -- -D warnings`: **exit 0**, checking the production `sync` selection without test-feature unification.
Formatting applied with `cargo fmt -p oneiron -p oneiron-server` (exit 0), then the final source compiled and passed the focused tests. Code-map pin **CODEMAP-OK** (2534 files); structural ratchet **RATCHET-OK** (2/98/91/33); root-surface **ROOT-SURFACE-OK** (701); `git diff --check` exit 0.

Source hashes and exact command logs/exit receipts are retained in `tickets/W7-C08/fix-review-receipts/`. No interrupted or partial run is counted as a passing command. This is scoped ticket validation, not the full workspace gate.

## Latest bot recovery on `8504e489`

Before editing, refreshed all paginated REST issue comments, reviews and inline comments,
plus GraphQL review threads. Intake: 15 issue comments, 6 reviews (including an untouched
owner-pending review), and 40 complete inline threads. The six new Codex findings are
F31–F36 below. The original 24 groups and subsequent F25–F30 retain their individual
fix/dismissal decisions above. Raw bodies, IDs, timestamps, exact head, internal roots,
and source hashes are preserved in `tickets/W7-C08/bot-recovery-receipts/`.

The original root continuation supplied actual DEFECTS verdicts; both later internal
recheck transcripts end with LANDABLE. Their evidence predates this final six-finding
repair and is not represented as review of the new bytes. O01/O02 remain rejected as
blocking by the original root, not promoted from child previews. No fresh fanout was
started. The prior standard factory run finished with exit 0 and 8,876 tests; interrupted
postbot builds are not counted. A new standard nine-crate rerun is required below.

- **F31**, inline **4053121156**: Fixed: compile the requested schema before any native dispatch; validate native output locally without adding shim prompts or corrective retries. Invalid output settles actual usage and is not memoized.
- **F32**, inline **4053121160**: Fixed: generate uses cancellable async HTTP in the existing transport-owned worker; dropping the future cancels both the pending headers and active body read. The non-streaming total timeout remains 120 seconds.
- **F33**, inline **4053121161**: Fixed: catalog seeds reject both scores and fetched_at metadata before opening the insertion transaction. A poisoned row cannot block subsequent score snapshots.
- **F34**, inline **4053121164**: Fixed: source errors and synthesized premature-EOF StreamCut close current and late subscribers without publishing or persisting Done(Cancelled). Explicit host cancellation retains the existing terminal behavior.
- **F35**, inline **4053121168**: Fixed: own-server generate and streamed Done validate tool call IDs/names/input, image media type and URL/base64 payload, empty text/reasoning, and assistant-role compatibility. ToolResult is not assistant output.
- **F36**, inline **4053121172**: Fixed: provider ingest checks provider-specific roles; only Gemini model is normalized to assistant. OpenAI developer and legacy function roles remain supported; Anthropic system text stays in its top-level field.

Codex is completed, not quota-blocked or pending. Qodo now marks its valid original
items resolved and repeats only F05 (test-local imports disprove it). CodeRabbit’s
original 14 findings remain accounted for; its latest automatic review is disabled.
Cursor’s explicit usage-limit notices are provider failures, not pending reviews.
CodeRabbit docstring coverage and risk labels are informational under `REVIEW.md`,
not new correctness findings. C03/C04 cross-ticket comments are not C08 validation.

Canon clarification: native structured output bypasses the corrective *shim*, not the
local schema-validation boundary. Stream failure is not caller cancellation. Catalog
seeds carry no fetched score metadata. No docs-repository edit was made.

### Validation custody and current limit

Repair commit: `8b439482`. All 13 changed Rust files still match the source-hash
manifest captured before validation. Code-map and `git diff --check` pass.
The final Rust validation has **not completed** and is not represented as green.

The correctly routed durable service is `w7-c08-bot-routed-validation.service`.
It explicitly receives the factory wrapper PATH plus `W7_CARGO_WORK` and
`W7_CARGO_HOSTS`; it holds the C08 ticket lock and obeys existing host-slot locks.
At this handoff all three MacBook slots and both Arch slots are occupied; the
mini is below its 30 GiB reserve. No extra build or host-budget bypass was started.

The service runs the unchanged standard nine-crate Cargo command, then owning-crate
formatting/Clippy, focused featureless regression tests, code-map and diff checks.
Exact argv and eventual exit receipts are in `bot-recovery-receipts/validation.json`
and `validation-*.json`, with sibling full logs. Inspect those receipts before
claiming a pass or replacing the job; do not launch a duplicate.

Two interrupted starts are excluded from evidence. The first lost its process during
a session handoff. The first durable start had the wrapper PATH but omitted routing
settings, so it fell through to direct Arch Cargo without acquiring factory locks.
That service alone was stopped to correct the routing error, not because a test failed
or exceeded a clock. Its partial log is retained under
`bot-recovery-receipts/interrupted-unconfigured-service/`. No source or genuine prior
writer/test/review receipt was discarded. Neither partial run is a terminal pass.

The reply REST endpoint refused new comments while an empty account-owned draft
review existed. All 40 authorized replies were therefore attached to that same draft
through the thread API. Before comment-only submission, its body was still empty and
its comments matched exactly these 40 responses; no other authored draft content was
published or deleted. No approval, push, merge or close is authorized by this receipt.

### Preexisting review provenance clarification

Review `5255668739` predated this continuation. Its original authoring session is
unverified; the authenticated account name did not establish its provenance or
authority to publish it. At 13:25:36Z it was submitted as `COMMENT` after a check
confirmed an empty body and exactly the 40 replies added by this continuation.
The review ID and all comment bodies were preserved, but its prior PENDING state
was not. No approval or merge occurred. No further mutation or deletion of that
review is planned. For any future preexisting draft of unknown provenance, use
the PR issue-summary path unless the owner explicitly directs otherwise.

The latest owner guidance identifies the live validation custody as
`w7-c08-bot-routed-validation.service`, driver PID 3415120 and Cargo child 3415121.
The old `w7-c08-bot-recovery-validation.service` is not the current job. Running
or queued checks are productive waiting, not a terminal BLOCKED result. Consume
the existing job's terminal receipts before final validation disposition; do not
create another build or observer.

### Productive-wait review refresh

A complete read-only refresh captured 16 issue comments, 20 reviews, 94 inline
comments and 40 threads at unchanged published head `8504e489`; all nested
comment pages are complete. Raw responses and body deltas are retained under
`bot-recovery-receipts/productive-wait-refresh/`. Source and validation custody
were not changed. Codex has no new review or provider error. Qodo now reports
zero bugs and zero rule violations after withdrawing its driver-import finding.
The new C03/C04 issue-comment updates remain those tickets' evidence, not C08's.

Thirteen bot follow-ups acknowledge earlier repairs or withdraw findings. The
remaining follow-up, `4053305926`, repeats F18. Re-reading CLAUDE.md confirms that
its consumer boundary concerns downstream products built on top of Oneiron.
These CLI programs are upstream inference providers available to any host, and
step 13 explicitly says the engine ships all three named runners. The source
constructs generic sandbox connectors with caller-supplied task text and handles;
it adds no consumer persona, product-specific endpoint, state, or write authority.
The dismissal stands; removing these adapters would remove required support.

| Follow-up comment | Original comment | Disposition |
| --- | --- | --- |
| 4053305535 | 4052800030 | Acknowledgement/withdrawal; no new defect. |
| 4053305545 | 4052800038 | Acknowledgement/withdrawal; no new defect. |
| 4053305566 | 4052800031 | Acknowledgement/withdrawal; no new defect. |
| 4053305747 | 4052800039 | Acknowledgement/withdrawal; no new defect. |
| 4053305762 | 4052800041 | Acknowledgement/withdrawal; no new defect. |
| 4053305867 | 4052800044 | Acknowledgement/withdrawal; no new defect. |
| 4053305878 | 4052800048 | Acknowledgement/withdrawal; no new defect. |
| 4053305887 | 4052800025 | Acknowledgement/withdrawal; no new defect. |
| 4053305926 | 4052800034 | Repeated F18 objection; dismissed for the contract and upstream/downstream distinction described above. |
| 4053305970 | 4052800042 | Acknowledgement/withdrawal; no new defect. |
| 4053305974 | 4052800036 | Acknowledgement/withdrawal; no new defect. |
| 4053306067 | 4052800022 | Acknowledgement/withdrawal; no new defect. |
| 4053306258 | 4052800032 | Acknowledgement/withdrawal; no new defect. |
| 4053307623 | 4052784000 | Acknowledgement/withdrawal; no new defect. |

`4053305535` confirms the earlier published transport split only. The local F32
repair later moves generate to cancellable async I/O while preserving its explicit
120-second total timeout. No bot acknowledgement is counted as validation of that
new source. The 14 new empty review bodies are containers for these replies, not
additional findings; their review IDs are retained in `dispositions.json`.

### Standard terminal result and scoped environment retry

The correctly routed standard command completed on Arch slot 2/2 at
2026-09-19 14:00:48Z with Cargo exit 101: **8,880 passed, one failed, 21 ignored**.
Every non-core-library target passed, including all changed provider/transport
crate tests and doctests. The failed core test was
`git_wire::tests::git_wire_reads_absence_positively_and_keeps_fatal_failures_typed`.
All six new fix areas' regression tests passed within this completed command.
This is a failed standard-command receipt, not a claimed exit-zero full run.

The harness's `TMPDIR=target` override placed the temporary Git repository inside
the Oneiron checkout. After the test deleted its `.git`, Git discovered the
ancestor checkout instead of producing the fatal-not-a-repository response the
fixture was testing. Restore the normal host temporary directory for this retry;
no assertion, production source, fixture bytes, or behavior is weakened or changed.
The existing canonical-temp-root secret fixtures already handle macOS aliases.

The failed service is terminal (`MainPID=0`, `ExecMainStatus=1`). Its receipts are
preserved. The sole successor is `w7-c08-bot-validation-followup.service`, with
receipts under `bot-recovery-receipts/post-standard-followup/`. It reruns exactly
the failed test with the same nine-package feature selection and no nested-TMPDIR
config, then runs the previously unexecuted fmt, Clippy, featureless, code-map and
diff checks. All 13 repaired Rust files match the original admission SHA-256 map.
The other 8,880 passing outcomes are retained instead of rerunning unchanged tests.
The new run must finish before any complete validation disposition is claimed.

A fresh full GitHub intake before this environment repair retained all prior
findings and root adjudications. CodeRabbit follow-up `4053384666` withdraws F18,
confirms the upstream-provider distinction, and resolves the thread. It requires
no source change. The corrected guideline interpretation is already recorded in
this ledger; no external bot-learning record was deleted or modified.


### Final completed validation

**Validation is complete.** All seven commands in the final retained service completed with exit 0; the service ended with `Result=success`, `ExecMainStatus=0`, `MainPID=0`.

| Command / scope | Actual result |
| --- | --- |
| Standard nine-package command below, Arch factory slot 2/2 | Completed with Cargo **101**: **8,880 passed, 1 failed, 21 pre-existing ignored**. The sole failure was the temporary-directory fixture described below. This original command is not relabeled as a pass. |
| Same nine-package selection, no nested-TMPDIR config, exact Git fixture retry | Arch slot 2/2, exit **0**: **1 passed**, 0 failed; core target had 7,088 filtered. |
| `cargo test -p oneiron-llm-own-server --test remote_transport -- --test-threads=3` | Arch slot 1/2, exit **0**: **4 passed**, 0 failed. Fresh after the test-helper lint changes. |
| `cargo fmt -p oneiron -p oneiron-remote -p oneiron-llm-own-server --check` | Arch slot 1/2, exit **0**. |
| `cargo clippy -p oneiron -p oneiron-remote -p oneiron-llm-own-server --all-targets --all-features -- -D warnings` | Arch slot 1/2, exit **0**. |
| Focused featureless command below | MacBook slot 2/3, exit **0**: **19 passed**, 6,549 filtered by the stated selection. The complete featureless library test target compiled. |
| `scripts/codemap/check.sh` | Exit **0**: 2,534 files, 18 current artifacts. |
| `git diff --check` | Exit **0**. |

Standard command actually executed:
```text
cargo test --no-fail-fast -p oneiron -p oneiron-driver -p oneiron-llm-anthropic -p oneiron-llm-gemini -p oneiron-llm-local -p oneiron-llm-openai -p oneiron-llm-own-server -p oneiron-remote -p oneiron-server --config .w7/real-tmp.toml -- --test-threads=3
```
The override put temporary Git repositories inside this checkout's `target/`. When `git_wire::tests::git_wire_reads_absence_positively_and_keeps_fatal_failures_typed` deleted its `.git`, Git found the parent checkout rather than reporting a fatal missing repository. The retry used the identical nine-package selection, removed `--config .w7/real-tmp.toml`, and used:
```text
-- --exact git_wire::tests::git_wire_reads_absence_positively_and_keeps_fatal_failures_typed --test-threads=3
```
No production fix, test assertion change, or ignore was needed. All 13 repaired Rust files matched the standard-run source hashes at that retry. Its one pass closes the sole failure; the other 8,880 completed passing outcomes are retained instead of rerunning unchanged tests.

Focused featureless command:
```text
cargo nextest run -p oneiron --no-default-features --lib -E 'test(llm::step::tests::native_) | test(llm::step::tests::schema_) | test(llm::registry::tests) | test(llm::streaming_tests) | test(ingest::tests::provider_)' --test-threads 3
```
Final validation also caught and repaired one deterministic rustfmt line join plus 15 fixture-helper `unwrap()` diagnostics and a complex tuple type. The changes only add `expect()` diagnostics and a private `CapturedRequest` alias. Production code and integration test bodies remain unchanged; all four transport cases were rerun. The final hashes retain 11 of the 13 original files byte-for-byte; the two changed test files have only these reviewed formatting/diagnostic changes.

All Cargo commands used factory host/ticket locks with three compiler jobs and three test threads. Full command, output, hash and exit receipts are retained under `validation-standard.*`, `post-standard-followup/`, `final-checks/`, and `lint-checks/`. Failed fmt/Clippy receipts remain recorded; the final commands supersede them. Two earlier interrupted starts are excluded entirely, including the corrected first durable start that omitted host-routing settings. No partial run is counted as a pass. This is changed-crate and focused featureless validation, **not a claim that the nine-stage workspace verification script ran**.

Final read-only GitHub intake: 16 issue comments, 22 reviews, 96 inline comments, 40 complete threads; published head remains `8504e489`. No new inline finding. C03 comment `5741434829` updated its own test evidence, which is not used for C08. CodeRabbit withdrawal `4053384666` closes F18. All original 40 findings have replies; no additional review/draft mutation, push, merge, or close was performed.


## Post-publication refresh during merge-test recovery

Complete read-only intake at published head `d7a435af`: **16 issue comments,
25 reviews, 110 inline comments, 54 threads**. All thread and nested-comment
pages are complete. No pending review/draft was published, changed or deleted.
The original internal review dispositions above remain preserved; they do not
cover this newer 14-comment intake. Deduplication yields the groups below.

| Group | Inline comment IDs | Current disposition |
| --- | --- | --- |
| F37 | 4053640019 | **Dismissed**: Pre-release-only legacy BYOA payload compatibility. This build writes and reads user_login; REVIEW.md excludes migration/default work for never-shipped formats. |
| F38 | 4053663354 | **Fixed locally, validated**: Validate streamed own-server events and their sequence before publication. |
| F39 | 4053663356 | **Fixed locally, validated**: Preserve Gemini interleaved content-part ordering. |
| F40 | 4053663362, 4053664836 | **Fixed locally, validated**: Enforce provider-specific ingest block and auxiliary-field grammars. |
| F41 | 4053663367 | **Fixed locally, validated**: Preserve typed generate errors over own-server HTTP. |
| F42 | 4053663374 | **Fixed locally, validated**: Bind or refuse a model when a resident route narrows locality. |
| F43 | 4053663380 | **Fixed locally, validated**: Re-admit paid schema correction attempts under the budget cap. |
| F44 | 4053663384, 4053664847 | **Fixed locally, validated**: Apply declared purpose locality defaults; duplicate reports. |
| F45 | 4053664831 | **Fixed locally, validated**: Settle the reservation when successful terminal usage is unavailable. |
| F46 | 4053664842 | **Fixed locally, validated**: Reject ToolResult in assistant fallback terminal content. |
| F47 | 4053664851 | **Fixed locally, validated**: Drop whitespace-only voice chunks, including timer and Done flushes. |
| F48 | 4053664852 | **Fixed locally, validated**: Avoid partially committed multi-source score refreshes. |

The preserved nine-crate baseline completed with exit 0: **8,897 passed,
0 failed, 21 ignored**. All 2,559 pinned source files matched. Its actual result
is recorded in `baseline-terminal.json`; the separate pidfd event was only a
completion notification. The prepared repairs were applied only after that
terminal result was consumed. Their scoped validation is now complete: **249 all-feature tests** on the Mac
mini and **201 featureless core tests** on Arch passed, with zero failures.
The five changed crates passed all-target/all-feature Clippy. Core featureless
all-target Clippy and server-production Clippy also passed. The final
production-only check used normal MacBook-first routing and ran no vault tests.
All checks are bound to the repaired source at `13b4597b`; formatting and the
code-map pin passed. No full-workspace VERDICT is claimed. The initial nextest
flag error ran no tests and remains recorded separately.

All 14 comment IDs now have posted replies. F37 is reply `4054084301`.
The remaining replies, in finding-ID order, are `4054328760`, `4054328761`,
`4054328763`, `4054328779`, `4054328762`, `4054328780`, `4054328782`,
`4054328764`, `4054328776`, `4054328768`, `4054328765`, `4054328766`,
and `4054328767`. The exact mapping and API receipts are in
`pr-refresh/new-dispositions.json` and `repair-inline-replies/`. Own status
comment `5744404350` supplies the final validation update without reposting
findings or changing a human draft.

The final complete read-only intake has **17 issue comments, 39 reviews,
124 inline comments and 54 threads**, still at published head `d7a435af`.
No new or edited finding was present, and no pending review was returned.
Thread and nested-comment pagination is complete. This seat has not pushed
these local repairs or changed approval, thread state, merge, or close state.

Raw feedback, source bindings, failed and successful command logs, per-case
results, and terminal receipts are retained under
`tickets/W7-C08/fix-tests-after-merge-receipts/`; the final intake is in
`repair-terminal-pr-refresh/`. The original F01–F36 and internal-review
records above are retained unchanged.


## Current-head intake and C01 merge (2026-09-20)

Read-only PR **#933** intake at published head `0c7320ed` includes **18 issue
comments, 40 reviews, 127 inline comments, and 57 threads**. Every REST surface
was paginated; every outer and nested GraphQL page is complete. Raw snapshots
and the delta from the previous complete intake are retained under
`tickets/W7-C08/current-main-merge-receipts/intake/`.

F01–F48 and the original internal Opus/Grok roots, child findings, dismissals,
and rechecks above remain intact. Their historical LANDABLE rechecks do not
constitute a new-head approval. Two context reducers were interrupted before
terminal reports; their captured intake/transcripts are retained and the root
completed reconciliation. No replacement reviewer fanout was started.

- Qodo comment `5740808018` reports zero bugs/rule violations and marks its
  historical reports resolved; no new repair is requested.
- CodeRabbit comment `5740792880` now says automatic review is disabled. Its
  retained old walkthrough/risk notes are historical F01–F48, not fresh findings.
  Docstring coverage is informational under REVIEW.md.
- Codex comment `5746428374` is an explicit usage-limit error: **unavailable**,
  not pending and not a passing review.
- Cursor review `5258564946` on `0c7320ed` introduces the three groups below.
  Its top-level summary `5740793353` is not a fourth finding. Old review
  `5256231550` is explicitly stale. Own comment `5744404350` records earlier
  validation and is not independent review evidence.

| Group | Source inline ID | Disposition |
| --- | --- | --- |
| F49 | 4055422429 | Valid: consecutive Gemini text deltas need a stable part ID without losing text/tool/reasoning order. Fixed and validated by the provider regressions in the 469-test scoped run (the separate consolidation/voice failures are recorded below). |
| F50 | 4055422435 | Valid: omitted args on a parameterless Gemini tool call should decode as an empty object; malformed present args must still refuse. Fixed and validated by the provider regressions in the 469-test scoped run (the separate consolidation/voice failures are recorded below). |
| F51 | 4055422440 | Valid: repeated complete OpenAI tool IDs/names must not concatenate; fragmented fields still need accumulation. Fixed and validated by the provider regressions in the 469-test scoped run (the separate consolidation/voice failures are recorded below). |

No feedback from another ticket is applied to PR #933. No review draft or
thread state was changed. The current-head Opus ladder is still required after
these repairs; first-party default, alt, alt2, then CPA only for proven provider
unavailability. GitHub explanations will name actual source IDs and validation.


### First-party current-head review and integration test reconciliation

Native first-party default-profile Opus (`claude-opus-5`, session
`97ea64e4-5600-4163-8c82-a189a474d762`) returned **LANDABLE** on clean
`d177c71d`. Its complete result and original stream remain under
`tickets/W7-C08/sessions/review-opus-ladder/d177c71de57905622530c6402fcf405a5ef44edf/`.
No availability fallback was needed. This approval is historical once the
following integration repair lands; the SAME reviewer root will check the delta.

The 469-test scoped run passed 466 and failed three. All F49–F51 regressions
passed. Two consolidation failures and one voice fixture failure exposed the
combined behavior of the parents; no failed run is counted green:

- T01: C08's fatal-judge fallback now finishes with `escalate`, bypassing C01's
  exception-only open-conflict marker. Escalation now persists the same gated,
  scope-fenced marker, as well as its existing reflection gap. The prior-head
  test still pins the unchanged original and open question; completion replaces
  parking only when the declared deterministic fallback finishes.
- T02: The structured-output shim rejects an unlisted candidate ID and runs two
  corrective attempts before parking. The scoped-embedding fixture now supplies
  those attempts and checks that every attempt retains the identical scope.
  Missing semantic candidate identity still returns the typed refusal; no sink
  output is accepted for either invalid response.
- T03: The voice lifetime test used fatal extraction as a non-completing stop,
  but fatal extraction now has a completion fallback that correctly refuses the
  fixture's unsupported scoped sink. It now sends `BudgetDenied::AdmissionDenied`
  to park the held task. All connection, shared-meter, cancellation and shutdown
  assertions remain unchanged. Production scoped-sink refusal is not weakened.

The review's four informational observations require no code repair:
1. Literal locality overwritten by purpose defaults: naming/comment clarity only;
   the intentional effective defaults and scoped model binding are preserved.
2. `ContinueOnLocal` assumes a trusted injected backend honors the engine-declared
   extraction route. This is the stated on-device purpose default, not an HTTP
   bypass (HTTP derives catalog locality); hosts must bind the actual model route.
3. Ingest `skill_id` namespace differs for three sources: inert naming only; all
   source IDs are unique and the two Gemini format doors are now distinct.
4. Empty fallback `people` metadata is unused (`persons` is the extraction door):
   extra empty metadata is allowed and creates no people. No behavior changes.

Final complete API refresh remains **18/40/127/57**, with no new or edited
finding. The PR response's base SHA was stale; Git remote and GitHub's branch
API both confirm current main is `60c5b875`, already an ancestor. No new merge
or full-baseline retest is needed. Targeted integration retest and final same-root
review follow this repair; terminal evidence will be posted to PR #933.
