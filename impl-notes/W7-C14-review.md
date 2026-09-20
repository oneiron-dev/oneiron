# W7-C14 existing review findings — consolidated disposition

This reconciles the two existing internal reports. It is not a new review.
Head examined: `c1736fef2a6d9d30fa6e2636a7c7d6944814772a`. A fresh `gh pr view w7/W7-C14`
returned **no PR for this branch**, not a quota error or pending review. Therefore
Qodo, Codex, and CodeRabbit top-level comments, reviews, and inline threads do not
exist for this branch yet. The PR933 packet concerns another branch and is not
applicable. Raw lookup/head receipts remain in `target/w7-checks/review-reconcile/`.
When a PR exists, its latest complete external review set must be collected before
review-driven changes, and dispositions plus validation must be posted there.

Sources (unchanged raw reports retained in this worktree):
- `.w7/surface-acceptance-audit.md` — steps 1–18 and 26–28.
- `.w7/document-acceptance-audit.md` — steps 19–25.
The original read-only reducer's transcript was retained after session recovery.
This ledger completes its reconciliation without replacing the original reports.

Statuses: **Repaired** means current code/test addresses the finding; runtime
coverage is only the already recorded scoped proof. **Not required** means the
extra condition is outside this cluster's stated acceptance, not a claim that the
suggested test exists. **Pending** is still acceptance work; no blanket pass.

## Surface findings

| ID | Existing finding | Current disposition and evidence |
|---|---|---|
| S01 | Connected search/execute/ask parity absent | Repaired: `crates/oneiron-server/src/api/facade/tests.rs` and remote facade tests exercise embedded/HTTP results; the 23-test server repair run and remote suites passed. |
| S02 | search searches SDK docs, not memories | Not required: OF-246's SDK-stub discovery is the selected `search` door. Vault retrieval remains the typed query/recall path. `memory/verb_table/verbs.rs` and `.w7/sdk-context.md` record the distinction. |
| S03 | ask has no standard/deep composer | Not required: step 1 requires a round-trip read surface, not host model/composer injection. Minimal chat is engine-side; unsupported host-only callbacks are not serialized. |
| S04 | WS census, host-only exclusion, MCP opt-in absence tests missing | Table/codegen and wire route census are implemented in `memory/verb_table`, `scripts/sdk/generate.py`, server facade and livequery dispatch. No new hand-listed binding exists. Extra negative tests are not step 1/17/18 acceptance; MCP context-pack remains opt-in. |
| S05 | Span cursor lacks historical Loro storage | Not required: acceptance explicitly requires recorded-version resolution and stale-version refusal. `lens/mediation/span_handles.rs` reconstructs a deterministic document from exact pinned bytes; `lens/tests/span_handles.rs` proves cursor/version binding and stale refusal. It does not claim historical editing. |
| S06 | Hidden graph target only tested at atom decoder | Projector reads through scoped visibility; graph bounds/duplicate/dangling rejection and five-section fixture are tested in `lens/tests/vault_lens.rs`. A separate hidden-neighbor scenario is extra coverage, not evidence of a bypass. |
| S07 | on-this-day uses search_claims_as_of rather than recall | Repaired behavior: projector uses valid-time claim reads, and the current/last-year fixture proves re-query plus scrubber transition. Renaming this to a different API would not improve the asserted law. |
| S08 | Missing-intent rollback and inactive skip-regen tests absent | Not required additional branches: `lens/mounts.rs::regenerate_on_upgrade` returns the last-good revision on missing intent and refuses regeneration of inactive mounts. Required stored-intent, diff gate, and regeneration failure behavior is tested in `lens/tests/mounts.rs`. |
| S09 | In-memory mount registry loses registration on restart | Not required: step 7 persists intent prompts, not executable shell registrations. `put_lens_intent` stores replicated records; the host supplies the mount registry. No restart-persistent registry is claimed. |
| S10 | Held→approve→publish for the same intent absent | Repaired: `artifact_hosting/tests.rs::publish_verb_parks_then_approved_once_publish_replays_after_reopen` and `publish_approval_binds_artifact_channel_version_actor_and_intent`; approved pending/crash recovery in `artifact_hosting/publish/tests.rs`. Covered in the 404-test changed-core run. |
| S11 | Cross-artifact grant negative absent | Repaired: exact grant codec/scope test plus approval binding test in `artifact_hosting/tests.rs`; scope contains the artifact identity and cannot authorize another artifact. |
| S12 | Public-tier enabling door absent | No cloud/public tier was introduced. It stays off; local publication still requires the gated per-artifact action. Step 27's explicit acceptance is pinned blob publish/preview/repoint/local bytes, not provisioning a cloud service. The implementation notes preserve this limit; no public-hosting enablement is claimed. |
| S13 | Blob HTTP bytes unproven | Repaired: `oneiron-server/src/api/tests/surface_routes.rs::local_artifact_route_serves_pinned_blob_exports`, in the 91-test server integration pass. |
| S14 | Hosting matches code/blob rather than family id; locator guard pending | Repaired: registry `ArtifactFamilyKind` is the closed dispatch enum. Matching its Code/Blob variants is family-kind dispatch, not raw-byte ad hoc branching. `anchored_annotation` family/locator admission passed the changed-core run. |
| S15 | Skill-trigger bidirectional test absent | Additional coverage, not step 28 fixture requirement: task/run both directions and Proposed reports/candidates are tested in `artifact_hosting/provenance/tests.rs`. Skill uses the same typed trigger/ledger projection; no separate sidecar. |
| S16 | HTTP context assembly bypasses streaming publish barrier | Inapplicable to a one-shot context response: API applies Scope during assembly; model-generation chunks must use `disclosure/generation.rs`. The host-loop requirement is explicit. Core widening/redaction and server unidentified-reader/absence-clamp tests passed. No hosted streaming model loop was added. |
| S17 | Cross-vendor adversarial pass absent | Not required by steps 9–11 acceptance. Scoped context red-team and widening barrier tests exist and passed. No empirical cross-vendor model claim is made. |
| S18 | Separate ranking bypass tests at EP1–EP4 absent | Additional coverage: Scope is an admission conjunct, not a ranking input. Assembled-context red-team tests prove exclusion; acceptance does not mandate four new retrieval variants. |
| S19 | Reaction HTTP toggle/pills/inbox and context slot untested | Repaired: `api/tests/reactions.rs::reaction_routes_roundtrip_pills_signals_and_membership_visibility`, included in server integration proof. Core T1–T8 covers record/group/signal behavior. |
| S20 | ParticipatesIn substitutes missing CONV-05; raw reads unfiltered | Current base has no shared CONV-05 door. Reaction API/read paths enforce message membership-time visibility and fail closed. Low-level storage reads are not actor-authorized surface routes. The fixture proves late-member exclusion. Future convergence with a new shared visibility implementation is not a permissive fallback. |
| S21 | Tapback unsupported planning error only direct catalog lookup | Repaired: `outbound/tests/reaction_capabilities.rs` dispatches unsupported LINE/MfB/email/LinkedIn react intents, asserts typed capability refusal and zero executor calls. |
| S22 | 65-scalar / non-vocabulary bridge glyph test absent | Glyph bounds are covered by reaction codec/admission tests. Step 13 requires manifest vocabulary and typed unsupported-verb planning; provider send implementation and a glyph catalog are explicit non-goals. Extra transport-vocabulary tests are not claimed. |
| S23 | LinkedIn reaction unsupported row absent | Repaired: reaction-capabilities test explicitly includes `linkedin` and asserts `Unsupported`. |
| S24 | Container-command argv not separately tested | The production command runtime is implemented; required provision/destroy/vault-ref/catalog acceptance uses the injected harness in `linkedin_connector/sandbox_host/tests.rs`. No real container or host install is claimed. Argv inspection is extra coverage. |
| S25 | Sandbox/LinkedIn full-vault reopen test absent | Existing durable reservation and consume-before-send rows are vault-scoped. Step 14 duplicate-send and step 15 lifecycle tests pass. Additional full-vault restart variants are not stated acceptance. |
| S26 | Connect request uses existing DM cap counter | Intentional conservative seat cap: the same seat send budget covers both DMs and connect requests. The cap/kill-switch regression in `outbound/tests/linkedin_connect.rs` prevents transport. A new independent allowance could weaken the hold. |
| S27 | LinkedIn pre-read not isolated in assertions | Existing fake observation sequence is exhausted after dispatch, transport called once, and the unverified-return case cannot deliver. Tests prove before/after observation and duplicate guard; no new isolated test required. |
| S28 | Gmail non-owner human, cross-intent, reopen variants missing | Existing owner-authority transaction check, digest binding, consume-once key and changed-message/readonly/unapproved tests cover the required approval/send posture. Those variants are additional coverage, not evidence of an authorization bypass. |
| S29 | Broad OAuth modify/compose not tested | Mapping is closed to explicit MailSend; inbox read behavior stays separate. Existing scope/readonly tests pass. No broad OAuth inference is introduced. |
| S30 | ONE-1824 closure unavailable | No administrative closure is claimed. The delegated-grant substrate exists on this base and fake-wire integration passes; the external issue status does not invalidate the implemented seam or authorize a live send. |

## Document findings

| ID | Existing finding | Current disposition and evidence |
|---|---|---|
| D01 (G1) | Organ dependency fitness absent | Repaired implementation: `scripts/tests/test_docedit_direction.py` traverses actual workspace dependency declarations and proves engine→organ, never reverse. It avoids source-string assertions. The existing fitness check is now wired into offline CI; its exact command passed (one test). |
| D02 (G2) | Second corpus / unchanged-engine number absent | **Still pending:** SpreadsheetBench fresh truth and all three complete comparisons now recorded. Native570/2951 vs LO2648/2951; unchanged753/2951 is far below the canon threshold. FUSE fresh truth started once after SB custody release; its measurement/comparisons and the full rewrite decision remain open. No default promotion. |
| D03 (G3) | Mac-absent functions unwired | Repaired: `oneiron-xlsx-formula/tests/session.rs::windows_only_functions_return_name_errors_in_the_native_mac_session` passes through the real session; ENCODEURL/FILTERXML/WEBSERVICE produce #NAME?. |
| D04 (G4) | Upstream Stemma 1,060-test suite not run | Scope correction: the source fork deliberately excludes upstream app/runtime/import/diff systems. Its retained 47 annotation tests passed; the package provenance names the exact retained scope. No full-upstream suite count or capability claim is made. Step 24's native Word round trip is separately proved. |
| D05 (G5a) | 25 refused DOCX fixtures unscored | Correct accounting, not a pass claim: 40 no-op exact, 15 native proposals accepted, 25 refused/unscored. Stored measurements and canonical Word receipts preserve these categories. No requirement to fabricate support for refused protected/complex documents. |
| D06 (G5b) | Join proof synthetic, not broad corpus | The authored join fixture proves accepted/rejected text and paragraph boundaries in Word. Extra join-case selection over every corpus is not stated acceptance; 15-proposal measurement remains explicitly scoped. |
| D07 (G6) | DOCX locator bounds-only | Repaired: `anchored_annotation/model.rs::Locator::docx` calls `DocxSpan::parse` for canonical body/pN plus Unicode-scalar offsets; native anchor tests reject invalid path/version/family. Current changed-core pass includes the parser admission. |
| D08 (G7) | PPTArena stored receipt unbound | Repaired in `scripts/tests/test_office_measurements.py`: manifest hash and complete per-file retained identity receipt are checked offline. The new CI pattern executes this suite. No Office-validity claim for all PPTArena files. |
| D09 (G8a) | XLSX settlement stamp unproven | Repaired: `oneiron-xlsx-formula/tests/session.rs::native_xlsx_session_settles_once_with_bound_engine_stamp`, in the 19-test current pass. Native preparation/settlement carries engine identity and consumes once. |
| D10 (G8b) | Native XLSX Excel open-clean missing | Repaired for the acceptance fixture: native XLOOKUP Excel receipt observes 2, saves output, restores custody; stored proof is under spreadsheet-compat/measurements/native-xlookup. Full corpus accuracy remains D02, not inferred from this sample. |

## Remaining actions

1. D01 is closed: existing dependency-direction fixture command added to offline CI; one test passed.
2. D02: consume complete existing corpus jobs, compare identical fresh truth, and
   record the actual decision. Keep native opt-in unless the full threshold holds.
3. Preserve all scoped proof boundaries. A code/test path alone is not an executed
   test result; exact green commands remain in `W7-C14-validation.json` and notes.
4. Once a PR exists, refresh all external findings and post this disposition plus
   subsequent fixes/validation. No GitHub post can be attached to a nonexistent PR.
