# WORKLOG — ONE-1779 [CA-08] consultancy preset content

Worktree: `/Volumes/Cinema/w5-lt/ca-1773` · branch `ONE-1779` off `origin/main`
0eff00d21 (1775 #627 stage ladder + 1778 #630 surface merged — CA-B dispatch
gate satisfied; `StageLadderDefinition` consumed live, never re-spelled).
Blueprint: `/Users/olety/.claude-wave5/blueprints/CA/ONE-1779.md`.
Claims: `/Users/olety/.claude-wave5/blueprints/CA/CLAIMS.md`.

## Packet — exact

CREATE
- `/Volumes/Cinema/w5-lt/ca-1773/crates/oneiron/src/campaign/presets.rs`
- `/Volumes/Cinema/w5-lt/ca-1773/crates/oneiron/src/campaign/presets/tests.rs`

MODIFY
- `/Volumes/Cinema/w5-lt/ca-1773/crates/oneiron/src/campaign.rs` — one `pub mod
  presets;` declaration plus its doc comment. Seven added lines, nothing else.
  Collision order `… → 1775 → 1778 → 1779` honored (1778 is the parent commit).

`git diff --name-only origin/main...HEAD` is exactly those three paths.

Explicitly NOT touched: `campaign/stage.rs` (parent owns the schema and the
machinery — `StageLadderDefinition`, `NoShowRecoveryRule`, `ReplyCode`,
`ReplyDisposition`, `NO_SHOW_BUMP_AFTER_SECS`, `validate_ladder` all IMPORTED),
`campaign/claims.rs` / `claim.rs` / `comm.rs` (CA-01 owns `StageEvidenceClass`
and `StageKey`; imported), `calendar/**`, `attempt_queue.rs`, `outbound.rs`,
gate files, `registry.rs`, `store.rs`, `vault.rs`, `lib.rs`,
`oneiron-server/**`, `oneiron-docs/`, `Cargo.toml`. No
`campaign/presets/consultancy.v1.json` asset was created — the engine ships
shape + loader only.

`Cargo.lock` was dirty on arrival and was regenerated again by the first
`cargo check` (calendar deps); never staged, not in any commit.

**PACKET_AMEND candidates: none.**

## Blueprint deviations — declared, not absorbed

1. **ADDED FIELD `CampaignPresetData::audit_window_days: u32`** (validated `==
   14`). The ratified content-invariant block requires `audit duration = 14
   days`, and the keystone skeleton has nowhere to put it: no field on
   `CampaignPresetData`, and `StageDefinition` carries only `{key, label}`.
   Encoding it in a stage LABEL would make the engine content-sniff free text;
   reusing `CommitmentRhythmData` would conflate the audit with the desk month.
   One `u32` plus a private `CONSULTANCY_AUDIT_WINDOW_DAYS = 14` is the minimal
   honest encoding. Declarative only — no timer, no TASK_LIST execution.
2. **ADDED ATTRIBUTE `#[serde(deny_unknown_fields)]`** on every preset-owned
   struct. The skeleton omits it, but done-means bullet 3 requires the loader to
   reject *unknown* fields, which serde accepts silently by default. Not applied
   to `StageLadderDefinition` (parent-owned type, not this ticket's to annotate).
3. **Error family.** The skeleton's signature is `Result<CampaignPresetData>`
   without naming a variant; the loader raises `Error::InvalidConfig(String)`,
   matching the in-family precedent `campaign/compliance.rs:509`
   (`Error::InvalidConfig(format!("campaign compliance pack: {message}"))`).
   `validate_ladder`'s `InvalidClaimBody` rejections are re-raised inside that
   family with the parent's own reason text preserved, so a host sees one error
   shape and CA-04's wording is not re-implemented.

Judgment calls that are NOT deviations, recorded so the screen can rule them:

- **Brief section ORDER is not validated**, only presence + uniqueness. The
  blueprint says the SOW config "includes" its sections; order and headings are
  host presentation, which the amendment explicitly moves out of the engine.
- **`owner_attested_allowed` positioning is not re-validated.** CA-04's
  `require_owner_attestable` already refuses attestation at or before the
  proposal stage, structurally. A second wall here would be a duplicate gate.
- **`exit_rules` content is not validated.** It is host-declared free text; the
  engine has nothing deterministic to check.
- **"No pitch copy" is enforced by SHAPE, not by text scanning.**
  `CampaignTemplateData` has no offer / CTA / free-body field, so a prospecting
  sequence is inexpressible as a Mom-Test template; the data half is the
  validated interviewee-vs-prospect exclusion. A substring blacklist over the
  host's question text would test the fixture, not the code.

## Intake notes from the 1775 verdict

- **(a) Fixture clock ordering — HONORED.** `REPLY_AT < BOOKING_AT <
  EVENT_START < EVENT_END < OUTCOME_AT`, i.e. ladder order IS clock order, so no
  stage head is ever superseded by evidence recorded before it and no
  `InvalidTimeRange` window is inverted. The constants carry that reasoning as a
  comment at their definition.
- **(b) CA-03 enqueue SUCCESS path — NOT taken; ledgered.** It does not fall out
  of these fixtures. `snooze_with_wake` reaches the success path only with
  `reentry_attempt: Some(_)`, which requires a persisted
  `CampaignEnrollmentEvent` at `membership_event_ref`. The only writer,
  `campaign::enrollment::put_event`, is module-private with no public or
  `pub(crate)` door, and the legitimate route is a full detection pass
  (SAVED_QUERY + owner actor + epoch + evidence hash + scope digest) — CA-03
  test territory, and reaching it from here would need an `enrollment.rs`
  visibility widening, i.e. a PACKET violation. Left for a CA-03-owned lane.

## Gates

- `cargo fmt -p oneiron --check` clean.
- `cargo clippy -p oneiron --all-features --all-targets -j 6` clean, zero
  warnings.
- `cargo check -p oneiron --all-features -j 6` clean.
- `cargo check -p oneiron` (default features) clean apart from ONE pre-existing
  warning, charged to no lane: `dead_code` on
  `crates/oneiron/src/batch.rs:4388 facet_of_endpoints_provably_off_table`
  (`batch.rs` is not in this diff; the warning is on the base commit and was
  recorded in the ONE-1775 worklog too).
- `cargo test -p oneiron --all-features -j 6`: full suite green — lib **3970
  passed, 0 failed, 17 ignored** plus every integration binary and both
  doctests, 0 failed anywhere.
- `cargo test -p oneiron --all-features --lib campaign::presets`: **11 passed,
  0 failed.**

Blueprint source oracles, both EMPTY as required:

- `rg -n "Vault|put_claim|supersede_claim|enqueue|schedule_outbound|register_structural_kind|TypeByteBand|ENTITY_TYPE_" crates/oneiron/src/campaign/presets.rs` → no matches.
- `rg -n "include_str!|CONSULTANCY_PRESET_JSON|EmbeddedCampaignPreset|consultancy\.v1\.json" crates/oneiron/src/campaign/presets.rs crates/oneiron/src/campaign/presets/tests.rs` → no matches.

(Two module-doc sentences were reworded — "enqueues nothing" → "queues no work",
"`include_str!` asset" → "compiled-in asset" — so the oracles are mechanically
empty rather than empty-modulo-prose. No behavior changed.)

## Done-means checklist

| Blueprint bullet | Where |
|---|---|
| `campaign.rs` exports `presets`; `cargo check` clean; no new dependency, embedded asset, registry, or installer | packet + gates above; `Cargo.toml` untouched |
| `cargo test -p oneiron campaign::presets::tests` passes | 11/11 |
| `consultancy_v1_deserializes_against_ca04_schema` | exact id/version vs the Rust constants, round trip through `serde_json`, and rejection arms for a removed required field, an unknown field, a wrong id, a wrong version, and a blank display name |
| `consultancy_stage_order_is_call_deposit_audit_desk` | full ordered 8-stage list asserted verbatim; `member` / `cold` absent; `audit_window_days == 14`; rejects a dropped stage, an inserted `member` stage, and a 30-day audit |
| `consultancy_stage_evidence_map_is_complete` | every transition's `(to, class)` pair asserted; `call_held` = `calendar_event_outcome`; `proposal_sent` = `document_artifact_and_send_receipt`; the four downstream stages asserted `is_external_hook`; rejects a re-classed `call_held`, a re-classed `deposit_paid`, and an unreachable `desk_client` |
| `held_is_required_for_call_held` | runs the PRESET's own ladder on a vault: silence → `read_event_outcome == None` → `NoChange`, head stays `call_booked`; explicit `unknown` → `NoChange`; only `Held` advances, citing one outcome claim with `basis = Machine` at `OUTCOME_AT` |
| `no_show_uses_reengagement_route` | `bump_after_secs == 259_200` AND `== NO_SHOW_BUMP_AFTER_SECS`; live `no_show` routes `Reengage` with steps `[SameDayReschedule, BumpAfter{259200}, Snooze]`; head stays `call_booked` — a no-show never writes `call_held`; three rejection arms |
| `consultancy_reply_routes_cover_all_six_codes` | all six codes, in order, each with its ratified disposition (`positive_now → Promote{replied}`, `positive_later → Snooze`, `referral → RouteReferral`, `objection → RecordOnly`, `not_interested → Exit`, `complaint → Suppress`); rejects a re-routed code and a missing one |
| `positive_later_snooze_is_a_dial` | min = 60 d, max = 90 d, default inside the range, `wake_on_new_trigger`, `restart_touch_index == 0`; then `snooze_with_wake` with `AtOrNewTrigger` lands CA-01's combined `Paused { until: Some(..), new_trigger: Some(true) }`; five rejection arms |
| `warm_reconnect_requires_evidence_slot` | `warm_requires_evidence`; the preset's clocks through `route_membership_lane`: no reference → `Cold`, blank thread → `Cold`, real thread → `WarmReconnect` carrying the reference; rejects `warm_requires_evidence: false` and a zero clock |
| `sow_and_one_pager_are_arch0032b_shaped` | both kinds, all required section keys, non-empty host headings/bodies, evidence slots on `context_and_evidence` and `observed_evidence`; the serialized field set is exactly `{key, kind, sections, title_template}` / `{body_template, heading, key, required_evidence_slots}` — no send, e-sign, payment, or action field is expressible; four rejection arms |
| `desk_month_is_declarative_only` | `P1M`; `period_open`/`weekly_evidence`/`renewal_review`/`period_close` on their four anchors; evidence hooks on each; renewal evidence external-only; the period is a JSON STRING and the rhythm's field set is exactly `{checkpoints, period, renewal_evidence}` — no schedule or commitment type; five rejection arms including a `before_period_end` checkpoint with a positive offset |
| `mom_test_template_is_research_not_prospecting` | six question blocks in order, each asking something; `participant_role == "interviewee"`; exclusions contain `prospect`; field sets asserted so no pitch/offer/CTA slot exists; four rejection arms |
| loader-only source oracle | empty (above) |
| no-embedded-content source oracle | empty (above) |
| no docs mirror or Astro change in the diff | diff is three engine paths |

## Notes for the screen

- **Every behavioural assertion runs the loaded preset's OWN ladder through
  ONE-1775's public functions** (`apply_coded_reply`,
  `apply_external_stage_evidence`, `apply_event_outcome`, `snooze_with_wake`,
  `route_membership_lane`). This is deliberately not a re-test of CA-04: the
  subject is whether this preset's DATA agrees with the mechanism it
  instantiates, which a pure-data assertion cannot establish.
- **The fixture is hand-authored JSON, not a serialized struct.** The wire field
  NAMES are half the contract with the host, and a fixture built through the
  Rust types could never catch a rename.
- **Every fixture string is synthetic** (`"fixture heading A"`, `"fixture
  question 1"`). Real SOW / one-pager / interview copy in a test file would be
  the embedded consultancy content this ticket exists to keep out, merely
  relocated.
- The ratified 8 stage names and their evidence classes live in ONE array,
  `CONSULTANCY_STAGE_EVIDENCE`, which is the single source for both the order
  check and the evidence-map check.
- Host-asset residence (where the real `crm.consultancy.v1` pack config lives)
  remains the batch integrator's `_parked.md` item; this ticket claims no
  external asset path and did not edit the park file.
