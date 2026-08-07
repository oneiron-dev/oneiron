# WORKLOG — ONE-CA03-ENQ (micro closure leg)

Branch `ONE-CA03-ENQ` off `origin/main` @ `4f5360daa`.
Closes known hole **H1** from the ONE-1775 verdict, confirmed by ONE-1779.

## The hole

`campaign/stage.rs::snooze_with_wake` reaches CA-03's enqueue surface only when
`ReentryPlan::reentry_attempt` is `Some(_)`, and CA-03's `enqueue` refuses any
payload whose `membership_event_ref` does not resolve to a persisted
`CampaignEnrollmentEvent`. The writer for that row — `campaign::enrollment::put_event`
— is **module-private by design**: an enrollment event is engine-detected at
`detect_enrollment`, never caller-asserted.

Consequence: a cross-module oracle can reach only the REFUSAL arm. That is
exactly where ONE-1779 stopped (`tests/campaign_stage_ladder_oracle.rs::reentry_rides_the_existing_enrollment_attempt_kind`
asserts `Error::EntityNotFound` with the membership untouched). The SUCCESS arm —
the pause landing AND the attempt actually reaching the queue — was unexercised
on main.

## Fix

Closed from **inside the owning module**: one new test in
`/Volumes/Cinema/w5-lt/skills/crates/oneiron/src/campaign/enrollment.rs`
(`mod tests`), driving the legitimate route — persist the event through the
module door, then drive ONE-1775's **public** `snooze_with_wake` with a
resolvable `reentry_attempt`.

`campaign::enrollment::tests::reentry_snooze_pauses_the_member_and_enqueues_the_attempt`
asserts both durable consequences of the one call:

1. the `campaign.member` head is replaced with `Paused { until, new_trigger }`
   (both fields set, from `WakeCondition::AtOrNewTrigger`) and the channel rows
   that authorize contact ride across the transition;
2. the attempt **landed**: exactly one queue row, kind
   `campaign.enrollment.macro`, state `Queued`, `dedupe_key` equal to
   `enrollment_dedupe_key`, payload decoding back to the three refs — and the
   row is **executable**, its refs still cross-binding to the persisted program
   step via `resolve_program_step`.

The cohort row the test pauses is built from `step.member_channel()`, i.e. the
way CA-03's own membership leg (`execute_claimed`) writes it — not a hand-spelled
channel.

## Is the success path actually correct?

**Yes — no production defect.** The path was unexercised, not broken. Zero
production lines changed; `campaign/stage.rs` is byte-identical to main.

## Coverage is not vacuous (mutation-verified)

Deleted the enqueue call from `snooze_with_wake` and re-ran:

| Suite | With enqueue deleted |
|---|---|
| new test | **FAILED** (`one re-entry, one queue row`, left 0 / right 1) |
| other 70 `campaign::` lib tests | all green |
| `campaign_stage_ladder_oracle` (19) | all green |
| `campaign_enrollment_oracle` | all green |

Only the new test catches it. That is the hole, demonstrated mechanically.
`stage.rs` was restored from backup; final `git diff --name-only` shows the one
test file.

## Diff

One file, test-only: `crates/oneiron/src/campaign/enrollment.rs` (+145 / -3).

**No production visibility was widened.** No `pub`/`pub(crate)` lift was needed,
so **no PACKET_AMEND is required** — the module door was sufficient, which is
precisely why the fix belongs here rather than in an integration oracle.

Supporting test-only refactor: `install_fixture` was split so the persisted rows
(`install_enrollment_rows`) can be seeded WITHOUT `install_send_policy`. Required
— the send-policy manifest's `actor_ceilings` gate the test's `campaign.member`
seed to `pending` (`gate.pending.actor_ceiling`), and the re-entry path sends
nothing, so installing a governance manifest there would only obstruct the
fixture. Behavior for all existing callers is unchanged (`install_fixture` still
installs the policy first, then the rows). Also hoisted the duplicated sender
seed byte `0x57` to a named `SENDER_SEED`.

Seeds `0x91`/`0x92`/`0x93` route through the band-asserting `test_util::entity`
helper and are outside `PINNED_ID_BYTES` and outside every seed the existing
enrollment fixtures claim.

The vault uses `open_test_vault_with` (which clears the default policy manifest)
rather than the module's `vault_fixture`: the `campaign.` predicates carry no
rule in the default manifest, so a cohort row seeded under it lands `pending` on
the criticality floor. The CA-01/CA-03/CA-04 oracles all take the same carve-out
— the subject here is the re-entry seam, not the manifest.

## Gates

- `cargo fmt -p oneiron -- --check` — clean
- `cargo clippy -p oneiron --all-features --all-targets` — zero errors, zero warnings
- `cargo test -p oneiron --all-features --lib` — **3983 passed, 0 failed**, 6 ignored
- `cargo test -p oneiron --all-features` campaign oracles (stage_ladder, enrollment,
  claim_gate, compliance, send_hygiene) — **52 passed, 0 failed**

## GATE-2 board

Nothing to rule on. Test-only, no visibility widening, no PACKET_AMEND, no
production behavior change, no known-hole banked.
