//! Review 6881 P1 (#6881, FIX 3983): a caller's live-run claim put asking
//! Auto reaches the host's auto checker as a Dreamer write does. Moved from
//! `gate/tests/auto_checker.rs` (the oneiron lib test target does not
//! compile); the gate fixtures go through
//! `oneiron::test_doors::live_run_claim_put`, built only under
//! `--cfg oneiron_test_support`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use oneiron::claim_check::AutoCheckNotes;
use oneiron::error::GateError;
use oneiron::llm::decision::{
    DecisionAnswer, DecisionBand, DecisionBandPolicy, DecisionCall, DecisionDial, DecisionProvider,
    DecisionRung, HeldLadder, ProviderDecision, ProviderPin,
};
use oneiron::llm::{AutoCheckCandidate, AutoCheckDecisions, BoundedAutoChecker};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::live_run_claim_put as doors;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimSource, ClaimSubject, EdgeActorClass, EntityId, Error,
    Result, Vault, WriteActor, WriteEnvelope, WriteProvenance,
};
use rmpv::Value;

const CHECKER_REF: &str = "host-checker-v1";
/// A host names its hold reasons in prose.
const HOLD_REASON: &str = "checker: hedged verdict";
/// The provenance key and value the live-run claim put door stamps on the
/// Auto request it marks (`gate::CHECKED_PRODUCER_PROVENANCE_KEY` and
/// `gate::LIVE_RUN_CLAIM_PUT_PRODUCER`), as the wire carries them, so this
/// file also builds on main for the red run.
const CHECKED_PRODUCER_PROVENANCE_KEY: &str = "checked_producer";
const LIVE_RUN_CLAIM_PUT_PRODUCER: &str = "live_run_claim_put";

fn test_id(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).expect("test id")
}

fn gate_rejection_parts(err: Error) -> (&'static str, Vec<&'static str>) {
    match err {
        Error::Gate(GateError::GateWriteRejected {
            outcome,
            reason_codes,
        }) => (outcome, reason_codes),
        other => panic!("expected GateWriteRejected, got {other:?}"),
    }
}

/// The host's decision head on the checker's Big rung: it answers every auto
/// check `hold` and counts each consult.
struct RecordingAutoChecker {
    calls: AtomicUsize,
}

impl RecordingAutoChecker {
    fn hold() -> Self {
        Self {
            calls: AtomicUsize::new(0),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::Relaxed)
    }
}

impl DecisionProvider for RecordingAutoChecker {
    fn pin(&self) -> ProviderPin {
        ProviderPin {
            rung: DecisionRung::Big,
            model: "host-checker".into(),
            version: "1".into(),
        }
    }

    fn decide(&self, _call: &DecisionCall<'_>) -> Result<ProviderDecision> {
        let _ = self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(ProviderDecision {
            answer: DecisionAnswer::Choice("hold".to_owned()),
            probability: Some(0.99),
            paired: None,
            person: None,
            served: None,
            cost_per_thousand: None,
        })
    }
}

/// The host's hold reasons: one, in prose.
struct HoldReasons;

impl AutoCheckNotes for HoldReasons {
    fn hold_reasons(
        &self,
        _candidate: &AutoCheckCandidate<'_>,
        _due: Instant,
    ) -> Result<Vec<String>> {
        Ok(vec![HOLD_REASON.to_owned()])
    }
}

/// The host's bounded checker over `head`, assembled as a host assembles it
/// (`oneiron-server` `decision_host`): a decision ladder whose Big rung is the
/// host's head, its dial at Big.
fn bounded(head: Arc<RecordingAutoChecker>) -> BoundedAutoChecker {
    BoundedAutoChecker::new(AutoCheckDecisions {
        ladder: HeldLadder {
            big: Some(head as Arc<dyn DecisionProvider>),
            ..HeldLadder::unstaffed()
        },
        principal: test_id(0x51),
        dial: DecisionDial {
            first: DecisionRung::Big,
            ceiling: DecisionRung::Big,
            band: DecisionBand::default(),
        },
        bands: DecisionBandPolicy::default(),
        wording: "May this write land without the owner's review?".to_owned(),
        notes: Arc::new(HoldReasons),
        calibrated: None,
    })
}

/// Seeds the rows the Dreamer fixture's `dreamer_parts` seeds, the actor and
/// the claim's subject, as PERSON rows.
fn seed_dreamer_parts(vault: &Vault, body: &ClaimBody) -> Result<()> {
    let at = TimeRange { start: 1, end: 1 };
    vault.put_entity(
        &doors::first_party_connector_actor_id(),
        ENTITY_TYPE_PERSON,
        at,
        1,
        b"dreamer actor",
    )?;
    if let ClaimSubject::Entity(subject) = body.subject {
        vault.put_entity(&subject, ENTITY_TYPE_PERSON, at, 1, b"dreamer subject")?;
    }
    Ok(())
}

/// A caller's live-run claim put (FIX 3983) as the gate sees it: the agent the checker manifest ceilings at
/// Auto, a Generated source, and the door's provenance, with or without the marker its Auto request carries.
fn live_run_put_envelope(
    vault: &Vault,
    body: &ClaimBody,
    marked: bool,
    approval: ClaimApprovalStatus,
) -> Result<WriteEnvelope> {
    // The Dreamer fixture seeds the actor and the subject; the envelope below replaces its provenance.
    seed_dreamer_parts(vault, body)?;
    let mut provenance = vec![(Value::from("surface"), Value::from("self.*"))];
    if marked {
        provenance.push((
            Value::from(CHECKED_PRODUCER_PROVENANCE_KEY),
            Value::from(LIVE_RUN_CLAIM_PUT_PRODUCER),
        ));
    }
    Ok(WriteEnvelope::new(
        WriteActor::new(
            doors::first_party_connector_actor_id(),
            EdgeActorClass::Agent,
        ),
        ClaimSource::Generated,
        WriteProvenance::new(Value::Map(provenance))?,
        approval,
    ))
}

/// Review 6881 P1: a caller's live-run claim put asking Auto is a Generated producer the host's auto checker
/// reviews, as it reviews a Dreamer write. With a checker named and none injected the write is held
/// checker-unavailable (the door then resubmits it Proposed), and a checker that holds parks it. The same agent
/// write without the door's marker is not consulted: the checker's scope widens by this one producer only.
#[test]
fn a_live_run_claim_put_asking_auto_reaches_the_checker() -> Result<()> {
    let (_tmp, vault) = doors::checker_vault(Some(CHECKER_REF))?;
    let body = doors::checker_body(&vault, ClaimApprovalStatus::Auto)?;
    let marked = live_run_put_envelope(&vault, &body, true, ClaimApprovalStatus::Auto)?;

    let result = doors::gate_claim_write(&vault, &test_id(0x3d), &body, &marked, None, false);
    let (outcome, reason_codes) =
        gate_rejection_parts(result.expect_err(
            "FAILBEFORE 6881 P1: the live-run put landed Auto with no checker consulted",
        ));
    assert_eq!(outcome, "pending");
    assert_eq!(reason_codes, vec!["gate.pending.checker.unavailable"]);

    let holding = Arc::new(RecordingAutoChecker::hold());
    let bounded_holding = bounded(holding.clone());
    let result = doors::gate_claim_write(
        &vault,
        &test_id(0x3e),
        &body,
        &marked,
        Some(&bounded_holding),
        false,
    );
    assert_eq!(holding.calls(), 1, "the checker is consulted once");
    let (outcome, reason_codes) = gate_rejection_parts(result.expect_err("the checker holds it"));
    assert_eq!(outcome, "pending");
    assert_eq!(reason_codes, vec!["gate.pending.checker"]);

    let unmarked = live_run_put_envelope(&vault, &body, false, ClaimApprovalStatus::Auto)?;
    let untouched = Arc::new(RecordingAutoChecker::hold());
    let bounded_untouched = bounded(untouched.clone());
    doors::gate_claim_write(
        &vault,
        &test_id(0x3f),
        &body,
        &unmarked,
        Some(&bounded_untouched),
        false,
    )?;
    assert_eq!(
        untouched.calls(),
        0,
        "an unmarked agent write is not consulted"
    );
    Ok(())
}

/// Review 6908 P1: the door resubmits a held Auto request Proposed, with the same marker. With the checker still
/// unavailable, the resubmission pends at Proposed and parks with a pending review the owner rules on, instead of
/// landing Proposed with no review. Code mode's Proposed put carries no marker and is not consulted.
#[test]
fn a_held_live_run_put_resubmitted_proposed_parks_with_a_pending_review() -> Result<()> {
    let (_tmp, vault) = doors::checker_vault(Some(CHECKER_REF))?;
    let body = doors::checker_body(&vault, ClaimApprovalStatus::Proposed)?;
    let resubmitted = live_run_put_envelope(&vault, &body, true, ClaimApprovalStatus::Proposed)?;
    let held = test_id(0x40);

    let result = doors::gate_claim_write(&vault, &held, &body, &resubmitted, None, true);
    let reviews: Vec<_> = vault
        .pending_gate_consents(64)?
        .into_iter()
        .filter(|record| record.claim_id == *held.as_bytes())
        .collect();
    assert_eq!(
        reviews.len(),
        1,
        "FAILBEFORE 6908 P1: the held resubmission parks with no pending review ({result:?})"
    );
    assert_eq!(
        reviews[0].reason_codes,
        vec!["gate.pending.checker.unavailable"]
    );

    let code_mode = live_run_put_envelope(&vault, &body, false, ClaimApprovalStatus::Proposed)?;
    let untouched = Arc::new(RecordingAutoChecker::hold());
    let bounded_untouched = bounded(untouched.clone());
    let plain = test_id(0x41);
    doors::gate_claim_write(
        &vault,
        &plain,
        &body,
        &code_mode,
        Some(&bounded_untouched),
        true,
    )?;
    assert_eq!(
        untouched.calls(),
        0,
        "a code-mode Proposed put is not consulted"
    );
    assert!(
        vault
            .pending_gate_consents(64)?
            .iter()
            .all(|record| record.claim_id != *plain.as_bytes()),
        "a code-mode Proposed put parks no review"
    );
    Ok(())
}
