//! AUTO-SIGNALS-RECENT-WRITES-COUNTS-TRAY-CLOSE-RECEIPTS: the auto checker's
//! `recent_writes` signal counts the actor's writes, the gate's own decisions
//! on them, and not the receipt that answers one of them later.
//!
//! An agent's held write A parks in the tray. Its Auto writes B, C and D each
//! reach the host's checker, which records the signals it is shown and holds
//! them. Between C and D the tray lets A go, which writes A's `let_go`
//! receipt in the agent's name. D's count must grow from C's by exactly what
//! C's grew from B's (C's own receipts), so the let-go is no write.
//!
//! The gate fixtures go through `oneiron::test_doors::live_run_claim_put`, as
//! tests/live_run_claim_put.rs does. Built only under
//! `--cfg oneiron_test_support`.
//!
//! Red on main: D sees one write more than the step (A's let-go receipt).
//! Green on the head.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test auto_signals_recent_writes`
#![cfg(oneiron_test_support)]

use std::sync::{Arc, Mutex};
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
use serde_json::Value as JsonValue;

const CHECKER_REF: &str = "host-checker-v1";
/// A host names its hold reasons in prose.
const HOLD_REASON: &str = "checker: hedged verdict";
/// The provenance key and value the live-run claim put door stamps on the
/// request it marks (`gate::CHECKED_PRODUCER_PROVENANCE_KEY` and
/// `gate::LIVE_RUN_CLAIM_PUT_PRODUCER`), as the wire carries them.
const CHECKED_PRODUCER_PROVENANCE_KEY: &str = "checked_producer";
const LIVE_RUN_CLAIM_PUT_PRODUCER: &str = "live_run_claim_put";

fn test_id(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).expect("test id")
}

/// The host's decision head on the checker's Big rung: it answers every auto
/// check `hold`, and records the state of every call it is shown.
struct SignalRecordingChecker {
    states: Mutex<Vec<JsonValue>>,
}

impl SignalRecordingChecker {
    fn hold() -> Self {
        Self {
            states: Mutex::new(Vec::new()),
        }
    }

    fn states(&self) -> Vec<JsonValue> {
        self.states.lock().expect("checker log").clone()
    }
}

impl DecisionProvider for SignalRecordingChecker {
    fn pin(&self) -> ProviderPin {
        ProviderPin {
            rung: DecisionRung::Big,
            model: "host-checker".into(),
            version: "1".into(),
        }
    }

    fn decide(&self, call: &DecisionCall<'_>) -> Result<ProviderDecision> {
        self.states
            .lock()
            .expect("checker log")
            .push(call.state.clone());
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

/// The host's bounded checker over `head`, assembled as a host assembles it:
/// a decision ladder whose Big rung is the host's head, its dial at Big, and
/// no world kept on the device, so every rung reads the candidate.
fn bounded(head: Arc<SignalRecordingChecker>) -> BoundedAutoChecker {
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
        world_hold: None,
    })
}

/// Seeds the actor and the claim's subject as PERSON rows, as the Dreamer
/// fixture does.
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

/// A caller's live-run claim put, marked by the door (FIX 3983): the agent
/// the checker manifest ceilings at Auto, a Generated source, the door's
/// provenance.
fn live_run_put_envelope(
    vault: &Vault,
    body: &ClaimBody,
    approval: ClaimApprovalStatus,
) -> Result<WriteEnvelope> {
    seed_dreamer_parts(vault, body)?;
    Ok(WriteEnvelope::new(
        WriteActor::new(
            doors::first_party_connector_actor_id(),
            EdgeActorClass::Agent,
        ),
        ClaimSource::Generated,
        WriteProvenance::new(Value::Map(vec![
            (Value::from("surface"), Value::from("self.*")),
            (
                Value::from(CHECKED_PRODUCER_PROVENANCE_KEY),
                Value::from(LIVE_RUN_CLAIM_PUT_PRODUCER),
            ),
        ]))?,
        approval,
    ))
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

/// The `recent_writes` signal in a checker call's state, wherever the
/// ladder places the candidate's state.
fn recent_writes_in(state: &JsonValue) -> Option<u64> {
    match state {
        JsonValue::Object(map) => map
            .get("recent_writes")
            .and_then(JsonValue::as_u64)
            .or_else(|| map.values().find_map(recent_writes_in)),
        JsonValue::Array(items) => items.iter().find_map(recent_writes_in),
        _ => None,
    }
}

/// The agent's Auto live-run put of `body` as `id`, which the checker holds.
/// Returns the `recent_writes` the checker was shown for it.
fn held_auto_put(
    vault: &Vault,
    checker: &BoundedAutoChecker,
    head: &SignalRecordingChecker,
    id: &EntityId,
    body: &ClaimBody,
) -> Result<u64> {
    let envelope = live_run_put_envelope(vault, body, ClaimApprovalStatus::Auto)?;
    let calls_before = head.states().len();
    let result = doors::gate_claim_write(vault, id, body, &envelope, Some(checker), true);
    let states = head.states();
    assert_eq!(
        states.len(),
        calls_before + 1,
        "the checker is consulted once ({result:?})"
    );
    let (outcome, reason_codes) = gate_rejection_parts(result.expect_err("the checker holds it"));
    assert_eq!(outcome, "pending");
    assert_eq!(reason_codes, vec!["gate.pending.checker"]);
    let state = states.last().expect("the call's state");
    Ok(recent_writes_in(state)
        .unwrap_or_else(|| panic!("the checker is shown recent_writes: {state}")))
}

#[test]
fn an_answer_to_a_held_write_is_not_counted_as_a_recent_write() -> Result<()> {
    let (_tmp, vault) = doors::checker_vault(Some(CHECKER_REF))?;
    let head = Arc::new(SignalRecordingChecker::hold());
    let checker = bounded(head.clone());

    // A: the agent's Proposed live-run put, held checker-unavailable (no
    // checker is lent), parks with its pending review.
    let parked = test_id(0x70);
    let proposed = doors::checker_body(&vault, ClaimApprovalStatus::Proposed)?;
    let resubmitted = live_run_put_envelope(&vault, &proposed, ClaimApprovalStatus::Proposed)?;
    let held = doors::gate_claim_write(&vault, &parked, &proposed, &resubmitted, None, true);
    assert!(
        vault
            .pending_gate_consents(64)?
            .iter()
            .any(|record| record.claim_id == *parked.as_bytes()),
        "the held Proposed put parks a pending review ({held:?})"
    );

    // B, C: the agent's Auto puts, each held by the checker.
    let auto = doors::checker_body(&vault, ClaimApprovalStatus::Auto)?;
    let seen_b = held_auto_put(&vault, &checker, &head, &test_id(0x71), &auto)?;
    assert!(seen_b >= 1, "A's held write counts for B ({seen_b})");
    let seen_c = held_auto_put(&vault, &checker, &head, &test_id(0x72), &auto)?;
    let step = seen_c
        .checked_sub(seen_b)
        .expect("the count never falls between two writes");
    assert!(
        step >= 1,
        "B's held write counts for C ({seen_b} -> {seen_c})"
    );

    // The tray lets A go: its let_go receipt answers A in the agent's name.
    let let_go = vault
        .let_go_pending_ask(&parked)?
        .expect("the let-go answers A's pending review");
    assert_eq!(let_go.outcome, "let_go");

    // D: one more Auto put. Since C, only C itself was written.
    let seen_d = held_auto_put(&vault, &checker, &head, &test_id(0x73), &auto)?;
    assert_eq!(
        seen_d,
        seen_c + step,
        "FAILBEFORE AUTO-SIGNALS-RECENT-WRITES-COUNTS-TRAY-CLOSE-RECEIPTS: the let-go answer to A counted as a write ({seen_b} -> {seen_c} -> {seen_d})"
    );
    Ok(())
}
