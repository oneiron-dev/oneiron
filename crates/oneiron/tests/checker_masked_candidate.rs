//! CHECKER-PREVIEW-READS-UNMASKED-CANDIDATE: the claim gate consults the
//! host's auto checker before base apply masks a candidate's secrets.
//!
//! (1) The checker reads the value as the write stores it: each secret the
//! batch door's plan places stands under a handle, so no credential reaches a
//! rung that may run off the device. (2) A candidate held at its preflight
//! that the mask rewrites at apply parks with a pending review bound to the
//! stored body, instead of failing the preflight receipt's replay match.
//! (3) PREFLIGHT-FACET-REPUT-REPLAY-MISMATCH: a held re-put of a claim born
//! under a facet the vault default has since left parks at its birth facet.
//! (4) RAW-CLAIM-PUT-MASK-REPLAY-MISMATCH: a held raw CLAIM put the mask
//! rewrites at apply parks with a review of the stored body.
//!
//! The gate fixtures go through `oneiron::test_doors::live_run_claim_put`;
//! the stored claim's consent binding through
//! `oneiron::test_doors::checker_masked_candidate`. Built only under
//! `--cfg oneiron_test_support`.
#![cfg(oneiron_test_support)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use oneiron::claim_check::AutoCheckNotes;
use oneiron::error::GateError;
use oneiron::llm::decision::{
    DecisionAnswer, DecisionBand, DecisionBandPolicy, DecisionCall, DecisionDial, DecisionProvider,
    DecisionRung, HeldLadder, ProviderDecision, ProviderPin,
};
use oneiron::llm::{AutoCheckCandidate, AutoCheckDecisions, BoundedAutoChecker};
use oneiron::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_FACET, ENTITY_TYPE_PERSON};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::checker_masked_candidate::stored_claim_with_consent_diff;
use oneiron::test_doors::live_run_claim_put as doors;
use oneiron::write_envelope::claim_body::encode_claim_body;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimCandidate, ClaimSource, ClaimSubject, EdgeActorClass,
    EntityId, Error, Result, Vault, WriteActor, WriteEnvelope, WriteProvenance,
};
use rmpv::Value;

const CHECKER_REF: &str = "host-checker-v1";
/// A host names its hold reasons in prose.
const HOLD_REASON: &str = "checker: hedged verdict";
/// The provenance key and value the live-run claim put door stamps on the
/// request it marks (`gate::CHECKED_PRODUCER_PROVENANCE_KEY` and
/// `gate::LIVE_RUN_CLAIM_PUT_PRODUCER`), as the wire carries them.
const CHECKED_PRODUCER_PROVENANCE_KEY: &str = "checked_producer";
const LIVE_RUN_CLAIM_PUT_PRODUCER: &str = "live_run_claim_put";
const PLAIN_VALUE: &str = "Ada Lovelace";
/// The value a re-put writes over [`PLAIN_VALUE`].
const REPUT_VALUE: &str = "Augusta Ada King";
/// The hold a checker the manifest names and no host lends puts on a marked
/// live-run put.
const CHECKER_UNAVAILABLE: &str = "gate.pending.checker.unavailable";
/// The hold the manifest's critical `health.*` rule puts on a Proposed claim.
const CRITICALITY_FLOOR: &str = "gate.pending.criticality_floor";
/// A predicate under the checker manifest's critical `health.` prefix.
const HEALTH_PREDICATE: &str = "health.allergy";

fn test_id(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).expect("test id")
}

/// A GitHub personal token the write door's provider rule places
/// (`ghp_` and 36 token characters), spelled in parts so no scanner of
/// this source reads a token.
fn provider_token() -> String {
    ["gh", "p_", "abcdefghijklmnopqrstuvwxyz0123456789"].concat()
}

fn token_value(token: &str) -> String {
    format!("deploy key {token} for staging")
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
/// check `hold`, and records every state and candidate preview it is shown.
struct RecordingAutoChecker {
    calls: AtomicUsize,
    seen: Mutex<Vec<String>>,
}

impl RecordingAutoChecker {
    fn hold() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            seen: Mutex::new(Vec::new()),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::Relaxed)
    }

    fn seen(&self) -> Vec<String> {
        self.seen.lock().expect("checker log").clone()
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

    fn decide(&self, call: &DecisionCall<'_>) -> Result<ProviderDecision> {
        let _ = self.calls.fetch_add(1, Ordering::Relaxed);
        self.seen
            .lock()
            .expect("checker log")
            .push(call.state.to_string());
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

/// The host's hold reasons: one, in prose. The notes reader is shown the
/// candidate too, so it records the preview it reads.
struct HoldReasons(Arc<RecordingAutoChecker>);

impl AutoCheckNotes for HoldReasons {
    fn hold_reasons(
        &self,
        candidate: &AutoCheckCandidate<'_>,
        _due: Instant,
    ) -> Result<Vec<String>> {
        self.0
            .seen
            .lock()
            .expect("checker log")
            .push(candidate.value_preview.to_owned());
        Ok(vec![HOLD_REASON.to_owned()])
    }
}

/// The host's bounded checker over `head`, assembled as a host assembles it:
/// a decision ladder whose Big rung is the host's head, its dial at Big, and
/// no world kept on the device, so every rung reads the candidate.
fn bounded(head: Arc<RecordingAutoChecker>) -> BoundedAutoChecker {
    BoundedAutoChecker::new(AutoCheckDecisions {
        ladder: HeldLadder {
            big: Some(head.clone() as Arc<dyn DecisionProvider>),
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
        notes: Arc::new(HoldReasons(head)),
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

/// The checker fixture's claim with `value` in place of its own.
fn checker_body_with_value(
    vault: &Vault,
    approval: ClaimApprovalStatus,
    value: &str,
) -> Result<ClaimBody> {
    let mut body = doors::checker_body(vault, approval)?;
    body.value = Value::from(value);
    Ok(body)
}

/// Asks the checker about an Auto live-run put of `value` through the claim
/// write door; the checker holds it. Returns what the checker was shown.
fn consulted_previews(value: &str) -> Result<Vec<String>> {
    let (_tmp, vault) = doors::checker_vault(Some(CHECKER_REF))?;
    let body = checker_body_with_value(&vault, ClaimApprovalStatus::Auto, value)?;
    let envelope = live_run_put_envelope(&vault, &body, ClaimApprovalStatus::Auto)?;
    let head = Arc::new(RecordingAutoChecker::hold());
    let checker = bounded(head.clone());
    let result = doors::gate_claim_write(
        &vault,
        &test_id(0x60),
        &body,
        &envelope,
        Some(&checker),
        false,
    );
    assert_eq!(
        head.calls(),
        1,
        "the checker is consulted once ({result:?})"
    );
    let (outcome, reason_codes) = gate_rejection_parts(result.expect_err("the checker holds it"));
    assert_eq!(outcome, "pending");
    assert_eq!(reason_codes, vec!["gate.pending.checker"]);
    Ok(head.seen())
}

/// (1) The checker never reads a credential the write would lift into
/// custody: its preview holds the value as stored, a handle where the token
/// was.
#[test]
fn the_checker_reads_a_claim_value_with_its_token_under_a_handle() -> Result<()> {
    let token = provider_token();
    let seen = consulted_previews(&token_value(&token))?;
    assert!(!seen.is_empty(), "the checker recorded what it read");
    for shown in &seen {
        assert!(
            !shown.contains(&token),
            "FAILBEFORE CHECKER-PREVIEW-READS-UNMASKED-CANDIDATE: the checker read the raw token: {shown}"
        );
        assert!(
            shown.contains("deploy key [secret sc"),
            "the checker reads the value with a handle where the token was: {shown}"
        );
    }
    Ok(())
}

/// Guard: a value with no secret reaches the checker as written.
#[test]
fn the_checker_reads_a_claim_value_without_a_secret_as_written() -> Result<()> {
    let seen = consulted_previews(PLAIN_VALUE)?;
    assert!(!seen.is_empty(), "the checker recorded what it read");
    for shown in &seen {
        assert!(
            shown.contains(PLAIN_VALUE),
            "the checker reads the value as written: {shown}"
        );
        assert!(!shown.contains("[secret"), "no handle is placed: {shown}");
    }
    Ok(())
}

/// `body` as the candidate a caller offers: its evidence, and its scope, so
/// its `sensitivity: public` stamp keeps it at band 0 and only the checker
/// can hold it (an unstamped claim reads private and waits on its source).
fn candidate_of(body: &ClaimBody) -> ClaimCandidate {
    let mut candidate = ClaimCandidate::new(
        body.predicate.clone(),
        body.subject,
        body.value.clone(),
        body.confidence,
    );
    if let Some(evidence) = body.evidence.clone() {
        candidate = candidate.with_evidence(evidence);
    }
    if let Some(scope) = body.scope.clone() {
        candidate = candidate.with_scope(scope);
    }
    candidate
}

/// Commits a Proposed live-run put of `value` as a batch: its preflight
/// records the checker-unavailable hold (a checker is named, none is lent),
/// and its apply masks the candidate before it carries that hold.
fn commit_proposed_put(vault: &Vault, id: &EntityId, value: &str) -> Result<()> {
    let body = checker_body_with_value(vault, ClaimApprovalStatus::Proposed, value)?;
    let envelope = live_run_put_envelope(vault, &body, ClaimApprovalStatus::Proposed)?;
    vault
        .batch()
        .claim_candidate(
            id,
            candidate_of(&body),
            &envelope,
            TimeRange { start: 2, end: 2 },
            2,
        )
        .commit()?;
    Ok(())
}

/// The pending review the gate parked for `id` with `reason`, which must be
/// bound to the body the vault stores for it.
fn parked_review_bound_to_stored_body(
    vault: &Vault,
    id: &EntityId,
    reason: &str,
) -> Result<ClaimBody> {
    let reviews: Vec<_> = vault
        .pending_gate_consents(64)?
        .into_iter()
        .filter(|record| record.claim_id == *id.as_bytes())
        .collect();
    assert_eq!(reviews.len(), 1, "the held put parks one pending review");
    assert_eq!(reviews[0].reason_codes, vec![reason]);
    let (stored, stored_diff) = stored_claim_with_consent_diff(vault, id)?;
    assert_eq!(stored.approval, ClaimApprovalStatus::Proposed);
    assert_eq!(
        reviews[0].diff_handle, stored_diff,
        "the pending review is bound to the stored body, which the owner's answer is judged against"
    );
    Ok(stored)
}

/// (2) A held candidate the mask rewrites at apply parks Proposed with its
/// pending review, bound to the stored (masked) body.
#[test]
fn a_held_put_the_mask_rewrites_parks_with_a_review_of_the_stored_body() -> Result<()> {
    let (_tmp, vault) = doors::checker_vault(Some(CHECKER_REF))?;
    let id = test_id(0x61);
    let token = provider_token();
    let committed = commit_proposed_put(&vault, &id, &token_value(&token));
    assert!(
        committed.is_ok(),
        "FAILBEFORE CHECKER-PREVIEW-READS-UNMASKED-CANDIDATE: the held put failed its replay match instead of parking: {committed:?}"
    );
    let stored = parked_review_bound_to_stored_body(&vault, &id, CHECKER_UNAVAILABLE)?;
    let stored_value = stored.value.as_str().expect("a text value").to_owned();
    assert!(
        !stored_value.contains(&token),
        "the stored value holds no token: {stored_value}"
    );
    assert!(
        stored_value.starts_with("deploy key [secret sc"),
        "the stored value holds the token's handle: {stored_value}"
    );
    Ok(())
}

/// Guard: a held candidate the mask leaves as written parks as before.
#[test]
fn a_held_put_without_a_secret_parks_with_a_review_of_the_stored_body() -> Result<()> {
    let (_tmp, vault) = doors::checker_vault(Some(CHECKER_REF))?;
    let id = test_id(0x62);
    commit_proposed_put(&vault, &id, PLAIN_VALUE)?;
    let stored = parked_review_bound_to_stored_body(&vault, &id, CHECKER_UNAVAILABLE)?;
    assert_eq!(stored.value, Value::from(PLAIN_VALUE));
    Ok(())
}

/// Births `id` under the vault's default facet as an unmarked Generated Auto
/// candidate, which the manifest lets land with no review. Returns that
/// facet.
fn born_with_no_review(vault: &Vault, id: &EntityId) -> Result<EntityId> {
    let born_under = vault.default_facet()?;
    let body = checker_body_with_value(vault, ClaimApprovalStatus::Auto, PLAIN_VALUE)?;
    seed_dreamer_parts(vault, &body)?;
    let envelope = WriteEnvelope::new(
        WriteActor::new(
            doors::first_party_connector_actor_id(),
            EdgeActorClass::Agent,
        ),
        ClaimSource::Generated,
        WriteProvenance::new(Value::Map(vec![(
            Value::from("surface"),
            Value::from("self.*"),
        )]))?,
        ClaimApprovalStatus::Auto,
    );
    vault
        .batch()
        .claim_candidate(
            id,
            candidate_of(&body),
            &envelope,
            TimeRange { start: 1, end: 1 },
            1,
        )
        .commit()?;
    let (born, _) = stored_claim_with_consent_diff(vault, id)?;
    assert_eq!(born.approval, ClaimApprovalStatus::Auto, "the birth lands");
    assert_eq!(born.scope_facet, born_under, "the birth takes the default");
    assert!(
        vault
            .pending_gate_consents(64)?
            .iter()
            .all(|record| record.claim_id != *id.as_bytes()),
        "the birth leaves no review"
    );
    Ok(born_under)
}

/// Makes a new FACET the vault default, as the owner. Returns it.
fn move_default_facet(vault: &Vault) -> Result<EntityId> {
    let moved_to = test_id(0x64);
    vault.put_entity(
        &moved_to,
        ENTITY_TYPE_FACET,
        TimeRange { start: 1, end: 1 },
        1,
        b"facet",
    )?;
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the embedded owner PERSON");
    vault
        .set_default_facet(moved_to, WriteActor::new(owner, EdgeActorClass::Human))
        .expect("the owner moves the vault default");
    assert_eq!(vault.default_facet()?, moved_to);
    Ok(moved_to)
}

/// (3) A held re-put of a claim born under a facet the vault default has
/// since left parks at its birth facet, with its review bound to the stored
/// body: the preflight judges the body the apply stores.
#[test]
fn a_held_reput_after_the_default_facet_moved_parks_at_its_birth_facet() -> Result<()> {
    let (_tmp, vault) = doors::checker_vault(Some(CHECKER_REF))?;
    let id = test_id(0x63);
    let born_under = born_with_no_review(&vault, &id)?;
    let moved_to = move_default_facet(&vault)?;
    let committed = commit_proposed_put(&vault, &id, REPUT_VALUE);
    assert!(
        committed.is_ok(),
        "FAILBEFORE PREFLIGHT-FACET-REPUT-REPLAY-MISMATCH: the held re-put failed its replay match instead of parking: {committed:?}"
    );
    let stored = parked_review_bound_to_stored_body(&vault, &id, CHECKER_UNAVAILABLE)?;
    assert_eq!(stored.value, Value::from(REPUT_VALUE));
    assert_eq!(
        stored.scope_facet, born_under,
        "the re-put keeps its birth facet"
    );
    assert_eq!(vault.default_facet()?, moved_to);
    Ok(())
}

/// Guard: the same held re-put, with the vault default still where the
/// claim was born, parks as before.
#[test]
fn a_held_reput_under_its_birth_default_parks() -> Result<()> {
    let (_tmp, vault) = doors::checker_vault(Some(CHECKER_REF))?;
    let id = test_id(0x65);
    let born_under = born_with_no_review(&vault, &id)?;
    commit_proposed_put(&vault, &id, REPUT_VALUE)?;
    let stored = parked_review_bound_to_stored_body(&vault, &id, CHECKER_UNAVAILABLE)?;
    assert_eq!(stored.value, Value::from(REPUT_VALUE));
    assert_eq!(stored.scope_facet, born_under);
    Ok(())
}

/// Commits a raw put of a Proposed `health.*` claim body holding `value`.
/// No envelope reaches the gate: the manifest's critical rule holds it for
/// the owner, and the mask rewrites its bytes at apply when `value` holds a
/// secret.
fn commit_raw_health_put(vault: &Vault, id: &EntityId, value: &str) -> Result<()> {
    let mut body = doors::checker_body(vault, ClaimApprovalStatus::Proposed)?;
    seed_dreamer_parts(vault, &body)?;
    body.predicate = HEALTH_PREDICATE.to_owned();
    body.source = None;
    body.scope_facet = vault.default_facet()?;
    body.value = Value::from(value);
    let bytes = encode_claim_body(&body).expect("a valid claim body encodes");
    vault
        .batch()
        .put(
            id,
            ENTITY_TYPE_CLAIM,
            TimeRange { start: 2, end: 2 },
            2,
            &bytes,
        )
        .commit()?;
    Ok(())
}

/// (4) A held raw CLAIM put the mask rewrites at apply parks Proposed with
/// its review bound to the stored (masked) body.
#[test]
fn a_held_raw_claim_put_the_mask_rewrites_parks_with_a_review_of_the_stored_body() -> Result<()> {
    let (_tmp, vault) = doors::checker_vault(Some(CHECKER_REF))?;
    let id = test_id(0x66);
    let token = provider_token();
    let committed = commit_raw_health_put(&vault, &id, &token_value(&token));
    assert!(
        committed.is_ok(),
        "FAILBEFORE RAW-CLAIM-PUT-MASK-REPLAY-MISMATCH: the held raw put failed its replay match instead of parking: {committed:?}"
    );
    let stored = parked_review_bound_to_stored_body(&vault, &id, CRITICALITY_FLOOR)?;
    let stored_value = stored.value.as_str().expect("a text value").to_owned();
    assert!(
        !stored_value.contains(&token),
        "the stored value holds no token: {stored_value}"
    );
    assert!(
        stored_value.starts_with("deploy key [secret sc"),
        "the stored value holds the token's handle: {stored_value}"
    );
    Ok(())
}

/// Guard: a held raw CLAIM put the mask leaves as written parks as before.
#[test]
fn a_held_raw_claim_put_without_a_secret_parks_with_a_review_of_the_stored_body() -> Result<()> {
    let (_tmp, vault) = doors::checker_vault(Some(CHECKER_REF))?;
    let id = test_id(0x67);
    commit_raw_health_put(&vault, &id, PLAIN_VALUE)?;
    let stored = parked_review_bound_to_stored_body(&vault, &id, CRITICALITY_FLOOR)?;
    assert_eq!(stored.value, Value::from(PLAIN_VALUE));
    Ok(())
}
