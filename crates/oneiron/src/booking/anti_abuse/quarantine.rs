use std::num::NonZeroU32;

use super::evaluation::{BookingRequestFacts, quarantine_claim_id};
use super::rate::{BookingRateDecision, consume_rate_token_in_txn};
use super::storage::{
    QUARANTINE_CLAIM_PREDICATE, QUARANTINE_RATE_DOMAIN, QUARANTINE_REASON_CODE,
    QUARANTINE_RUN_ID_PREFIX, engine_failure, hex_lower,
};
use crate::booking::BookingError;
use crate::booking::lifecycle::{booking_writer, digest_with};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::store::{
    GateDecisionId, GateDecisionRecord, PENDING_GATE_CONSENT_VERSION, PendingGateConsentRecord,
};
use crate::temporal::TimeRange;
use crate::{EntityId, Vault};

// -------------------------------------------------------------------------
// Quarantine (pending-review record through the gate's own ledger rows)
// -------------------------------------------------------------------------

/// What a quarantined submission left behind: the owner-reviewable record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BookingQuarantineReceipt {
    /// The pending-consent row key bytes (also hexed into `claim_ref`).
    pub claim_id: [u8; 16],
    pub decision_id: [u8; 16],
    pub claim_ref: String,
    pub decision_ref: String,
    pub reason_codes: Vec<String>,
}

/// The review payload on the quarantine claim: hashed identity only — raw
/// addresses never cross into persistence here either.
fn quarantine_claim_value(facts: &BookingRequestFacts, reason: &str) -> rmpv::Value {
    let mut entries = vec![
        (
            rmpv::Value::from("page_ref"),
            rmpv::Value::from(facts.page_ref.to_hex()),
        ),
        (
            rmpv::Value::from("ip_hash"),
            rmpv::Value::from(hex_lower(&facts.ip_hash)),
        ),
        (
            rmpv::Value::from("submitted_at_millis"),
            rmpv::Value::from(facts.submitted_at_millis),
        ),
        (rmpv::Value::from("reason"), rmpv::Value::from(reason)),
    ];
    if let Some(event_type) = &facts.event_type {
        entries.push((
            rmpv::Value::from("event_type"),
            rmpv::Value::from(event_type.0.as_str()),
        ));
    }
    if let Some(email_hash) = &facts.email_hash {
        entries.push((
            rmpv::Value::from("email_hash"),
            rmpv::Value::from(hex_lower(email_hash)),
        ));
    }
    rmpv::Value::Map(entries)
}

/// Routes one borderline submission to a durable pending-review inbox card,
/// never silently deleting it.
///
/// Three rows land in ONE booking-writer transaction, all through existing
/// crate doors: a minimal CLAIM body for the quarantined submission (via
/// [`Vault::put_claim_in_txn`], the door the booking lifecycle's claim
/// helper uses), plus the gate's own `GateDecisionRecord` +
/// `PendingGateConsentRecord` pair — exactly what `inbox.rs` pending-group
/// construction reads. The pending row stamps a content-keyed synthetic run
/// id, and `resolve_run_identity` keeps it verbatim as the group key because
/// no Dreamer attempt rows anchor it; the `diff_handle` / frontier pair
/// binds the exact stored claim body through
/// [`crate::gate::claim_consent_binding_parts`], so an owner verdict from
/// the inbox verifies against this row instead of going stale on arrival.
///
/// The claim names the booking page as its subject through the ordinary
/// claim door, so the page the guard ran for must exist in the vault — the
/// same subject precondition the calendar outcome recorder takes. A request
/// against a page the vault does not hold surfaces as an engine error, not a
/// dropped record.
///
/// # Errors
///
/// Storage failures, claim-door rejections (including a missing page
/// subject), and consent-binding failures.
fn quarantine_receipt(claim_id: [u8; 16]) -> BookingQuarantineReceipt {
    let decision_id = GateDecisionId::from_bytes(claim_id);
    BookingQuarantineReceipt {
        claim_id,
        decision_id: decision_id.as_bytes(),
        claim_ref: hex_lower(&claim_id),
        decision_ref: decision_id.to_hex(),
        reason_codes: vec![QUARANTINE_REASON_CODE.to_owned()],
    }
}

fn quarantine_borderline_submission_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    facts: &BookingRequestFacts,
    reason: &str,
    created_at: u64,
) -> Result<BookingQuarantineReceipt, BookingError> {
    let claim_id = quarantine_claim_id(facts, reason);
    let claim_ref = EntityId::from_bytes(claim_id)
        .map_err(|error| engine_failure("quarantine claim id", error))?;
    let reason_codes = vec![QUARANTINE_REASON_CODE.to_owned()];
    let run_id = format!("{QUARANTINE_RUN_ID_PREFIX}{}", hex_lower(&claim_id));
    let mut body = ClaimBody::new(
        QUARANTINE_CLAIM_PREDICATE,
        ClaimSubject::Entity(facts.page_ref),
        quarantine_claim_value(facts, reason),
        1.0,
        ClaimApprovalStatus::Proposed,
        ClaimLifecycleStatus::Active,
    );
    body.source = Some(ClaimSource::Observed);
    body.valid_from = Some(created_at);
    let decision_id = GateDecisionId::from_bytes(claim_id);
    let receipt = quarantine_receipt(claim_id);

    if let Some(existing) = vault
        .store
        .pending_gate_consent_in_txn(&*wtxn, &claim_ref)
        .map_err(|error| engine_failure("quarantine pending read", error))?
    {
        return Ok(BookingQuarantineReceipt {
            claim_id,
            decision_id: existing.decision_id.as_bytes(),
            claim_ref: hex_lower(&claim_id),
            decision_ref: existing.decision_id.to_hex(),
            reason_codes: existing.reason_codes,
        });
    }
    if vault
        .get_claim_in_txn(&*wtxn, &claim_ref)
        .map_err(|error| engine_failure("quarantine claim read", error))?
        .is_some()
    {
        return Ok(receipt);
    }
    let (diff_handle, read_frontier_hash) =
        crate::gate::claim_consent_binding_parts(&vault.store, wtxn, &body)
            .map_err(|error| engine_failure("quarantine consent binding", error))?;
    vault
        .put_claim_in_txn(
            wtxn,
            &claim_ref,
            &body,
            TimeRange {
                start: created_at,
                end: created_at,
            },
            created_at,
        )
        .map_err(|error| engine_failure("quarantine claim write", error))?;
    let decision = GateDecisionRecord {
        version: 0,
        decision_id,
        created_at,
        outcome: "pending".to_owned(),
        reason_codes: reason_codes.clone(),
        receipt_reasons: Vec::new(),
        system_notices: Vec::new(),
        actor_class: "booking.http_guard".to_owned(),
        actor_ref: None,
        content_kind: "booking.submission".to_owned(),
        policy_manifest_version: "booking.anti_abuse.v1".to_owned(),
        claim_id: Some(claim_id),
        grant_ref: None,
        diff_handle: diff_handle.clone(),
        read_frontier_hash,
        redacted_at: None,
    };
    let pending = PendingGateConsentRecord {
        version: PENDING_GATE_CONSENT_VERSION,
        claim_id,
        decision_id,
        created_at,
        diff_handle,
        read_frontier_hash,
        reason_codes,
        dreamer_run_id: Some(run_id),
    };
    vault
        .store
        .append_gate_decision_in_txn(wtxn, &decision)
        .map_err(|error| engine_failure("quarantine decision append", error))?;
    vault
        .store
        .put_pending_gate_consent_in_txn(wtxn, &pending)
        .map_err(|error| engine_failure("quarantine pending record", error))?;
    Ok(receipt)
}

/// Result of atomically admitting a potentially duplicate quarantine request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BookingQuarantineAdmission {
    Accepted(BookingQuarantineReceipt),
    RateLimited { retry_after_secs: u64 },
}

/// Atomically replay or admit one quarantine submission.
///
/// The duplicate lookup, page-wide aggregate quota decision, and first claim,
/// decision, and pending-consent write share the booking writer transaction.
/// Thus concurrent exact retries replay one receipt without consuming another
/// token, while distinct identities cannot overspend the page-wide budget.
pub fn admit_quarantine_submission(
    vault: &Vault,
    facts: &BookingRequestFacts,
    reason: &str,
    per_minute: NonZeroU32,
    created_at: u64,
) -> Result<BookingQuarantineAdmission, BookingError> {
    booking_writer(vault, |wtxn| {
        let claim_id = quarantine_claim_id(facts, reason);
        let claim_ref = EntityId::from_bytes(claim_id)
            .map_err(|error| engine_failure("quarantine claim id", error))?;
        if vault
            .store
            .pending_gate_consent_in_txn(&*wtxn, &claim_ref)
            .map_err(|error| engine_failure("quarantine pending read", error))?
            .is_some()
            || vault
                .get_claim_in_txn(&*wtxn, &claim_ref)
                .map_err(|error| engine_failure("quarantine claim read", error))?
                .is_some()
        {
            return Ok(BookingQuarantineAdmission::Accepted(quarantine_receipt(
                claim_id,
            )));
        }
        let scope_hash = digest_with(QUARANTINE_RATE_DOMAIN, facts.page_ref.as_bytes());
        match consume_rate_token_in_txn(
            vault,
            wtxn,
            b"quarantine",
            &scope_hash,
            per_minute,
            created_at,
        )? {
            BookingRateDecision::Allowed => Ok(BookingQuarantineAdmission::Accepted(
                quarantine_borderline_submission_in_txn(vault, wtxn, facts, reason, created_at)?,
            )),
            BookingRateDecision::Exceeded { retry_after_secs } => {
                Ok(BookingQuarantineAdmission::RateLimited { retry_after_secs })
            }
        }
    })
}

pub fn quarantine_borderline_submission(
    vault: &Vault,
    facts: &BookingRequestFacts,
    reason: &str,
    created_at: u64,
) -> Result<BookingQuarantineReceipt, BookingError> {
    booking_writer(vault, |wtxn| {
        quarantine_borderline_submission_in_txn(vault, wtxn, facts, reason, created_at)
    })
}
