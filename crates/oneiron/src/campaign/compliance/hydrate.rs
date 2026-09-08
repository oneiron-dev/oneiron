//! External-effect gate leg and vault-to-facts hydration (evidence, jurisdiction, message elements).

use crate::campaign::claims::{
    PREDICATE_CAMPAIGN_MEMBER, PREDICATE_COMM_JURISDICTION, decode_comm_jurisdiction_value,
};
use crate::claim::{ClaimBody, ClaimLifecycleStatus, ClaimSubject};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::gate::ExternalEffectGateInput;
use crate::store::Store;

use super::codec::{
    active_claim_bodies_in_txn, claim_body_in_txn, map_entries, nested_entity_ref, nested_flag,
    nested_map, nested_text, resolve_comm_party_in_txn, sole_active_claim_body_in_txn,
};
use super::evaluate::{
    ComplianceVerdict, DispatchComplianceFacts, HydratedJpPublicationFacts, HydratedListProvenance,
    evaluate_dispatch_compliance, normalize_jurisdiction, normalize_token,
};
use super::pack_store::active_compliance_pack_in_txn;
use super::rules::{
    CONFIDENCE_MILLIS_SCALE, PREDICATE_CRM_COMPLIANCE_EVIDENCE,
    PREDICATE_CRM_COMPLIANCE_JP_PUBLICATION, PREDICATE_CRM_COMPLIANCE_LIST_PROVENANCE,
    PREDICATE_CRM_COMPLIANCE_MESSAGE_ELEMENTS,
};

// ---------------------------------------------------------------------------
// Hydration
// ---------------------------------------------------------------------------

/// The external-effect gate's campaign-compliance leg.
///
/// Returns `None` when compliance does not govern the effect at all: no
/// counterparty, no comm-owned PERSON behind the address, or a PERSON carrying
/// no campaign membership. Membership IS the campaign scope — the CRM pack's
/// ratified law is that a cohort is claims — so a booking confirmation or a
/// support reply never enters this stage.
pub(crate) fn campaign_compliance_gate(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    effect: &ExternalEffectGateInput,
    now_utc: u64,
) -> Result<Option<ComplianceVerdict>> {
    let Some(counterparty) = effect.counterparty.as_deref() else {
        return Ok(None);
    };
    let Some(subject) = resolve_comm_party_in_txn(store, txn, counterparty)? else {
        return Ok(None);
    };
    if !has_active_claim_in_txn(store, txn, &subject, PREDICATE_CAMPAIGN_MEMBER)? {
        return Ok(None);
    }
    let pack = active_compliance_pack_in_txn(store, txn)?;
    let facts = hydrate_dispatch_compliance_facts(store, txn, effect, subject, now_utc)?;
    Ok(Some(evaluate_dispatch_compliance(&pack, &facts)))
}

/// Resolves every fact the evaluator is allowed to see.
///
/// Each evidence reference is RESOLVED from the vault, bound to this
/// counterparty, and class-validated here. A reference that fails any of those
/// yields `None`, so the evaluator sees "no evidence" rather than "an assertion
/// that a record exists" — presence of a ref is never sufficient.
pub(crate) fn hydrate_dispatch_compliance_facts(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    effect: &ExternalEffectGateInput,
    counterparty: EntityId,
    now_utc: u64,
) -> Result<DispatchComplianceFacts> {
    let observation = jurisdiction_observation_in_txn(store, txn, &counterparty)?;
    let evidence = dispatch_evidence_in_txn(store, txn, &counterparty)?;
    let elements = message_elements_in_txn(store, txn, effect.channel_identity_ref)?;
    Ok(DispatchComplianceFacts {
        counterparty,
        jurisdiction: observation.as_ref().map(|(token, _)| token.clone()),
        jurisdiction_confidence_millis: observation.and_then(|(_, confidence)| confidence),
        channel: normalize_token(&effect.channel),
        legal_form: evidence.legal_form,
        list_provenance: evidence.list_provenance,
        jp_publication: evidence.jp_publication,
        // A send with no bound sending identity has no identity to disclose,
        // whatever a configuration row claims.
        sender_identity_present: elements.sender_identity && effect.channel_identity_ref.is_some(),
        physical_address_present: elements.physical_address,
        optout_mechanism_present: elements.optout_mechanism,
        commercial_marking_present: elements.commercial_marking,
        now_utc,
    })
}

/// The newest ACTIVE `comm.jurisdiction` observation, with its confidence.
///
/// Two live heads at the same `observed_at` are a real possibility (an
/// offline-minted twin, a re-import), and edge-iteration order is not a tie
/// break a gate may depend on — so ties resolve on the token itself. Same
/// vault, same answer, every run.
fn jurisdiction_observation_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    subject: &EntityId,
) -> Result<Option<(String, Option<u16>)>> {
    let mut observations = Vec::new();
    for body in active_claim_bodies_in_txn(store, txn, subject, PREDICATE_COMM_JURISDICTION)? {
        let value = decode_comm_jurisdiction_value(&body.value)?;
        observations.push((
            value.observed_at,
            normalize_jurisdiction(&value.jurisdiction),
            confidence_millis(body.confidence),
        ));
    }
    observations
        .sort_unstable_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));
    Ok(observations
        .into_iter()
        .next()
        .map(|(_, token, confidence)| (token, confidence)))
}

/// `ClaimBody::confidence` is a fraction in `[0, 1]`; the pack's floor is in
/// thousandths. A non-finite or out-of-range value is not a confidence.
fn confidence_millis(confidence: f32) -> Option<u16> {
    if !confidence.is_finite() || !(0.0..=1.0).contains(&confidence) {
        return None;
    }
    Some((confidence * CONFIDENCE_MILLIS_SCALE).round() as u16)
}

#[derive(Debug, Default)]
struct DispatchEvidence {
    legal_form: Option<String>,
    list_provenance: Option<HydratedListProvenance>,
    jp_publication: Option<HydratedJpPublicationFacts>,
}

fn dispatch_evidence_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    subject: &EntityId,
) -> Result<DispatchEvidence> {
    let Some(body) =
        sole_active_claim_body_in_txn(store, txn, subject, PREDICATE_CRM_COMPLIANCE_EVIDENCE)?
    else {
        return Ok(DispatchEvidence::default());
    };
    let entries = map_entries(&body.value);
    Ok(DispatchEvidence {
        legal_form: nested_text(entries, "legal_form"),
        list_provenance: hydrate_list_provenance(store, txn, subject, entries)?,
        jp_publication: hydrate_jp_publication(store, txn, subject, entries)?,
    })
}

/// Resolves the list-provenance reference and confirms its class.
///
/// Three ways this yields `None`, and all three are the same answer to the
/// evaluator: the reference is absent, it resolves to nothing or to a record of
/// another kind, or the record's own class contradicts the claimed one.
fn hydrate_list_provenance(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    subject: &EntityId,
    entries: &[(rmpv::Value, rmpv::Value)],
) -> Result<Option<HydratedListProvenance>> {
    let Some(nested) = nested_map(entries, "list_provenance") else {
        return Ok(None);
    };
    let (Some(record_ref), Some(claimed_class)) = (
        nested_entity_ref(nested, "ref"),
        nested_text(nested, "class"),
    ) else {
        return Ok(None);
    };
    let Some(record) = evidence_record_in_txn(
        store,
        txn,
        subject,
        &record_ref,
        PREDICATE_CRM_COMPLIANCE_LIST_PROVENANCE,
    )?
    else {
        return Ok(None);
    };
    let stored_class = nested_text(map_entries(&record.value), "class");
    Ok(
        (stored_class.as_ref() == Some(&claimed_class)).then_some(HydratedListProvenance {
            record_ref,
            claimed_class,
        }),
    )
}

fn hydrate_jp_publication(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    subject: &EntityId,
    entries: &[(rmpv::Value, rmpv::Value)],
) -> Result<Option<HydratedJpPublicationFacts>> {
    let Some(record_ref) =
        nested_map(entries, "jp_publication").and_then(|nested| nested_entity_ref(nested, "ref"))
    else {
        return Ok(None);
    };
    let Some(record) = evidence_record_in_txn(
        store,
        txn,
        subject,
        &record_ref,
        PREDICATE_CRM_COMPLIANCE_JP_PUBLICATION,
    )?
    else {
        return Ok(None);
    };
    let facts = map_entries(&record.value);
    Ok(Some(HydratedJpPublicationFacts {
        record_ref,
        published_by_recipient: nested_flag(facts, "published_by_recipient"),
        in_course_of_business: nested_flag(facts, "in_course_of_business"),
        no_marketing_statement_attached: nested_flag(facts, "no_marketing_statement_attached"),
    }))
}

/// A cited record counts only when it is an ACTIVE CLAIM of the expected
/// predicate whose subject is THIS counterparty. The subject binding is what
/// stops one contact's evidence from authorizing another's dispatch.
fn evidence_record_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    subject: &EntityId,
    record_ref: &EntityId,
    predicate: &str,
) -> Result<Option<ClaimBody>> {
    let Some(body) = claim_body_in_txn(store, txn, record_ref)? else {
        return Ok(None);
    };
    let bound = body.predicate == predicate
        && body.lifecycle == ClaimLifecycleStatus::Active
        && body.subject == ClaimSubject::Entity(*subject);
    Ok(bound.then_some(body))
}

#[derive(Debug, Default)]
struct MessageElements {
    sender_identity: bool,
    physical_address: bool,
    optout_mechanism: bool,
    commercial_marking: bool,
}

/// Message elements are a property of the SENDING identity's template, so they
/// are read from the channel identity the effect is bound to. No identity, or
/// no configuration row, means no element is established.
fn message_elements_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    channel_identity_ref: Option<EntityId>,
) -> Result<MessageElements> {
    let Some(identity) = channel_identity_ref else {
        return Ok(MessageElements::default());
    };
    let Some(body) = sole_active_claim_body_in_txn(
        store,
        txn,
        &identity,
        PREDICATE_CRM_COMPLIANCE_MESSAGE_ELEMENTS,
    )?
    else {
        return Ok(MessageElements::default());
    };
    let entries = map_entries(&body.value);
    Ok(MessageElements {
        sender_identity: nested_flag(entries, "sender_identity"),
        physical_address: nested_flag(entries, "physical_address"),
        optout_mechanism: nested_flag(entries, "optout_mechanism"),
        commercial_marking: nested_flag(entries, "commercial_marking"),
    })
}

// ---------------------------------------------------------------------------
// Claim substrate reads
// ---------------------------------------------------------------------------

fn has_active_claim_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    subject: &EntityId,
    predicate: &str,
) -> Result<bool> {
    Ok(!active_claim_bodies_in_txn(store, txn, subject, predicate)?.is_empty())
}
