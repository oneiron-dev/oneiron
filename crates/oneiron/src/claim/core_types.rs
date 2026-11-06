//! The CLAIM body itself: [`ClaimBody`], [`ClaimSubject`], the pinned
//! MessagePack key set, and the structural-validation dispatcher every
//! type-0 write funnels through. The codec lives in the `codec` child.
//!
//! `validate_claim_body_and_decode` is the one place a reviewer checks for
//! "is this predicate validated": it fans out by predicate to the local
//! validators in `predicate_validators.rs` / `lexical_query_hint.rs` and to
//! the domain modules that own their own claim shapes.

use rmpv::Value;

use super::*;
use crate::error::{Error, Result};
use crate::serialize::pack_format::FieldProfile;
#[cfg(test)]
use crate::temporal::TimeRange;
use crate::write_envelope::{
    affect_trigger::{AFFECT_TRIGGER_PREDICATE, validate_affect_trigger_claim_structure},
    coping_outcome::{COPING_OUTCOME_PREDICATE, validate_coping_outcome_claim_structure},
};

pub use crate::write_envelope::claim_body::{
    CLAIM_BODY_KEYS, ClaimBody, ClaimSubject, CursorSpan, EvidenceKind, EvidenceRef,
    RelationshipScope, RelationshipSet, SessionClaimBundle, SessionClaimBundleClaim,
    decode_claim_body, meet_relationship_scopes, relationship_scope_includes,
    relationship_scope_of, relationship_scope_transcript,
};
pub(crate) use crate::write_envelope::claim_body::{
    CLAIM_FIELDS_FULL, CLAIM_FIELDS_MINIMAL, CLAIM_FIELDS_STANDARD, EDGE_REF_LEN,
    EVIDENCE_REFS_KEY, KEY_CONF, KEY_SAL, KEY_SCOPE, KEY_SESSION, KEY_WORLD,
    SessionClaimBundleMember, decode_relationship_scope, encode_claim_body,
    encode_relationship_scope, public_evidence_refs, public_evidence_value,
};

/// The CLAIM fields `profile` reads: the same lists the serializer
/// projects, so a host projection cannot drift from them (FIX 11037).
pub fn claim_fields(profile: FieldProfile) -> &'static [&'static str] {
    match profile {
        FieldProfile::Minimal => CLAIM_FIELDS_MINIMAL,
        FieldProfile::Standard => CLAIM_FIELDS_STANDARD,
        FieldProfile::Full => CLAIM_FIELDS_FULL,
    }
}

/// Structural validation entry point for raw type-0 body bytes (D18).
/// See [`crate::claim::decode_claim_body`] for the rules.
///
/// This is the WRITE-ONLY chokepoint (the read path — `Vault::get_claim` —
/// decodes via [`crate::claim::decode_claim_body`] directly): every type-0 write on every
/// door (`Vault::put_claim`, both batch builders' public puts, the
/// reserved-namespace `put_reserved_claim` door, the `put_replicated`
/// sync-replay doors, and the provenance lifecycle rewrites) validates
/// through it, either up front or via `apply_put`. On top of the D18 rules
/// it runs the predicate-aware structural branch for reserved
/// `edge.provenance` Claims (ONE-1159) — see
/// [`validate_edge_provenance_claim_structure`]. Reads stay untouched:
/// pre-existing stored junk keeps its current read behavior (typed failure
/// at the provenance ops that interpret it), it just can no longer be
/// (re)written.
pub(crate) fn validate_claim_body_and_decode(
    data: &[u8],
    allow_reserved_predicate: bool,
) -> Result<ClaimBody> {
    validate_claim_body_and_decode_with_descriptor(
        data,
        allow_reserved_predicate,
        |predicate| Ok(crate::comm::is_compiled_generic_claim_predicate(predicate)),
        crate::comm::check_claim_against_compiled_descriptor,
    )
}

fn validate_claim_body_and_decode_with_descriptor(
    data: &[u8],
    allow_reserved_predicate: bool,
    is_generic: impl FnOnce(&str) -> Result<bool>,
    check_descriptor: impl FnOnce(&ClaimBody) -> Result<()>,
) -> Result<ClaimBody> {
    let body = decode_claim_body(data, allow_reserved_predicate)?;
    // Lineage before predicate shape (ONE-1710): the forgery guard is
    // predicate-agnostic, so it must not sit behind a predicate-specific
    // branch that only some claims enter.
    validate_claim_source_lineage(&body)?;
    crate::write_envelope::carry_forward::validate_claim(&body)?;
    crate::blob_artifact::esign::validate_event_claim(&body)?;
    super::supersession_provenance::validate(&body)?;
    if body.predicate.starts_with("world_access.") || body.predicate.starts_with("activated.") {
        crate::context_board::validate_board_claim(&body)?;
    } else if body.predicate == crate::provenance::PREDICATE_EDGE_PROVENANCE {
        validate_edge_provenance_claim_structure(&body)?;
    } else if body.predicate == PREDICATE_LEXICAL_QUERY_HINT {
        lexical_query_hint_target(&body)?;
    } else if crate::edit_distance::miner::is_compiled_preference(&body.predicate) {
        crate::edit_distance::miner::validate_compiled_preference(&body)?;
    } else if is_expression_preference_predicate(&body.predicate) {
        validate_expression_preference_claim_structure(&body)?;
    } else if body.predicate == PREDICATE_COMPANION_EXPRESSION {
        validate_companion_expression_claim_structure(&body)?;
    } else if body.predicate == AFFECT_TRIGGER_PREDICATE {
        validate_affect_trigger_claim_structure(&body)?;
    } else if body.predicate == COPING_OUTCOME_PREDICATE {
        validate_coping_outcome_claim_structure(&body)?;
    } else if body.predicate == PREDICATE_CONFLICT_OPEN
        || body.predicate == PREDICATE_CONFLICT_RESOLVED
    {
        validate_conflict_claim_structure(&body)?;
    } else if body.predicate == PREDICATE_COREFERENCE_STATUS {
        validate_coreference_status_claim_structure(&body)?;
    } else if body.predicate == PREDICATE_COREFERENCE_SHARE_CONSENT {
        validate_coreference_share_consent_claim_structure(&body)?;
    } else if body.predicate == crate::write_envelope::identity_pair::PREDICATE_ENTITY_DISTINCT_FROM
    {
        crate::write_envelope::identity_pair::validate_distinct_from_claim_structure(&body)?;
    } else if crate::write_envelope::thread_claim::is_thread_claim_predicate(&body.predicate) {
        crate::write_envelope::thread_claim::validate_thread_claim_structure(&body)?;
    } else if crate::write_envelope::channel_identity::is_channel_identity_claim_predicate(
        &body.predicate,
    ) {
        crate::channel_identity::validate_channel_identity_claim_structure(&body)?;
    } else if crate::channel_identity_provider::is_line_chat_observation_claim_predicate(
        &body.predicate,
    ) {
        crate::channel_identity_provider::validate_line_chat_observation_claim_structure(&body)?;
    } else if crate::write_envelope::identity_reputation::is_identity_reputation_claim_predicate(
        &body.predicate,
    ) {
        crate::write_envelope::identity_reputation::validate_identity_reputation_claim_structure(
            &body,
        )?;
    } else if crate::provider_confidence::is_actor_confidence_prior_claim_predicate(&body.predicate)
    {
        crate::provider_confidence::validate_actor_confidence_prior_claim_structure(&body)?;
    } else if crate::provider_confidence::is_provider_enrichment_claim_predicate(&body.predicate) {
        crate::provider_confidence::validate_provider_enrichment_claim_structure(&body)?;
    } else if body.predicate == crate::write_envelope::subject_record::PREDICATE_ACTOR_SUBJECT_REF {
        crate::write_envelope::subject_record::validate_actor_subject_claim_structure(&body)?;
    } else if body.predicate == crate::write_envelope::claim_predicate::PREDICATE_PERSON_SUBSTRATE {
        crate::write_envelope::subject_record::validate_person_substrate_claim_structure(&body)?;
    } else if body.predicate == crate::skill_reliability::PREDICATE_SKILL_RELIABILITY {
        crate::skill_reliability::validate_imported_reliability(&body)?;
    } else if crate::write_envelope::learning_predicate::is_learning_predicate(&body.predicate) {
        crate::learning::validate_learning_claim_structure(&body)?;
    } else if crate::actor_claims::is_actor_claim_predicate(&body.predicate) {
        crate::actor_claims::validate_actor_claim_structure(&body)?;
    } else if crate::counterparty_contact::is_counterparty_contact_claim_predicate(&body.predicate)
    {
        crate::counterparty_contact::validate_counterparty_contact_claim_structure(&body)?;
    } else if crate::commitment::is_commitment_claim_predicate(&body.predicate) {
        crate::commitment::validate_commitment_claim_structure(&body)?;
    } else if crate::calendar::claims::is_calendar_claim_predicate(&body.predicate) {
        crate::calendar::claims::validate_calendar_claim_structure(&body)?;
    } else if is_generic(&body.predicate)? {
        // Generic classes use the caller's descriptor. A synchronized builtin
        // descriptor instead keeps the native family validation below.
        check_descriptor(&body)?;
        return Ok(body);
    } else if crate::write_envelope::cohort_claims::is_campaign_pack_claim_predicate(
        &body.predicate,
    ) {
        // EXACT-predicate match, deliberately ahead of the `comm.` family: the
        // CRM pack owns `comm.do_not_contact` / `comm.bounce` /
        // `comm.jurisdiction` while `comm.rs` keeps `comm.opt_out` and friends.
        crate::write_envelope::cohort_claims::validate_campaign_pack_claim_structure(&body)?;
    } else if crate::write_envelope::communication::is_comm_claim_predicate(&body.predicate) {
        crate::comm::validate_comm_claim_structure(&body)?;
    } else if crate::disclosure::is_disclosure_claim_predicate(&body.predicate) {
        crate::disclosure::validate_disclosure_claim_structure(&body)?;
    } else if crate::delivery_window::is_delivery_window_claim_predicate(&body.predicate) {
        crate::delivery_window::validate_delivery_window_claim_structure(&body)?;
    } else if crate::booking::is_booking_family_claim_predicate(&body.predicate) {
        // EXACT-predicate membership, like every arm above: a `booking.` prefix
        // would silently adopt every future booking predicate. The lifecycle
        // heads are validated here too, so none breaks a read (FIX 5994).
        crate::booking::validate_booking_family_claim(&body)?;
    } else if crate::write_envelope::voice_segment::is_voice_segment_claim_predicate(
        &body.predicate,
    ) {
        crate::write_envelope::voice_segment::validate_voice_segment_claim_structure(&body)?;
    } else if crate::claim::reaction_record::is_reaction_claim_predicate(&body.predicate) {
        crate::claim::reaction_record::validate_reaction_claim_structure(&body)?;
    }
    check_descriptor(&body)?;
    Ok(body)
}

/// The same structural and family validation as
/// [`validate_claim_body_and_decode`], using the synchronized class descriptor
/// when readable and the compiled fallback otherwise (ARCH-0057). The compiled
/// generic seed does not prefilter a synchronized descriptor's value.
pub(crate) fn validate_claim_body_and_decode_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    data: &[u8],
    allow_reserved_predicate: bool,
) -> Result<ClaimBody> {
    validate_claim_body_and_decode_with_descriptor(
        data,
        allow_reserved_predicate,
        |predicate| {
            Ok(crate::comm::is_compiled_generic_claim_predicate(predicate)
                && crate::comm::claim_class_descriptor_in_txn(store, txn, predicate)?.is_some_and(
                    |descriptor| {
                        descriptor.validator_kind == crate::comm::ClaimValidatorKind::Generic
                    },
                ))
        },
        |body| {
            store
                .record_hooks
                .check_claim_against_descriptor_in_txn(store, txn, body)
        },
    )
}

pub(crate) fn validate_claim_body_bytes(data: &[u8], allow_reserved_predicate: bool) -> Result<()> {
    validate_claim_body_and_decode(data, allow_reserved_predicate).map(|_| ())
}

#[cfg(test)]
mod import_validation_tests {
    use super::*;
    use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON};
    use crate::test_util::{entity, open_test_vault_with};

    #[test]
    fn provider_enrichment_replicated_import_accepts_valid_and_rejects_invalid() -> Result<()> {
        let doors = &[
            false,
            #[cfg(feature = "sync")]
            true,
        ];
        for &transactional in doors {
            let mut config = crate::config::VaultConfig::device();
            config.map_size = 16 * 1024 * 1024;
            config.dimensions = 4;
            config.embedding_model = None;
            let (_dir, vault) = open_test_vault_with(config);
            let subject = entity(0x91);
            let id = entity(0x92);
            let at = TimeRange {
                start: 100,
                end: 100,
            };
            vault.put_entity(&subject, ENTITY_TYPE_PERSON, at, 100, b"person")?;
            let admit = |body: &ClaimBody| -> Result<()> {
                let data = encode_claim_body(body)?;
                #[cfg(feature = "sync")]
                if transactional {
                    return vault.with_write_txn(|txn| {
                        vault
                            .batch_in()
                            .put_replicated(&id, ENTITY_TYPE_CLAIM, at, 100, &data)
                            .apply(txn)
                    });
                }
                let _ = transactional;
                vault
                    .batch()
                    .put_replicated(&id, ENTITY_TYPE_CLAIM, at, 100, &data)
                    .commit()
            };
            let mut body = ClaimBody::new(
                crate::provider_confidence::PREDICATE_PROVIDER_ENRICHMENT,
                ClaimSubject::Entity(subject),
                Value::Map(vec![(Value::from("provider"), Value::from("fixture"))]),
                0.8,
                ClaimApprovalStatus::Auto,
                ClaimLifecycleStatus::Active,
            )?;
            body.source = Some(ClaimSource::Imported);
            admit(&body)?;
            assert_eq!(vault.get_claim(&id)?, Some(body.clone()));
            let before = vault.get(&id)?;
            for (value, expected) in [
                (
                    Value::from("model"),
                    "provider-attributed claim value must be a map",
                ),
                (
                    Value::Map(Vec::new()),
                    "provider-attributed claim value is missing provider",
                ),
            ] {
                body.value = value;
                assert!(matches!(
                    admit(&body),
                    Err(Error::InvalidClaimBody(reason)) if reason == expected
                ));
                assert_eq!(vault.get(&id)?, before);
            }
        }
        Ok(())
    }
}
