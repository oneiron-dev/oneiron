use super::*;
use crate::store::Store;

// ---------------------------------------------------------------------------
// Claim writers
// ---------------------------------------------------------------------------

/// Refuses a passport whose subject is not a live `ChannelIdentity` record.
///
/// `put_claim_in_txn` already refuses a missing subject; this adds the TYPE
/// check, so a passport can never be filed against an arbitrary entity that
/// merely happens to exist.
pub(super) fn require_channel_identity(
    vault: &Vault,
    wtxn: &heed::RwTxn<'_>,
    id: EntityId,
) -> Result<()> {
    let raw = vault
        .store
        .entities
        .get(wtxn, id.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    let header = EntityMetadataHeader::parse(&raw).ok_or_else(|| corrupt("entity header"))?;
    if header.entity_type == ENTITY_TYPE_CHANNEL_IDENTITY {
        Ok(())
    } else {
        Err(Error::InvalidEntityType(header.entity_type))
    }
}

pub(super) fn put_passport_claim(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    passport: &ThreadPassport,
    references: &[CanonicalMessageId],
    in_reply_to: Option<&CanonicalMessageId>,
) -> Result<()> {
    let mut body = ClaimBody::new(
        PREDICATE_THREAD_PASSPORT,
        ClaimSubject::Entity(passport.identity_ref),
        encode_passport_value(passport, references, in_reply_to),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    body.valid_from = Some(passport.observed_at);
    // Observed: a passport records what a provider event did, not a belief the
    // engine inferred.
    body.source = Some(ClaimSource::Observed);
    vault.put_claim_in_txn(
        wtxn,
        &EntityId::now(),
        &body,
        TimeRange {
            start: passport.observed_at,
            end: passport.observed_at,
        },
        passport.observed_at,
    )
}

pub(super) fn put_alias_claim(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    identity_ref: EntityId,
    from_thread_ref: &str,
    to_thread_ref: &str,
    observed_at: u64,
) -> Result<()> {
    let mut body = ClaimBody::new(
        PREDICATE_THREAD_ALIAS,
        ClaimSubject::Entity(identity_ref),
        encode_alias_value(identity_ref, from_thread_ref, to_thread_ref, observed_at),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    body.valid_from = Some(observed_at);
    body.source = Some(ClaimSource::Observed);
    vault.put_claim_in_txn(
        wtxn,
        &EntityId::now(),
        &body,
        TimeRange {
            start: observed_at,
            end: observed_at,
        },
        observed_at,
    )
}

pub(crate) fn is_thread_claim_predicate(predicate: &str) -> bool {
    matches!(
        predicate,
        PREDICATE_THREAD_PASSPORT | PREDICATE_THREAD_ALIAS
    )
}

/// Missing replicated owners are pending, not authoritative. Indexed readers
/// cannot discover them until the ChannelIdentity arrives. A known wrong type
/// is rejected on every road, before any byte or derived edge is staged.
pub(crate) fn validate_thread_claim_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: &ClaimBody,
    replicated: bool,
) -> Result<()> {
    if let Some(raw) = store.entities.get(rtxn, id.as_bytes())?
        && EntityMetadataHeader::parse(&raw)
            .is_some_and(|header| header.entity_type == crate::registry::ENTITY_TYPE_CLAIM)
        && let Ok(prior) =
            crate::claim::decode_claim_body(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..], true)
        && is_thread_claim_predicate(&prior.predicate)
        && (prior.predicate != body.predicate
            || prior.subject != body.subject
            || prior.value != body.value
            || prior.source != body.source
            || prior.valid_from != body.valid_from)
    {
        return Err(Error::InvalidClaimBody(
            "observed thread evidence is immutable; append new reference evidence",
        ));
    }
    if !is_thread_claim_predicate(&body.predicate) {
        return Ok(());
    }
    validate_thread_claim_owner_in_txn(store, rtxn, body, replicated)?;
    if !replicated && body.lifecycle == ClaimLifecycleStatus::Active {
        validate_thread_claim_provenance_in_txn(store, rtxn, id, body)?;
    }
    Ok(())
}

pub(super) fn validate_thread_claim_owner_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    body: &ClaimBody,
    replicated: bool,
) -> Result<()> {
    validate_thread_claim_structure(body)?;
    let ClaimSubject::Entity(subject) = body.subject else {
        unreachable!("validated subject")
    };
    let Some(raw) = store.entities.get(rtxn, subject.as_bytes())? else {
        return if replicated {
            Ok(())
        } else {
            Err(Error::EntityNotFound)
        };
    };
    let header = EntityMetadataHeader::parse(&raw).ok_or_else(|| corrupt("thread owner header"))?;
    if header.entity_type != ENTITY_TYPE_CHANNEL_IDENTITY {
        return Err(Error::InvalidClaimBody(
            "thread claim owner must be a ChannelIdentity",
        ));
    }
    Ok(())
}
