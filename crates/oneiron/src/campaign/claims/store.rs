//! Store-aware claim reads: stage CAS, live-head scans, and DNC matching.

use rmpv::Value;

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimBody, ClaimLifecycleStatus, ClaimSubject, decode_claim_body};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON};
use crate::store::Store;
use crate::vault::{edge_kind_prefix, parse_edge_record};

use super::{codec::*, types::*};

/// Restrictive fold over one person's live `crm.fit` claims: `NotFit` wins.
///
/// `icp_scope` is a parameter rather than a caller-side filter so scope
/// isolation is a property of this chokepoint — a caller that hands over a
/// person's whole `crm.fit` set cannot accidentally let one ICP's rejection
/// contaminate another's verdict. Returns `None` when no claim is scoped here.
#[must_use]
pub fn resolve_crm_fit(icp_scope: &EntityId, claims: &[CrmFitValue]) -> Option<CrmFitVerdict> {
    claims
        .iter()
        .filter(|claim| claim.icp_scope == *icp_scope)
        .fold(None, |resolved, claim| match (resolved, claim.verdict) {
            (Some(CrmFitVerdict::NotFit), _) | (_, CrmFitVerdict::NotFit) => {
                Some(CrmFitVerdict::NotFit)
            }
            _ => Some(CrmFitVerdict::Fit),
        })
}

/// Compare-and-swaps the `crm.stage` head INSIDE the caller's write txn.
///
/// This is THE stage-transition door: it takes the caller's `wtxn` rather than
/// opening its own, so the projector that writes the replacement head and the
/// supersession of the prior head are ONE atomic unit. A self-transaction
/// variant would force a writer to put the new head in one txn and supersede in
/// another, and two projectors planning from the same head could then leave two
/// live heads behind — the exact torn state the head check exists to prevent.
///
/// `expected_current_head_id` is the compare half of the CAS:
///
/// * `Some(id)` — `id` must be the ONLY other live head for this
///   `(subject, campaign_ref)`, and both claims must agree on predicate, PERSON
///   subject, and campaign scope. It is then superseded.
/// * `None` — the FIRST stage head for this `(subject, campaign_ref)`. The
///   compare is against the ABSENCE of a head, so a head another writer already
///   landed loses instead of silently becoming a second live head. There is
///   nothing to supersede, so the call only validates.
///
/// Every rejection happens before the first write of this call, and a rejection
/// aborts the caller's whole txn — so the replacement head the caller wrote
/// rolls back with it.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] with a distinct static reason per rejection:
/// either id is not a live `crm.stage` claim, subject or campaign scope
/// disagree, the expected head is not the current one, or a `None` (first-head)
/// CAS found a head already live. Supersession errors propagate unchanged from
/// [`Vault::supersede_claim`].
pub fn supersede_crm_stage_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    new_claim_id: &EntityId,
    expected_current_head_id: Option<&EntityId>,
    now: u64,
) -> Result<()> {
    let (new_subject, new_value) = read_crm_stage_claim_in_txn(&vault.store, wtxn, new_claim_id)?;
    let Some(expected_current_head_id) = expected_current_head_id else {
        let heads = other_live_crm_stage_heads_in_txn(
            &vault.store,
            wtxn,
            new_subject,
            &new_value.campaign_ref,
            new_claim_id,
        )?;
        if !heads.is_empty() {
            return Err(invalid_claim("crm.stage first head is not the only head"));
        }
        return Ok(());
    };
    let (old_subject, old_value) =
        read_crm_stage_claim_in_txn(&vault.store, wtxn, expected_current_head_id)?;
    if new_subject != old_subject {
        return Err(invalid_claim("crm.stage supersession subject mismatch"));
    }
    if new_value.campaign_ref != old_value.campaign_ref {
        return Err(invalid_claim("crm.stage supersession campaign mismatch"));
    }
    let heads = other_live_crm_stage_heads_in_txn(
        &vault.store,
        wtxn,
        new_subject,
        &new_value.campaign_ref,
        new_claim_id,
    )?;
    if heads.as_slice() != [*expected_current_head_id] {
        return Err(invalid_claim("crm.stage expected head is not current"));
    }
    vault.supersede_claim_in_txn(wtxn, new_claim_id, expected_current_head_id, now)
}

/// Reads one live `crm.stage` claim, returning its subject and decoded value.
fn read_crm_stage_claim_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<(EntityId, CrmStageValue)> {
    let body =
        claim_body_in_txn(store, txn, id)?.ok_or(invalid_claim("crm.stage claim is missing"))?;
    if body.predicate != PREDICATE_CRM_STAGE {
        return Err(invalid_claim("claim is not crm.stage"));
    }
    if body.lifecycle != ClaimLifecycleStatus::Active {
        return Err(invalid_claim("crm.stage claim is not live"));
    }
    let ClaimSubject::Entity(subject) = body.subject else {
        return Err(invalid_claim("crm.stage subject must be an entity"));
    };
    Ok((subject, decode_crm_stage_value(&body.value)?))
}

/// Live `crm.stage` claim ids on `subject` scoped to `campaign_ref`, excluding
/// `replacement` — the head the caller already wrote into this same txn, which
/// is never its own competition.
pub(super) fn other_live_crm_stage_heads_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    subject: EntityId,
    campaign_ref: &EntityId,
    replacement: &EntityId,
) -> Result<Vec<EntityId>> {
    let mut heads = Vec::new();
    for id in subject_claim_ids_in_txn(store, txn, &subject)? {
        if id == *replacement {
            continue;
        }
        let Some(body) = claim_body_in_txn(store, txn, &id)? else {
            continue;
        };
        if body.predicate != PREDICATE_CRM_STAGE || body.lifecycle != ClaimLifecycleStatus::Active {
            continue;
        }
        if decode_crm_stage_value(&body.value)?.campaign_ref == *campaign_ref {
            heads.push(id);
        }
    }
    Ok(heads)
}

/// Returns whether `value` suppresses contact on `channel` within `scope`.
///
/// Matching is restrictive in both directions of uncertainty:
///
/// * a stored `channel` of `None` covers every channel;
/// * a stored `scope` of [`DO_NOT_CONTACT_SCOPE_ALL`] covers every scope;
/// * a caller that does not know the channel (`channel = None`) cannot prove
///   the suppression is irrelevant, so it matches.
///
/// Everything else compares exactly after normalization.
#[must_use]
pub fn do_not_contact_applies(
    value: &CommDoNotContactValue,
    channel: Option<&str>,
    scope: &str,
) -> bool {
    let channel_matches = match (value.channel.as_deref(), channel) {
        (None, _) | (Some(_), None) => true,
        (Some(stored), Some(queried)) => stored == normalize_token(queried),
    };
    let scope_matches =
        value.scope == DO_NOT_CONTACT_SCOPE_ALL || value.scope == normalize_token(scope);
    channel_matches && scope_matches
}

/// Whether `person_ref` carries a live `comm.do_not_contact` head matching
/// `(channel, scope)`.
///
/// A matching head applies at ANY approval state — including `Proposed` — and
/// regardless of staleness or validity window: this is the restrictive-wins
/// law, and a suppression that expires on its own is a suppression that leaks.
/// Only superseding or retracting the head (an authorized clear stamp) removes
/// it from the fold.
pub(crate) fn matching_do_not_contact_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    person_ref: EntityId,
    channel: Option<&str>,
    scope: &str,
) -> Result<bool> {
    for id in subject_claim_ids_in_txn(store, txn, &person_ref)? {
        let Some(body) = claim_body_in_txn(store, txn, &id)? else {
            continue;
        };
        if body.predicate != PREDICATE_COMM_DO_NOT_CONTACT
            || body.lifecycle != ClaimLifecycleStatus::Active
        {
            continue;
        }
        if do_not_contact_applies(&decode_do_not_contact_value(&body.value)?, channel, scope) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The live `campaign.member` head on `person_ref` scoped to `campaign_ref`.
///
/// The membership counterpart of [`other_live_crm_stage_heads_in_txn`], and the
/// single door ONE-1776's suppression and sticky-sender writers read through:
/// both must supersede exactly the head they read, in the same txn, or leave two
/// live memberships behind.
///
/// Two live heads for one `(person, campaign)` is a TORN cohort, not a merge
/// problem — the two rows can disagree about state, channels, and derivation,
/// and picking one would silently discard the other's provenance. It is rejected
/// for the same reason `crm.stage` rejects a second head.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] when more than one live head exists; storage and
/// decode errors propagate.
pub(crate) fn live_campaign_member_head_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    person_ref: EntityId,
    campaign_ref: EntityId,
) -> Result<Option<(EntityId, CampaignMemberValue)>> {
    let mut head = None;
    for id in subject_claim_ids_in_txn(store, txn, &person_ref)? {
        let Some(body) = claim_body_in_txn(store, txn, &id)? else {
            continue;
        };
        if body.predicate != PREDICATE_CAMPAIGN_MEMBER
            || body.lifecycle != ClaimLifecycleStatus::Active
        {
            continue;
        }
        let value = decode_campaign_member_value(&body.value)?;
        if value.campaign != campaign_ref {
            continue;
        }
        if head.is_some() {
            return Err(invalid_claim("campaign.member has more than one live head"));
        }
        head = Some((id, value));
    }
    Ok(head)
}

/// The live CRM-pack claim head on `subject` carrying exactly `predicate` and
/// `value`.
///
/// The replay door. Provider webhooks and unsubscribe callbacks redeliver, so a
/// writer that always appends would grow one suppression head per redelivery of
/// the same fact. Equality is on the ENCODED value, so it is the same identity
/// test the decoder enforces, not a hand-written field comparison that can drift
/// from the schema.
pub(crate) fn identical_live_head_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    subject: EntityId,
    predicate: &str,
    value: &Value,
) -> Result<Option<EntityId>> {
    for id in subject_claim_ids_in_txn(store, txn, &subject)? {
        let Some(body) = claim_body_in_txn(store, txn, &id)? else {
            continue;
        };
        if body.predicate == predicate
            && body.lifecycle == ClaimLifecycleStatus::Active
            && body.value == *value
        {
            return Ok(Some(id));
        }
    }
    Ok(None)
}

/// Resolves the PERSON a `comm.do_not_contact` claim would be written against
/// for the external-effect gate's `counterparty` string.
///
/// INTERIM and deliberately narrow. `ExternalEffectGateInput::counterparty` is
/// a bare address at HEAD and no existing engine call turns one into an
/// `EntityId`, so this reads SPINE-COMM's node-local party shortcut (whose
/// writer stays in `comm.rs` — CA never edits that file) and then re-validates
/// the hit against synced truth: the row must still be a PERSON carrying
/// exactly this `party_key`. A stale shortcut therefore resolves to NOTHING
/// rather than to the wrong person.
///
/// `Ok(None)` means the leg contributes nothing — it never clears an opt-out
/// another source established. ONE-1868 owns the complete resolution (all
/// contact records matched by `(party_ref, channel_class)`, index repair, and
/// the full-scan fallback) so no shipping path can answer a false "no".
fn resolve_do_not_contact_subject_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    counterparty: &str,
) -> Result<Option<EntityId>> {
    let party_key = counterparty.trim();
    if party_key.is_empty() {
        return Ok(None);
    }
    let Some(raw_id) = store
        .vault_meta
        .get(txn, &comm_party_index_key(party_key))?
    else {
        return Ok(None);
    };
    let Ok(bytes) = <[u8; crate::entity_id::ENTITY_ID_LEN]>::try_from(raw_id.as_ref()) else {
        return Ok(None);
    };
    let Ok(id) = EntityId::from_bytes(bytes) else {
        return Ok(None);
    };
    let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Ok(None);
    };
    if header.entity_type != ENTITY_TYPE_PERSON {
        return Ok(None);
    }
    let mut cursor = std::io::Cursor::new(&raw[ENTITY_METADATA_HEADER_LEN..]);
    let Ok(body) = rmpv::decode::read_value(&mut cursor) else {
        return Ok(None);
    };
    let Value::Map(entries) = body else {
        return Ok(None);
    };
    let carries_party_key = entries.iter().any(|(key, value)| {
        key.as_str() == Some(COMM_PARTY_KEY_FIELD) && value.as_str() == Some(party_key)
    });
    Ok(carries_party_key.then_some(id))
}

/// The external-effect gate's do-not-contact leg.
///
/// Called from `gate::hydrate_external_effect_contact` so every external effect
/// that names a counterparty folds `comm.do_not_contact` at ONE chokepoint. The
/// result is OR-ed into `counterparty_opted_out`: this leg can only ever ADD
/// suppression, never clear truth a COUNTERPARTY_CONTACT contact record supplied.
pub(crate) fn counterparty_do_not_contact_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    counterparty: &str,
    channel: Option<&str>,
    scope: &str,
) -> Result<bool> {
    match resolve_do_not_contact_subject_in_txn(store, txn, counterparty)? {
        Some(person_ref) => matching_do_not_contact_in_txn(store, txn, person_ref, channel, scope),
        None => Ok(false),
    }
}

/// Synced-truth field naming a comm-owned PERSON's party. Mirrors the private
/// `comm.rs` constant; CA reads it and never writes it.
const COMM_PARTY_KEY_FIELD: &str = "party_key";

/// Node-local party shortcut prefix owned by `comm.rs`. Read-only mirror.
const COMM_PARTY_INDEX_PREFIX: &[u8] = b"comm.party.v1:";

fn comm_party_index_key(party_key: &str) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(party_key.as_bytes());
    let mut key = Vec::with_capacity(COMM_PARTY_INDEX_PREFIX.len() + digest.len());
    key.extend_from_slice(COMM_PARTY_INDEX_PREFIX);
    key.extend_from_slice(&digest);
    key
}

/// CLAIM ids attached to `subject` through inbound `claim_of` edges.
fn subject_claim_ids_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    subject: &EntityId,
) -> Result<Vec<EntityId>> {
    let prefix = edge_kind_prefix(subject, EdgeKind::ClaimOf);
    let mut ids = Vec::new();
    for entry in store.edges_in.prefix_iter(txn, &prefix)? {
        let (key, value) = entry?;
        ids.push(parse_edge_record(&key, &value)?.target);
    }
    Ok(ids)
}

/// Decodes the CLAIM body stored at `id`, or `None` when the row is absent or
/// is not a type-0 CLAIM.
fn claim_body_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<ClaimBody>> {
    let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Err(Error::CorruptedIndex("campaign pack claim header"));
    };
    if header.entity_type != ENTITY_TYPE_CLAIM {
        return Ok(None);
    }
    decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true).map(Some)
}
