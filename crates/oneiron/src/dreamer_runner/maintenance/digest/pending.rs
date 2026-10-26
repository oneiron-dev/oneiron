//! What a digest may carry that no digest carried yet, by its seen state.
//! Entry: `pending_proposals` and the three `unseen_*` readers.
//! The digest state and item types are in the parent.

use super::{
    CLEANUP_VIEW, DigestCleanup, DigestNoteTombstones, DigestOffer, DigestProposal, DigestState,
    NOTE_TOMBSTONE_VIEW, PROACTIVITY_POLICY_REQUEST_PREDICATE, ProactivityCadence, invalid,
};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource, EntityId, Result, Vault};

/// The pending offers no digest carried yet, as the digest shows them.
pub(super) fn unseen_offers(
    pending: &[crate::skill_optimize::TrainingOffer],
    state: &DigestState,
) -> Vec<DigestOffer> {
    pending
        .iter()
        .filter(|offer| !state.offers_seen.contains(&offer.id.to_hex()))
        .map(|offer| DigestOffer {
            offer: offer.id,
            digest: offer.digest.clone(),
            summary: format!(
                "{TRAINING_OFFER_GROUP}: {}",
                serde_json::to_string(&offer.candidate).unwrap_or_default()
            ),
        })
        .collect()
}
/// The cleanup decisions and open proposals no digest carried yet, as one
/// line; `None` when there are none.
pub(super) fn unseen_cleanup(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    state: &DigestState,
) -> Result<Option<DigestCleanup>> {
    let mut line = DigestCleanup {
        decisions: Vec::new(),
        archived: 0,
        skipped: 0,
        proposals: Vec::new(),
        proposed: 0,
        view: CLEANUP_VIEW.to_owned(),
    };
    for decision in crate::vault_cleanup::cleanup_digests_in_txn(vault, txn)? {
        let id = decision.id.to_hex();
        if state.cleanup_seen.contains(&id) {
            continue;
        }
        line.archived = line.archived.saturating_add(decision.archived.len() as u64);
        line.skipped = line.skipped.saturating_add(decision.skipped.len() as u64);
        line.decisions.push(id);
    }
    for proposal in crate::vault_cleanup::cleanup_proposals_in_txn(vault, txn)? {
        let id = proposal.id.to_hex();
        if state.cleanup_seen.contains(&id) {
            continue;
        }
        line.proposed = line
            .proposed
            .saturating_add(proposal.candidates.len() as u64);
        line.proposals.push(id);
    }
    Ok((!line.decisions.is_empty() || !line.proposals.is_empty()).then_some(line))
}
/// The open NOTE tombstone proposals no digest carried yet, as one line;
/// `None` when there are none.
pub(super) fn unseen_note_tombstones(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    state: &DigestState,
) -> Result<Option<DigestNoteTombstones>> {
    let proposals: Vec<String> = crate::note::open_tombstone_proposals_in_txn(vault, txn)?
        .into_iter()
        .map(|proposal| format!("{}:{}", proposal.note.to_hex(), proposal.proposed_at))
        .filter(|id| !state.note_tombstones_seen.contains(id))
        .collect();
    Ok((!proposals.is_empty()).then(|| DigestNoteTombstones {
        proposals,
        view: NOTE_TOMBSTONE_VIEW.to_owned(),
    }))
}

pub(super) fn pending_proposals(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    authority: EntityId,
    state: &DigestState,
    cadence: &ProactivityCadence,
) -> Result<Vec<(String, DigestProposal)>> {
    let mut pending = Vec::new();
    // Stream the producer index rather than using its capped 10k-ID query:
    // previously displayed proposals remain Proposed and still occupy index
    // slots. A full tray must not disable the scheduler's other deadlines.
    for row in crate::claim::PENDING_PRODUCER.iter_from(&vault.store, txn, authority.as_bytes())? {
        let ((_, id), _) = row?;
        let Some(bytes) = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &id)?
        else {
            continue;
        };
        let header = EntityMetadataHeader::parse(&bytes).ok_or_else(invalid)?;
        if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM
            || bytes.len() == ENTITY_METADATA_HEADER_LEN
        {
            continue;
        }
        let body = crate::claim::decode_claim_body(&bytes[ENTITY_METADATA_HEADER_LEN..], true)?;
        if body.predicate == PROACTIVITY_POLICY_REQUEST_PREDICATE
            || body.approval != ClaimApprovalStatus::Proposed
            || body.lifecycle != ClaimLifecycleStatus::Active
            || body.source != Some(ClaimSource::Generated)
            || body.stale
            || crate::claim::session_claim_producer(&body) != Some(authority)
        {
            continue;
        }
        let revision = *blake3::hash(&bytes[ENTITY_METADATA_HEADER_LEN..]).as_bytes();
        if state.seen.get(&id.to_hex()) == Some(&revision) {
            continue;
        }
        let group = if cadence.group_by_facet {
            body.predicate
                .split('.')
                .take(2)
                .collect::<Vec<_>>()
                .join(".")
        } else {
            "proposals".into()
        };
        pending.push((
            group,
            DigestProposal {
                claim_ref: id,
                revision,
                summary: format!("{}: {}", body.predicate, body.value),
                private_sources: Vec::new(),
                unverified: false,
            },
        ));
    }
    Ok(pending)
}
