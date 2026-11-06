//! Claim lifecycle primitives: precedence, close/retract, stamps, and loading shapes.

use super::{
    EdgeProvenanceClaimBody, EdgeRef, PREDICATE_EDGE_PROVENANCE, decode_edge_provenance_body,
    encode_edge_provenance_value, resolve_persisted_actor_class,
};
use crate::Vault;
use crate::batch::BatchOp;
use crate::claim::{ClaimBody, ClaimLifecycleStatus, encode_claim_body, validate_claim_body_bytes};
use crate::edge::EdgeProvenanceFlags;
use crate::entity_id::EntityId;
use crate::error::{ClaimError, Error, Result};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::store::Store;
use crate::temporal::TimeRange;
use heed::RwTxn;

pub(crate) use crate::write_envelope::provenance::edge_lifecycle::{
    ProvenancePrecedence, winner_index,
};

/// The public `short_id:content_hash` ref of the edge's CURRENT provenance
/// head: the D14 cohort WINNER among the live `edge.provenance` Claims for
/// `edge_ref`.
///
/// Edge-provenance wrappers carry a [`ClaimLifecycleStatus`], but they are NOT
/// chained by `Supersedes` edges the way generic claims are — their current
/// truth is selected by the existing D14 precedence order ([`winner_index`]:
/// greatest `learned_at`, then `confidence`, then claim-id bytes). This
/// reports that winner. It does not invent provenance `Supersedes` edges, and
/// the claim-verb chokepoints do not come here: they walk the real chain.
///
/// `None` when the cohort has no live member — every wrapper for the edge is
/// closed. That is a legitimate end state (the retracted dampening stamp), not
/// corruption, so the caller decides which head to name for it.
pub(super) fn active_cohort_winner_short_ref_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    edge_ref: &EdgeRef,
) -> Result<Option<String>> {
    let live = vault.live_edge_provenance_claims_in_txn(txn, edge_ref, None)?;
    let precedence: Vec<ProvenancePrecedence> =
        live.iter().map(StoredProvenanceClaim::precedence).collect();
    let Some(index) = winner_index(&precedence) else {
        return Ok(None);
    };
    vault.claim_short_ref_in(txn, &live[index].id).map(Some)
}

/// The public `short_id:content_hash` ref of the newest CLOSED wrapper for
/// `edge_ref`, ignoring `exclude` — the head to name once a SUPERSEDED target's
/// cohort has no live member left (its replacement was itself retracted, so it
/// still carries the edge's current stamp). Same D14 order as
/// [`active_cohort_winner_short_ref_in`].
///
/// Fails closed when the cohort holds nothing but `exclude`: a superseded
/// wrapper that nothing replaced is a broken cohort, and the only other answer
/// would be handing the caller back its own stale target.
pub(super) fn closed_cohort_head_short_ref_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    edge_ref: &EdgeRef,
    exclude: &EntityId,
) -> Result<String> {
    let closed = vault.edge_provenance_claims_in_txn(
        txn,
        edge_ref,
        Some(exclude),
        &[
            ClaimLifecycleStatus::Superseded,
            ClaimLifecycleStatus::Retracted,
        ],
    )?;
    let precedence: Vec<ProvenancePrecedence> = closed
        .iter()
        .map(StoredProvenanceClaim::precedence)
        .collect();
    let index = winner_index(&precedence).ok_or(Error::InvariantViolation(
        "superseded provenance wrapper has no newer cohort member",
    ))?;
    vault.claim_short_ref_in(txn, &closed[index].id)
}

pub(super) use crate::write_envelope::provenance::edge_lifecycle::{
    close_record_for_supersession, retract_record,
};

/// The 26-byte stamp primitive (D10): rewrites ONLY the two hot-flag bytes
/// at offsets 24/25 of the subject edge's value, preserving the first 24
/// bytes (weight + created_at + VAD) verbatim, and writes IDENTICAL bytes to
/// both `edges_out` and `edges_in`.
///
/// `pub(crate)` by design — the only public door to provenance flags is the
/// `edge.provenance` Claim lifecycle ([`crate::Vault::put_edge_provenance`]);
/// a flag without its truth-Claim would be unauditable.
pub(crate) fn restamp_edge_flags(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    subject: &EdgeRef,
    flags: EdgeProvenanceFlags,
) -> Result<()> {
    crate::ports::EdgeStoreMaintenance::port_edge_stamp_provenance(store, wtxn, subject, flags)
}

/// The D16 downgrade primitive: when deleting / SoftErasing an
/// `edge.provenance` Claim leaves NO surviving truth-Claim of any lifecycle
/// for an edge, the 26-byte provenanced value drops to the 24-byte bare
/// semantic layout — the first 24 bytes (weight + created_at + VAD) are
/// preserved verbatim and IDENTICAL bytes are written to both `edges_out`
/// and `edges_in`. A cached flag without ANY truth-Claim is unauditable; a
/// surviving RETRACTED Claim instead KEEPS the 26 B retracted dampening stamp
/// (the caller restamps it), so the downgrade fires only when neither an
/// active nor a retracted provenance Claim remains.
///
/// Returns whether the edge bytes changed: an already-bare 24-byte value is
/// the desired end state (idempotent no-op). A structural subject kind or a
/// non-contract value length fails typed — never a silent skip.
pub(crate) fn downgrade_edge_to_bare(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    subject: &EdgeRef,
) -> Result<bool> {
    crate::ports::EdgeStoreMaintenance::port_edge_clear_provenance(store, wtxn, subject)
}

pub(crate) use crate::write_envelope::provenance::edge_lifecycle::StoredProvenanceClaim;

/// Builds the re-put payload for a CLOSED provenance Claim: the wrapper's
/// `val` is replaced with the closed record, `to` mirrors the effective
/// `valid_to`, `life` becomes `lifecycle`, and the envelope keeps its
/// original `occurred.start` and `learned_at` (the D14 precedence key) while
/// `occurred.end` refreshes to the effective `valid_to` per D15. Fails typed
/// when the refreshed envelope would be inverted.
pub(super) fn closed_claim_put_payload(
    claim: &StoredProvenanceClaim,
    closed_record: &EdgeProvenanceClaimBody,
    lifecycle: ClaimLifecycleStatus,
) -> Result<(TimeRange, u64, ClaimBody, Vec<u8>)> {
    let valid_to = closed_record.valid_to.ok_or(Error::InvariantViolation(
        "closed provenance record must carry valid_to",
    ))?;
    let occurred = TimeRange {
        start: claim.occurred_start,
        end: valid_to,
    };
    if occurred.start > occurred.end {
        return Err(Error::Claim(ClaimError::InvalidProvenanceBody(
            "closing valid_to precedes the claim's occurred start",
        )));
    }
    let mut wrapper = claim.wrapper.clone();
    wrapper.value = encode_edge_provenance_value(closed_record);
    wrapper.valid_to = Some(valid_to);
    wrapper.lifecycle = lifecycle;
    let data = encode_claim_body(&wrapper)?;
    validate_claim_body_bytes(&data, true)?;
    Ok((occurred, claim.learned_at, wrapper, data))
}

/// A provenance-owner payload, not a policy permit. Only this module can mint
/// it, after the canonical record and the owner's lifecycle checks agree.
pub(crate) struct ProvenanceMaterialization {
    id: EntityId,
    occurred: TimeRange,
    learned_at: u64,
    data: Vec<u8>,
    pub(super) envelope: crate::WriteEnvelope,
    prior: Option<[u8; 32]>,
}

impl ProvenanceMaterialization {
    pub(super) fn new(
        id: EntityId,
        occurred: TimeRange,
        learned_at: u64,
        data: Vec<u8>,
        prior: Option<[u8; 32]>,
    ) -> Result<Self> {
        let body = crate::claim::validate_claim_body_and_decode(&data, true)?;
        if body.predicate != PREDICATE_EDGE_PROVENANCE {
            return Err(Error::Claim(ClaimError::NotAProvenanceClaim(
                "materialization requires edge.provenance",
            )));
        }
        let record = decode_edge_provenance_body(&body.value)?;
        let class = resolve_persisted_actor_class(&record, body.evidence.as_ref())?;
        let envelope = crate::WriteEnvelope::new(
            crate::WriteActor::new(record.actor_entity_ref, class),
            body.source.unwrap_or(crate::claim::ClaimSource::UserStated),
            crate::WriteProvenance::new(body.value.clone())?,
            body.approval,
        );
        Ok(Self {
            id,
            occurred,
            learned_at,
            data,
            envelope,
            prior,
        })
    }

    pub(crate) fn prior(&self) -> Option<[u8; 32]> {
        self.prior
    }

    pub(crate) fn into_parts(self) -> (EntityId, TimeRange, u64, Vec<u8>, crate::WriteEnvelope) {
        (
            self.id,
            self.occurred,
            self.learned_at,
            self.data,
            self.envelope,
        )
    }
}

pub(super) fn provenance_materialization_op(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    occurred: TimeRange,
    learned_at: u64,
    data: Vec<u8>,
) -> Result<(BatchOp, crate::batch::ClaimMaterialization)> {
    use sha2::{Digest, Sha256};
    let prior = store
        .port_entity_record(txn, &id)?
        .map(|row| row.encode())
        .map(|raw| Sha256::digest(&raw).into());
    let binding = crate::batch::ClaimMaterialization::provenance(ProvenanceMaterialization::new(
        id,
        occurred,
        learned_at,
        data.clone(),
        prior,
    )?)?;
    Ok((
        BatchOp::Put {
            id,
            entity_type: ENTITY_TYPE_CLAIM,
            occurred,
            learned_at,
            row_version: None,
            data,
            allow_maintenance: false,
            allow_reserved_predicate: true,
            hub_sync_imported: false,
        },
        binding,
    ))
}
