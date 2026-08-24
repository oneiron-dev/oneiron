//! Sync-path ingest for the type-76 family: event reads, participant and actor
//! validation shared with the local door, and the engine-stamped causality
//! sequence allocator/join.

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_FACET, ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT, is_structural_kind};
use crate::vault::Vault;

use super::decode_identity_topology_event_body;
use super::event_body_codec::validate_replicated_identity_topology_seq;
use super::ledger_fold::{IdentityTopologyAction, IdentityTopologyEvent};
use super::op_apply::{IdentityOpWrite, IdentityTopologyParticipantValidation};
use super::op_vocabulary::IdentityTopologyOp;
use super::proposal_resolution::{assert_amendment_in_scope, decode_identity_op_amendment};
use super::stored_event::{StoredIdentityOpAction, StoredIdentityOpEvent};
use super::transition_table::IdentityTopologyRejection;
use super::{IDENTITY_TOPOLOGY_REPLICATED_SEQ_CEILING, IDENTITY_TOPOLOGY_SEQ_KEY};

impl Vault {
    /// Transaction-composable [`Vault::identity_topology_event`].
    pub(crate) fn identity_topology_event_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<StoredIdentityOpEvent>> {
        let Some(raw) = self.store.entities.get(rtxn, id.as_bytes())? else {
            return Ok(None);
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT {
            return Err(Error::InvalidEntityType(header.entity_type));
        }
        // A STORED row that fails decode is on-disk corruption (the family
        // is engine-authored and door-validated on every admit path) —
        // classified as `CorruptedIndex`, never as the
        // `InvalidIdentityTopologyEventBody` ingress rejection, so local
        // damage can never be quarantine-classified as a rejectable
        // remote input.
        decode_identity_topology_event_body(&raw[ENTITY_METADATA_HEADER_LEN..])
            .map(Some)
            .map_err(|_| Error::CorruptedIndex("identity topology event body"))
    }

    /// The whole identity-topology event family, read from the type-76
    /// record index — the ONE enumeration surface the fold, the receipt
    /// projection, and any rebuild share (no side index is authoritative).
    /// Fail-closed: the family is engine-authored, so an undecodable row is
    /// corruption, never skipped.
    pub(crate) fn identity_topology_events_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
    ) -> Result<Vec<IdentityTopologyEvent>> {
        let mut events = Vec::new();
        for entry in self
            .store
            .type_index
            .prefix_iter(rtxn, &[ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT])?
        {
            let (key, _) = entry?;
            let event_id = crate::vault::entity_id_from_type_index_key(&key)?;
            let record = self
                .identity_topology_event_in_txn(rtxn, &event_id)?
                .ok_or(Error::CorruptedIndex("identity topology event index"))?;
            events.push(IdentityTopologyEvent {
                event_id,
                seq: record.seq,
                approval: record.approval,
                action: record.action.to_fold_action(),
            });
        }
        Ok(events)
    }

    /// Shared participant/storage validator for both the local topology
    /// door and replicated type-76 admission. Completeness is event-wide:
    /// one absent participant defers the WHOLE event, so a multi-source
    /// merge or multi-head split can never authorize a partial shell.
    /// Available participants must be structural and merge participants
    /// may never be FACETs.
    pub(super) fn validate_identity_op_participants_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        op: &IdentityTopologyOp,
    ) -> Result<IdentityTopologyParticipantValidation> {
        let is_merge = matches!(op, IdentityTopologyOp::Merge(_));
        let mut validation = IdentityTopologyParticipantValidation::Complete;
        for participant in op.participants() {
            let Some(entity_type) = self.get_entity_type_in_txn(rtxn, &participant)? else {
                validation = IdentityTopologyParticipantValidation::Deferred;
                continue;
            };
            if !is_structural_kind(entity_type) {
                return Ok(IdentityTopologyParticipantValidation::Invalid(
                    IdentityTopologyRejection::NotStructural {
                        entity: participant,
                    },
                ));
            }
            if is_merge && entity_type == ENTITY_TYPE_FACET {
                return Ok(IdentityTopologyParticipantValidation::Invalid(
                    IdentityTopologyRejection::FacetMerge {
                        entity: participant,
                    },
                ));
            }
        }
        Ok(validation)
    }

    /// Pre-mutation validation for one replicated record. Missing apply
    /// participants and a missing undo target are deferred; any available
    /// participant uses the exact same structural/FACET validator as the
    /// local apply door, and an available undo target must be a type-76
    /// event rather than an arbitrary entity row.
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub(crate) fn validate_replicated_identity_topology_event_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        record: &StoredIdentityOpEvent,
    ) -> Result<()> {
        validate_replicated_identity_topology_seq(record.seq)?;
        // An absent actor is a reference deferral, just like an absent
        // participant: the immutable event may land, but the effective fold
        // excludes it until the actor materializes and its class can be
        // checked. An available mismatched actor rejects before mutation.
        self.validate_replicated_identity_topology_actor_in_txn(rtxn, record)?;
        match record.action.to_fold_action() {
            IdentityTopologyAction::Apply(op) => {
                if let IdentityTopologyParticipantValidation::Invalid(rejection) =
                    self.validate_identity_op_participants_in_txn(rtxn, &op)?
                {
                    return Err(Error::IdentityTopologyRejected(rejection));
                }
            }
            // An undo inherits the participant validity of the event it
            // names; a resolution must instead satisfy the SAME door rule
            // the local `resolve_identity_proposal` enforced — replayed
            // verbatim, never a lighter replay-side pass.
            IdentityTopologyAction::Undo { target } => {
                let Some(entity_type) = self.get_entity_type_in_txn(rtxn, &target)? else {
                    return Ok(());
                };
                if entity_type != ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT {
                    return Err(Error::InvalidEntityType(entity_type));
                }
                let target_record = self
                    .identity_topology_event_in_txn(rtxn, &target)?
                    .ok_or(Error::CorruptedIndex("identity topology event index"))?;
                if let IdentityTopologyAction::Apply(op) = target_record.action.to_fold_action()
                    && let IdentityTopologyParticipantValidation::Invalid(rejection) =
                        self.validate_identity_op_participants_in_txn(rtxn, &op)?
                {
                    return Err(Error::IdentityTopologyRejected(rejection));
                }
            }
            IdentityTopologyAction::ResolveProposal { proposal, .. } => {
                let StoredIdentityOpAction::ProposalResolution {
                    scope,
                    amended_body,
                    ..
                } = &record.action
                else {
                    return Err(Error::InvariantViolation(
                        "replicated resolution row desugars to ResolveProposal",
                    ));
                };
                let Some(entity_type) = self.get_entity_type_in_txn(rtxn, &proposal)? else {
                    return Ok(());
                };
                if entity_type != ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT {
                    return Err(Error::InvalidEntityType(entity_type));
                }
                let proposal_record = self
                    .identity_topology_event_in_txn(rtxn, &proposal)?
                    .ok_or(Error::CorruptedIndex("identity topology event index"))?;
                // Exactly the local door's rule, replayed: the ruling axis
                // is this row's own consent (`record.approval`), the stamp
                // must match the tuple the proposal row derives, and an
                // amended body must stay inside review.
                let proposed_op = self.validate_identity_proposal_resolution_in_txn(
                    rtxn,
                    &proposal,
                    &proposal_record,
                    record.approval,
                    Some(scope),
                )?;
                if let Some(amended_body) = amended_body {
                    let amended_op = decode_identity_op_amendment(amended_body).map_err(|_| {
                        Error::InvalidIdentityTopologyEventBody(
                            "identity topology proposal resolution amended body",
                        )
                    })?;
                    assert_amendment_in_scope(&proposed_op, &amended_op)?;
                }
            }
        }
        Ok(())
    }

    /// `true` when an event's optional actor is available and class-valid;
    /// `false` when the actor reference is absent and therefore deferred.
    pub(super) fn validate_replicated_identity_topology_actor_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        record: &StoredIdentityOpEvent,
    ) -> Result<bool> {
        let Some(actor) = record.actor else {
            return Ok(true);
        };
        let Some(actor_type) = self.get_entity_type_in_txn(rtxn, &actor.entity_ref())? else {
            return Ok(false);
        };
        crate::provenance::validate_actor_class(actor_type, actor.actor_class())?;
        Ok(true)
    }

    pub(super) fn validate_identity_op_actor_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        write: &IdentityOpWrite,
    ) -> Result<()> {
        let Some(actor) = write.actor else {
            return Ok(());
        };
        let actor_type = self
            .get_entity_type_in_txn(rtxn, &actor.entity_ref())?
            .ok_or(Error::EntityNotFound)?;
        crate::provenance::validate_actor_class(actor_type, actor.actor_class())
    }

    /// Reads the engine-stamped causality clock (0 when never advanced).
    ///
    /// `pub(crate)`: ONE-1748's ramp stamps this watermark on its own rows so a
    /// rebuild can interleave them with ledger rulings in the order they were
    /// actually written, rather than by caller-supplied wall time.
    pub(crate) fn read_identity_topology_seq_in_txn(&self, rtxn: &heed::RoTxn<'_>) -> Result<u64> {
        match self.store.vault_meta.get(rtxn, IDENTITY_TOPOLOGY_SEQ_KEY)? {
            None => Ok(0),
            Some(raw) => {
                let arr: [u8; 8] = raw
                    .as_ref()
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("identity topology seq"))?;
                Ok(u64::from_be_bytes(arr))
            }
        }
    }

    /// Allocates the next engine-stamped causality sequence, inside the
    /// caller's write txn (a rolled-back op burns no committed gap).
    pub(super) fn next_identity_topology_seq_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
    ) -> Result<u64> {
        let previous = self.read_identity_topology_seq_in_txn(&*wtxn)?;
        let next = previous
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("identity topology seq"))?;
        if next >= IDENTITY_TOPOLOGY_REPLICATED_SEQ_CEILING {
            return Err(Error::InvalidIdentityTopologyEventBody(
                "identity topology event seq is in the reserved terminal range",
            ));
        }
        self.store
            .vault_meta
            .put(wtxn, IDENTITY_TOPOLOGY_SEQ_KEY, &next.to_be_bytes())?;
        Ok(next)
    }

    /// Joins a replicated record's engine-stamped `seq` into the local
    /// causality clock: `seq = max(local, incoming)`, in the caller's write
    /// txn. Every sync ingest path (fresh accept, idempotent replay,
    /// rebuild) runs this join, so a LOCAL event allocated after ingest can
    /// never order before the ingested history in the `(seq, event_id)`
    /// fold — without it, an undo of a synced merge folds BEFORE the merge
    /// it targets, is rejected `NotCurrent`, and ledger and edge truth
    /// permanently diverge.
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub(crate) fn advance_identity_topology_seq_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        incoming_seq: u64,
    ) -> Result<()> {
        if incoming_seq > self.read_identity_topology_seq_in_txn(&*wtxn)? {
            self.store.vault_meta.put(
                wtxn,
                IDENTITY_TOPOLOGY_SEQ_KEY,
                &incoming_seq.to_be_bytes(),
            )?;
        }
        Ok(())
    }
}
