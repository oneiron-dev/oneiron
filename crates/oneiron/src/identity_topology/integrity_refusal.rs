//! The engine's integrity refusals on the type-76 family: a deletion's or a
//! redaction's signed refusal of a decision whose participant or author is
//! about to go (moved from `admission_disposition`, mesh PR2a). Each is an
//! engine seal under `integrity_refusal`: negative only, it never claims the
//! owner's will, and it keeps today's admission exactly.

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::vault::Vault;

use super::act_admission::{EngineCause, ResolvedSeal, SealAuthority};
use super::admission_disposition::{
    AdmissionDisposition, AdmissionVerdict, SealTrust, joined_verdict_for_store_in_txn,
};
use super::stored_event::{StoredIdentityOpAction, StoredIdentityOpEvent};

/// Write a signed refusal for a wrong-class participant before its
/// participant disappears. The immutable decision row is never rewritten. The
/// generic store-only batch door cannot sign and refuses unsafe deletes instead.
impl Vault {
    /// On author erasure, retain the admission decision independently of
    /// personal attribution. An observed wrong class is terminal, with no
    /// actor ID in the refusal fact. An already validated event stays valid.
    pub(crate) fn record_actor_disposition_before_redaction_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        target: EntityId,
        actor: crate::write_envelope::WriteActor,
    ) -> Result<()> {
        let core =
            self.identity_topology_event_in_txn(wtxn, &target)?
                .ok_or(Error::CorruptedIndex(
                    "identity topology attribution target",
                ))?;
        let existing = joined_verdict_for_store_in_txn(
            &self.store,
            wtxn,
            &target,
            &core,
            &mut SealTrust::default(),
        )?;
        if existing.is_some_and(|verdict| verdict != AdmissionVerdict::Validated) {
            return Ok(());
        }
        let Some(kind) =
            super::store_entity_helpers::identity_topology_entity_type_for_store_in_txn(
                &self.store,
                wtxn,
                &actor.entity_ref(),
            )?
        else {
            return Ok(());
        };
        if crate::provenance::validate_actor_class(kind, actor.actor_class()).is_err() {
            return self.append_signed_identity_disposition_in_txn(
                wtxn,
                target,
                &core,
                (AdmissionVerdict::RefusedActorClass, None),
                EngineCause::IntegrityRefusal,
            );
        }
        // No positive is minted here: this vault would seal a decision it
        // never made, and its seal counts (H161). A decision still waiting
        // for its own producer's seal keeps waiting for it.
        Ok(())
    }

    /// Appends an engine seal of `target`'s decision `core` under `cause`: an
    /// integrity refusal, negative only. It never claims the owner's will.
    pub(crate) fn append_signed_identity_disposition_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        target: EntityId,
        core: &StoredIdentityOpEvent,
        (verdict, reason): (AdmissionVerdict, Option<EntityId>),
        cause: EngineCause,
    ) -> Result<()> {
        use crate::batch::{BatchOp, apply_ops};
        use crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT;
        use crate::temporal::TimeRange;
        let id = self.store.clock.entity_id()?;
        let signer = ResolvedSeal::engine_in_txn(self, wtxn, cause)?;
        let fact = AdmissionDisposition::signed(
            &signer,
            target,
            core,
            verdict,
            reason,
            SealAuthority::Engine(cause),
        )?;
        fact.record_sealed_here(self, wtxn, id)?;
        let seq = self.next_identity_topology_seq_in_txn(wtxn)?;
        let row = StoredIdentityOpEvent {
            seq,
            validated_at_write: false,
            invalidated: false,
            at: core.at,
            actor: None,
            source: core.source,
            approval: crate::claim::ClaimApprovalStatus::Auto,
            confidence: 1.0,
            evidence: None,
            action: StoredIdentityOpAction::AdmissionDisposition(fact),
        };
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            wtxn,
            vec![BatchOp::Put {
                id,
                entity_type: ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT,
                occurred: TimeRange {
                    start: core.at,
                    end: core.at,
                },
                learned_at: core.at,
                data: super::encode_identity_topology_event_body(&row)?,
                allow_maintenance: true,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            }],
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )?;
        Ok(())
    }

    pub(crate) fn record_invalid_participant_dispositions_for_delete_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        participant: &EntityId,
    ) -> Result<()> {
        let mut pending = Vec::new();
        let mut trust = SealTrust::default();
        for event in super::store_entity_helpers::identity_topology_events_for_store_in_txn(
            &self.store,
            &*wtxn,
        )? {
            let super::ledger_fold::IdentityTopologyAction::Apply(op) = event.action else {
                continue;
            };
            if !op.participants().contains(participant) {
                continue;
            }
            let Some(kind) =
                super::store_entity_helpers::identity_topology_entity_type_for_store_in_txn(
                    &self.store,
                    &*wtxn,
                    participant,
                )?
            else {
                continue;
            };
            let invalid = if !crate::registry::is_structural_kind(kind) {
                Some(AdmissionVerdict::RefusedNonStructural)
            } else if matches!(op, super::op_vocabulary::IdentityTopologyOp::Merge(_))
                && kind == crate::registry::ENTITY_TYPE_FACET
            {
                Some(AdmissionVerdict::RefusedFacetMerge)
            } else {
                None
            };
            let core = super::store_entity_helpers::identity_topology_event_for_store_in_txn(
                &self.store,
                &*wtxn,
                &event.event_id,
            )?
            .ok_or(Error::CorruptedIndex("identity topology event index"))?;
            let existing = joined_verdict_for_store_in_txn(
                &self.store,
                &*wtxn,
                &event.event_id,
                &core,
                &mut trust,
            )?;
            if existing.is_some_and(|v| v != AdmissionVerdict::Validated) {
                continue;
            }
            let (verdict, reason) = if let Some(invalid) = invalid {
                (invalid, Some(*participant))
            } else {
                // Only an observed wrong actor class is recorded here, from
                // fully checked refs. No positive is minted: this vault would
                // seal a decision it never made, and its seal counts (H161).
                if existing.is_some()
                    || !matches!(
                        super::store_entity_helpers::validate_identity_op_participants_for_store_in_txn(
                            &self.store, &*wtxn, &op,
                        )?,
                        super::op_apply::IdentityTopologyParticipantValidation::Complete
                    ) {
                    continue;
                }
                let Some(actor) = super::admitted_author_in_txn(&self.store, wtxn, event.event_id)?
                else {
                    continue;
                };
                let Some(actor_kind) =
                    super::store_entity_helpers::identity_topology_entity_type_for_store_in_txn(
                        &self.store,
                        wtxn,
                        &actor.entity_ref(),
                    )?
                else {
                    continue;
                };
                if crate::provenance::validate_actor_class(actor_kind, actor.actor_class()).is_ok()
                {
                    continue;
                }
                (AdmissionVerdict::RefusedActorClass, None)
            };
            pending.push((event.event_id, core, verdict, reason));
        }
        for (target, core, verdict, reason) in pending {
            self.append_signed_identity_disposition_in_txn(
                wtxn,
                target,
                &core,
                (verdict, reason),
                EngineCause::IntegrityRefusal,
            )?;
        }
        Ok(())
    }
}
