//! Signed append-only admission facts, independent of a decision's erasable author.

use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::{Error, Result, SyncError};
use crate::store::Store;
use crate::vault::Vault;

use super::stored_event::{StoredIdentityOpAction, StoredIdentityOpEvent};

const DOMAIN: &[u8] = b"oneiron.identity-topology.admission.v1\0";
const BAD: &str = "identity topology admission disposition invalid";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionVerdict {
    Validated,
    RefusedActorClass,
    RefusedNonStructural,
    RefusedFacetMerge,
    /// Local projection only: incompatible signed refusals, never a wire verdict.
    RefusedConflict,
}

impl AdmissionVerdict {
    fn as_str(self) -> &'static str {
        match self {
            Self::Validated => "validated",
            Self::RefusedActorClass => "refused_actor_class",
            Self::RefusedNonStructural => "refused_nonstructural",
            Self::RefusedFacetMerge => "refused_facet_merge",
            Self::RefusedConflict => "refused_conflict",
        }
    }
    fn parse(s: &str) -> Option<Self> {
        match s {
            "validated" => Some(Self::Validated),
            "refused_actor_class" => Some(Self::RefusedActorClass),
            "refused_nonstructural" => Some(Self::RefusedNonStructural),
            "refused_facet_merge" => Some(Self::RefusedFacetMerge),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionDisposition {
    pub target: EntityId,
    pub core_digest: [u8; 32],
    pub verdict: AdmissionVerdict,
    pub reason: Option<EntityId>,
    pub signer_pk: [u8; 32],
    pub signature: [u8; 64],
}

impl AdmissionDisposition {
    fn transcript(
        target: &EntityId,
        digest: &[u8; 32],
        verdict: AdmissionVerdict,
        reason: Option<EntityId>,
    ) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(DOMAIN.len() + 16 + 32 + 32);
        bytes.extend_from_slice(DOMAIN);
        bytes.extend_from_slice(target.as_bytes());
        bytes.extend_from_slice(digest);
        bytes.extend_from_slice(verdict.as_str().as_bytes());
        bytes.push(0);
        if let Some(id) = reason {
            bytes.extend_from_slice(id.as_bytes());
        }
        bytes
    }

    pub(super) fn sign(
        vault: &Vault,
        wtxn: &mut heed::RwTxn<'_>,
        target: EntityId,
        core: &StoredIdentityOpEvent,
        verdict: AdmissionVerdict,
        reason: Option<EntityId>,
    ) -> Result<Self> {
        let identity = crate::identity::ensure_device_identity_in_txn(vault, wtxn)?;
        let core_digest = core_digest(core)?;
        let signature = identity
            .signing_key
            .sign(&Self::transcript(&target, &core_digest, verdict, reason))
            .to_bytes();
        Ok(Self {
            target,
            core_digest,
            verdict,
            reason,
            signer_pk: identity.signing_key.verifying_key().to_bytes(),
            signature,
        })
    }

    pub(super) fn verify(&self) -> Result<()> {
        if self.verdict == AdmissionVerdict::RefusedConflict
            || (matches!(
                self.verdict,
                AdmissionVerdict::Validated | AdmissionVerdict::RefusedActorClass
            ) && self.reason.is_some())
            || (matches!(
                self.verdict,
                AdmissionVerdict::RefusedNonStructural | AdmissionVerdict::RefusedFacetMerge
            ) && self.reason.is_none())
        {
            return Err(Error::Sync(SyncError::InvalidIdentityTopologyEventBody(
                BAD,
            )));
        }
        let key = VerifyingKey::from_bytes(&self.signer_pk)
            .map_err(|_| Error::Sync(SyncError::InvalidIdentityTopologyEventBody(BAD)))?;
        key.verify(
            &Self::transcript(&self.target, &self.core_digest, self.verdict, self.reason),
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| Error::Sync(SyncError::InvalidIdentityTopologyEventBody(BAD)))
    }

    pub(super) fn encode_entries(&self, entries: &mut Vec<(Value, Value)>) {
        use super::wire_keys::*;
        entries.push((
            BODY_KEY_TARGET.into(),
            Value::Binary(self.target.as_bytes().to_vec()),
        ));
        entries.push((
            BODY_KEY_CORE_DIGEST.into(),
            Value::Binary(self.core_digest.to_vec()),
        ));
        entries.push((BODY_KEY_VERDICT.into(), self.verdict.as_str().into()));
        if let Some(reason) = self.reason {
            entries.push((
                BODY_KEY_REASON.into(),
                Value::Binary(reason.as_bytes().to_vec()),
            ));
        }
        entries.push((
            BODY_KEY_SIGNER.into(),
            Value::Binary(self.signer_pk.to_vec()),
        ));
        entries.push((
            BODY_KEY_SIGNATURE.into(),
            Value::Binary(self.signature.to_vec()),
        ));
    }

    pub(super) fn decode(map: &[(Value, Value)]) -> Result<Self> {
        use super::event_body_codec::{decode_id_value, map_field};
        use super::wire_keys::*;
        let field = |key| {
            map_field(map, key)
                .and_then(Value::as_slice)
                .ok_or(Error::Sync(SyncError::InvalidIdentityTopologyEventBody(
                    BAD,
                )))
        };
        let target = decode_id_value(
            map_field(map, BODY_KEY_TARGET).ok_or(Error::Sync(
                SyncError::InvalidIdentityTopologyEventBody(BAD),
            ))?,
            BAD,
        )?;
        let core_digest: [u8; 32] = field(BODY_KEY_CORE_DIGEST)?
            .try_into()
            .map_err(|_| Error::Sync(SyncError::InvalidIdentityTopologyEventBody(BAD)))?;
        let verdict = map_field(map, BODY_KEY_VERDICT)
            .and_then(Value::as_str)
            .and_then(AdmissionVerdict::parse)
            .ok_or(Error::Sync(SyncError::InvalidIdentityTopologyEventBody(
                BAD,
            )))?;
        let reason = map_field(map, BODY_KEY_REASON)
            .map(|v| decode_id_value(v, BAD))
            .transpose()?;
        let signer_pk: [u8; 32] = field(BODY_KEY_SIGNER)?
            .try_into()
            .map_err(|_| Error::Sync(SyncError::InvalidIdentityTopologyEventBody(BAD)))?;
        let signature: [u8; 64] = field(BODY_KEY_SIGNATURE)?
            .try_into()
            .map_err(|_| Error::Sync(SyncError::InvalidIdentityTopologyEventBody(BAD)))?;
        let disposition = Self {
            target,
            core_digest,
            verdict,
            reason,
            signer_pk,
            signature,
        };
        disposition.verify()?;
        Ok(disposition)
    }
}

/// Canonical immutable decision core: actor and mutable historical flags are
/// explicitly excluded. Its other fields, including seq and consent, are bound.
pub(crate) fn core_digest(record: &StoredIdentityOpEvent) -> Result<[u8; 32]> {
    if matches!(
        record.action,
        StoredIdentityOpAction::AdmissionDisposition(_)
    ) {
        return Err(Error::Sync(SyncError::InvalidIdentityTopologyEventBody(
            BAD,
        )));
    }
    let mut canonical = record.clone();
    canonical.actor = None;
    canonical.validated_at_write = false;
    canonical.invalidated = false;
    Ok(*blake3::hash(&super::encode_identity_topology_event_body(&canonical)?).as_bytes())
}

/// A missing target is a pending fact, never an authority shortcut. Conflicts
/// between incompatible refusals or different core digests fail closed.
pub(super) fn joined_verdict_for_store_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    target: &EntityId,
    core: &StoredIdentityOpEvent,
) -> Result<Option<AdmissionVerdict>> {
    let digest = core_digest(core)?;
    let mut validated = false;
    let mut refused = None;
    for id in crate::ports::EntityStoreRead::port_entity_ids_by_type(
        store,
        rtxn,
        crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT,
        None,
    )? {
        let id = id?;
        let row = super::store_entity_helpers::identity_topology_event_for_store_in_txn(
            store, rtxn, &id,
        )?
        .ok_or(Error::CorruptedIndex("identity topology event index"))?;
        let StoredIdentityOpAction::AdmissionDisposition(fact) = row.action else {
            continue;
        };
        // A wrong-core fact cannot poison the whole vault. It remains inert:
        // admission rejects it when the core is already available; if it
        // arrived earlier, target arrival cannot retroactively quarantine
        // the already committed row, but its digest never binds this core.
        if fact.target != *target || fact.core_digest != digest {
            continue;
        }
        fact.verify()
            .map_err(|_| Error::CorruptedIndex("identity topology admission signature"))?;
        if fact.verdict == AdmissionVerdict::Validated {
            validated = true;
        } else if refused.is_some_and(|v| v != (fact.verdict, fact.reason)) {
            refused = Some((AdmissionVerdict::RefusedConflict, None));
        } else {
            refused = Some((fact.verdict, fact.reason));
        }
    }
    Ok(refused
        .map(|(verdict, _)| verdict)
        .or(validated.then_some(AdmissionVerdict::Validated)))
}

/// Peer admission check for both arrival orders. A pending target is not
/// accepted as proof; the signed fact stays inert until core binding succeeds.
pub(crate) fn validate_incoming_disposition_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    incoming_id: &EntityId,
    incoming: &StoredIdentityOpEvent,
) -> Result<()> {
    let StoredIdentityOpAction::AdmissionDisposition(fact) = &incoming.action else {
        return Ok(());
    };
    fact.verify()?;
    if fact.target == *incoming_id {
        return Err(Error::Sync(SyncError::InvalidIdentityTopologyEventBody(
            BAD,
        )));
    }
    if let Some(row) = super::store_entity_helpers::identity_topology_event_for_store_in_txn(
        store,
        rtxn,
        &fact.target,
    )? && fact.core_digest != core_digest(&row)?
    {
        return Err(Error::Sync(SyncError::InvalidIdentityTopologyEventBody(
            "identity topology admission core conflict",
        )));
    }
    Ok(())
}

/// Write a signed refusal for a wrong-class participant, or preserve a
/// fully validated decision with positive proof, before its participant
/// disappears. The immutable decision row is never rewritten. The generic
/// store-only batch door cannot sign and refuses unsafe deletes instead.
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
        let existing = joined_verdict_for_store_in_txn(&self.store, wtxn, &target, &core)?;
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
                AdmissionVerdict::RefusedActorClass,
                None,
            );
        }
        if existing == Some(AdmissionVerdict::Validated) {
            return Ok(());
        }
        // A positive is minted only after every referenced participant is
        // complete and valid, never just because the actor was valid.
        if let super::ledger_fold::IdentityTopologyAction::Apply(op) = core.action.to_fold_action()
            && matches!(
                super::store_entity_helpers::validate_identity_op_participants_for_store_in_txn(
                    &self.store,
                    wtxn,
                    &op,
                )?,
                super::op_apply::IdentityTopologyParticipantValidation::Complete
            )
        {
            self.append_signed_identity_disposition_in_txn(
                wtxn,
                target,
                &core,
                AdmissionVerdict::Validated,
                None,
            )?;
        }
        Ok(())
    }

    pub(crate) fn append_signed_identity_disposition_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        target: EntityId,
        core: &StoredIdentityOpEvent,
        verdict: AdmissionVerdict,
        reason: Option<EntityId>,
    ) -> Result<()> {
        use crate::batch::{BatchOp, apply_ops};
        use crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT;
        use crate::temporal::TimeRange;
        let fact = AdmissionDisposition::sign(self, wtxn, target, core, verdict, reason)?;
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
                id: self.store.clock.entity_id()?,
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
            let existing =
                joined_verdict_for_store_in_txn(&self.store, &*wtxn, &event.event_id, &core)?;
            if existing.is_some_and(|v| v != AdmissionVerdict::Validated) {
                continue;
            }
            let (verdict, reason) = if let Some(invalid) = invalid {
                (invalid, Some(*participant))
            } else {
                // A historical positive may only be minted from actual,
                // fully checked refs. Producer booleans and local markers
                // alone never turn a deferred op into signed authority.
                if existing.is_some()
                    || !matches!(
                        super::store_entity_helpers::validate_identity_op_participants_for_store_in_txn(
                            &self.store, &*wtxn, &op,
                        )?,
                        super::op_apply::IdentityTopologyParticipantValidation::Complete
                    ) {
                    continue;
                }
                if let Some(actor) =
                    super::effective_author_in_txn(&self.store, wtxn, event.event_id)?
                {
                    let Some(actor_kind) = super::store_entity_helpers::identity_topology_entity_type_for_store_in_txn(
                        &self.store, wtxn, &actor.entity_ref(),
                    )? else { continue };
                    if crate::provenance::validate_actor_class(actor_kind, actor.actor_class())
                        .is_err()
                    {
                        pending.push((
                            event.event_id,
                            core,
                            AdmissionVerdict::RefusedActorClass,
                            None,
                        ));
                        continue;
                    }
                }
                (AdmissionVerdict::Validated, None)
            };
            pending.push((event.event_id, core, verdict, reason));
        }
        for (target, core, verdict, reason) in pending {
            self.append_signed_identity_disposition_in_txn(wtxn, target, &core, verdict, reason)?;
        }
        Ok(())
    }
}

/// A genuine signed producer fact for cross-module sync/batch fixtures. The
/// test still delivers the core and fact as SEPARATE records in either order.
#[cfg(all(test, feature = "sync"))]
pub(crate) fn signed_validated_row_for_test(
    vault: &Vault,
    target: EntityId,
    core: &StoredIdentityOpEvent,
) -> Result<(EntityId, StoredIdentityOpEvent)> {
    vault.with_write_txn(|wtxn| {
        let fact = AdmissionDisposition::sign(
            vault,
            wtxn,
            target,
            core,
            AdmissionVerdict::Validated,
            None,
        )?;
        let row = StoredIdentityOpEvent {
            seq: core
                .seq
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow("identity fixture seq"))?,
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
        Ok((vault.store.clock.entity_id()?, row))
    })
}
