//! The owner's answer to an exact hub-update proposal.

use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, encode_claim_body,
};
use crate::consent::{AuthenticatedOwner, ComposedEffect, EffectFacts};
use crate::ports::EntityStoreRead;
use crate::{EntityId, TimeRange, Vault, error::Result};

use super::super::package_codec::invalid;
use super::super::ref_sync::{RefFetch, pinned_tracking};
use super::super::{HubPackage, HubPin, HubRef, SkillHubAdapter, TrackedHubRef};
use super::{
    PREDICATE_SKILL_HUB_PROVENANCE, PREDICATE_SKILL_HUB_UPDATE_PROPOSAL,
    encode_capability_surface_value, map_text, map_value, same_hub_ref,
};

struct PendingHubUpdate {
    body: ClaimBody,
    occurred: TimeRange,
    learned_at: u64,
}

impl Vault {
    /// Accepts the exact package a pending hub update names, or rejects only
    /// that proposal. Acceptance preserves the skill's local lifecycle and
    /// governance, and records the owner's approval with the new package.
    /// Fetches and dependency queries finish before the effect's writer opens.
    pub fn settle_hub_update_proposal(
        &self,
        owner: &AuthenticatedOwner,
        entity: &EntityId,
        proposal: &EntityId,
        accept: bool,
    ) -> Result<ClaimApprovalStatus> {
        if !accept {
            return self.with_write_txn_grouped(|txn| {
                self.check_restore_owner_in_txn(txn, owner)?;
                let pending = self.pending_hub_update_in_txn(txn, entity, proposal)?;
                self.close_hub_update_in_txn(
                    txn,
                    proposal,
                    pending,
                    ClaimApprovalStatus::Rejected,
                    self.now_recorded_at(),
                )?;
                Ok(ClaimApprovalStatus::Rejected)
            });
        }

        let (pending, tracked, fallback, hash) = {
            let txn = self.store.env.read_txn()?;
            self.check_restore_owner_in_txn(&txn, owner)?;
            let pending = self.pending_hub_update_in_txn(&txn, entity, proposal)?;
            let proposed_source = HubRef::from_value(
                map_value(&pending.body.value, "hubRef")
                    .ok_or_else(|| invalid("hub update proposal has no source"))?,
            )?;
            let hash = crate::skill::SkillContentHash::parse_hex(
                map_text(&pending.body.value, "contentHash")
                    .ok_or_else(|| invalid("hub update proposal has no content hash"))?,
            )?;
            let source = self.hub_update_source_in_txn(&txn, entity, &proposed_source)?;
            let tracked = self.hub_update_tracking_in_txn(&txn, &source)?;
            if tracked.hub_ref != proposed_source {
                return Err(invalid("hub update proposal pin changed"));
            }
            let fallback = match source.pin {
                HubPin::Commit(commit) => Some(commit),
                _ => None,
            };
            (pending, tracked, fallback, hash)
        };
        let (package, revision) = match self.hub_ref_fetch(&tracked, fallback.as_deref())? {
            RefFetch::Git(adapter, _) => (
                adapter.fetch_package(&tracked.hub_ref)?,
                adapter.resolved_commit().to_owned(),
            ),
            RefFetch::Http(adapter, _) => {
                let package = adapter.fetch_package(&tracked.hub_ref)?;
                let revision = package.content_hash()?.to_hex();
                (package, revision)
            }
        };
        check_proposed_package(&pending, hash, &package)?;
        crate::skill::encode_skill_record(&package.record)?;
        let binding = encode_claim_body(&pending.body)?;
        let inventory = super::super::osv::dependency_inventory(&package)?;
        let at = self.now_recorded_at();
        let (_, _, scans) =
            self.dependency_advisories(hash, &inventory, &super::super::osv::OsvDevClient, at)?;
        self.with_write_txn_grouped(|txn| {
            self.check_restore_owner_in_txn(txn, owner)?;
            let current_proposal = self.pending_hub_update_in_txn(txn, entity, proposal)?;
            if encode_claim_body(&current_proposal.body)? != binding {
                return Err(invalid("hub update proposal changed during its fetch"));
            }
            let source = self.hub_update_source_in_txn(txn, entity, &tracked.hub_ref)?;
            let current_tracking = self.hub_update_tracking_in_txn(txn, &source)?;
            if current_tracking.hub_ref != tracked.hub_ref
                || current_tracking.sync_policy != tracked.sync_policy
            {
                return Err(invalid("hub update ref policy changed during its fetch"));
            }
            let current = self.read_skill_record_in_txn(txn, entity)?;
            super::validate_sync_package(
                &current,
                &package,
                &tracked.hub_ref,
                hash,
                tracked.sync_policy,
            )?;
            let mut proposed_record = package.record.clone();
            proposed_record.content_hash = Some(hash);
            let requires_held_out = current.lifecycle_status
                == crate::skill::SkillLifecycle::Active
                && crate::skill_optimize::skill_body_binding_digest(&current)?
                    != crate::skill_optimize::skill_body_binding_digest(&proposed_record)?;
            if map_value(&current_proposal.body.value, "requiresHeldOut")
                .and_then(rmpv::Value::as_bool)
                != Some(requires_held_out)
            {
                return Err(invalid("hub update proposal review context changed"));
            }
            if super::super::import_receipt::marketplace_hash_blocked_in_txn(
                &self.store,
                txn,
                hash,
            )? {
                return Err(invalid("the owner's hash rule blocks this hub update"));
            }
            let effect = ComposedEffect::new(EffectFacts::new(format!(
                "skill.hub_update_proposal.accept:{}:{}:{}:{}",
                entity.to_hex(),
                proposal.to_hex(),
                hash.to_hex(),
                blake3::hash(&binding).to_hex(),
            ))?)
            .digest();
            self.approve_once_in_txn(txn, owner, effect)?;
            let authorization =
                crate::consent::approve_once_authorization_in_txn(&self.store, txn, &effect)?
                    .ok_or_else(|| invalid("hub update consent missing"))?;
            let occurred = TimeRange { start: at, end: at };
            // The owner's answer admits this exact widening and answers the
            // scan ask. Automatic sync still uses its original savepoint gate.
            self.apply_hub_sync_in_txn(
                txn,
                entity,
                &current,
                &tracked.hub_ref,
                &package,
                hash,
                &scans,
                occurred,
                at,
                Some(&authorization),
            )?;
            let mut approved = self.read_skill_record_in_txn(txn, entity)?;
            approved.approval_status = ClaimApprovalStatus::Approved;
            self.apply_hub_sync_skill_record(txn, entity, &approved, occurred, at)?;
            let mut saved = package.clone();
            saved.record = self.read_skill_record_in_txn(txn, entity)?;
            self.persist_hub_package_in_txn(txn, entity, &saved)?;
            self.close_hub_update_in_txn(
                txn,
                proposal,
                current_proposal,
                ClaimApprovalStatus::Approved,
                at,
            )
        })?;
        self.mark_hub_ref(&tracked, &revision, true)?;
        Ok(ClaimApprovalStatus::Approved)
    }

    /// Admits the exact imported write with the owner's one-use consent.
    /// Constructing the native proof spends it in this same transaction.
    pub(super) fn apply_hub_update_record_with_consent_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        entity: &EntityId,
        record: &crate::skill::SkillRecord,
        occurred: TimeRange,
        learned_at: u64,
        authorization: &crate::consent::ApproveOnceAuthorization,
    ) -> Result<()> {
        let data = crate::skill::encode_skill_record(record)?;
        let proof = super::super::HubAdmissionProof::consent(
            &self.store,
            txn,
            *entity,
            &data,
            authorization,
        )?;
        crate::batch::apply_ops_with_gate_mode(
            &self.store,
            &self.config,
            &self.analyzer,
            txn,
            vec![crate::batch::BatchOp::Put {
                id: *entity,
                entity_type: crate::registry::ENTITY_TYPE_SKILL,
                occurred,
                learned_at,
                row_version: None,
                data,
                allow_maintenance: false,
                allow_reserved_predicate: false,
                hub_sync_imported: true,
            }],
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            crate::batch::ApplyOpsGateMode::new(false, true).with_hub_admission(proof),
        )
    }

    fn pending_hub_update_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        entity: &EntityId,
        proposal: &EntityId,
    ) -> Result<PendingHubUpdate> {
        let body = self
            .get_claim_in_txn(txn, proposal)?
            .ok_or_else(|| invalid("hub update proposal missing"))?;
        if body.predicate != PREDICATE_SKILL_HUB_UPDATE_PROPOSAL
            || body.subject != ClaimSubject::Entity(*entity)
            || body.lifecycle != ClaimLifecycleStatus::Active
            || body.approval != ClaimApprovalStatus::Proposed
        {
            return Err(invalid("hub update proposal is no longer pending"));
        }
        let record = self
            .store
            .port_entity_record(txn, proposal)?
            .ok_or_else(|| invalid("hub update proposal missing"))?;
        Ok(PendingHubUpdate {
            body,
            occurred: record.occurred,
            learned_at: record.learned_at,
        })
    }

    fn hub_update_source_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        entity: &EntityId,
        expected: &HubRef,
    ) -> Result<HubRef> {
        let rows =
            self.active_claims_for_predicate_in_txn(txn, entity, PREDICATE_SKILL_HUB_PROVENANCE)?;
        if rows.is_empty() {
            return Ok(expected.clone());
        }
        for (_, body, _) in rows {
            let source = HubRef::from_value(
                map_value(&body.value, "hubRef")
                    .ok_or_else(|| invalid("hub provenance claim is missing hubRef"))?,
            )?;
            if same_hub_ref(&source, expected) {
                return Ok(source);
            }
        }
        Err(invalid("hub update no longer matches the skill's source"))
    }

    fn hub_update_tracking_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        source: &HubRef,
    ) -> Result<TrackedHubRef> {
        match self.hub_ref_sync_in_txn(txn, &source.hub_id, &source.ref_string)? {
            Some(tracked) => Ok(tracked),
            None => pinned_tracking(source.clone()),
        }
    }

    fn close_hub_update_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        proposal: &EntityId,
        pending: PendingHubUpdate,
        approval: ClaimApprovalStatus,
        at: u64,
    ) -> Result<()> {
        let closed_at = at.max(pending.occurred.start);
        let mut body = pending.body;
        body.approval = approval;
        body.lifecycle = ClaimLifecycleStatus::Retracted;
        body.valid_to = Some(closed_at);
        self.put_reserved_claim_in_txn(
            txn,
            proposal,
            &body,
            TimeRange {
                start: pending.occurred.start,
                end: closed_at,
            },
            pending.learned_at,
        )
    }
}

fn check_proposed_package(
    pending: &PendingHubUpdate,
    hash: crate::skill::SkillContentHash,
    package: &HubPackage,
) -> Result<()> {
    if package.content_hash()? != hash
        || map_text(&pending.body.value, "version") != Some(package.record.version.as_str())
        || map_value(&pending.body.value, "capabilities")
            != Some(&encode_capability_surface_value(&package.capabilities))
        || map_value(&pending.body.value, "requiresHeldOut")
            .and_then(rmpv::Value::as_bool)
            .is_none()
    {
        return Err(invalid(
            "refetched package differs from the hub update proposal",
        ));
    }
    Ok(())
}
