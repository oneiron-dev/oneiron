//! A same-revision refresh that expands an admitted catalog key's slate is
//! staged beside the slate the key routes on (FIX 11677). The key keeps
//! routing on its admitted rows; the staged slate replaces them only once
//! the owner stamps it and a fresh full suite passes on it, or once the
//! owner attests it in place of the suite. Another refresh restages it, and
//! one that reaches no further than the routing slate drops it.
use crate::Vault;
use crate::connector_key::qualification::{
    ConnectorQualificationReceipt, GroundingOracle, OWNER_ATTESTED_QUALIFICATION_SUITE,
    QualificationConnector, QualificationPlan, QualificationReport, qualify_connector_with_schemas,
};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::super::manifest_drift::ResolvedConnectorManifest;
use super::super::record::{ConnectorKeyRecord, ConnectorKeyStatus, invalid_body};
use super::super::slate::{
    ConnectorGrantSlate, bind_connector_slate_in_txn, read_connector_slate_in_txn,
};
use super::super::txn::{
    append_connector_key_op_record, read_connector_key_in_txn, rewrite_connector_key_in_txn,
};
use super::manifest_ops::{
    ConnectorManifestQualifier, OwnerAttestedManifestQualifier, qualify_staged_manifest,
    validate_staged_manifest,
};
use super::qualification::{
    ConnectorQualificationError, require_pack_qualification, slate_catalog,
};

/// Whether an expansion of `record`'s slate stages beside it: the key is
/// admitted (qualified, its manifest approved, no consent owed).
pub(super) fn stages_beside(record: &ConnectorKeyRecord, _routing: &ConnectorGrantSlate) -> bool {
    matches!(
        record.status,
        ConnectorKeyStatus::Active | ConnectorKeyStatus::Suspended
    ) && record.catalog.is_some()
        && !record.consent_required
        && record.qualification_receipt.is_some()
        && record.retained_manifest.is_some()
}

impl Vault {
    /// Stages `next_slate_ref`, an expansion of admitted key `id`'s slate at
    /// its pinned revision, beside the slate it routes on, in the caller's
    /// writer. Nothing the key routes on moves, and its per-grant keys stay
    /// as they are.
    pub(super) fn stage_connector_slate_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        record: ConnectorKeyRecord,
        next_slate_ref: EntityId,
        at: u64,
    ) -> Result<ConnectorKeyRecord> {
        if record.staged_slate_ref != Some(next_slate_ref) {
            bind_connector_slate_in_txn(self, wtxn, next_slate_ref, id)?;
        }
        let staged = ConnectorKeyRecord {
            staged_slate_ref: Some(next_slate_ref),
            ..record
        };
        staged.validate()?;
        rewrite_connector_key_in_txn(&self.store, wtxn, id, &staged)?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, wtxn)?;
        append_connector_key_op_record(
            &self.store,
            wtxn,
            id,
            "gate.connector_key.stage_slate",
            &staged,
            policy.read_frontier_hash()?,
            at,
        )?;
        Ok(staged)
    }

    /// Drops the slate staged beside admitted key `id`'s routing one: a
    /// refresh that reaches no further than the routing slate reports
    /// `staged:false`, and must not leave qualify/attest targeting an
    /// obsolete expansion. A key with nothing staged is returned unchanged,
    /// with no op record.
    pub fn drop_staged_connector_slate(
        &self,
        id: &EntityId,
        at: u64,
    ) -> Result<ConnectorKeyRecord> {
        let mut wtxn = self.store.env.write_txn()?;
        let record =
            read_connector_key_in_txn(&self.store, &wtxn, id)?.ok_or(Error::EntityNotFound)?;
        if record.staged_slate_ref.is_none() {
            return Ok(record);
        }
        let dropped = ConnectorKeyRecord {
            staged_slate_ref: None,
            ..record
        };
        dropped.validate()?;
        rewrite_connector_key_in_txn(&self.store, &mut wtxn, id, &dropped)?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &wtxn)?;
        append_connector_key_op_record(
            &self.store,
            &mut wtxn,
            id,
            "gate.connector_key.drop_staged_slate",
            &dropped,
            policy.read_frontier_hash()?,
            at,
        )?;
        wtxn.commit()?;
        Ok(dropped)
    }

    /// Runs all ARCH-0028 probes on the slate staged beside admitted key
    /// `id` at `expected_revision`, under the owner's current stamp on it.
    /// A pass swaps it in: the key routes on the staged slate, with its new
    /// rows, under the receipt this run earned. The key and the staged slate
    /// are re-read after the probes, so a restage or a restamp during the
    /// run swaps nothing. Its manifest stays off routing until both suites
    /// pass, then the slate and approved manifest commit together.
    #[allow(clippy::too_many_arguments)]
    pub fn qualify_staged_connector_slate(
        &self,
        owner: &AuthenticatedOwner,
        id: &EntityId,
        manifest: ResolvedConnectorManifest,
        expected_revision: &str,
        manifest_suite: &dyn ConnectorManifestQualifier,
        connector: &dyn QualificationConnector,
        plan: &QualificationPlan,
        oracle: &dyn GroundingOracle,
        at: u64,
    ) -> std::result::Result<(ConnectorKeyRecord, QualificationReport), ConnectorQualificationError>
    {
        validate_staged_manifest(&manifest, expected_revision)?;
        let (before, staged_id, stamped_revision, manifest_hash, schemas) = {
            let txn = self.store.env.read_txn().map_err(Error::from)?;
            let (record, staged_id, staged) =
                self.stamped_staged_slate_in_txn(&txn, id, expected_revision)?;
            if crate::gate::resolve_policy_manifest(&self.store, &txn)?.is_fail_closed() {
                return Err(invalid_body("connector admission policy is unavailable").into());
            }
            (
                record,
                staged_id,
                staged.revision(),
                staged.manifest_hash(),
                staged
                    .resolved_schemas()
                    .ok_or_else(|| invalid_body("resolved connector schemas required"))?,
            )
        };
        let manifest_report = if before.retained_manifest.as_ref() != Some(&manifest) {
            Some(qualify_staged_manifest(
                manifest_suite,
                &manifest,
                expected_revision,
            )?)
        } else {
            None
        };
        let report = qualify_connector_with_schemas(connector, plan, oracle, Some(&schemas))?;
        let mut wtxn = self.store.env.write_txn()?;
        let (record, current_id, staged) =
            self.stamped_staged_slate_in_txn(&wtxn, id, expected_revision)?;
        if record.retained_manifest != before.retained_manifest
            || record.pending_manifest != before.pending_manifest
            || record.admission_epoch != before.admission_epoch
        {
            return Err(Error::ConcurrentWrite("connector manifest candidate").into());
        }
        if current_id != staged_id
            || staged.revision() != stamped_revision
            || staged.manifest_hash() != manifest_hash
            || staged.tool_names() != report.tools.iter().map(|tool| tool.name.as_str()).collect()
        {
            return Err(invalid_body("connector staged slate changed during qualification").into());
        }
        let receipt = ConnectorQualificationReceipt::new(
            report.report_hash.clone(),
            expected_revision.to_owned(),
            manifest_hash,
            at,
        )?;
        let (swapped, counts) = self.swap_staged_slate_in_txn(
            &mut wtxn,
            owner,
            id,
            record,
            (staged_id, &staged),
            receipt,
            (manifest, manifest_report),
            "gate.connector_key.qualify_staged",
            at,
        )?;
        wtxn.commit().map_err(Error::from)?;
        for (quota, measured) in counts {
            self.measure_connector_manifest_entries(quota, measured);
        }
        self.measure_connector_key_shape(&swapped);
        Ok((swapped, report))
    }

    /// CONNECTOR-QUALIFY = A on a staged slate: the owner attests the slate
    /// staged beside admitted key `id` in place of the suite, as
    /// [`Self::attest_connector_key`] attests a pending key, and it swaps in
    /// under an owner-attested receipt. His current stamp on it stands as
    /// the condition.
    pub fn attest_staged_connector_slate(
        &self,
        owner: &AuthenticatedOwner,
        id: &EntityId,
        manifest: ResolvedConnectorManifest,
        expected_revision: &str,
        at: u64,
    ) -> Result<ConnectorKeyRecord> {
        validate_staged_manifest(&manifest, expected_revision)?;
        let mut wtxn = self.store.env.write_txn()?;
        let (record, staged_id, staged) =
            self.stamped_staged_slate_in_txn(&wtxn, id, expected_revision)?;
        let manifest_report = if record.retained_manifest.as_ref() != Some(&manifest) {
            Some(qualify_staged_manifest(
                &OwnerAttestedManifestQualifier { owner },
                &manifest,
                expected_revision,
            )?)
        } else {
            None
        };
        let mut digest = blake3::Hasher::new();
        digest.update(OWNER_ATTESTED_QUALIFICATION_SUITE.as_bytes());
        digest.update(owner.decision_id().to_hex().as_bytes());
        digest.update(&staged.manifest_hash());
        digest.update(&staged.grant_hash());
        let receipt = ConnectorQualificationReceipt::owner_attested(
            digest.finalize().to_hex().to_string(),
            expected_revision.to_owned(),
            staged.manifest_hash(),
            at,
        )?;
        let (swapped, counts) = self.swap_staged_slate_in_txn(
            &mut wtxn,
            owner,
            id,
            record,
            (staged_id, &staged),
            receipt,
            (manifest, manifest_report),
            "gate.connector_key.owner_attest_staged",
            at,
        )?;
        wtxn.commit()?;
        for (quota, measured) in counts {
            self.measure_connector_manifest_entries(quota, measured);
        }
        self.measure_connector_key_shape(&swapped);
        Ok(swapped)
    }

    /// Admitted key `id` at `expected_revision`, with the slate staged
    /// beside its routing one, when the owner's stamp on that slate holds.
    fn stamped_staged_slate_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        expected_revision: &str,
    ) -> Result<(ConnectorKeyRecord, EntityId, ConnectorGrantSlate)> {
        let record =
            read_connector_key_in_txn(&self.store, txn, id)?.ok_or(Error::EntityNotFound)?;
        if !matches!(
            record.status,
            ConnectorKeyStatus::Active | ConnectorKeyStatus::Suspended
        ) || record.catalog.is_none()
            || record.protocol_revision.as_deref() != Some(expected_revision)
        {
            return Err(invalid_body("connector not admitted at this revision"));
        }
        let staged_id = record
            .staged_slate_ref
            .ok_or_else(|| invalid_body("connector has no staged slate"))?;
        let staged = read_connector_slate_in_txn(self, txn, staged_id)?
            .ok_or_else(|| invalid_body("connector staged slate missing"))?;
        require_pack_qualification(self, txn, &record, &staged, expected_revision)?;
        if staged.owner_actor().is_none() || staged.revision() == 0 || !staged.stamp_holds() {
            return Err(invalid_body("connector staged slate not stamped"));
        }
        Ok((record, staged_id, staged))
    }

    /// `staged` (stored as `staged_id`) replaces the slate admitted key `id`
    /// routes on, under `receipt`. Its per-grant keys carry or retire
    /// against it.
    #[allow(clippy::too_many_arguments)]
    fn swap_staged_slate_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        id: &EntityId,
        record: ConnectorKeyRecord,
        (staged_id, staged): (EntityId, &ConnectorGrantSlate),
        receipt: ConnectorQualificationReceipt,
        (manifest, manifest_report): (ResolvedConnectorManifest, Option<String>),
        op: &'static str,
        at: u64,
    ) -> Result<(ConnectorKeyRecord, [(u64, u64); 3])> {
        let actor = owner.revalidate_in_txn(self, wtxn)?;
        crate::memory::verify_deletion_authority_in_txn(
            self,
            wtxn,
            actor,
            crate::edge::EdgeActorClass::Human,
        )
        .map_err(|_| invalid_body("connector manifest owner binding required"))?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, wtxn)?;
        if policy.is_fail_closed() {
            return Err(invalid_body("connector admission policy is unavailable"));
        }
        let holder = record.actor_entity_ref.as_ref().map(EntityId::to_hex);
        let counts =
            manifest.admission_counts(policy.connector_admission.effective(holder.as_deref()));
        let manifest_changed = manifest_report.is_some();
        let manifest_receipt = manifest_report
            .map(|report| {
                ConnectorQualificationReceipt::new(
                    report,
                    receipt.protocol_revision.clone(),
                    manifest.hash()?,
                    at,
                )
            })
            .transpose()?;
        let admission_epoch = record
            .admission_epoch
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("connector admission epoch"))?;
        let swapped = ConnectorKeyRecord {
            catalog: slate_catalog(record.catalog.clone(), staged),
            slate_ref: Some(staged_id),
            slate_revision: Some(staged.revision()),
            staged_slate_ref: None,
            admission_epoch,
            qualification_receipt: Some(receipt),
            ..record
        };
        let approved = ConnectorKeyRecord {
            qualification_receipt: manifest_receipt
                .or_else(|| swapped.qualification_receipt.clone()),
            retained_manifest: Some(manifest),
            pending_manifest: None,
            ..swapped.clone()
        };
        approved.validate()?;
        rewrite_connector_key_in_txn(&self.store, wtxn, id, &approved)?;
        append_connector_key_op_record(
            &self.store,
            wtxn,
            id,
            op,
            if manifest_changed {
                &swapped
            } else {
                &approved
            },
            policy.read_frontier_hash()?,
            at,
        )?;
        if manifest_changed {
            append_connector_key_op_record(
                &self.store,
                wtxn,
                id,
                "gate.connector_key.manifest_approve",
                &approved,
                policy.read_frontier_hash()?,
                at,
            )?;
        }
        self.sync_derived_keys_in_txn(wtxn, &approved, at)?;
        Ok((approved, counts))
    }
}
